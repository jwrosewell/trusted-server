//! An endpoint that reports the permissions resolved for a request.
//!
//! The permission model decides what a deployment may do for a given visitor,
//! and until now that decision was only observable in its effects: a provider
//! ran or it did not, an Edge Cookie was written or it was not. This endpoint
//! makes the decision itself readable, which is what an operator needs to
//! answer "why did nothing happen for this visitor".
//!
//! # What it reports, and the honest caveat
//!
//! It reports the permissions for **its own request**, not for the page request
//! that preceded it. Those are two different requests and the endpoint cannot
//! see the earlier one.
//!
//! In practice they agree, because the resolution depends only on things that
//! are the same for both: the visitor's country and region, the consent and
//! opt-out signals carried on the request, and the deployment's rules. A page
//! request and a fetch from that page carry the same cookies and reach the same
//! geo, so they resolve the same way.
//!
//! They can disagree, and the response says so rather than implying a guarantee.
//! A signal that changed between the two requests, a consent banner that wrote a
//! cookie after the page loaded, or a different geo answer will all produce a
//! different result. The `scope` field states this in the response so a reader
//! is not misled by a value that looks authoritative for the page.

use error_stack::{Report, ResultExt as _};
use http::{HeaderValue, Response, header};
use serde::Serialize;

use crate::ec::EcContext;
use crate::error::TrustedServerError;
use crate::permissions::Permission;
use crate::settings::Settings;
use edgezero_core::body::Body as EdgeBody;

/// Canonical path of the permissions endpoint.
///
/// Lives in the internal `/_ts/` namespace shared by the other Trusted Server
/// routes. Adapters register this path.
pub const PERMISSIONS_PATH: &str = "/_ts/permissions";

/// One permission and whether it is set for this request.
#[derive(Debug, Serialize)]
pub struct PermissionReport {
    /// The Privacy Taxonomy Data Use identifier, for example
    /// `marketing.advertising.first_party.contextual`.
    pub id: &'static str,
    /// Whether this permission is set for this request.
    pub set: bool,
}

/// Where the country and region used for the decision came from.
#[derive(Debug, Serialize)]
pub struct GeoReport {
    /// The country the geo provider returned, if any.
    pub country: Option<String>,
    /// The region the geo provider returned, if any.
    pub region: Option<String>,
    /// Whether the geo provider returned anything at all. When this is false
    /// the deployment's configured default country decided the baseline, which
    /// is the common case on an adapter with no geo provider wired.
    pub resolved: bool,
    /// The deployment's configured fallback, used when the provider returns
    /// nothing or returns a place with no rule.
    pub default_country: Option<String>,
}

/// The response body.
#[derive(Debug, Serialize)]
pub struct PermissionsResponse {
    /// What this answer describes, stated so a reader does not take it as a
    /// guarantee about the page request.
    pub scope: &'static str,
    /// Where the decision's country and region came from.
    pub geo: GeoReport,
    /// Every modeled permission and whether it is set.
    pub permissions: Vec<PermissionReport>,
    /// How many permissions are set.
    pub set_count: usize,
    /// How many permissions the model knows about.
    pub total_count: usize,
    /// Whether the configured Edge Cookie provider's required permissions are
    /// set. False here with permissions set means the provider requires
    /// something this visitor has not granted.
    pub edge_cookie_allowed: bool,
}

/// Builds the report for a request from its already-resolved context.
///
/// Reads the state the request pipeline resolved rather than resolving again,
/// so the report cannot disagree with the decision the request actually acted
/// on. That matters: a second resolution could differ if anything it reads
/// changed in between, and a diagnostic that disagrees with the behaviour it
/// describes is worse than none.
#[must_use]
pub fn build_report(settings: &Settings, ec_context: &EcContext) -> PermissionsResponse {
    let state = ec_context.permissions();
    let geo_info = ec_context.geo_info();

    let permissions: Vec<PermissionReport> = Permission::all()
        .map(|permission| PermissionReport {
            id: permission.as_str(),
            set: state.is_set(permission),
        })
        .collect();

    let set_count = permissions.iter().filter(|entry| entry.set).count();
    let total_count = permissions.len();

    PermissionsResponse {
        scope: "Permissions resolved for this request. A page request from the \
                same visitor resolves the same way when its signals and geo are \
                the same, which is the ordinary case, but this is not a record \
                of the page request itself.",
        geo: GeoReport {
            country: geo_info.map(|info| info.country.clone()),
            region: geo_info.and_then(|info| info.region.clone()),
            resolved: geo_info.is_some(),
            default_country: settings.geo.default_country.clone(),
        },
        permissions,
        set_count,
        total_count,
        edge_cookie_allowed: ec_context.ec_allowed(),
    }
}

/// Serves the permissions report as JSON.
///
/// # Errors
///
/// Returns an error when the report cannot be serialized, which cannot happen
/// for the types above and is handled rather than unwrapped so a serialization
/// change can never panic a request.
pub fn handle_permissions(
    settings: &Settings,
    ec_context: &EcContext,
    query: Option<&str>,
) -> Result<Response<EdgeBody>, Report<TrustedServerError>> {
    let report = build_report(settings, ec_context);

    // `?view=html` renders the same report as a readable panel, so it can be
    // embedded in a page or opened directly by an operator. The JSON stays the
    // default because it is the machine-readable form and the one a caller
    // integrating with this will want.
    if query.is_some_and(wants_html_view) {
        return Ok(html_response(&report));
    }
    let json = serde_json::to_string(&report).change_context(TrustedServerError::Proxy {
        message: "Failed to serialize the permissions report".to_string(),
    })?;

    let mut response = Response::new(EdgeBody::from(json));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    // The answer is specific to one visitor's signals, so it must never be
    // stored by a shared cache and served to a different visitor.
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(response)
}

/// Whether a query string asks for the readable view.
fn wants_html_view(query: &str) -> bool {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .any(|(key, value)| key == "view" && value.eq_ignore_ascii_case("html"))
}

/// Escapes text for embedding in HTML.
///
/// Every value rendered below comes from the deployment's own configuration or
/// from the permission model's fixed identifiers, so none of it is attacker
/// controlled today. It is escaped anyway, because a panel that renders
/// request-derived values unescaped is one config change away from being a
/// vulnerability, and the cost of doing it now is nothing.
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Renders the report as a self-contained panel.
fn html_response(report: &PermissionsResponse) -> Response<EdgeBody> {
    let rows: String = report
        .permissions
        .iter()
        .map(|entry| {
            let (mark, class) = if entry.set {
                ("SET", "s")
            } else {
                ("unset", "u")
            };
            format!(
                "<tr class=\"{class}\"><td>{mark}</td><td>{}</td></tr>",
                escape(entry.id)
            )
        })
        .collect();

    let geo = match (&report.geo.country, &report.geo.region) {
        (Some(country), Some(region)) => format!("{}/{}", escape(country), escape(region)),
        (Some(country), None) => escape(country),
        _ => format!(
            "none resolved, default {}",
            report
                .geo
                .default_country
                .as_deref()
                .map_or_else(|| "unset".to_owned(), escape)
        ),
    };

    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Permissions</title><style>body{{font:13px/1.5 -apple-system,Segoe UI,Arial,sans-serif;margin:0;padding:12px;color:#222}}h1{{font-size:15px;margin:0 0 2px}}p{{margin:0 0 10px;color:#666;font-size:11px}}table{{border-collapse:collapse;width:100%}}td{{padding:2px 6px;border-bottom:1px solid #eee}}td:first-child{{width:44px;font-weight:700;font-size:10px;letter-spacing:.04em}}tr.s td:first-child{{color:#0a7d32}}tr.u td:first-child{{color:#bbb}}tr.u td{{color:#999}}.k{{color:#666;font-size:11px;margin-bottom:10px}}</style><h1>Permissions for this request</h1><p>{scope}</p><div class=\"k\">Location: {geo} &middot; {set} of {total} set &middot; Edge Cookie allowed: {ec}</div><table>{rows}</table>",
        scope = escape(report.scope),
        geo = geo,
        set = report.set_count,
        total = report.total_count,
        ec = if report.edge_cookie_allowed {
            "yes"
        } else {
            "no"
        },
        rows = rows,
    );

    let mut response = Response::new(EdgeBody::from(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_modeled_permission_is_reported() {
        let settings = Settings::default();
        let context = EcContext::default();

        let report = build_report(&settings, &context);

        assert_eq!(
            report.permissions.len(),
            Permission::all().count(),
            "the report must name every permission the model knows about, not \
             only the ones that are set, or a reader cannot tell an absent \
             permission from an unset one"
        );
        assert_eq!(
            report.total_count,
            report.permissions.len(),
            "should count what it reports"
        );
    }

    #[test]
    fn set_count_matches_the_entries_marked_set() {
        let settings = Settings::default();
        let context = EcContext::default();

        let report = build_report(&settings, &context);

        let counted = report.permissions.iter().filter(|entry| entry.set).count();
        assert_eq!(
            report.set_count, counted,
            "the summary count must agree with the entries, or the two halves \
             of the response contradict each other"
        );
    }

    #[test]
    fn geo_reports_unresolved_when_no_provider_answered() {
        let settings = Settings::default();
        let context = EcContext::default();

        let report = build_report(&settings, &context);

        assert!(
            !report.geo.resolved,
            "with no geo provider the report must say so, because that is the \
             reason a deployment sees the default baseline rather than a bug"
        );
        assert!(
            report.geo.country.is_none(),
            "should report no country when none was resolved"
        );
    }

    #[test]
    fn the_response_serializes_to_json() {
        let settings = Settings::default();
        let context = EcContext::default();

        let response = handle_permissions(&settings, &context, None)
            .expect("should serialize a report built from a default context");

        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json",
            "should declare JSON"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store",
            "a per-visitor answer must never be stored by a shared cache"
        );
    }

    #[test]
    fn the_html_view_is_served_only_when_asked_for() {
        let settings = Settings::default();
        let context = EcContext::default();

        let json = handle_permissions(&settings, &context, Some("other=1"))
            .expect("should serve JSON for an unrelated query");
        assert_eq!(
            json.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json",
            "an unrelated query must not switch the format"
        );

        let html = handle_permissions(&settings, &context, Some("view=html"))
            .expect("should serve the readable view when asked");
        assert_eq!(
            html.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8",
            "should serve HTML when the query asks for it"
        );
    }

    #[test]
    fn html_values_are_escaped() {
        assert_eq!(
            escape("<script>&\"x\""),
            "&lt;script&gt;&amp;&quot;x&quot;",
            "markup characters must not survive into the panel"
        );
    }
}
