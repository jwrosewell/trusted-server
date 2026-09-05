//! 51Degrees IP Intelligence geo provider.
//!
//! Resolves a request's country from its client address by calling a
//! 51Degrees cloud service over HTTP. The service is expected to run beside
//! the appliance, in the same deployment, so the call is over loopback rather
//! than the internet.
//!
//! # What this provider decides, and why the distinction matters
//!
//! The permission model treats "no location" and "the lookup failed" as
//! different answers, and this provider is careful to return the right one.
//!
//! - A successful response with a usable country returns [`GeoInfo`].
//! - A successful response with no usable country returns `Ok(None)`, which
//!   the caller reads as no location, so the permission policy's declared
//!   top-node jurisdiction applies.
//! - A transport failure, a non-success status or an unreadable body returns
//!   an error, which the caller reads as a failed lookup, so the consent gates
//!   fail closed and permissions resolve to the requires-signal floor.
//!
//! Collapsing the last two would be the worst possible bug here, because an
//! outage would quietly adopt the policy's default rather than failing safe.
//!
//! # Two properties of the service that will catch a reader out
//!
//! **Missing is spelled `Unknown`, not absent.** The service returns the
//! string `Unknown` for a property it cannot determine, so a check that only
//! tests for an empty or absent value treats it as a real answer. Every string
//! read here goes through [`usable`], which rejects it.
//!
//! **The region is a name, not a code.** The service returns `England` where
//! [`GeoInfo::region`] is documented as an ISO 3166-2 subdivision code without
//! the country prefix, which is what the permission rules match on. Writing a
//! name into that field would silently mis-key every region rule, so this
//! provider leaves the region unset and says so once per process. Populating
//! it needs a name-to-code mapping that nothing here owns yet.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use edgezero_core::body::Body as EdgeBody;
use error_stack::{Report, ResultExt as _};
use serde::{Deserialize, Serialize};
use trusted_server_core::error::TrustedServerError;
use trusted_server_core::integrations::{IntegrationBuilder, IntegrationRegistration};
use trusted_server_core::platform::{
    GeoInfo, PlatformBackendSpec, PlatformError, PlatformGeo, PlatformHttpRequest, RuntimeServices,
};
use trusted_server_core::settings::Settings;
use validator::Validate;

/// Identifier for this provider, used as the `[geo] provider` selector value
/// and as the backend discriminator.
pub const GEO_PROVIDER_ID: &str = "fiftyone_degrees";

/// The value the service uses for a property it could not determine.
const UNKNOWN: &str = "Unknown";

/// Cap on the response body read from the service.
///
/// The `areas` property alone is a multipolygon that runs to tens of
/// kilobytes, so this is generous rather than tight. It exists so a wrong
/// endpoint cannot grow the process heap without bound.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Said once per process, not once per request, because the region gap is a
/// property of the integration rather than of any one visitor.
static REGION_UNMAPPED_WARNED: OnceLock<()> = OnceLock::new();

/// Configuration for the 51Degrees geo provider.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct FiftyOneDegreesGeoConfig {
    /// Whether this provider is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// The full URL of the JSON endpoint, including any resource key the
    /// deployment requires in the path.
    ///
    /// The self-hosted container is single-tenant and authorises by licence
    /// key at start-up, so its endpoint carries no key, for example
    /// `http://127.0.0.1:8080/api/v4/json`. A multi-tenant service keys the
    /// path instead, for example
    /// `https://cloud.example.com/api/v4/<resource key>.json`. Both are just a
    /// URL to this provider, which is why there is no separate key setting to
    /// get wrong or to leak into a log.
    #[validate(url)]
    pub endpoint: String,

    /// How long to wait for the service before giving up.
    ///
    /// A geo lookup sits in front of the permission decision, so it is on the
    /// critical path of every request. The default is deliberately short.
    #[serde(default = "default_timeout_ms")]
    #[validate(range(min = 1, max = 10_000))]
    pub timeout_ms: u32,
}

impl trusted_server_core::settings::IntegrationConfig for FiftyOneDegreesGeoConfig {
    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

const fn default_enabled() -> bool {
    true
}

const fn default_timeout_ms() -> u32 {
    500
}

/// Returns the value when the service actually determined it.
///
/// Rejects the empty string and the service's own `Unknown` spelling, which is
/// a present-looking value that means absent.
#[must_use]
fn usable(value: Option<&str>) -> Option<&str> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case(UNKNOWN))
}

/// Reads a string property out of the response's `ip` section.
fn ip_string<'a>(body: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    usable(body.get("ip")?.get(name)?.as_str())
}

/// Reads a number property out of the response's `ip` section.
fn ip_number(body: &serde_json::Value, name: &str) -> Option<f64> {
    body.get("ip")?.get(name)?.as_f64()
}

/// Builds [`GeoInfo`] from a decoded service response.
///
/// Returns `None` when the response carries no usable country, which is a
/// resolved-nothing answer rather than a failure.
#[must_use]
pub fn geo_from_response(body: &serde_json::Value) -> Option<GeoInfo> {
    let country = ip_string(body, "countrycode")?.to_owned();

    // The service answers with a region name and `GeoInfo::region` is
    // documented as an ISO 3166-2 subdivision code, which the permission rules
    // match on. A name in that field would not match any rule and would look
    // like a resolved region while behaving like an unresolved one, so it is
    // deliberately dropped until a mapping exists.
    if ip_string(body, "region").is_some() {
        REGION_UNMAPPED_WARNED.get_or_init(|| {
            log::warn!(
                "51Degrees geo: the service returns a region name and the permission model \
                 matches ISO 3166-2 subdivision codes, so the region is left unset. Country \
                 rules apply; region rules do not."
            );
        });
    }

    Some(GeoInfo {
        city: usable(ip_string(body, "town"))
            .unwrap_or_default()
            .to_owned(),
        country,
        continent: usable(ip_string(body, "continent"))
            .unwrap_or_default()
            .to_owned(),
        latitude: ip_number(body, "latitude").unwrap_or_default(),
        longitude: ip_number(body, "longitude").unwrap_or_default(),
        metro_code: 0,
        region: None,
        asn: None,
    })
}

/// Geo provider backed by a 51Degrees cloud service.
#[derive(Debug)]
pub struct FiftyOneDegreesGeo {
    config: FiftyOneDegreesGeoConfig,
}

impl FiftyOneDegreesGeo {
    /// Creates a provider from its configuration.
    #[must_use]
    pub const fn new(config: FiftyOneDegreesGeoConfig) -> Self {
        Self { config }
    }

    /// Builds the request URL for one client address.
    ///
    /// The evidence goes in as the plain `client-ip` query parameter. It is
    /// **not** `query.client-ip`: in the 51Degrees convention `query.` names
    /// where a piece of evidence came from, and the parameter itself carries
    /// no prefix. Sending the prefixed form is accepted and silently ignored,
    /// and the answer then describes whoever opened the connection, which over
    /// loopback is this machine. That mistake is invisible in testing because
    /// a wrong answer looks exactly like a right one.
    fn request_url(&self, client_ip: IpAddr) -> Result<String, Report<PlatformError>> {
        let mut url = url::Url::parse(&self.config.endpoint)
            .change_context(PlatformError::Geo)
            .attach_with(|| format!("endpoint is not a URL: {}", self.config.endpoint))?;
        url.query_pairs_mut()
            .append_pair("client-ip", &client_ip.to_string());
        Ok(url.into())
    }

    /// Builds the backend registration for the configured endpoint.
    ///
    /// Core has an internal helper that does this for its own integrations,
    /// but it is crate-private, so a vendor crate outside core builds the spec
    /// itself. The discriminator keeps this provider's dynamic backend
    /// distinct from any other caller that happens to target the same host.
    fn backend_spec(&self) -> Result<PlatformBackendSpec, Report<PlatformError>> {
        let parsed = url::Url::parse(&self.config.endpoint)
            .change_context(PlatformError::Geo)
            .attach_with(|| format!("endpoint is not a URL: {}", self.config.endpoint))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| Report::new(PlatformError::Geo).attach("endpoint has no host"))?
            .to_owned();
        let timeout = core::time::Duration::from_millis(u64::from(self.config.timeout_ms));
        Ok(PlatformBackendSpec {
            scheme: parsed.scheme().to_owned(),
            host,
            port: parsed.port(),
            host_header_override: None,
            certificate_check: true,
            first_byte_timeout: timeout,
            between_bytes_timeout: timeout,
            discriminator: Some(GEO_PROVIDER_ID.to_owned()),
        })
    }
}

#[async_trait(?Send)]
impl PlatformGeo for FiftyOneDegreesGeo {
    async fn lookup(
        &self,
        client_ip: Option<IpAddr>,
        services: &RuntimeServices,
    ) -> Result<Option<GeoInfo>, Report<PlatformError>> {
        if !self.config.enabled {
            return Ok(None);
        }

        // No address is nothing to look up rather than a failure, so the
        // policy's declared default applies rather than the failure floor.
        let Some(client_ip) = client_ip else {
            return Ok(None);
        };

        let url = self.request_url(client_ip)?;
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(&url)
            .header(http::header::ACCEPT, "application/json")
            .body(EdgeBody::empty())
            .change_context(PlatformError::Geo)
            .attach("could not build the geo request")?;

        let backend = services
            .backend()
            .ensure(&self.backend_spec()?)
            .change_context(PlatformError::Geo)
            .attach("could not resolve a backend for the geo endpoint")?;

        let response = services
            .http_client()
            .send(PlatformHttpRequest::new(request, backend))
            .await
            .change_context(PlatformError::Geo)
            .attach("the geo service did not answer")?;

        let status = response.response.status();
        if !status.is_success() {
            return Err(Report::new(PlatformError::Geo)
                .attach(format!("the geo service answered {status}")));
        }

        let bytes = response
            .response
            .into_body()
            .into_bytes_bounded(MAX_RESPONSE_BYTES)
            .await
            .change_context(PlatformError::Geo)
            .attach("could not read the geo response body")?;

        let body: serde_json::Value = serde_json::from_slice(&bytes)
            .change_context(PlatformError::Geo)
            .attach("the geo service did not return JSON")?;

        Ok(geo_from_response(&body))
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Where this module came from, reported when two modules claim one id.
const SOURCE: &str = "trusted-server-geo-51degrees";

/// Reads this provider's configuration block, when the deployment has one.
fn read_config(
    settings: &Settings,
) -> Result<Option<FiftyOneDegreesGeoConfig>, Report<TrustedServerError>> {
    settings.integration_config::<FiftyOneDegreesGeoConfig>(GEO_PROVIDER_ID)
}

/// Declares the geo provider so `[geo] provider` can select it.
///
/// # Errors
///
/// Returns an error when the configuration block cannot be parsed or fails
/// validation.
pub fn register(
    settings: &Settings,
) -> Result<Option<IntegrationRegistration>, Report<TrustedServerError>> {
    let Some(config) = read_config(settings)? else {
        return Ok(None);
    };
    Ok(Some(
        IntegrationRegistration::builder(GEO_PROVIDER_ID)
            .with_geo_provider(Arc::new(FiftyOneDegreesGeo::new(config)))
            .build(),
    ))
}

/// Validates the configuration for deployment and reports whether this module
/// is enabled.
///
/// # Errors
///
/// Returns an error when the configuration block cannot be parsed or fails
/// validation.
pub fn validate(settings: &Settings) -> Result<bool, Report<TrustedServerError>> {
    Ok(read_config(settings)?.is_some())
}

/// The builder an adapter passes to `build_state_with_registrations`.
#[must_use]
pub fn builder() -> IntegrationBuilder {
    IntegrationBuilder::new(GEO_PROVIDER_ID, SOURCE, register, validate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_located_address_resolves_its_country() {
        let body = json!({"ip": {
            "countrycode": "GB",
            "country": "United Kingdom",
            "region": "England",
            "town": "Reading",
            "latitude": 51.45,
            "longitude": -0.97,
        }});

        let geo = geo_from_response(&body).expect("a country should resolve a location");
        assert_eq!(
            geo.country, "GB",
            "should take the ISO alpha-2 country code"
        );
        assert_eq!(geo.city, "Reading", "should take the town as the city");
    }

    #[test]
    fn a_region_name_is_never_written_into_the_iso_code_field() {
        let body = json!({"ip": {"countrycode": "GB", "region": "England"}});

        let geo = geo_from_response(&body).expect("a country should resolve a location");
        assert_eq!(
            geo.region, None,
            "a region name must not be written where the permission rules expect an ISO code"
        );
    }

    #[test]
    fn the_services_unknown_spelling_is_treated_as_absent() {
        let body = json!({"ip": {
            "countrycode": "GB",
            "town": "Unknown",
            "continent": "unknown",
        }});

        let geo = geo_from_response(&body).expect("a country should resolve a location");
        assert_eq!(geo.city, "", "should not report `Unknown` as a town");
        assert_eq!(
            geo.continent, "",
            "should reject the unknown spelling whatever its case"
        );
    }

    #[test]
    fn an_unknown_country_resolves_no_location_rather_than_a_country_called_unknown() {
        let body = json!({"ip": {"countrycode": "Unknown", "town": "Reading"}});

        assert!(
            geo_from_response(&body).is_none(),
            "an undetermined country must resolve no location, so the policy default applies"
        );
    }

    #[test]
    fn a_response_with_no_ip_section_resolves_no_location() {
        let body = json!({"device": {"ismobile": false}});

        assert!(
            geo_from_response(&body).is_none(),
            "a key with no IP intelligence entitlement returns device data only"
        );
    }

    fn settings_with(body: &str) -> Settings {
        Settings::from_toml(&format!(
            r#"
                [[handlers]]
                path = "^/_ts/admin"
                username = "admin"
                password = "admin-pass"

                [publisher]
                domain = "test-publisher.example.com"
                cookie_domain = ".test-publisher.example.com"
                origin_url = "https://origin.test-publisher.example.com"
                proxy_secret = "geo-51degrees-test-proxy-secret"

                [ec]
                passphrase = "test-secret-key-32-bytes-minimum"

                [geo]
                provider = "fiftyone_degrees"

                [integrations.fiftyone_degrees]
                {body}
            "#
        ))
        .expect("should parse the test settings")
    }

    #[test]
    fn the_module_declares_a_geo_provider_the_selector_can_reach() {
        let settings = settings_with(r#"endpoint = "http://127.0.0.1:8080/api/v4/json""#);

        let registration = register(&settings)
            .expect("should read the configuration")
            .expect("should register when a configuration block is present");

        assert_eq!(
            registration.integration_id, GEO_PROVIDER_ID,
            "the module id is what `[geo] provider` names"
        );
        assert!(
            registration.geo_provider.is_some(),
            "declaring no provider would make the selector resolve nothing at startup"
        );
    }

    #[test]
    fn no_configuration_block_declares_nothing() {
        let settings = Settings::from_toml(
            r#"
                [[handlers]]
                path = "^/_ts/admin"
                username = "admin"
                password = "admin-pass"

                [publisher]
                domain = "test-publisher.example.com"
                cookie_domain = ".test-publisher.example.com"
                origin_url = "https://origin.test-publisher.example.com"
                proxy_secret = "geo-51degrees-test-proxy-secret"

                [ec]
                passphrase = "test-secret-key-32-bytes-minimum"

                # Settings refuses an Edge Cookie provider with no geo selector
                # unless the operator acknowledges single-jurisdiction operation,
                # which is the state this test is about.
                [geo]
                assume_single_jurisdiction = true
            "#,
        )
        .expect("should parse settings with no block for this module");

        assert!(
            register(&settings)
                .expect("should read absent configuration")
                .is_none(),
            "a deployment that does not configure this vendor must not get its provider"
        );
        assert!(
            !validate(&settings).expect("should read absent configuration"),
            "should report the module as not enabled"
        );
    }

    #[test]
    fn an_endpoint_that_is_not_a_url_is_refused_at_startup() {
        let settings = settings_with(r#"endpoint = "not-a-url""#);

        assert!(
            validate(&settings).is_err(),
            "a bad endpoint must stop the deploy rather than fail on the first visitor"
        );
    }

    #[test]
    fn the_evidence_parameter_is_unprefixed() {
        let provider = FiftyOneDegreesGeo::new(FiftyOneDegreesGeoConfig {
            enabled: true,
            endpoint: "http://127.0.0.1:8080/api/v4/json".to_owned(),
            timeout_ms: 500,
        });

        let url = provider
            .request_url("2.125.160.216".parse().expect("should parse the address"))
            .expect("should build a URL");

        assert!(
            url.contains("client-ip=2.125.160.216"),
            "the parameter is the bare evidence name, got {url}"
        );
        assert!(
            !url.contains("query.client-ip"),
            "the prefixed form is accepted and ignored, so the answer would describe the caller"
        );
    }
}
