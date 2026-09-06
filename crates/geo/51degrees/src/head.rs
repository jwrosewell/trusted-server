//! Client hint delegation, written into the page the publisher serves.
//!
//! # Why this cannot be done any other way
//!
//! High entropy client hints are not sent to a third party unless the top level
//! page delegates them. There are two ways to delegate: `Permissions-Policy`
//! with `Accept-CH` response headers, or a `Delegate-CH` meta tag in the served
//! markup. The specification is explicit that **a `Delegate-CH` meta tag
//! injected by JavaScript is ignored**, so a publisher cannot fix this with a
//! tag manager, and a script in the page cannot fix it either. It has to be in
//! the HTML as it is served.
//!
//! That is the byte stream Trusted Server is already rewriting, so this is one
//! of the few places the problem can be solved at all. The 51Degrees Prebid
//! module can only look for the tag and warn when it is missing, which is
//! exactly what it does, because a module inside the page has no other option.
//!
//! # What is emitted, and why only four hints
//!
//! The content follows 51Degrees' own published example verbatim in shape:
//! lower case hint names, a space, the origin, separated by semicolons. Only
//! the four high entropy hints are delegated. `Sec-CH-UA` and
//! `Sec-CH-UA-Mobile` are low entropy and are sent to third parties already, so
//! delegating them would add noise to the page for no effect.
//!
//! # What is not emitted here
//!
//! `Critical-CH`, which is what makes the browser retry the current navigation
//! rather than wait for the next one, is a response header and cannot be a meta
//! tag. It is not set anywhere yet.

use trusted_server_core::integrations::{IntegrationHeadInjector, IntegrationHtmlContext};

use crate::PROVIDER_ID;

/// The high entropy hints 51Degrees reads, in the order its own example lists
/// them.
///
/// Lower case because that is how the vendor's example writes them and how the
/// specification's examples write them.
const DELEGATED_HINTS: &[&str] = &[
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-model",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
];

/// Writes the client hint delegation into the head of every page.
#[derive(Debug)]
pub struct FiftyOneDegreesHeadInjector {
    /// The origin the hints are delegated to, for example
    /// `https://cloud.51degrees.com`. Derived from the configured endpoint, so
    /// a deployment using its own private cloud delegates to that instead.
    endpoint_origin: Option<String>,
}

impl FiftyOneDegreesHeadInjector {
    /// Creates the injector for a configured endpoint.
    ///
    /// An endpoint that is not a URL, or has no host, yields an injector that
    /// writes nothing. Startup validation refuses such an endpoint anyway, so
    /// this is the belt rather than the decision.
    #[must_use]
    pub fn new(endpoint: &str) -> Self {
        let endpoint_origin = url::Url::parse(endpoint).ok().and_then(|url| {
            let host = url.host_str()?;
            let scheme = url.scheme();
            Some(url.port().map_or_else(
                || format!("{scheme}://{host}"),
                |port| format!("{scheme}://{host}:{port}"),
            ))
        });
        Self { endpoint_origin }
    }

    /// The delegation tag for one origin.
    #[must_use]
    fn delegation_tag(origin: &str) -> String {
        let pairs = DELEGATED_HINTS
            .iter()
            .map(|hint| format!("{hint} {origin}"))
            .collect::<Vec<_>>()
            .join("; ");
        format!(r#"<meta http-equiv="Delegate-CH" content="{pairs}">"#)
    }

    /// Whether the endpoint is the page's own origin, in which case there is no
    /// third party to delegate to.
    ///
    /// Rare in practice, because a publisher group runs its services on a
    /// corporate domain rather than on a brand's domain, but writing a tag that
    /// delegates a page's hints to itself would be noise a later reader mistakes
    /// for a mistake.
    #[must_use]
    fn is_same_origin(origin: &str, ctx: &IntegrationHtmlContext<'_>) -> bool {
        origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .is_some_and(|host| host.eq_ignore_ascii_case(ctx.request_host))
    }
}

impl IntegrationHeadInjector for FiftyOneDegreesHeadInjector {
    fn integration_id(&self) -> &'static str {
        PROVIDER_ID
    }

    fn head_inserts(&self, ctx: &IntegrationHtmlContext<'_>) -> Vec<String> {
        let Some(origin) = self.endpoint_origin.as_deref() else {
            return Vec::new();
        };
        if Self::is_same_origin(origin, ctx) {
            return Vec::new();
        }
        vec![Self::delegation_tag(origin)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusted_server_core::integrations::IntegrationDocumentState;

    fn context(request_host: &str) -> IntegrationHtmlContext<'_> {
        IntegrationHtmlContext {
            request_host,
            request_scheme: "https",
            origin_host: "origin.example",
            document_state: DOCUMENT_STATE.get_or_init(IntegrationDocumentState::default),
        }
    }

    static DOCUMENT_STATE: std::sync::OnceLock<IntegrationDocumentState> =
        std::sync::OnceLock::new();

    #[test]
    fn the_tag_matches_the_shape_the_vendor_publishes() {
        let injector = FiftyOneDegreesHeadInjector::new("https://cloud.51degrees.com/api/v4/json");

        let inserts = injector.head_inserts(&context("politico.example"));

        assert_eq!(
            inserts,
            vec![
                r#"<meta http-equiv="Delegate-CH" content="sec-ch-ua-full-version-list https://cloud.51degrees.com; sec-ch-ua-model https://cloud.51degrees.com; sec-ch-ua-platform https://cloud.51degrees.com; sec-ch-ua-platform-version https://cloud.51degrees.com">"#
                    .to_owned()
            ],
            "the shape is taken from 51Degrees' own published example, and a browser \
             that does not recognise the content ignores the whole tag silently"
        );
    }

    #[test]
    fn the_delegation_follows_the_configured_endpoint() {
        // A publisher group running its own private cloud delegates to that,
        // not to the public one.
        let injector =
            FiftyOneDegreesHeadInjector::new("https://cloud.publisher-group.example/api/v4/json");

        let inserts = injector.head_inserts(&context("politico.example"));

        assert!(
            inserts[0].contains("https://cloud.publisher-group.example"),
            "got {}",
            inserts[0]
        );
        assert!(
            !inserts[0].contains("51degrees"),
            "a private deployment must not delegate to the public cloud"
        );
    }

    #[test]
    fn only_the_high_entropy_hints_are_delegated() {
        let injector = FiftyOneDegreesHeadInjector::new("https://cloud.51degrees.com/api/v4/json");

        let tag = injector
            .head_inserts(&context("politico.example"))
            .remove(0);

        assert!(
            !tag.contains("sec-ch-ua-mobile"),
            "Sec-CH-UA-Mobile is low entropy and reaches third parties already, so \
             delegating it adds noise to every page for no effect"
        );
        assert!(tag.contains("sec-ch-ua-model"), "the model is the point");
    }

    #[test]
    fn nothing_is_written_when_the_endpoint_is_the_pages_own_origin() {
        // There is no third party to delegate to, and a tag delegating a page's
        // hints to itself is noise a later reader takes for a mistake.
        let injector = FiftyOneDegreesHeadInjector::new("https://politico.example/api/v4/json");

        assert!(
            injector
                .head_inserts(&context("politico.example"))
                .is_empty()
        );
    }

    #[test]
    fn nothing_is_written_for_an_endpoint_that_is_not_a_url() {
        let injector = FiftyOneDegreesHeadInjector::new("not-a-url");

        assert!(
            injector
                .head_inserts(&context("politico.example"))
                .is_empty()
        );
    }

    #[test]
    fn a_port_is_carried_into_the_origin() {
        // A private cloud on a non-default port is still one origin, and an
        // origin missing its port delegates to a different one.
        let injector = FiftyOneDegreesHeadInjector::new("http://127.0.0.1:8080/api/v4/json");

        let tag = injector
            .head_inserts(&context("politico.example"))
            .remove(0);

        assert!(tag.contains("http://127.0.0.1:8080"), "got {tag}");
    }
}
