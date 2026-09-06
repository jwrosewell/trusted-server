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

pub mod client;
pub mod device;
pub mod head;
pub mod identity;

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use error_stack::Report;
use serde::{Deserialize, Serialize};
use trusted_server_core::error::TrustedServerError;
use trusted_server_core::integrations::{IntegrationBuilder, IntegrationRegistration};
use trusted_server_core::platform::{GeoInfo, PlatformError, PlatformGeo, RuntimeServices};
use trusted_server_core::settings::Settings;
use validator::Validate;

use crate::client::CloudClient;
use crate::device::FiftyOneDegreesDevice;
use crate::head::FiftyOneDegreesHeadInjector;
use crate::identity::FiftyOneDegreesIdentity;

/// Identifier for this vendor's module.
///
/// One module supplies more than one provider, so this is the value a
/// deployment writes for **both** `[geo] provider` and `[device] provider`,
/// and it names the `[integrations.fiftyone_degrees]` configuration block they
/// share.
pub const PROVIDER_ID: &str = "fiftyone_degrees";

/// Kept as the name the geo selector was introduced under.
pub const GEO_PROVIDER_ID: &str = PROVIDER_ID;

/// Folded into the dynamic backend name, so this crate's calls are not
/// confused with another caller's to the same host.
pub(crate) const BACKEND_DISCRIMINATOR: &str = PROVIDER_ID;

/// The value the service uses for a property it could not determine.
const UNKNOWN: &str = "Unknown";

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
    /// The self-hosted container is single-tenant and authorized by license
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

    /// Whether to ask the service for a 51Degrees identifier as well.
    ///
    /// Off by default, because asking for an identifier is a different act
    /// from asking where a request came from and should be a deployment's
    /// decision rather than a side effect of turning geo on. Switching it on
    /// adds two parameters to the same call and costs no extra round trip.
    #[serde(default)]
    pub identity: bool,

    /// Whether to ask the browser to retry the first navigation carrying its
    /// client hints, by sending `Critical-CH`.
    ///
    /// **On by default.** Without it the first page view of a session is served
    /// blind, with the hints arriving only in time for the second, so the first
    /// auction of every session is priced on a User-Agent alone. With it the
    /// browser reissues the navigation and the first page is priced properly.
    /// The cost is one extra origin fetch at the start of a session, paid once.
    ///
    /// # Why this cannot loop
    ///
    /// The retry is bounded by the hints, not by anything this crate does. A
    /// browser retries only when the named hints were absent from the request,
    /// and the retried request carries them, so the second response satisfies
    /// the check and is rendered. A browser that does not support client hints
    /// at all ignores the header rather than retrying forever.
    ///
    /// Set to `false` on a deployment that would rather serve the first page
    /// immediately and accept a worse first auction.
    #[serde(default = "default_critical_client_hints")]
    pub critical_client_hints: bool,
}

impl trusted_server_core::settings::IntegrationConfig for FiftyOneDegreesGeoConfig {
    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

const fn default_enabled() -> bool {
    true
}

const fn default_critical_client_hints() -> bool {
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
pub(crate) fn usable(value: Option<&str>) -> Option<&str> {
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
                 rules apply, region rules do not."
            );
        });
    }

    Some(GeoInfo {
        city: usable(ip_string(body, "town"))
            .unwrap_or_default()
            .to_owned(),
        country,
        // Never resolved, because the service has no continent property.
        // Established against the live service rather than assumed: asking for
        // `ip.Continent` returns an empty `ip` element, exactly as asking for a
        // property that does not exist does, while `ip.CountryCode` comes back
        // with its value and its null reason. Reading a key that can never be
        // present would be a field that looks supported and is always empty.
        continent: String::new(),
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
    enabled: bool,
    client: Arc<CloudClient>,
}

impl FiftyOneDegreesGeo {
    /// Creates a provider sharing one client, and so one call, with the other
    /// providers this crate supplies.
    #[must_use]
    pub const fn new(enabled: bool, client: Arc<CloudClient>) -> Self {
        Self { enabled, client }
    }
}

#[async_trait(?Send)]
impl PlatformGeo for FiftyOneDegreesGeo {
    async fn lookup(
        &self,
        client_ip: Option<IpAddr>,
        services: &RuntimeServices,
    ) -> Result<Option<GeoInfo>, Report<PlatformError>> {
        if !self.enabled {
            return Ok(None);
        }

        // No address is nothing to look up rather than a failure, so the
        // policy's declared default applies rather than the failure floor.
        let Some(client_ip) = client_ip else {
            return Ok(None);
        };

        // Only the `ip` element of this answer describes the address. See
        // `CloudClient::answer_for_address`, which explains why an entry made
        // for a different `User-Agent` is still the right answer here.
        let answer = self.client.answer_for_address(client_ip, services).await?;
        Ok(geo_from_response(answer.body()))
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
    settings.integration_config::<FiftyOneDegreesGeoConfig>(PROVIDER_ID)
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
    // One client, so the geo and device providers of a single request share
    // one call rather than making one each.
    let client = Arc::new(CloudClient::new(
        config.endpoint.clone(),
        config.timeout_ms,
        config.identity,
    ));
    Ok(Some(
        IntegrationRegistration::builder(PROVIDER_ID)
            // The client hint delegation. It has to be in the served markup,
            // because a browser ignores a Delegate-CH meta tag that JavaScript
            // added, so no script in the page can do this and a publisher
            // cannot do it with a tag manager either.
            .with_head_injector(Arc::new(FiftyOneDegreesHeadInjector::new(&config.endpoint)))
            .with_geo_provider(Arc::new(FiftyOneDegreesGeo::new(
                config.enabled,
                Arc::clone(&client),
            )))
            .with_device_provider(Arc::new(FiftyOneDegreesDevice::new(Arc::clone(&client))))
            .with_ec_provider(Arc::new(FiftyOneDegreesIdentity::new(
                client,
                config.critical_client_hints,
            )))
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
    IntegrationBuilder::new(PROVIDER_ID, SOURCE, register, validate)
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
    fn critical_client_hints_is_on_unless_a_deployment_turns_it_off() {
        // The default decides what every deployment that says nothing gets, so
        // it is asserted rather than left to the serde attribute.
        let configured: FiftyOneDegreesGeoConfig = serde_json::from_value(json!({
            "endpoint": "https://cloud.example.com/api/v4/json"
        }))
        .expect("should read a configuration naming only the endpoint");

        assert!(
            configured.critical_client_hints,
            "without it the first page view of a session is priced on a User-Agent alone"
        );

        let switched_off: FiftyOneDegreesGeoConfig = serde_json::from_value(json!({
            "endpoint": "https://cloud.example.com/api/v4/json",
            "critical_client_hints": false
        }))
        .expect("should read the switch");

        assert!(!switched_off.critical_client_hints);
    }

    #[test]
    fn the_continent_is_never_claimed() {
        let body = json!({"ip": {"countrycode": "GB", "continent": "Europe"}});

        let info = geo_from_response(&body).expect("should resolve the country");

        assert!(
            info.continent.is_empty(),
            "the service has no continent property, so a value under that name did not              come from IP intelligence and must not be presented as though it had"
        );
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
        }});

        let geo = geo_from_response(&body).expect("a country should resolve a location");
        assert_eq!(geo.city, "", "should not report `Unknown` as a town");

        // Lower case too, because the check is on the spelling and not on the
        // exact string the service happened to send when it was written.
        let lower = json!({"ip": {"countrycode": "GB", "town": "unknown"}});
        let geo = geo_from_response(&lower).expect("a country should resolve a location");
        assert_eq!(
            geo.city, "",
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
        let client = CloudClient::new(
            "https://cloud.example.com/api/v4/json".to_owned(),
            500,
            false,
        );

        let url = client
            .request_url(&crate::client::Evidence {
                client_ip: "2.125.160.216".to_owned(),
                user_agent: "Mozilla/5.0".to_owned(),
                browser: Vec::new(),
            })
            .expect("should build the request URL");

        assert!(
            url.contains("client-ip=2.125.160.216"),
            "the bare evidence name is what the service reads, got {url}"
        );
        assert!(
            !url.contains("query.client-ip"),
            "the prefixed form is accepted and ignored, and the answer then describes              this machine rather than the visitor, which looks identical to success"
        );
    }
}
