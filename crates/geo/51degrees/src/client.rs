//! One cloud call per request, shared by every provider this crate supplies.
//!
//! Three separate traits ask this crate for three separate things: the country
//! for the permission model, the device for the bid request, and the 51Did for
//! Edge Cookie identity. All three come back in a single cloud response, and
//! calling three times for one request would triple the latency on the critical
//! path for nothing.
//!
//! # What this actually costs, measured
//!
//! The first request from an address costs two calls, not one. Geo runs first
//! in the request and cannot see the `User-Agent`, so it asks about the
//! address alone, and the device provider then has to ask its own question.
//! Every later request from that address, while the entry is fresh, costs at
//! most one: geo reuses the device call's answer, and a repeat visitor with an
//! unchanged `User-Agent` costs none. Read from the appliance's own log on
//! 6 September 2026 rather than reasoned about, after the module heading here
//! had claimed one call per request and the log said otherwise.
//!
//! # Why a cache rather than a per-request context
//!
//! The provider seam has no shared per-request store. `PlatformGeo::lookup`
//! receives a client address and the runtime services, `DeviceProvider::detect`
//! receives request evidence, and neither can reach a scratch area the other
//! wrote to. So the sharing has to happen inside this crate.
//!
//! It is keyed on the evidence rather than on the request, which is the
//! stronger arrangement and not a workaround. Identical evidence produces an
//! identical answer, so two providers within one request hit the same entry,
//! and so does the same visitor on their next page. That second effect is worth
//! more than the first on a long-lived appliance, where the process survives
//! between requests. On the edge, where each request is a fresh instance, it
//! would be worth nothing.
//!
//! # What it deliberately does not do
//!
//! It does not cache failures. A timeout or a 500 is not an answer about a
//! visitor, and remembering one would turn a momentary outage into a minute of
//! wrong results. Every failure is retried by the next caller.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use edgezero_core::body::Body as EdgeBody;
use error_stack::{Report, ResultExt as _};
use trusted_server_core::platform::{
    PlatformBackendSpec, PlatformError, PlatformHttpRequest, RuntimeServices,
};

use crate::BACKEND_DISCRIMINATOR;

/// Entries held before the oldest is dropped.
///
/// Sized for a busy page rather than for a busy site: the point is to serve the
/// three providers of one request and a visitor's next few pages, not to be a
/// long-term store. A bounded map also means a crawler cycling through
/// addresses cannot grow the process without limit.
const MAX_ENTRIES: usize = 4096;

/// How long an answer is reused.
///
/// Short, because a visitor can change network between pages and an identifier
/// derived from stale evidence is worse than one derived from a fresh call.
const ENTRY_LIFETIME: Duration = Duration::from_secs(60);

/// The evidence a cloud answer depends on.
///
/// Two requests with the same values get the same answer, which is what makes
/// sharing sound rather than convenient. Anything added here that the cloud
/// call does not actually send would split the cache for no reason, and
/// anything the call sends that is missing here would serve one visitor's
/// answer to another.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Evidence {
    /// The visitor's address, as sent in the `client-ip` parameter.
    pub client_ip: String,
    /// The visitor's `User-Agent`.
    pub user_agent: String,
}

/// A decoded cloud response, shared between the providers of one request.
#[derive(Debug, Clone)]
pub struct CloudAnswer {
    body: serde_json::Value,
}

impl CloudAnswer {
    /// Wraps a decoded response.
    #[must_use]
    pub const fn new(body: serde_json::Value) -> Self {
        Self { body }
    }

    /// The whole decoded response.
    #[must_use]
    pub const fn body(&self) -> &serde_json::Value {
        &self.body
    }

    /// One element of the response, such as `ip`, `device` or `fodid`.
    ///
    /// Returns `None` when the resource key is not entitled to that product,
    /// which is the ordinary case rather than a failure: a key without IP
    /// intelligence simply has no `ip` element, and the provider that reads it
    /// resolves nothing rather than erroring.
    #[must_use]
    pub fn element(&self, name: &str) -> Option<&serde_json::Value> {
        self.body.get(name)
    }
}

struct Entry {
    answer: CloudAnswer,
    stored: Instant,
}

/// Caches cloud answers by evidence so one request costs one call.
#[derive(Debug)]
pub struct AnswerCache {
    entries: Mutex<HashMap<Evidence, Entry>>,
}

impl core::fmt::Debug for Entry {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Entry")
    }
}

impl Default for AnswerCache {
    fn default() -> Self {
        Self::new()
    }
}

impl AnswerCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Returns a stored answer for this evidence, when one is still fresh.
    #[must_use]
    pub fn get(&self, evidence: &Evidence) -> Option<CloudAnswer> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(evidence)?;
        if entry.stored.elapsed() >= ENTRY_LIFETIME {
            return None;
        }
        Some(entry.answer.clone())
    }

    /// Returns any fresh answer stored for this address, whatever evidence
    /// it was stored under.
    ///
    /// Only the `ip` element of the returned answer describes the address.
    /// See [`CloudClient::answer_for_address`], the sole caller, for why that
    /// is enough for the geo provider and wrong for anyone else.
    #[must_use]
    pub fn any_for_address(&self, client_ip: &str) -> Option<CloudAnswer> {
        let entries = self.entries.lock().ok()?;
        entries
            .iter()
            .find(|(evidence, entry)| {
                evidence.client_ip == client_ip && entry.stored.elapsed() < ENTRY_LIFETIME
            })
            .map(|(_, entry)| entry.answer.clone())
    }

    /// Stores an answer, dropping expired entries and then the oldest if the
    /// cache is still full.
    pub fn put(&self, evidence: Evidence, answer: CloudAnswer) {
        let Ok(mut entries) = self.entries.lock() else {
            // A poisoned lock means another thread panicked while holding it.
            // Losing the cache is not a reason to fail the request, so the
            // caller simply pays for its own call.
            return;
        };
        entries.retain(|_, entry| entry.stored.elapsed() < ENTRY_LIFETIME);
        if entries.len() >= MAX_ENTRIES
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.stored)
                .map(|(key, _)| key.clone())
        {
            entries.remove(&oldest);
        }
        entries.insert(
            evidence,
            Entry {
                answer,
                stored: Instant::now(),
            },
        );
    }
}

/// Builds the query for one cloud call.
///
/// Every parameter here was established by measurement rather than from the
/// documentation, and three of them are not guessable.
///
/// `client-ip` is the bare evidence name. `query.client-ip` is the evidence
/// **key**, where the prefix says where the value came from, and sending that
/// form is accepted and silently ignored, so the answer then describes whoever
/// opened the connection.
///
/// `id.usage` must be present or the 51Did engine does not run at all, with no
/// element and no warning in the response. `non-marketing` is the value that
/// needs no licence key.
///
/// Each property this crate reads is requested explicitly through `values`,
/// because a product whose properties are not asked for is not returned.
/// `Areas` is deliberately never requested: it is a multipolygon that runs to
/// thousands of characters and nothing here reads it.
///
/// Device properties are asked for only when there is a `User-Agent` to answer
/// them from. The geo provider cannot see one through its seam, so its call
/// would otherwise ask twelve device questions whose answers describe an empty
/// `User-Agent` and which no caller may read.
#[must_use]
pub fn query_parameters(evidence: &Evidence, want_identity: bool) -> Vec<(String, String)> {
    let mut parameters = vec![
        ("client-ip".to_owned(), evidence.client_ip.clone()),
        ("User-Agent".to_owned(), evidence.user_agent.clone()),
    ];
    let want_device = !evidence.user_agent.trim().is_empty();
    let properties = IP_PROPERTIES
        .iter()
        .chain(if want_device { DEVICE_PROPERTIES } else { &[] });
    for property in properties {
        parameters.push(("values".to_owned(), (*property).to_owned()));
    }
    if want_identity && want_device {
        parameters.push(("id.usage".to_owned(), "non-marketing".to_owned()));
        parameters.push(("values".to_owned(), "FODiD.IdProbGlobal".to_owned()));
    }
    parameters
}

/// IP intelligence properties this crate reads.
///
/// There is no continent property. Asking for `ip.Continent` returns an empty
/// `ip` element, which is exactly what asking for a property that does not
/// exist returns, while `ip.CountryCode` comes back with its value and, on an
/// unentitled key, the reason it is null. So the geo answer never carries a
/// continent, and [`crate::geo_from_response`] does not read one.
const IP_PROPERTIES: &[&str] = &[
    "ip.CountryCode",
    "ip.Region",
    "ip.Town",
    "ip.Latitude",
    "ip.Longitude",
];

/// Device properties that map onto the `OpenRTB` device object.
///
/// Measured against the live service on 6 September 2026 with the resource key
/// on this machine: `DeviceType`, `IsMobile`, `IsCrawler`, `ScreenPixelsWidth`
/// and `ScreenPixelsHeight` resolve. `HardwareVendor`, `HardwareName`,
/// `HardwareModel`, `PlatformName`, `PlatformVersion`, `BrowserName` and
/// `BrowserVersion` each come back null with a reason saying they are a paid
/// feature needing a license key. They are still requested here, because the
/// same code then fills the make, model and operating system the moment an
/// entitled key is configured, and until then those bid request fields are
/// absent rather than invented.
const DEVICE_PROPERTIES: &[&str] = &[
    "device.DeviceType",
    "device.HardwareVendor",
    "device.HardwareName",
    "device.HardwareModel",
    "device.PlatformName",
    "device.PlatformVersion",
    "device.BrowserName",
    "device.BrowserVersion",
    "device.ScreenPixelsWidth",
    "device.ScreenPixelsHeight",
    "device.IsMobile",
    "device.IsCrawler",
];

/// Reads the service version, so a deployment can assert what it is talking to.
///
/// Worth calling at startup. On this machine a hosts entry points
/// `cloud.51degrees.com` at staging, and if that entry is removed the same
/// hostname silently reaches production, which carries no 51Did at all. The
/// identity provider would then return nothing rather than fail, which is the
/// worst shape a misconfiguration can take.
///
/// # Errors
///
/// Returns [`PlatformError::Geo`] when the endpoint cannot be parsed.
pub fn version_url(endpoint: &str) -> Result<String, Report<PlatformError>> {
    let base = url::Url::parse(endpoint)
        .change_context(PlatformError::Geo)
        .attach_with(|| format!("endpoint is not a URL: {endpoint}"))?;
    let root = base
        .join("/api/v4/info/version")
        .change_context(PlatformError::Geo)
        .attach("could not build the version URL")?;
    Ok(root.into())
}

// ---------------------------------------------------------------------------
// The call
// ---------------------------------------------------------------------------

/// Cap on the response body read from the service.
///
/// The `areas` property alone is a multipolygon that runs to tens of
/// kilobytes, so this is generous rather than tight. It exists so a wrong
/// endpoint cannot grow the process heap without bound.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Calls the cloud service, and hands one answer to every provider that asks.
///
/// Held as an `Arc` by each provider this crate supplies, so they share the
/// cache rather than each keeping their own.
#[derive(Debug)]
pub struct CloudClient {
    endpoint: String,
    timeout: Duration,
    want_identity: bool,
    cache: AnswerCache,
}

impl CloudClient {
    /// Creates a client for one endpoint.
    #[must_use]
    pub fn new(endpoint: String, timeout_ms: u32, want_identity: bool) -> Self {
        Self {
            endpoint,
            timeout: Duration::from_millis(u64::from(timeout_ms)),
            want_identity,
            cache: AnswerCache::new(),
        }
    }

    /// The configured endpoint, for a caller reporting what it talks to.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The answer for a request whose address and `User-Agent` are both known.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::Geo`] when the service cannot be reached, does
    /// not answer with a success status, or does not answer with JSON.
    pub async fn answer(
        &self,
        evidence: &Evidence,
        services: &RuntimeServices,
    ) -> Result<CloudAnswer, Report<PlatformError>> {
        if let Some(found) = self.cache.get(evidence) {
            return Ok(found);
        }
        let answer = self.fetch(evidence, services).await?;
        self.cache.put(evidence.clone(), answer.clone());
        Ok(answer)
    }

    /// The answer for a caller that knows the address but not the
    /// `User-Agent`.
    ///
    /// `PlatformGeo::lookup` receives a client address and the runtime
    /// services. No `User-Agent` reaches it through that seam, so the geo
    /// provider cannot build the key the device provider builds, and an exact
    /// match would miss an answer already paid for.
    ///
    /// Reusing an entry stored under a different key is sound here and only
    /// here, because the `ip` element depends on the address alone. The
    /// `device` and `fodid` elements of the same entry describe whichever
    /// `User-Agent` made that call, so **only the `ip` element of this answer
    /// may be read**, and the geo provider is the only caller.
    ///
    /// # Errors
    ///
    /// As [`answer`](Self::answer).
    pub async fn answer_for_address(
        &self,
        client_ip: IpAddr,
        services: &RuntimeServices,
    ) -> Result<CloudAnswer, Report<PlatformError>> {
        let address = client_ip.to_string();
        if let Some(found) = self.cache.any_for_address(&address) {
            return Ok(found);
        }
        let evidence = Evidence {
            client_ip: address,
            user_agent: String::new(),
        };
        let answer = self.fetch(&evidence, services).await?;
        self.cache.put(evidence, answer.clone());
        Ok(answer)
    }

    /// Builds the request URL for one piece of evidence.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::Geo`] when the endpoint is not a URL.
    pub fn request_url(&self, evidence: &Evidence) -> Result<String, Report<PlatformError>> {
        let mut url = url::Url::parse(&self.endpoint)
            .change_context(PlatformError::Geo)
            .attach_with(|| format!("endpoint is not a URL: {}", self.endpoint))?;
        {
            let mut pairs = url.query_pairs_mut();
            for (name, value) in query_parameters(evidence, self.want_identity) {
                // An empty parameter is not evidence. Sending one asks the
                // service to describe an empty User-Agent rather than leaving
                // the question unasked.
                if value.is_empty() {
                    continue;
                }
                pairs.append_pair(&name, &value);
            }
        }
        Ok(url.into())
    }

    /// Builds the backend registration for the configured endpoint.
    ///
    /// Core has an internal helper that does this for its own integrations,
    /// but it is crate-private, so a vendor crate outside core builds the spec
    /// itself. The discriminator keeps this crate's dynamic backend distinct
    /// from any other caller that happens to target the same host.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::Geo`] when the endpoint is not a URL or has no
    /// host.
    pub fn backend_spec(&self) -> Result<PlatformBackendSpec, Report<PlatformError>> {
        let parsed = url::Url::parse(&self.endpoint)
            .change_context(PlatformError::Geo)
            .attach_with(|| format!("endpoint is not a URL: {}", self.endpoint))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| Report::new(PlatformError::Geo).attach("endpoint has no host"))?
            .to_owned();
        Ok(PlatformBackendSpec {
            scheme: parsed.scheme().to_owned(),
            host,
            port: parsed.port(),
            host_header_override: None,
            certificate_check: true,
            first_byte_timeout: self.timeout,
            between_bytes_timeout: self.timeout,
            discriminator: Some(BACKEND_DISCRIMINATOR.to_owned()),
        })
    }

    /// Makes one call and decodes the answer.
    async fn fetch(
        &self,
        evidence: &Evidence,
        services: &RuntimeServices,
    ) -> Result<CloudAnswer, Report<PlatformError>> {
        let url = self.request_url(evidence)?;
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(&url)
            .header(http::header::ACCEPT, "application/json")
            .body(EdgeBody::empty())
            .change_context(PlatformError::Geo)
            .attach("could not build the cloud request")?;

        let backend = services
            .backend()
            .ensure(&self.backend_spec()?)
            .change_context(PlatformError::Geo)
            .attach("could not resolve a backend for the cloud endpoint")?;

        let response = services
            .http_client()
            .send(PlatformHttpRequest::new(request, backend))
            .await
            .change_context(PlatformError::Geo)
            .attach("the cloud service did not answer")?;

        let status = response.response.status();
        if !status.is_success() {
            return Err(Report::new(PlatformError::Geo)
                .attach(format!("the cloud service answered {status}")));
        }

        let bytes = response
            .response
            .into_body()
            .into_bytes_bounded(MAX_RESPONSE_BYTES)
            .await
            .change_context(PlatformError::Geo)
            .attach("could not read the cloud response body")?;

        let body: serde_json::Value = serde_json::from_slice(&bytes)
            .change_context(PlatformError::Geo)
            .attach("the cloud service did not return JSON")?;

        Ok(CloudAnswer::new(body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> Evidence {
        Evidence {
            client_ip: "2.125.160.216".to_owned(),
            user_agent: "Mozilla/5.0".to_owned(),
        }
    }

    fn answer(country: &str) -> CloudAnswer {
        CloudAnswer::new(serde_json::json!({"ip": {"countrycode": country}}))
    }

    #[test]
    fn an_answer_is_shared_by_the_next_caller_with_the_same_evidence() {
        let cache = AnswerCache::new();
        cache.put(evidence(), answer("GB"));

        let found = cache
            .get(&evidence())
            .expect("the second provider in the same request must not call again");

        assert_eq!(
            found
                .element("ip")
                .and_then(|ip| ip["countrycode"].as_str()),
            Some("GB"),
            "should return the stored answer"
        );
    }

    #[test]
    fn different_evidence_does_not_share_an_answer() {
        let cache = AnswerCache::new();
        cache.put(evidence(), answer("GB"));

        let other = Evidence {
            client_ip: "8.8.8.8".to_owned(),
            user_agent: "Mozilla/5.0".to_owned(),
        };

        assert!(
            cache.get(&other).is_none(),
            "serving one visitor's answer to another is the failure this key exists to prevent"
        );
    }

    #[test]
    fn a_different_user_agent_is_different_evidence() {
        let cache = AnswerCache::new();
        cache.put(evidence(), answer("GB"));

        let other = Evidence {
            client_ip: evidence().client_ip,
            user_agent: "curl/8".to_owned(),
        };

        assert!(
            cache.get(&other).is_none(),
            "the device answer depends on the user agent, so it cannot be shared across them"
        );
    }

    #[test]
    fn the_cache_stays_bounded() {
        let cache = AnswerCache::new();
        for index in 0..(MAX_ENTRIES + 50) {
            cache.put(
                Evidence {
                    client_ip: format!("10.0.0.{index}"),
                    user_agent: "Mozilla/5.0".to_owned(),
                },
                answer("GB"),
            );
        }

        let held = cache.entries.lock().expect("should lock the cache").len();

        assert!(
            held <= MAX_ENTRIES,
            "a crawler cycling addresses must not grow the process without limit, held {held}"
        );
    }

    #[test]
    fn a_call_with_no_user_agent_asks_no_device_questions() {
        let address_only = Evidence {
            client_ip: "2.125.160.216".to_owned(),
            user_agent: String::new(),
        };

        let parameters = query_parameters(&address_only, true);

        assert!(
            parameters
                .iter()
                .all(|(_, value)| !value.starts_with("device.")),
            "the geo provider cannot see a User-Agent, so asking twelve device              questions would buy answers about an empty one that nothing may read"
        );
        assert!(
            parameters
                .iter()
                .any(|(_, value)| value == "ip.CountryCode"),
            "the address question is the one this call exists to ask"
        );
        assert!(
            !parameters.iter().any(|(name, _)| name == "id.usage"),
            "an identifier derived from an empty User-Agent is not one worth asking for"
        );
    }

    #[test]
    fn the_identity_parameters_are_both_present_or_neither() {
        let with = query_parameters(&evidence(), true);
        let without = query_parameters(&evidence(), false);

        assert!(
            with.iter()
                .any(|(k, v)| k == "id.usage" && v == "non-marketing"),
            "the 51Did engine does not run at all without id.usage, and says nothing when it does not"
        );
        assert!(
            with.iter()
                .any(|(k, v)| k == "values" && v == "FODiD.IdProbGlobal"),
            "a property that is not requested is not returned"
        );
        assert!(
            !without.iter().any(|(k, _)| k == "id.usage"),
            "a deployment not using identity should not ask for it"
        );
    }

    #[test]
    fn the_address_parameter_is_unprefixed_and_areas_is_never_requested() {
        let parameters = query_parameters(&evidence(), true);

        assert!(
            parameters.iter().any(|(k, _)| k == "client-ip"),
            "the bare evidence name is what the service reads"
        );
        assert!(
            !parameters.iter().any(|(k, _)| k == "query.client-ip"),
            "the prefixed form is accepted and ignored, so the answer would describe the appliance"
        );
        assert!(
            !parameters
                .iter()
                .any(|(_, v)| v.eq_ignore_ascii_case("ip.Areas")),
            "Areas is a multipolygon of thousands of characters that nothing here reads"
        );
    }
}
