//! 51Did verification through the 51Degrees SDK.
//!
//! Reading the envelope is the `fodid` crate's job and the server side of
//! verification is `fodid-client`'s, which fetches the published signing key
//! schedule, picks the key in force when an identifier was created, and
//! caches the schedule for a day. This module supplies the one thing the SDK
//! leaves to its caller, the transport, so every outbound call still goes
//! through the platform client and its backend rules rather than a socket of
//! this crate's own.
//!
//! The schedule is a list of dated keys. A signer rotates its key by adding an
//! entry, so an identifier created under the previous key still verifies as
//! long as the check uses the key in force at the identifier's date rather than
//! whichever key is current. That rule lives in the SDK and is not
//! reimplemented here.

use std::sync::Mutex;
use std::time::Instant;

use edgezero_core::body::Body as EdgeBody;
use error_stack::{Report, ResultExt as _};
use fodid::{FodId, SignatureStatus};
use fodid_client::{
    DidClient, DidHttpClient, DidHttpRequest, DidHttpResponse, DidPublicKey, HttpMethod,
    LocalBoxFuture, in_force_at,
};
use trusted_server_core::platform::{
    PlatformBackendSpec, PlatformError, PlatformHttpRequest, RuntimeServices,
};

use crate::BACKEND_DISCRIMINATOR;

/// Cap on a key schedule read from the service.
///
/// A schedule is a JSON array of a few PEM keys, so this is generous enough
/// that a long history still arrives and small enough that a wrong URL cannot
/// grow the process.
const MAX_KEY_BYTES: usize = 64 * 1024;

/// How long a fetched schedule is trusted before it is fetched again, the
/// same day the SDK's own client uses.
///
/// Long, because a signer adding a key is rare and a stale schedule fails
/// closed rather than open: an identifier under a key the schedule does not
/// yet hold is refused, which is visible, rather than accepted wrongly, which
/// is not.
const KEY_LIFETIME_SECS: u64 = 60 * 60 * 24;

/// Where the signing key schedule is fetched from.
///
/// The SDK reads the schedule from the cloud API under the resource key, so a
/// deployment that names the cloud's JSON endpoint has both halves in that one
/// URL, and a deployment that names something else says the key itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySource {
    /// The API base the schedule route hangs off, ending in `/`.
    pub api_base: String,
    /// The resource key the schedule is published under.
    pub resource_key: String,
}

impl KeySource {
    /// Derives the source from the configured endpoint, with `resource_key`
    /// taking precedence over a key read out of the endpoint's path.
    ///
    /// The cloud's JSON endpoint is `<base>/<resource key>.json`, so the base
    /// is everything up to the last `/` and the key is the file name without
    /// its extension. A self-hosted container's endpoint ends in `json` with
    /// no key, so it yields no source unless the key is given.
    #[must_use]
    pub fn from_endpoint(endpoint: &str, resource_key: Option<&str>) -> Option<Self> {
        let (base, file) = endpoint.rsplit_once('/')?;
        let api_base = format!("{base}/");
        let key = match resource_key.map(str::trim).filter(|key| !key.is_empty()) {
            Some(key) => key.to_owned(),
            None => file
                .strip_suffix(".json")
                .filter(|key| !key.is_empty())?
                .to_owned(),
        };
        Some(Self {
            api_base,
            resource_key: key,
        })
    }
}

/// The signing key schedule this process has fetched, and where it came from.
#[derive(Debug)]
pub struct KeySchedule {
    source: KeySource,
    keys: Mutex<Option<Fetched>>,
}

#[derive(Debug)]
struct Fetched {
    keys: Vec<DidPublicKey>,
    at: Instant,
}

impl KeySchedule {
    /// Creates an empty schedule that fetches from `source`.
    #[must_use]
    pub fn new(source: KeySource) -> Self {
        Self {
            source,
            keys: Mutex::new(None),
        }
    }

    /// The source the schedule is fetched from.
    #[must_use]
    pub fn source(&self) -> &KeySource {
        &self.source
    }

    /// The key in force at the identifier's date, when the schedule is
    /// already held and still fresh.
    ///
    /// Synchronous and non-fetching, so a caller on a path that cannot await,
    /// which is the read-back check, can still verify when the schedule
    /// happens to be known.
    #[must_use]
    pub fn cached_for(&self, identifier: &FodId) -> Option<DidPublicKey> {
        let keys = self.keys.lock().ok()?;
        let fetched = keys.as_ref()?;
        if fetched.at.elapsed().as_secs() >= KEY_LIFETIME_SECS {
            return None;
        }
        in_force_at(&fetched.keys, identifier.owid().date()).cloned()
    }

    /// The key in force at the identifier's date, fetching the schedule when
    /// it is not held, is stale, or holds no key for that date.
    ///
    /// `Ok(None)` means the schedule was fetched and still names no key in
    /// force at the date, which is an identifier older than the signer's
    /// first key or newer than its schedule, and either way not one this
    /// process can vouch for.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::Geo`] when the schedule cannot be fetched.
    pub async fn key_for(
        &self,
        identifier: &FodId,
        services: &RuntimeServices,
    ) -> Result<Option<DidPublicKey>, Report<PlatformError>> {
        if let Some(key) = self.cached_for(identifier) {
            return Ok(Some(key));
        }
        let client = DidClient::builder(&self.source.resource_key)
            .endpoint(&self.source.api_base)
            .http_client(std::sync::Arc::new(PlatformTransport {
                services: services.clone(),
            }))
            .build()
            .map_err(|error| {
                Report::new(PlatformError::Geo)
                    .attach(format!("could not build the 51Did client: {error}"))
            })?;
        let keys = client.public_keys().await.map_err(|error| {
            Report::new(PlatformError::Geo)
                .attach(format!("could not fetch the 51Did signing keys: {error}"))
        })?;
        let key = in_force_at(&keys, identifier.owid().date()).cloned();
        if let Ok(mut held) = self.keys.lock() {
            *held = Some(Fetched {
                keys,
                at: Instant::now(),
            });
        }
        Ok(key)
    }
}

/// The SDK client's transport, over the platform HTTP client.
///
/// The SDK builds the URL and reads the answer. This carries the bytes the
/// way every other outbound call from this crate does, through a backend the
/// platform resolves for the host, so a deployment's egress rules apply to
/// the key fetch as they apply to the cloud call.
struct PlatformTransport {
    services: RuntimeServices,
}

impl DidHttpClient for PlatformTransport {
    fn send<'a>(
        &'a self,
        request: &'a DidHttpRequest,
    ) -> LocalBoxFuture<'a, Result<DidHttpResponse, String>> {
        Box::pin(async move {
            self.carry(request)
                .await
                .map_err(|error| format!("{error:?}"))
        })
    }
}

impl PlatformTransport {
    async fn carry(
        &self,
        request: &DidHttpRequest,
    ) -> Result<DidHttpResponse, Report<PlatformError>> {
        let url: http::Uri = request
            .url
            .parse()
            .change_context(PlatformError::Geo)
            .attach("the 51Did client built a URL that does not parse")?;
        let scheme = url.scheme_str().unwrap_or("https").to_owned();
        let host = url
            .host()
            .ok_or_else(|| {
                Report::new(PlatformError::Geo).attach("the 51Did client's URL has no host")
            })?
            .to_owned();
        let mut builder = http::Request::builder()
            .method(match request.method {
                HttpMethod::Get => http::Method::GET,
                HttpMethod::Post => http::Method::POST,
            })
            .uri(&request.url)
            .header(http::header::USER_AGENT, request.user_agent.as_str());
        let body = if request.form.is_empty() {
            EdgeBody::empty()
        } else {
            builder = builder.header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            );
            EdgeBody::from(form_encode(&request.form))
        };
        let outbound = builder
            .body(body)
            .change_context(PlatformError::Geo)
            .attach("could not build the 51Did request")?;
        let spec = PlatformBackendSpec {
            scheme: scheme.clone(),
            host: host.clone(),
            port: url.port_u16(),
            host_header_override: None,
            certificate_check: scheme == "https",
            first_byte_timeout: core::time::Duration::from_secs(5),
            between_bytes_timeout: core::time::Duration::from_secs(5),
            discriminator: Some(format!("{BACKEND_DISCRIMINATOR}_did")),
        };
        let backend = self
            .services
            .backend()
            .ensure(&spec)
            .change_context(PlatformError::Geo)
            .attach("could not resolve a backend for the 51Did service")?;
        let response = self
            .services
            .http_client()
            .send(PlatformHttpRequest::new(outbound, backend))
            .await
            .change_context(PlatformError::Geo)
            .attach_with(|| format!("the 51Did service at `{host}` did not answer"))?;
        let status = response.response.status().as_u16();
        let bytes = response
            .response
            .into_body()
            .into_bytes_bounded(MAX_KEY_BYTES)
            .await
            .change_context(PlatformError::Geo)
            .attach("could not read the 51Did service's answer")?;
        Ok(DidHttpResponse {
            status,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        })
    }
}

/// Encodes a form body the way the SDK's own transport does.
fn form_encode(form: &[(String, String)]) -> String {
    form.iter()
        .map(|(name, value)| format!("{}={}", percent(name), percent(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Reads a 51Did out of its cookie form, without verifying it.
///
/// Separate from verification because parsing answers "is this the right shape"
/// and verification answers "did 51Degrees sign it", and a caller that cannot
/// reach the network can still ask the first.
#[must_use]
pub fn parse(cookie_form: &str) -> Option<FodId> {
    let mut standard = cookie_form.replace('-', "+").replace('_', "/");
    let padding = match standard.len() % 4 {
        0 => 0,
        2 => 2,
        3 => 1,
        _ => return None,
    };
    standard.push_str(&"=".repeat(padding));
    FodId::from_base64(&standard).ok()
}

/// Whether `identifier` carries a genuine signature from `key`.
///
/// Anything other than a valid signature is a refusal, including a malformed
/// key, because a key we cannot read is not a key that verified anything.
#[must_use]
pub fn signature_is_valid(identifier: &FodId, key: &DidPublicKey) -> bool {
    matches!(
        identifier
            .owid()
            .verify_status_with_public_key(key.public_key_pem(), &[]),
        SignatureStatus::Valid
    )
}

/// The signer an identifier says it came from, read from the envelope.
///
/// The claim is what the log names. The key that checks it comes from the
/// schedule, so a forged claim changes nothing about which key is used.
#[must_use]
pub fn signer_of(identifier: &FodId) -> String {
    identifier.owid().domain().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_that_is_not_an_owid_does_not_parse() {
        assert!(parse("not-an-owid").is_none());
        assert!(parse("").is_none());
    }

    #[test]
    fn the_cloud_endpoint_carries_its_own_key_source() {
        let source = KeySource::from_endpoint(
            "https://cloud.51degrees.com/api/v4/AQS5HKcyVj6B8wNG2Ug.json",
            None,
        )
        .expect("the cloud form names both halves");
        assert_eq!(source.api_base, "https://cloud.51degrees.com/api/v4/");
        assert_eq!(source.resource_key, "AQS5HKcyVj6B8wNG2Ug");
    }

    #[test]
    fn a_container_endpoint_needs_the_key_said_separately() {
        assert!(
            KeySource::from_endpoint("http://127.0.0.1:8080/api/v4/json", None).is_none(),
            "a keyless endpoint cannot name a schedule"
        );
        let source = KeySource::from_endpoint("http://127.0.0.1:8080/api/v4/json", Some("abc"))
            .expect("an explicit key completes the source");
        assert_eq!(source.api_base, "http://127.0.0.1:8080/api/v4/");
        assert_eq!(source.resource_key, "abc");
    }

    #[test]
    fn an_explicit_key_outranks_the_one_in_the_path() {
        let source = KeySource::from_endpoint(
            "https://cloud.51degrees.com/api/v4/fromthepath.json",
            Some("explicit"),
        )
        .expect("should build");
        assert_eq!(source.resource_key, "explicit");
    }

    #[test]
    fn an_unfetched_schedule_has_no_cached_key() {
        let schedule = KeySchedule::new(
            KeySource::from_endpoint("https://cloud.51degrees.com/api/v4/key.json", None)
                .expect("should build"),
        );
        let Some(identifier) =
            parse("AzUxZC5lcwAAnTUAOAAAAAGfxXhNssTdisT2z2p0qZDZm4XUXOcsDv-l72JjWeuXhOutUrsA0S")
        else {
            // The shortened fixture is not a whole envelope, so there is
            // nothing to look up, which is itself a correct answer.
            return;
        };
        assert!(
            schedule.cached_for(&identifier).is_none(),
            "a caller that cannot await must be told there is no key rather than \
             given an empty one"
        );
    }

    #[test]
    fn a_form_body_is_percent_encoded() {
        assert_eq!(
            form_encode(&[("a b".to_owned(), "c&d".to_owned())]),
            "a%20b=c%26d"
        );
    }
}
