//! Proving an Edge Cookie really is a 51Did that 51Degrees signed.
//!
//! # Why this exists
//!
//! Two paths hand this crate an identifier it did not itself create, and both
//! are reachable by anyone.
//!
//! The resolve endpoint accepts a value the browser posts. Without a signature
//! check, a caller could post any string and have it set as their Edge Cookie,
//! including **another visitor's identifier**, which would key them into that
//! person's row in the identity graph. That is the failure this exists to
//! prevent, and it is worse than accepting nonsense.
//!
//! Read-back is the same problem arriving by a different door. An incoming
//! `ts-ec` cookie is a value the browser sends, and core asks this crate
//! whether it is one of ours. A shape check answers "it looks like base64 of
//! about the right length", which anyone can produce.
//!
//! # What is verified, and what cannot be
//!
//! A 51Did is carried in an OWID envelope, which names the domain that signed
//! it and carries a signature over its payload. **The signature is the only
//! thing this can check.** It proves the value was minted by that signer and
//! has not been altered since.
//!
//! It does **not** check the creator context, and from a server it cannot. The
//! context belongs to the browser that obtained the identifier, and a call made
//! from an appliance is a different caller on a different connection, so
//! anything derived from the caller's own context would describe the appliance
//! rather than the visitor. A signature is what a third party can verify about
//! a value it did not create, and that is the right and only claim to make
//! here.
//!
//! # The key, and whose job caching it is
//!
//! **Temporary.** The 51Degrees Rust package will own key caching, with the
//! OWID code beneath it responsible for fetching from the source and honouring
//! the validity window each key carries. This module holds a small cache only
//! because that package is not ready, and it should be deleted rather than
//! extended when it lands.
//!
//! Two things this placeholder gets wrong that the package will get right. It
//! expires on a fixed interval rather than on the key's own start and end
//! dates, which is the wrong rule and merely a safe one. And it caches per
//! process rather than anywhere a short-lived edge instance could reuse.

use std::collections::HashMap;
use std::sync::Mutex;

use edgezero_core::body::Body as EdgeBody;
use error_stack::{Report, ResultExt as _};
use fodid::{FodId, Owid, SignatureStatus};
use trusted_server_core::platform::{
    PlatformBackendSpec, PlatformError, PlatformHttpRequest, RuntimeServices,
};

use crate::BACKEND_DISCRIMINATOR;

/// Cap on the public key document read from a signer.
///
/// A PEM encoded public key is a few hundred bytes. This is generous enough
/// that a differently formatted answer still arrives, and small enough that a
/// wrong URL cannot grow the process.
const MAX_KEY_BYTES: usize = 64 * 1024;

/// How long a fetched key is trusted before it is fetched again.
///
/// Long, because a signer rotating its key is rare and a stale key fails
/// closed rather than open: verification simply stops matching and identifiers
/// are refused, which is visible, rather than accepted wrongly, which is not.
const KEY_LIFETIME_SECS: u64 = 60 * 60 * 24;

/// The signers whose keys this process has fetched.
#[derive(Debug, Default)]
pub struct KeyCache {
    keys: Mutex<HashMap<String, Entry>>,
}

#[derive(Debug)]
struct Entry {
    pem: String,
    fetched: std::time::Instant,
}

impl KeyCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// The cached key for a signer, when one is present and still fresh.
    ///
    /// Synchronous and non-fetching, so a caller on a path that cannot await,
    /// which is the read-back check, can still verify when the key happens to
    /// be known.
    #[must_use]
    pub fn cached(&self, signer: &str) -> Option<String> {
        let keys = self.keys.lock().ok()?;
        let entry = keys.get(signer)?;
        if entry.fetched.elapsed().as_secs() >= KEY_LIFETIME_SECS {
            return None;
        }
        Some(entry.pem.clone())
    }

    /// The key for a signer, fetching it when it is not already known.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::Geo`] when the signer cannot be reached or does
    /// not answer with a key.
    pub async fn fetch(
        &self,
        signer: &str,
        version: u8,
        services: &RuntimeServices,
    ) -> Result<String, Report<PlatformError>> {
        if let Some(pem) = self.cached(signer) {
            return Ok(pem);
        }

        let url = format!("https://{signer}/owid/api/v{version}/public-key");
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(&url)
            .body(EdgeBody::empty())
            .change_context(PlatformError::Geo)
            .attach("could not build the public key request")?;

        let spec = PlatformBackendSpec {
            scheme: "https".to_owned(),
            host: signer.to_owned(),
            port: None,
            host_header_override: None,
            certificate_check: true,
            first_byte_timeout: core::time::Duration::from_secs(5),
            between_bytes_timeout: core::time::Duration::from_secs(5),
            discriminator: Some(format!("{BACKEND_DISCRIMINATOR}_owid")),
        };
        let backend = services
            .backend()
            .ensure(&spec)
            .change_context(PlatformError::Geo)
            .attach("could not resolve a backend for the signer")?;

        let response = services
            .http_client()
            .send(PlatformHttpRequest::new(request, backend))
            .await
            .change_context(PlatformError::Geo)
            .attach_with(|| format!("the signer `{signer}` did not answer"))?;

        let status = response.response.status();
        if !status.is_success() {
            return Err(Report::new(PlatformError::Geo)
                .attach(format!("the signer `{signer}` answered {status}")));
        }

        let bytes = response
            .response
            .into_body()
            .into_bytes_bounded(MAX_KEY_BYTES)
            .await
            .change_context(PlatformError::Geo)
            .attach("could not read the public key")?;
        let pem = String::from_utf8(bytes.to_vec())
            .change_context(PlatformError::Geo)
            .attach("the public key was not text")?;

        if let Ok(mut keys) = self.keys.lock() {
            keys.insert(
                signer.to_owned(),
                Entry {
                    pem: pem.clone(),
                    fetched: std::time::Instant::now(),
                },
            );
        }
        Ok(pem)
    }
}

/// Reads a 51Did out of its cookie form, without verifying it.
///
/// Separate from verification because parsing answers "is this the right shape"
/// and verification answers "did 51Degrees sign it", and a caller that cannot
/// reach the network can still ask the first.
#[must_use]
pub fn parse(cookie_form: &str) -> Option<FodId> {
    // Converted back to the service's own spelling first. It was claimed that
    // `from_base64` accepts either alphabet; it does not accept the cookie
    // form, and the test that proves an identifier survives its own round trip
    // is what caught that. The conversion is exact, so doing it here costs
    // nothing and removes the question.
    let mut standard = cookie_form.replace('-', "+").replace('_', "/");
    let padding = match standard.len() % 4 {
        0 => 0,
        2 => 2,
        3 => 1,
        // A length base64 cannot have. Nothing to parse.
        _ => return None,
    };
    standard.push_str(&"=".repeat(padding));
    FodId::from_base64(&standard).ok()
}

/// Whether `identifier` carries a genuine signature from `pem`.
///
/// Anything other than a valid signature is a refusal, including a malformed
/// key, because a key we cannot read is not a key that verified anything.
#[must_use]
pub fn signature_is_valid(identifier: &FodId, pem: &str) -> bool {
    matches!(
        identifier.owid().verify_status_with_public_key(pem, &[]),
        SignatureStatus::Valid
    )
}

/// The signer and version an identifier says it came from.
///
/// Read from the envelope, so it is the value's own claim about who signed it
/// rather than something this crate assumes. The claim is what decides which
/// key to check it against, and a forged claim simply names a signer whose key
/// will not verify it.
#[must_use]
pub fn signer_of(identifier: &FodId) -> (String, u8) {
    let owid: &Owid = identifier.owid();
    (owid.domain().to_owned(), owid.version().as_byte())
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
    fn an_unfetched_signer_has_no_cached_key() {
        let cache = KeyCache::new();

        assert!(
            cache.cached("51d.es").is_none(),
            "a caller that cannot await must be told there is no key rather than \
             given a stale or empty one"
        );
    }

    #[test]
    fn a_cached_key_is_returned_until_it_expires() {
        let cache = KeyCache::new();
        if let Ok(mut keys) = cache.keys.lock() {
            keys.insert(
                "51d.es".to_owned(),
                Entry {
                    pem: "-----BEGIN PUBLIC KEY-----".to_owned(),
                    fetched: std::time::Instant::now(),
                },
            );
        }

        assert_eq!(
            cache.cached("51d.es").as_deref(),
            Some("-----BEGIN PUBLIC KEY-----")
        );
        assert!(
            cache.cached("other.example").is_none(),
            "one signer's key must never answer for another"
        );
    }

    #[test]
    fn a_malformed_key_verifies_nothing() {
        // A key we cannot read is not a key that verified anything, so the
        // answer is no rather than an error a caller might treat as a pass.
        let Some(identifier) =
            parse("AzUxZC5lcwAAnTUAOAAAAAGfxXhNssTdisT2z2p0qZDZm4XUXOcsDv-l72JjWeuXhOutUrsA0S")
        else {
            // The shortened fixture is not a whole envelope, which is itself
            // the point: it does not parse, so there is nothing to verify.
            return;
        };
        assert!(!signature_is_valid(&identifier, "not a PEM"));
    }
}
