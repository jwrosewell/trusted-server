//! Edge Cookie identity from the 51Did in the same 51Degrees cloud answer.
//!
//! The identifier is created by the service, not by this crate, and arrives as
//! the `fodid` element of the response the geo and device providers already
//! paid for. So selecting this provider alongside the other two costs no extra
//! call.
//!
//! # The identifier is transported, not altered
//!
//! The service issues standard base64, which uses `+`, `/` and `=`. Core's Edge
//! Cookie alphabet is `[A-Za-z0-9._~-]` and refuses all three, and its cap is
//! 256 characters against a measured identifier length of 184. So the raw form
//! cannot be a cookie value, and writing it produces a cookie that is silently
//! refused on the next request with nothing logged anywhere.
//!
//! This provider therefore writes the URL-safe alphabet, a pure substitution of
//! `-` for `+` and `_` for `/` with the padding dropped. It is exactly
//! reversible by [`from_cookie_form`], which exists so anything handing the
//! identifier back to 51Degrees can recover the spelling the service issued.
//! The identifier is carried, not changed.
//!
//! # Why [`accepts_id`](EdgeCookieProvider::accepts_id) and
//! [`normalize_id_for_kv`](EdgeCookieProvider::normalize_id_for_kv) are both
//! overridden
//!
//! Because not overriding them is a bug this project has already shipped once.
//! The defaults describe the built-in HMAC identifier, which is `<64 hex>.<6
//! alphanumeric>` and is judged case-insensitively. A 51Did is base64, which is
//! longer, carries `+`, `/` and `=`, and **is case-sensitive**. Left on the
//! defaults, a perfectly good identifier is written to the cookie and then
//! silently refused on read-back, so every visitor looks new on every request
//! and nothing anywhere reports an error. That is the same failure the alphabet
//! causes, reached by a different route.
//!
//! The round-trip test at the bottom of this file is the one that would have
//! caught it.
//!
//! # What this provider does not do
//!
//! It does not create an identifier when the service returned none. A key
//! without the identity entitlement, or a request with no `User-Agent`, yields
//! no `fodid`, and this returns no identifier rather than falling back to
//! something derived here. An Edge Cookie that claims to be a 51Did and is not
//! would be worse than no Edge Cookie, because everything downstream treats the
//! provider code as a statement of where the identifier came from.

use std::sync::Arc;

use async_trait::async_trait;
use error_stack::Report;
use trusted_server_core::ec::provider::{
    ClientResolveInput, EdgeCookieProvider, GeneratedEdgeCookie, IdentityInput, ProviderCode,
};
use trusted_server_core::error::TrustedServerError;
use trusted_server_core::evidence::RequestInfo;
use trusted_server_core::permissions::{Permission, PermissionSet};
use trusted_server_core::platform::RuntimeServices;
use trusted_server_core::provider_code;

use crate::PROVIDER_ID;
use crate::client::{CloudAnswer, CloudClient};
use crate::device::evidence_for;

/// This provider's registered code, the `51dd~` namespace of every identifier
/// it creates.
///
/// Allocated in the provider-code registry so no other provider can create a
/// colliding identifier. Core applies it at creation and checks it at
/// read-back, and this provider only ever sees its own value part.
pub const IDENTITY_PROVIDER_CODE: ProviderCode = provider_code!("51dd");

/// The longest identifier this provider will accept.
///
/// Core caps a whole Edge Cookie value at 256 characters. This provider's code
/// prefix, `51dd~`, takes five of them, so 250 leaves the full value inside
/// core's cap whether core measures the value part or the whole cookie. A real
/// identifier measured against the live service is 184 characters, so this is
/// headroom rather than a squeeze.
const MAX_ID_BYTES: usize = 250;

/// Edge Cookie provider backed by the 51Did in a 51Degrees cloud answer.
#[derive(Debug)]
pub struct FiftyOneDegreesIdentity {
    client: Arc<CloudClient>,
    critical_client_hints: bool,
}

impl FiftyOneDegreesIdentity {
    /// Creates a provider sharing one client, and so one call, with the other
    /// providers this crate supplies.
    #[must_use]
    pub const fn new(client: Arc<CloudClient>, critical_client_hints: bool) -> Self {
        Self {
            client,
            critical_client_hints,
        }
    }

    /// The client hint headers to set alongside the identifier.
    ///
    /// # Why these ride on the identity response
    ///
    /// `Accept-CH` and `Critical-CH` are response headers, so a meta tag cannot
    /// carry them and the head injector cannot help. The only seam that reaches
    /// a response header is the Edge Cookie provider's, and it fires when an
    /// identifier is being created: no cookie yet, a provider selected, and the
    /// permissions set.
    ///
    /// That firing condition happens to be the right one. A visitor with no
    /// Edge Cookie is a visitor the browser has not yet been asked for hints,
    /// and one who has both has already been asked. So the headers go out
    /// exactly once per visitor rather than on every page.
    fn client_hint_headers(
        &self,
        answer: &CloudAnswer,
    ) -> Vec<(http::HeaderName, http::HeaderValue)> {
        let Some(accept_ch) = crate::head::accept_ch_from_answer(answer) else {
            return Vec::new();
        };
        let Ok(value) = http::HeaderValue::from_str(&accept_ch) else {
            return Vec::new();
        };
        let mut headers = vec![(http::HeaderName::from_static("accept-ch"), value.clone())];
        if self.critical_client_hints {
            headers.push((http::HeaderName::from_static("critical-ch"), value));
        }
        headers
    }
}

/// Reads the identifier out of a cloud answer and puts it in cookie form.
///
/// Returns `None` when the service produced none, which is the ordinary case
/// for a key without the identity entitlement rather than a failure.
#[must_use]
pub fn identifier_from_answer(answer: &CloudAnswer) -> Option<String> {
    let raw = answer
        .element("fodid")?
        .get("idprobglobal")?
        .as_str()?
        .trim();
    if raw.is_empty() {
        return None;
    }
    let value = to_cookie_form(raw);
    if !is_well_formed(&value) {
        log::warn!(
            "51Degrees returned an identifier that cannot be carried in a cookie,              {} characters, issuing none",
            value.len()
        );
        return None;
    }
    Some(value)
}

/// Converts the service's identifier into the form a cookie can carry.
///
/// The service returns standard base64, which uses `+`, `/` and `=`. Core's
/// Edge Cookie alphabet is `[A-Za-z0-9._~-]` and refuses all three, so a raw
/// identifier is written and then dropped on read-back, with nothing to see.
/// This is the URL-safe alphabet, which is a pure substitution and exactly
/// reversible by [`from_cookie_form`], so the identifier is transported rather
/// than altered.
#[must_use]
pub fn to_cookie_form(raw: &str) -> String {
    raw.replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_owned()
}

/// Converts a cookie-form identifier back to the form the service issued.
///
/// Provided because anything that hands the identifier onward to 51Degrees
/// needs the original spelling, and the substitution above is only safe if the
/// way back exists and is tested.
#[must_use]
pub fn from_cookie_form(value: &str) -> String {
    let mut raw = value.replace('-', "+").replace('_', "/");
    // Base64 is padded to a multiple of four characters, and a remainder of one
    // is a length base64 cannot have. Restoring three padding characters there
    // would build a string that looks valid and decodes to nothing, so a value
    // that was never an identifier is returned untouched instead.
    let padding = match raw.len() % 4 {
        0 => 0,
        2 => 2,
        3 => 1,
        _ => return raw,
    };
    raw.push_str(&"=".repeat(padding));
    raw
}

/// Whether `value` has the shape of an identifier this provider issues.
///
/// Deliberately a shape check and not a signature check. Core asks this to
/// decide whether an incoming cookie is worth reading back, and the answer must
/// not depend on reaching a service, because that would put a network call in
/// front of every request that carries a cookie.
#[must_use]
fn is_well_formed(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[async_trait(?Send)]
impl EdgeCookieProvider for FiftyOneDegreesIdentity {
    fn id(&self) -> &'static str {
        PROVIDER_ID
    }

    fn code(&self) -> ProviderCode {
        IDENTITY_PROVIDER_CODE
    }

    async fn generate(
        &self,
        request_info: &dyn RequestInfo,
        _input: &IdentityInput<'_>,
        services: &RuntimeServices,
    ) -> Result<GeneratedEdgeCookie, Report<TrustedServerError>> {
        let evidence = evidence_for(request_info);
        // A failure here is not an error the request should carry. The caller
        // logs a failed generation and serves the response with no Edge Cookie,
        // which is what a service outage should cost: no identity, not a broken
        // page.
        let answer = match self.client.answer(&evidence, services).await {
            Ok(answer) => answer,
            Err(error) => {
                log::warn!("51Degrees identity unavailable, issuing no Edge Cookie: {error:?}");
                return Ok(GeneratedEdgeCookie::default());
            }
        };

        Ok(GeneratedEdgeCookie {
            id: identifier_from_answer(&answer),
            response_headers: self.client_hint_headers(&answer),
        })
    }

    fn accepts_id(&self, value: &str) -> bool {
        // Not the default. The default describes the built-in HMAC shape and
        // would refuse every identifier this provider creates.
        is_well_formed(value)
    }

    fn normalize_id_for_kv(&self, value: &str) -> String {
        // Not the default either. The default lowercases the leading segment,
        // and base64 is case-sensitive, so lowercasing would fold distinct
        // identifiers onto one storage key.
        value.to_owned()
    }

    fn required_permissions(&self) -> PermissionSet {
        // Writes the Edge Cookie to the device, so it requires permission to
        // store on the device. Whether that needs a signal is decided by the
        // country rules, not here.
        PermissionSet::none().with(Permission::StoreOnDevice)
    }

    async fn resolve_from_client(
        &self,
        _input: &ClientResolveInput<'_>,
        _services: &RuntimeServices,
    ) -> Result<GeneratedEdgeCookie, Report<TrustedServerError>> {
        // This provider creates entirely at the edge, so there is nothing for
        // the page to post back. Accepting a client-supplied identifier here
        // would let a browser choose its own 51Did, which is exactly what a
        // server-derived identifier exists to prevent.
        Ok(GeneratedEdgeCookie::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// An identifier with the shape the live service returns: 184 characters
    /// of standard base64, five `+`, four `/`, and `==` padding, measured
    /// against a real staging response on 6 September 2026.
    ///
    /// Built rather than copied, so no real identifier is written into the
    /// source. Copying one by hand is also how the first version of this test
    /// was wrong: a character was lost in transcription, the length stopped
    /// being one base64 can have, and the test then failed against correct
    /// code.
    const RAW: &str = concat!(
        "v5zpMhSCBhtlg5lPPDsacnjSwVYotOIo+oQd+99fsXtdaBgUAMPyE/fQnVliHW/LlthFKzlO6D",
        "WFOWKCVg8r7HPDsGJN1O4dr7FcChb2AHP+3UtX/Lf+/CQ64yDqdIJWGRcf3P4tAjfNhLqygBkw",
        "bWGVHVJOp3qPk9TOj+cqEqqeGxPsqLrCBQ==",
    );

    fn provider() -> FiftyOneDegreesIdentity {
        FiftyOneDegreesIdentity::new(
            Arc::new(CloudClient::new(
                "https://cloud.example.com/api/v4/json".to_owned(),
                500,
                true,
            )),
            false,
        )
    }

    fn answer_with(identifier: &str) -> CloudAnswer {
        CloudAnswer::new(json!({ "fodid": { "idprobglobal": identifier } }))
    }

    #[test]
    fn a_real_identifier_becomes_a_cookie_core_will_carry() {
        let created = identifier_from_answer(&answer_with(RAW)).expect("the service returned one");

        assert!(
            created
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~')),
            "core refuses any other character, and refuses it silently, got {created}"
        );
        assert!(
            created.len() + "51dd~".len() <= 256,
            "core caps the whole cookie value and the code prefix counts, got {}",
            created.len()
        );
    }

    #[test]
    fn the_fixture_is_the_shape_the_service_returns() {
        // A fixture that drifts from the real shape tests nothing, and this
        // file exists because the exact length and alphabet are what break.
        assert_eq!(RAW.len(), 184, "a measured identifier is 184 characters");
        assert!(RAW.contains('+') && RAW.contains('/') && RAW.ends_with("=="));
        assert_eq!(
            RAW.trim_end_matches('=').len() % 4,
            2,
            "base64 ending in two padding characters leaves a remainder of two"
        );
    }

    #[test]
    fn a_value_base64_could_never_be_is_returned_untouched() {
        // A length with remainder one cannot come from base64. Inventing three
        // padding characters would produce a string that looks valid and
        // decodes to nothing.
        let impossible = "abcde";

        assert_eq!(
            from_cookie_form(impossible),
            impossible,
            "a value that was never an identifier must not be dressed up as one"
        );
    }

    #[test]
    fn the_cookie_form_returns_the_service_spelling_exactly() {
        let cookie = to_cookie_form(RAW);

        assert_ne!(
            cookie, RAW,
            "the raw form cannot be carried, so it has to change"
        );
        assert_eq!(
            from_cookie_form(&cookie),
            RAW,
            "the substitution is only safe because the way back is exact, and anything \
             handing this identifier to 51Degrees needs the spelling it issued"
        );
    }

    #[test]
    fn an_identifier_survives_the_round_trip_verbatim() {
        let provider = provider();
        let created = identifier_from_answer(&answer_with(RAW)).expect("the service returned one");

        assert!(
            provider.accepts_id(&created),
            "an identifier this provider created must be one it accepts, or every visitor \
             looks new on every request and nothing reports an error"
        );
        assert_eq!(
            provider.normalize_id_for_kv(&created),
            created,
            "the identifier is case-sensitive, so the storage key must be it unchanged"
        );
    }

    #[test]
    fn the_built_in_defaults_would_have_dropped_it() {
        // The point of the two overrides, stated as a test rather than as a
        // comment. If these defaults ever start accepting this shape the
        // overrides can go; until then removing them silently breaks identity.
        let created = identifier_from_answer(&answer_with(RAW)).expect("the service returned one");

        assert!(
            !trusted_server_core::ec::generation::is_valid_ec_id(&created),
            "the built-in shape check refuses this identifier, which is why accepts_id is \
             overridden"
        );
        assert_ne!(
            trusted_server_core::ec::generation::normalize_ec_id_for_kv(&created),
            created,
            "the built-in key normalization alters this identifier, which is why \
             normalize_id_for_kv is overridden"
        );
    }

    #[test]
    fn an_answer_with_no_identifier_creates_none() {
        let empty = CloudAnswer::new(json!({ "device": { "ismobile": true } }));

        assert!(
            identifier_from_answer(&empty).is_none(),
            "a key without the identity entitlement returns no fodid, and inventing one \
             would put a provider code on an identifier that did not come from that provider"
        );
    }

    #[test]
    fn a_null_identifier_creates_none() {
        let null = CloudAnswer::new(json!({ "fodid": { "idprobglobal": null } }));

        assert!(identifier_from_answer(&null).is_none());
    }

    #[test]
    fn an_identifier_too_long_for_a_cookie_creates_none() {
        let huge = answer_with(&"A".repeat(MAX_ID_BYTES + 1));

        assert!(
            identifier_from_answer(&huge).is_none(),
            "writing a cookie core will refuse is worse than writing none, because the \
             refusal is silent"
        );
    }

    #[test]
    fn an_identifier_with_characters_it_could_not_contain_is_refused() {
        let provider = provider();

        assert!(
            !provider.accepts_id("has a space"),
            "a cookie value is not a place to be generous about what is accepted"
        );
        assert!(
            !provider.accepts_id(""),
            "an empty cookie is not an identity"
        );
        assert!(
            !provider.accepts_id(&"A".repeat(MAX_ID_BYTES + 1)),
            "an unbounded cookie must not reach a storage key"
        );
        assert!(
            !provider.accepts_id("AzUx+l72"),
            "the raw alphabet is not the cookie alphabet, so a raw identifier arriving in \
             a cookie did not come from this provider"
        );
    }

    fn answer_naming_hints() -> CloudAnswer {
        CloudAnswer::new(json!({"device": {
            "setheaderbrowseraccept-ch": "Sec-CH-UA,Sec-CH-UA-Platform",
            "setheaderhardwareaccept-ch": "Sec-CH-UA-Model",
        }}))
    }

    fn provider_with(critical: bool) -> FiftyOneDegreesIdentity {
        FiftyOneDegreesIdentity::new(
            Arc::new(CloudClient::new(
                "https://cloud.example.com/api/v4/json".to_owned(),
                500,
                true,
            )),
            critical,
        )
    }

    #[test]
    fn the_accept_ch_header_rides_out_with_the_identifier() {
        let headers = provider_with(false).client_hint_headers(&answer_naming_hints());

        assert_eq!(headers.len(), 1, "Accept-CH only, got {headers:?}");
        assert_eq!(headers[0].0.as_str(), "accept-ch");
        assert_eq!(
            headers[0].1.to_str().expect("should be text"),
            "Sec-CH-UA, Sec-CH-UA-Platform, Sec-CH-UA-Model"
        );
    }

    #[test]
    fn a_deployment_can_turn_critical_ch_off() {
        // On by default, because without it the first page view of a session is
        // priced on a User-Agent alone. A deployment that would rather serve
        // that page immediately can switch it off, and this is that switch.
        let headers = provider_with(false).client_hint_headers(&answer_naming_hints());

        assert!(
            !headers
                .iter()
                .any(|(name, _)| name.as_str() == "critical-ch"),
            "got {headers:?}"
        );
    }

    #[test]
    fn critical_ch_is_sent_when_a_deployment_does_ask() {
        let headers = provider_with(true).client_hint_headers(&answer_naming_hints());

        let critical = headers
            .iter()
            .find(|(name, _)| name.as_str() == "critical-ch")
            .expect("should be present when asked for");
        assert_eq!(
            critical.1.to_str().expect("should be text"),
            "Sec-CH-UA, Sec-CH-UA-Platform, Sec-CH-UA-Model",
            "a browser retries only for the hints it was told are critical, so the two              headers have to name the same set"
        );
    }

    #[test]
    fn an_answer_naming_no_hints_sets_no_headers() {
        let headers = provider_with(true).client_hint_headers(&CloudAnswer::new(json!({})));

        assert!(headers.is_empty(), "got {headers:?}");
    }

    #[test]
    fn the_provider_code_is_the_registered_one() {
        assert_eq!(
            provider().code().to_string(),
            "51dd",
            "the code is allocated in the registry, so changing it here would create \
             identifiers that collide with another provider's"
        );
    }
}
