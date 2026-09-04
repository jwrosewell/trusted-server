//! The shared asset cache: raw origin responses for assets.
//!
//! Three caches are easy to confuse and they are not the same thing.
//!
//! | Cache           | Holds                               | Owner                       |
//! | --------------- | ----------------------------------- | --------------------------- |
//! | The host's own  | Whatever the platform decides       | Fastly and the like.        |
//! | Template cache  | Assembled page templates            | [`super::template_cache`].  |
//! | **Asset cache** | **Raw origin responses for assets** | **This module.**            |
//!
//! At the edge the platform already caches and the adapter is a thin wrapper
//! over it. A deployment with nothing in front of it has no such platform, so
//! every request for every asset reaches the publisher's origin every time.
//! This module is the contract for a cache that sits in that gap. The trait and
//! the do-nothing default live here; an implementation that actually stores
//! bytes lives in its own crate under `crates/cache` and is injected by the
//! adapter, so core depends on no cache library.
//!
//! # The rule this must not break
//!
//! A shared cache that stores one reader's response and serves it to the next
//! is a data breach rather than a bug. The template cache fought the same
//! problem and its answer is an allowlist plus an eligibility gate; this module
//! copies that shape. [`AssetCacheEligibility`] is the gate, and an
//! implementation is only ever handed a key and an entry that passed it.

use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName};
use http::{Method, StatusCode};

/// Response headers stored with an asset and replayed on a hit.
///
/// An allowlist, so a header an origin invents is excluded until somebody
/// decides otherwise. Two groups are here and nothing else. The representation
/// headers describe the bytes that were stored, so dropping one would serve a
/// body the reader cannot decode. The policy headers are per-URL statements
/// that are identical for every reader.
///
/// Deliberately absent: `Set-Cookie` and anything else that is per-reader,
/// `Cache-Control` and the other freshness headers, which this cache decides
/// for itself from the lifetime it stored, and `Vary`, because a response that
/// carries one this cache does not cover is refused rather than stored.
pub const ASSET_REPLAYABLE_HEADERS: &[&str] = &[
    // Representation of the stored bytes.
    "content-type",
    "content-encoding",
    "content-language",
    "etag",
    "last-modified",
    // Per-URL policy, identical for every reader.
    "cross-origin-resource-policy",
    "referrer-policy",
    "x-content-type-options",
    "timing-allow-origin",
    "access-control-allow-origin",
];

/// The one `Vary` input this cache covers, because the key carries it.
///
/// An origin that compresses varies on `Accept-Encoding`, which is nearly every
/// origin, so refusing that would mean the cache stored almost nothing. This
/// cache stores the origin's bytes exactly as sent, content coding included, so
/// it does not cover the header structurally the way the template cache does.
/// It covers it by putting the request's `Accept-Encoding` in the key instead.
/// Any other `Vary` input is refused.
const COVERED_VARY_HEADER: &str = "accept-encoding";

/// Identifies one stored asset.
///
/// # What is in the key, and why
///
/// The absolute target URL is stored **including its query string, verbatim**.
/// That is the answer to the signed-URL hazard: a per-reader token in a query
/// string makes the key unique to that reader, so the entry is never handed to
/// anybody else. It wastes a slot, which eviction reclaims. Normalizing or
/// stripping the query would turn that waste into two readers sharing one
/// entry, which is the failure this cache must not have.
///
/// The request method is in the key because a cache that ignored it would serve
/// a `GET` body to a `HEAD`. Only `GET` is ever stored today (see
/// [`AssetCacheEligibility::check_request`]) so the field is a guard rather
/// than a discriminator, and it stays correct if that ever widens.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AssetCacheKey {
    /// Request method, uppercase.
    method: String,
    /// Absolute target URL, query string included, exactly as requested.
    url: String,
    /// The request's `Accept-Encoding`, lowercased and whitespace-trimmed, or
    /// an empty string when the request sent none.
    accept_encoding: String,
}

impl AssetCacheKey {
    /// Builds a key for one asset request.
    #[must_use]
    pub fn new(method: &Method, url: &str, request_headers: &HeaderMap) -> Self {
        let accept_encoding = request_headers
            .get(header::ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_default();
        Self {
            method: method.as_str().to_ascii_uppercase(),
            url: url.to_owned(),
            accept_encoding,
        }
    }

    /// The request method this key covers.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The absolute target URL this key covers, query string included.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The `Accept-Encoding` value this key covers, or an empty string.
    #[must_use]
    pub fn accept_encoding(&self) -> &str {
        &self.accept_encoding
    }

    /// Approximate heap cost of holding this key, in bytes.
    ///
    /// Used by an implementation that bounds itself by memory rather than by
    /// number of entries, so the bound covers keys as well as bodies.
    #[must_use]
    pub fn size_in_bytes(&self) -> usize {
        self.method.len() + self.url.len() + self.accept_encoding.len()
    }
}

/// A stored asset: the origin's own bytes plus the headers needed to replay
/// them.
///
/// Build one with [`AssetCacheEntry::from_origin`], which keeps only the
/// headers in [`ASSET_REPLAYABLE_HEADERS`]. Constructing one field by field is
/// deliberately not possible from outside this module, so no caller can store
/// a `Set-Cookie` by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetCacheEntry {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl AssetCacheEntry {
    /// Builds an entry from an origin response, dropping every header outside
    /// [`ASSET_REPLAYABLE_HEADERS`].
    #[must_use]
    pub fn from_origin(status: StatusCode, origin_headers: &HeaderMap, body: Bytes) -> Self {
        let mut headers = HeaderMap::new();
        for name in ASSET_REPLAYABLE_HEADERS {
            let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            for value in origin_headers.get_all(&name) {
                headers.append(name.clone(), value.clone());
            }
        }
        Self {
            status,
            headers,
            body,
        }
    }

    /// The stored status code.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The stored headers, already filtered to the replayable allowlist.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The stored body, exactly as the origin sent it.
    #[must_use]
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Approximate heap cost of holding this entry, in bytes.
    ///
    /// Counts the body plus each stored header name and value. It is an
    /// approximation because it ignores the map's own overhead, and it is
    /// deliberately an undercount of nothing that matters: the body dominates
    /// for every asset large enough to care about.
    #[must_use]
    pub fn size_in_bytes(&self) -> usize {
        let headers: usize = self
            .headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len())
            .sum();
        self.body.len() + headers
    }
}

/// Why an asset read did not produce usable bytes.
///
/// Every variant means "fetch it from the origin yourself". None is a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::Display)]
pub enum AssetCacheMiss {
    /// No entry for this key.
    #[display("no cached asset for this key")]
    NotFound,
    /// This deployment has no asset cache.
    #[display("no asset cache in this deployment")]
    Unsupported,
}

impl core::error::Error for AssetCacheMiss {}

/// Errors an asset cache write can produce.
#[derive(Debug, derive_more::Display)]
pub enum AssetCacheError {
    /// This deployment has no asset cache.
    #[display("no asset cache in this deployment")]
    Unsupported,
    /// The implementation rejected the operation.
    #[display("asset cache backend error: {message}")]
    Backend {
        /// What the implementation reported.
        message: String,
    },
}

impl core::error::Error for AssetCacheError {}

/// Why a request or response may not be cached.
///
/// Carried so a refusal can be logged with its reason rather than as a silent
/// non-event, which is what makes a cache that stores nothing diagnosable.
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
pub enum AssetCacheRefusal {
    /// The request method is not one this cache stores.
    #[display("request method `{method}` is not cacheable, only GET is stored")]
    Method {
        /// The method that was refused.
        method: String,
    },
    /// The request carried per-reader credentials or state.
    #[display("request carries `{header}`, so the response could be specific to one reader")]
    ReaderSpecificRequest {
        /// The header that caused the refusal.
        header: String,
    },
    /// The response status is not one this cache stores.
    #[display("response status {status} is not cacheable, only 200 is stored")]
    Status {
        /// The status that was refused.
        status: u16,
    },
    /// The response set browser state, so it is specific to one reader.
    #[display("response carries `set-cookie`, so it is specific to one reader")]
    SetCookie,
    /// The origin's `Cache-Control` forbids storing the response.
    #[display("origin `cache-control` says `{directive}`")]
    CacheControlForbids {
        /// The directive that forbade it.
        directive: String,
    },
    /// The origin varies the response on something the key does not carry.
    #[display("origin varies on `{name}`, which the cache key does not carry")]
    UncoveredVary {
        /// The `Vary` input that is not covered.
        name: String,
    },
    /// The origin gave no lifetime, so this cache has none to honor.
    #[display(
        "origin `cache-control` has no `max-age` or `s-maxage`, so there is no lifetime to honor"
    )]
    NoLifetime,
    /// The lifetime the origin gave has already run out.
    #[display("origin lifetime has already expired once `age` is subtracted")]
    AlreadyStale,
    /// The body is larger than one entry is allowed to be.
    #[display("body is {size} bytes, over the {limit} byte per-entry limit")]
    TooLarge {
        /// Size of the body that was refused.
        size: usize,
        /// The configured per-entry limit.
        limit: usize,
    },
}

/// The limits an eligibility check enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetCacheLimits {
    /// Largest body a single entry may hold, in bytes.
    pub max_entry_bytes: usize,
    /// Longest lifetime this cache will honor, whatever the origin asked for.
    ///
    /// An origin asking for a year is not wrong, but an in-memory cache that
    /// honored it would hold a stale asset until the process restarted, with no
    /// way to invalidate it.
    pub max_ttl: Duration,
}

/// The gate that decides what this cache is willing to store.
///
/// Split in two because the two halves happen at different moments. The request
/// half runs before the lookup, so an ineligible request never reads the cache
/// either. The response half runs after the origin answered and returns the
/// lifetime to store the entry for, so eligibility and lifetime come from one
/// parse of one header rather than two that can disagree.
pub struct AssetCacheEligibility;

impl AssetCacheEligibility {
    /// Decides whether an asset request may use the cache at all.
    ///
    /// # Errors
    ///
    /// Returns the [`AssetCacheRefusal`] naming the reason. A refusal is a
    /// normal outcome, not a fault.
    pub fn check_request(
        method: &Method,
        request_headers: &HeaderMap,
    ) -> Result<(), AssetCacheRefusal> {
        if method != Method::GET {
            return Err(AssetCacheRefusal::Method {
                method: method.as_str().to_owned(),
            });
        }
        // Defense in depth rather than a live concern. The asset proxy's own
        // outbound allowlist (`ASSET_PROXY_FORWARD_HEADERS` in
        // `crate::proxy`) carries neither of these to the origin, so the origin
        // cannot vary on them today. This check is what keeps that true if the
        // allowlist ever grows: a reader's cookie or credentials reaching the
        // origin would turn a shared entry into one reader's response served to
        // the next.
        for name in [header::COOKIE, header::AUTHORIZATION] {
            if request_headers.contains_key(&name) {
                return Err(AssetCacheRefusal::ReaderSpecificRequest {
                    header: name.as_str().to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Decides whether an origin response may be stored, and for how long.
    ///
    /// Returns the lifetime to store it for, derived from the origin's own
    /// `Cache-Control` and reduced by any `Age` the origin reported, then
    /// capped at [`AssetCacheLimits::max_ttl`].
    ///
    /// # Errors
    ///
    /// Returns the [`AssetCacheRefusal`] naming the reason. A refusal is a
    /// normal outcome, not a fault.
    pub fn check_response(
        status: StatusCode,
        response_headers: &HeaderMap,
        body_len: usize,
        limits: AssetCacheLimits,
    ) -> Result<Duration, AssetCacheRefusal> {
        if status != StatusCode::OK {
            return Err(AssetCacheRefusal::Status {
                status: status.as_u16(),
            });
        }
        if response_headers.contains_key(header::SET_COOKIE) {
            return Err(AssetCacheRefusal::SetCookie);
        }
        if body_len > limits.max_entry_bytes {
            return Err(AssetCacheRefusal::TooLarge {
                size: body_len,
                limit: limits.max_entry_bytes,
            });
        }
        Self::check_vary(response_headers)?;

        let cache_control = header_values_joined(response_headers, &header::CACHE_CONTROL);
        for directive in ["no-store", "private", "no-cache"] {
            if has_directive(&cache_control, directive) {
                return Err(AssetCacheRefusal::CacheControlForbids {
                    directive: directive.to_owned(),
                });
            }
        }

        // `s-maxage` outranks `max-age` for a shared cache, which is what this
        // is: it holds one copy on behalf of every reader.
        let seconds = directive_seconds(&cache_control, "s-maxage")
            .or_else(|| directive_seconds(&cache_control, "max-age"))
            .ok_or(AssetCacheRefusal::NoLifetime)?;

        // The origin's lifetime counts from when the origin produced the
        // response, not from when it reached us. Ignoring `Age` would extend
        // every asset that came through another cache by however long it sat
        // there.
        let age = response_headers
            .get(header::AGE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let remaining = seconds
            .checked_sub(age)
            .filter(|remaining| *remaining > 0)
            .ok_or(AssetCacheRefusal::AlreadyStale)?;

        Ok(Duration::from_secs(remaining).min(limits.max_ttl))
    }

    /// Refuses a response that varies on anything the key does not carry.
    fn check_vary(response_headers: &HeaderMap) -> Result<(), AssetCacheRefusal> {
        for value in response_headers.get_all(header::VARY) {
            let Ok(value) = value.to_str() else {
                return Err(AssetCacheRefusal::UncoveredVary {
                    name: "<unreadable>".to_owned(),
                });
            };
            for name in value.split(',') {
                let name = name.trim().to_ascii_lowercase();
                if name.is_empty() || name == COVERED_VARY_HEADER {
                    continue;
                }
                return Err(AssetCacheRefusal::UncoveredVary { name });
            }
        }
        Ok(())
    }
}

/// Joins every value of one header into a single lowercase string.
fn header_values_joined(headers: &HeaderMap, name: &HeaderName) -> String {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(",")
        .to_ascii_lowercase()
}

/// Whether a comma-separated directive list contains a bare directive.
///
/// Matches on whole directives, so `no-cache` does not match inside a header
/// name listed by `no-cache="x-something"`.
fn has_directive(cache_control: &str, directive: &str) -> bool {
    cache_control
        .split(',')
        .map(str::trim)
        .any(|part| part == directive || part.starts_with(&format!("{directive}=")))
}

/// Reads the seconds value of a `name=seconds` directive.
fn directive_seconds(cache_control: &str, name: &str) -> Option<u64> {
    cache_control
        .split(',')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(&format!("{name}="))?.trim().parse().ok())
}

/// A deployment's asset cache.
///
/// `Send + Sync` on the trait, `?Send` on the futures, matching
/// [`super::PlatformTemplateCache`]: `RuntimeServices` is held in a static, so
/// the trait object crosses threads even though the futures never do.
#[async_trait::async_trait(?Send)]
pub trait PlatformAssetCache: Send + Sync {
    /// A stable identifier for the implementation, for logs and diagnostics.
    fn id(&self) -> &'static str;

    /// Reads a stored asset.
    ///
    /// # Errors
    ///
    /// Returns [`AssetCacheMiss`], which is not a failure: every variant means
    /// the caller should fetch from the origin itself.
    async fn get(&self, key: &AssetCacheKey) -> Result<AssetCacheEntry, AssetCacheMiss>;

    /// Stores an asset for `ttl`.
    ///
    /// Callers must have passed both halves of [`AssetCacheEligibility`] first.
    /// An implementation stores what it is given and cannot tell a shared asset
    /// from one reader's.
    ///
    /// # Errors
    ///
    /// Returns [`AssetCacheError`] when the implementation refuses or fails the
    /// write.
    async fn insert(
        &self,
        key: AssetCacheKey,
        entry: AssetCacheEntry,
        ttl: Duration,
    ) -> Result<(), AssetCacheError>;

    /// Drops every stored asset. The rollback lever.
    ///
    /// # Errors
    ///
    /// Returns [`AssetCacheError`] when the implementation cannot comply.
    async fn purge_all(&self) -> Result<(), AssetCacheError>;
}

impl core::fmt::Debug for dyn PlatformAssetCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PlatformAssetCache")
            .field("id", &self.id())
            .finish()
    }
}

/// The null object, used whenever no asset cache is selected.
///
/// Reporting [`AssetCacheMiss::Unsupported`] rather than erroring means a
/// deployment with no cache fetches every asset from the origin, which is
/// exactly what it did before this module existed. It degrades, it does not
/// fail.
pub struct UnavailableAssetCache;

#[async_trait::async_trait(?Send)]
impl PlatformAssetCache for UnavailableAssetCache {
    fn id(&self) -> &'static str {
        "unavailable"
    }

    async fn get(&self, _key: &AssetCacheKey) -> Result<AssetCacheEntry, AssetCacheMiss> {
        Err(AssetCacheMiss::Unsupported)
    }

    async fn insert(
        &self,
        _key: AssetCacheKey,
        _entry: AssetCacheEntry,
        _ttl: Duration,
    ) -> Result<(), AssetCacheError> {
        Err(AssetCacheError::Unsupported)
    }

    async fn purge_all(&self) -> Result<(), AssetCacheError> {
        Err(AssetCacheError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use http::header::HeaderValue;

    use super::*;

    const LIMITS: AssetCacheLimits = AssetCacheLimits {
        max_entry_bytes: 1_024,
        max_ttl: Duration::from_secs(3_600),
    };

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            let name = HeaderName::from_bytes(name.as_bytes()).expect("should parse header name");
            let value = value.parse().expect("should parse header value");
            map.append(name, value);
        }
        map
    }

    #[test]
    fn key_keeps_the_query_string_verbatim() {
        // Arrange: two readers given different signed tokens for one asset.
        let first = AssetCacheKey::new(
            &Method::GET,
            "https://cdn.example.com/a.css?token=reader-one",
            &HeaderMap::new(),
        );
        let second = AssetCacheKey::new(
            &Method::GET,
            "https://cdn.example.com/a.css?token=reader-two",
            &HeaderMap::new(),
        );

        // Assert: they never share an entry. This is the signed-URL hazard, and
        // a key that normalized or dropped the query would fail here.
        assert_ne!(
            first, second,
            "should give per-reader signed URLs separate cache keys"
        );
        assert_eq!(
            first.url(),
            "https://cdn.example.com/a.css?token=reader-one",
            "should keep the query string exactly as requested"
        );
    }

    #[test]
    fn key_separates_encodings() {
        // Arrange: the same asset asked for with and without compression.
        let plain = AssetCacheKey::new(&Method::GET, "https://a.example/x.js", &HeaderMap::new());
        let gzip = AssetCacheKey::new(
            &Method::GET,
            "https://a.example/x.js",
            &headers(&[("accept-encoding", "GZIP, br")]),
        );

        // Assert: separate entries, and the value is normalized to lowercase so
        // two spellings of one encoding do not split the entry in two.
        assert_ne!(plain, gzip, "should key compressed and plain bytes apart");
        assert_eq!(
            gzip.accept_encoding(),
            "gzip, br",
            "should lowercase the accept-encoding value"
        );
    }

    #[test]
    fn entry_drops_every_header_outside_the_allowlist() {
        // Arrange: an origin response carrying a cookie and a policy header.
        let origin = headers(&[
            ("content-type", "text/css"),
            ("set-cookie", "session=secret"),
            ("cache-control", "max-age=60"),
            ("x-content-type-options", "nosniff"),
        ]);

        // Act.
        let entry = AssetCacheEntry::from_origin(StatusCode::OK, &origin, Bytes::from("body"));

        // Assert: the cookie and the freshness header are gone, the
        // representation and policy headers stayed.
        assert!(
            !entry.headers().contains_key("set-cookie"),
            "should never store a set-cookie header"
        );
        assert!(
            !entry.headers().contains_key("cache-control"),
            "should not store the origin's freshness headers"
        );
        assert_eq!(
            entry
                .headers()
                .get("content-type")
                .map(HeaderValue::as_bytes),
            Some(&b"text/css"[..]),
            "should keep the content type"
        );
        assert!(
            entry.headers().contains_key("x-content-type-options"),
            "should keep an allowlisted policy header"
        );
    }

    #[test]
    fn entry_size_counts_body_and_headers() {
        let entry = AssetCacheEntry::from_origin(
            StatusCode::OK,
            &headers(&[("content-type", "text/css")]),
            Bytes::from("0123456789"),
        );

        // "content-type" is 12 bytes and "text/css" is 8, so the header pair
        // adds 20 to the 10 body bytes.
        assert_eq!(
            entry.size_in_bytes(),
            30,
            "should count the body and each stored header name and value"
        );
    }

    #[test]
    fn only_get_requests_are_cacheable() {
        assert_eq!(
            AssetCacheEligibility::check_request(&Method::POST, &HeaderMap::new()),
            Err(AssetCacheRefusal::Method {
                method: "POST".to_owned()
            }),
            "should refuse a POST"
        );
        assert!(
            AssetCacheEligibility::check_request(&Method::GET, &HeaderMap::new()).is_ok(),
            "should accept a plain GET"
        );
    }

    #[test]
    fn reader_specific_requests_are_refused() {
        for header in ["cookie", "authorization"] {
            assert_eq!(
                AssetCacheEligibility::check_request(
                    &Method::GET,
                    &headers(&[(header, "anything")])
                ),
                Err(AssetCacheRefusal::ReaderSpecificRequest {
                    header: header.to_owned()
                }),
                "should refuse a request carrying {header}"
            );
        }
    }

    #[test]
    fn only_200_responses_are_storable() {
        for status in [
            StatusCode::PARTIAL_CONTENT,
            StatusCode::NOT_MODIFIED,
            StatusCode::FOUND,
            StatusCode::NOT_FOUND,
        ] {
            let result = AssetCacheEligibility::check_response(
                status,
                &headers(&[("cache-control", "max-age=60")]),
                4,
                LIMITS,
            );
            assert_eq!(
                result,
                Err(AssetCacheRefusal::Status {
                    status: status.as_u16()
                }),
                "should refuse status {status}"
            );
        }
    }

    #[test]
    fn set_cookie_responses_are_refused() {
        let result = AssetCacheEligibility::check_response(
            StatusCode::OK,
            &headers(&[("cache-control", "max-age=60"), ("set-cookie", "a=b")]),
            4,
            LIMITS,
        );
        assert_eq!(
            result,
            Err(AssetCacheRefusal::SetCookie),
            "should refuse a response that sets browser state"
        );
    }

    #[test]
    fn cache_control_can_forbid_storing() {
        for directive in ["no-store", "private", "no-cache"] {
            let value = format!("max-age=600, {directive}");
            let result = AssetCacheEligibility::check_response(
                StatusCode::OK,
                &headers(&[("cache-control", &value)]),
                4,
                LIMITS,
            );
            assert_eq!(
                result,
                Err(AssetCacheRefusal::CacheControlForbids {
                    directive: directive.to_owned()
                }),
                "should honor `{directive}`"
            );
        }
    }

    #[test]
    fn no_cache_with_a_field_name_still_forbids() {
        // `no-cache="x-thing"` is narrower than a bare `no-cache`, but this
        // cache does not implement the narrow form, so it must refuse rather
        // than treat the response as freely storable.
        let result = AssetCacheEligibility::check_response(
            StatusCode::OK,
            &headers(&[("cache-control", "max-age=600, no-cache=\"x-thing\"")]),
            4,
            LIMITS,
        );
        assert_eq!(
            result,
            Err(AssetCacheRefusal::CacheControlForbids {
                directive: "no-cache".to_owned()
            }),
            "should refuse a qualified no-cache as well as a bare one"
        );
    }

    #[test]
    fn a_response_with_no_lifetime_is_refused() {
        let result = AssetCacheEligibility::check_response(
            StatusCode::OK,
            &headers(&[("content-type", "text/css")]),
            4,
            LIMITS,
        );
        assert_eq!(
            result,
            Err(AssetCacheRefusal::NoLifetime),
            "should refuse rather than invent a lifetime the origin did not give"
        );
    }

    #[test]
    fn shared_max_age_outranks_max_age() {
        let ttl = AssetCacheEligibility::check_response(
            StatusCode::OK,
            &headers(&[("cache-control", "max-age=60, s-maxage=120")]),
            4,
            LIMITS,
        )
        .expect("should accept a response with a lifetime");
        assert_eq!(
            ttl,
            Duration::from_secs(120),
            "should prefer s-maxage, because this is a shared cache"
        );
    }

    #[test]
    fn age_is_subtracted_from_the_lifetime() {
        let ttl = AssetCacheEligibility::check_response(
            StatusCode::OK,
            &headers(&[("cache-control", "max-age=100"), ("age", "40")]),
            4,
            LIMITS,
        )
        .expect("should accept a response with time left");
        assert_eq!(
            ttl,
            Duration::from_secs(60),
            "should count the lifetime from when the origin produced the response"
        );
    }

    #[test]
    fn an_already_stale_response_is_refused() {
        let result = AssetCacheEligibility::check_response(
            StatusCode::OK,
            &headers(&[("cache-control", "max-age=30"), ("age", "30")]),
            4,
            LIMITS,
        );
        assert_eq!(
            result,
            Err(AssetCacheRefusal::AlreadyStale),
            "should refuse a response whose lifetime has already run out"
        );
    }

    #[test]
    fn the_lifetime_is_capped() {
        let ttl = AssetCacheEligibility::check_response(
            StatusCode::OK,
            &headers(&[("cache-control", "max-age=31536000")]),
            4,
            LIMITS,
        )
        .expect("should accept a long-lived response");
        assert_eq!(
            ttl, LIMITS.max_ttl,
            "should cap an origin asking for a year at the configured ceiling"
        );
    }

    #[test]
    fn accept_encoding_is_the_only_vary_covered() {
        let ok = AssetCacheEligibility::check_response(
            StatusCode::OK,
            &headers(&[("cache-control", "max-age=60"), ("vary", "Accept-Encoding")]),
            4,
            LIMITS,
        );
        assert!(
            ok.is_ok(),
            "should accept the vary every compressing origin sends, because the key carries it"
        );

        let refused = AssetCacheEligibility::check_response(
            StatusCode::OK,
            &headers(&[
                ("cache-control", "max-age=60"),
                ("vary", "Accept-Encoding, Cookie"),
            ]),
            4,
            LIMITS,
        );
        assert_eq!(
            refused,
            Err(AssetCacheRefusal::UncoveredVary {
                name: "cookie".to_owned()
            }),
            "should refuse an origin that varies an asset by cookie"
        );

        let wildcard = AssetCacheEligibility::check_response(
            StatusCode::OK,
            &headers(&[("cache-control", "max-age=60"), ("vary", "*")]),
            4,
            LIMITS,
        );
        assert_eq!(
            wildcard,
            Err(AssetCacheRefusal::UncoveredVary {
                name: "*".to_owned()
            }),
            "should refuse `Vary: *`, which means uncacheable"
        );
    }

    #[test]
    fn an_oversized_body_is_refused() {
        let result = AssetCacheEligibility::check_response(
            StatusCode::OK,
            &headers(&[("cache-control", "max-age=60")]),
            LIMITS.max_entry_bytes + 1,
            LIMITS,
        );
        assert_eq!(
            result,
            Err(AssetCacheRefusal::TooLarge {
                size: LIMITS.max_entry_bytes + 1,
                limit: LIMITS.max_entry_bytes,
            }),
            "should refuse a body over the per-entry limit"
        );
    }

    #[tokio::test]
    async fn the_null_object_reports_unsupported_rather_than_erroring() {
        let cache = UnavailableAssetCache;
        let key = AssetCacheKey::new(&Method::GET, "https://a.example/x.css", &HeaderMap::new());

        assert_eq!(cache.id(), "unavailable", "should name itself");
        assert_eq!(
            cache.get(&key).await.expect_err("should not find anything"),
            AssetCacheMiss::Unsupported,
            "should report unsupported rather than not-found"
        );
        assert!(
            matches!(
                cache
                    .insert(
                        key,
                        AssetCacheEntry::from_origin(
                            StatusCode::OK,
                            &HeaderMap::new(),
                            Bytes::new()
                        ),
                        Duration::from_secs(1),
                    )
                    .await,
                Err(AssetCacheError::Unsupported)
            ),
            "should refuse a write when there is no cache"
        );
        assert!(
            matches!(cache.purge_all().await, Err(AssetCacheError::Unsupported)),
            "should refuse a purge when there is no cache"
        );
    }
}
