//! A memory-bound asset cache for a deployment with nothing in front of it.
//!
//! At the edge the platform already caches. A deployment with no platform cache
//! ahead of it fetches every asset from the publisher's origin on every
//! request, and this crate is what stops that. It stores raw origin responses
//! in the process, bounded by **bytes** rather than by number of entries.
//!
//! # Why bytes rather than entries
//!
//! Assets run from a few hundred bytes to megabytes, so a limit expressed as a
//! number of entries tells an operator nothing about how much memory the
//! process will use. On a box where memory is the constraint that matters, that
//! is the wrong unit. `moka` supports a weigher, which is the feature this crate
//! is built around: every entry is charged its own real size and the total is
//! what is bounded.
//!
//! # What it will and will not store
//!
//! Nothing here decides. The eligibility gate lives in `trusted-server-core`
//! (`AssetCacheEligibility`) and the caller runs it, so this crate is only ever
//! handed a key and an entry that already passed. That is deliberate: the rule
//! a shared cache must not break, that one reader's response is never served to
//! the next, is stated once in core rather than restated in each provider.

use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use moka::policy::Expiry;
use trusted_server_core::platform::{
    AssetCacheEntry, AssetCacheError, AssetCacheKey, AssetCacheMiss, PlatformAssetCache,
};

/// The provider key this cache is selected by, in `[cache] provider`.
pub const PROVIDER_ID: &str = "51degrees";

/// One stored asset plus the lifetime it was stored for.
///
/// The lifetime travels with the value because each asset expires on its own
/// origin's `Cache-Control` rather than on one cache-wide setting, and `moka`
/// reads a per-entry lifetime off the value through [`Expiry`].
#[derive(Debug, Clone)]
struct Stored {
    entry: AssetCacheEntry,
    ttl: Duration,
}

/// Reads each entry's own lifetime.
///
/// `expire_after_create` is the only hook implemented, so an entry expires a
/// fixed time after it was stored and reading it does not extend it. That is
/// what honoring an origin's `max-age` means: the origin stated how long the
/// bytes are good for, counted from when it produced them, and a read says
/// nothing about that.
struct PerEntryLifetime;

impl Expiry<AssetCacheKey, Stored> for PerEntryLifetime {
    fn expire_after_create(
        &self,
        _key: &AssetCacheKey,
        value: &Stored,
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

/// A memory-bound, in-process asset cache.
///
/// Cheap to clone: the underlying store is shared, so a clone is another handle
/// on the same cache rather than a second cache.
#[derive(Clone)]
pub struct FiftyOneDegreesAssetCache {
    inner: Cache<AssetCacheKey, Stored>,
}

impl FiftyOneDegreesAssetCache {
    /// Builds a cache holding at most `max_bytes` of assets.
    ///
    /// The bound counts each entry's real size, being its body, its stored
    /// headers and its key, so the number the operator configures is the number
    /// that governs memory. Eviction is `moka`'s, which admits an entry only
    /// when it is worth more than what it would displace, so one pass of a
    /// crawler over rarely-read assets does not flush the assets a real page
    /// needs.
    #[must_use]
    pub fn new(max_bytes: u64) -> Self {
        let inner = Cache::builder()
            .max_capacity(max_bytes)
            .weigher(|key: &AssetCacheKey, value: &Stored| {
                // Saturating, because moka's weight is a u32 and an entry
                // larger than that would wrap to a small number and defeat the
                // bound. The per-entry limit in the eligibility gate keeps real
                // entries far below this, so the clamp is a guard rather than a
                // path anything takes.
                u32::try_from(
                    key.size_in_bytes()
                        .saturating_add(value.entry.size_in_bytes()),
                )
                .unwrap_or(u32::MAX)
            })
            .expire_after(PerEntryLifetime)
            .build();
        Self { inner }
    }

    /// Builds a cache behind an [`Arc`], ready to inject.
    ///
    /// The shape an adapter wants, so the call site reads as one expression
    /// inside `build_asset_cache`.
    #[must_use]
    pub fn shared(max_bytes: u64) -> Arc<dyn PlatformAssetCache> {
        Arc::new(Self::new(max_bytes))
    }

    /// Bytes currently held, after any pending eviction work is applied.
    ///
    /// `moka` applies eviction lazily, so this runs the pending maintenance
    /// first. Present for tests and for an operator diagnostic, not for the
    /// request path.
    pub async fn weighted_size(&self) -> u64 {
        self.inner.run_pending_tasks().await;
        self.inner.weighted_size()
    }

    /// Number of entries currently held, after pending eviction work.
    ///
    /// Present for tests and diagnostics. The bound is on bytes, not on this.
    pub async fn entry_count(&self) -> u64 {
        self.inner.run_pending_tasks().await;
        self.inner.entry_count()
    }
}

#[async_trait::async_trait(?Send)]
impl PlatformAssetCache for FiftyOneDegreesAssetCache {
    fn id(&self) -> &'static str {
        PROVIDER_ID
    }

    async fn get(&self, key: &AssetCacheKey) -> Result<AssetCacheEntry, AssetCacheMiss> {
        match self.inner.get(key).await {
            Some(stored) => {
                log::trace!("asset cache hit for {}", key.url());
                Ok(stored.entry)
            }
            None => Err(AssetCacheMiss::NotFound),
        }
    }

    async fn insert(
        &self,
        key: AssetCacheKey,
        entry: AssetCacheEntry,
        ttl: Duration,
    ) -> Result<(), AssetCacheError> {
        log::trace!(
            "asset cache storing {} bytes for {}s: {}",
            entry.size_in_bytes(),
            ttl.as_secs(),
            key.url()
        );
        self.inner.insert(key, Stored { entry, ttl }).await;
        Ok(())
    }

    async fn purge_all(&self) -> Result<(), AssetCacheError> {
        self.inner.invalidate_all();
        self.inner.run_pending_tasks().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::header::{HeaderMap, HeaderName, HeaderValue};
    use http::{Method, StatusCode};

    use super::*;

    /// Builds an entry whose body is `size` bytes and which carries one header.
    fn entry(size: usize) -> AssetCacheEntry {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("text/css"),
        );
        AssetCacheEntry::from_origin(StatusCode::OK, &headers, Bytes::from(vec![b'x'; size]))
    }

    fn key(path: &str) -> AssetCacheKey {
        AssetCacheKey::new(
            &Method::GET,
            &format!("https://cdn.example.com/{path}"),
            &HeaderMap::new(),
        )
    }

    #[tokio::test]
    async fn an_asset_survives_the_round_trip_byte_for_byte() {
        // Arrange.
        let cache = FiftyOneDegreesAssetCache::new(1_000_000);
        let stored = entry(64);
        let asset_key = key("a.css");

        // Act.
        cache
            .insert(asset_key.clone(), stored.clone(), Duration::from_secs(60))
            .await
            .expect("should store an eligible asset");
        let read = cache
            .get(&asset_key)
            .await
            .expect("should read back what was just stored");

        // Assert: not just "something came back", but the same bytes and the
        // same headers. A cache that returned a different representation would
        // pass a weaker assertion.
        assert_eq!(
            read.body(),
            stored.body(),
            "should return the origin's bytes unchanged"
        );
        assert_eq!(
            read.headers(),
            stored.headers(),
            "should return the stored headers unchanged"
        );
        assert_eq!(read.status(), StatusCode::OK, "should return the status");
    }

    #[tokio::test]
    async fn a_key_that_was_never_stored_is_a_plain_miss() {
        let cache = FiftyOneDegreesAssetCache::new(1_000_000);
        assert_eq!(
            cache
                .get(&key("never.css"))
                .await
                .expect_err("should not find an asset that was never stored"),
            AssetCacheMiss::NotFound,
            "should report not-found rather than unsupported"
        );
    }

    #[tokio::test]
    async fn the_cache_is_bounded_by_bytes_and_not_by_entries() {
        // Arrange: a cache of 10 KiB, and 40 assets of 1 KiB each. Forty
        // entries would be four times the bound if the limit were counted in
        // entries; ten is what a byte bound allows.
        let max_bytes = 10 * 1024;
        let cache = FiftyOneDegreesAssetCache::new(max_bytes);

        // Act.
        for index in 0..40 {
            cache
                .insert(
                    key(&format!("asset-{index}.css")),
                    entry(1024),
                    Duration::from_secs(600),
                )
                .await
                .expect("should accept an eligible asset");
        }

        // Assert: this is the measurement that fails if the weigher is removed.
        // Without it moka counts entries, every one weighs 1, all forty fit,
        // and both assertions below break.
        let held = cache.weighted_size().await;
        let entries = cache.entry_count().await;
        assert!(
            held <= max_bytes,
            "should hold no more than {max_bytes} bytes, held {held}"
        );
        assert!(
            entries < 40,
            "should have evicted to stay inside the byte bound, held {entries} of 40 entries"
        );
        assert!(
            entries > 0,
            "should still be holding something, held {entries} entries"
        );
    }

    #[tokio::test]
    async fn an_asset_larger_than_the_whole_cache_is_never_admitted() {
        // A cache of 1 KiB cannot hold a 4 KiB asset. moka refuses to admit it
        // rather than emptying itself to make room.
        let cache = FiftyOneDegreesAssetCache::new(1024);
        cache
            .insert(key("huge.css"), entry(4096), Duration::from_secs(600))
            .await
            .expect("insert should report success even when the entry is not admitted");

        assert_eq!(
            cache.entry_count().await,
            0,
            "should not admit an entry heavier than the whole cache"
        );
        assert_eq!(
            cache
                .get(&key("huge.css"))
                .await
                .expect_err("should not read back an entry that was never admitted"),
            AssetCacheMiss::NotFound,
            "should miss on an entry that was never admitted"
        );
    }

    #[tokio::test]
    async fn an_entry_expires_on_its_own_lifetime() {
        // Arrange: two assets stored at the same moment with different
        // lifetimes. Per-entry expiry is the point; one cache-wide setting
        // could not do this.
        let cache = FiftyOneDegreesAssetCache::new(1_000_000);
        cache
            .insert(key("short.css"), entry(32), Duration::from_millis(100))
            .await
            .expect("should store the short-lived asset");
        cache
            .insert(key("long.css"), entry(32), Duration::from_secs(600))
            .await
            .expect("should store the long-lived asset");

        // Act: real time, because moka reads the system clock and a paused
        // tokio timer does not move it.
        tokio::time::sleep(Duration::from_millis(400)).await;
        cache.entry_count().await;

        // Assert.
        assert_eq!(
            cache
                .get(&key("short.css"))
                .await
                .expect_err("should have expired"),
            AssetCacheMiss::NotFound,
            "should drop an entry once its own lifetime has run out"
        );
        assert!(
            cache.get(&key("long.css")).await.is_ok(),
            "should keep an entry whose lifetime has not run out"
        );
    }

    #[tokio::test]
    async fn reading_an_entry_does_not_extend_its_lifetime() {
        // A cache that reset the clock on every read would keep a popular asset
        // forever and never see the origin's update.
        let cache = FiftyOneDegreesAssetCache::new(1_000_000);
        cache
            .insert(key("read.css"), entry(32), Duration::from_millis(200))
            .await
            .expect("should store the asset");

        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(
            cache.get(&key("read.css")).await.is_ok(),
            "should still be fresh half way through its lifetime"
        );

        tokio::time::sleep(Duration::from_millis(300)).await;
        cache.entry_count().await;
        assert_eq!(
            cache
                .get(&key("read.css"))
                .await
                .expect_err("should have expired despite the read"),
            AssetCacheMiss::NotFound,
            "should expire on the lifetime it was created with, not on last read"
        );
    }

    #[tokio::test]
    async fn purge_all_empties_the_cache() {
        let cache = FiftyOneDegreesAssetCache::new(1_000_000);
        for index in 0..5 {
            cache
                .insert(
                    key(&format!("p-{index}.css")),
                    entry(32),
                    Duration::from_secs(600),
                )
                .await
                .expect("should store the asset");
        }
        assert_eq!(
            cache.entry_count().await,
            5,
            "should be holding five assets"
        );

        cache.purge_all().await.expect("should purge");

        assert_eq!(
            cache.entry_count().await,
            0,
            "should be holding nothing after a purge"
        );
    }

    #[tokio::test]
    async fn the_provider_names_itself() {
        let cache = FiftyOneDegreesAssetCache::new(1024);
        assert_eq!(
            cache.id(),
            "51degrees",
            "should report the key it is selected by"
        );
        assert_eq!(
            PROVIDER_ID,
            cache.id(),
            "should keep the exported key and the reported id in step"
        );
    }

    #[tokio::test]
    async fn a_clone_is_a_handle_on_the_same_cache() {
        // Documented in the type's own doc comment, so it is worth a test: an
        // adapter cloning the handle must not end up with a second, empty
        // cache.
        let cache = FiftyOneDegreesAssetCache::new(1_000_000);
        let clone = cache.clone();
        clone
            .insert(key("shared.css"), entry(32), Duration::from_secs(600))
            .await
            .expect("should store through the clone");

        assert!(
            cache.get(&key("shared.css")).await.is_ok(),
            "should read through the original what the clone stored"
        );
    }

    #[tokio::test]
    async fn the_shared_constructor_produces_a_usable_trait_object() {
        // The exact shape an adapter injects, exercised through the trait
        // rather than through the concrete type, so the seam itself is proven.
        let cache: Arc<dyn PlatformAssetCache> = FiftyOneDegreesAssetCache::shared(1_000_000);
        let stored = entry(48);
        cache
            .insert(key("obj.css"), stored.clone(), Duration::from_secs(60))
            .await
            .expect("should store through the trait object");

        let read = cache
            .get(&key("obj.css"))
            .await
            .expect("should read through the trait object");
        assert_eq!(
            read.body(),
            stored.body(),
            "should round trip through the trait object byte for byte"
        );
        assert_eq!(
            cache.id(),
            "51degrees",
            "should report the provider key through the trait object"
        );
    }
}
