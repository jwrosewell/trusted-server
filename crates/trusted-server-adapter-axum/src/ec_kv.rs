//! Persistent-store implementation of the core [`EcKvStore`] primitives.
//!
//! The Edge Cookie identity graph does not use the platform key-value store
//! directly. It talks to [`EcKvStore`], a narrower trait with a generation
//! marker for compare-and-swap writes, a metadata column beside the body, and
//! prefix counting. The Fastly adapter satisfies it with the Fastly KV Store's
//! own `if_generation_match` and metadata support
//! (`crates/trusted-server-adapter-fastly/src/ec_kv.rs`). The Axum adapter had
//! no implementation at all, so every route that needs the graph was wired to
//! `None` and answered "not configured".
//!
//! `PersistentKvStore`, the `redb` database this adapter opens in
//! [`crate::platform::open_kv_store`], stores opaque bytes with no metadata
//! column and no generation marker. Both are packed into the stored value
//! instead, so one store write still carries the whole entry, and the
//! read-modify-write that compare-and-swap needs is serialized by a
//! process-wide lock.
//!
//! # Why a process-wide lock is the right scope
//!
//! `redb` takes an exclusive file lock, so only one process can hold the
//! database at a time and a second appliance process refuses to start rather
//! than sharing it. Within the one process that can hold it, a `Mutex` makes
//! the read-modify-write atomic. Sharing identity state across instances is a
//! different piece of work and is not solved here.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use error_stack::Report;
use trusted_server_core::ec::kv_backend::{
    EcKvLookup, EcKvStore, EcKvWrite, EcKvWriteMode, EcKvWriteOutcome,
};
use trusted_server_core::error::TrustedServerError;
use trusted_server_core::platform::PlatformKvStore;

/// Key prefix for identity-graph entries.
///
/// The identity graph uses the Edge Cookie id as its key. The adapter's single
/// `redb` database is shared with anything else that reaches the platform key
/// value store, so entries are namespaced here rather than trusting that
/// nothing else ever writes a colliding key.
const KEY_PREFIX: &str = "ec/";

/// Bytes of the generation marker at the head of a stored value.
const GENERATION_BYTES: usize = 8;

/// Bytes of the metadata length that follows the generation marker.
const METADATA_LENGTH_BYTES: usize = 4;

/// Serializes writes so a read-modify-write stays atomic within the process.
///
/// The store is rebuilt per request, mirroring the Fastly adapter, so the lock
/// has to outlive any one instance.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Takes the process-wide write lock.
///
/// The lock guards nothing but ordering, so a panic in another thread while it
/// was held leaves no broken invariant and the poison is recovered from rather
/// than propagated.
fn write_lock() -> MutexGuard<'static, ()> {
    WRITE_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Packs an entry into the single opaque value the platform store holds.
///
/// Layout, lengths big-endian:
///
/// | offset             | bytes | meaning                  |
/// | ------------------ | ----- | ------------------------ |
/// | 0                  | 8     | generation, `u64`        |
/// | 8                  | 4     | metadata length, `u32`   |
/// | 12                 | n     | metadata                 |
/// | 12 + n             | rest  | entry body               |
fn encode_entry(generation: u64, metadata: &str, body: &str) -> Vec<u8> {
    let metadata = metadata.as_bytes();
    let body = body.as_bytes();
    let mut out =
        Vec::with_capacity(GENERATION_BYTES + METADATA_LENGTH_BYTES + metadata.len() + body.len());
    out.extend_from_slice(&generation.to_be_bytes());
    // A metadata block longer than `u32::MAX` cannot be represented, and the
    // identity graph never writes one, so saturating is a truthful cap rather
    // than a silent truncation risk: the length is checked on decode.
    let metadata_len = u32::try_from(metadata.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&metadata_len.to_be_bytes());
    out.extend_from_slice(metadata);
    out.extend_from_slice(body);
    out
}

/// One decoded entry: the generation marker and the two byte blocks beside it.
struct StoredEntry {
    generation: u64,
    metadata: Vec<u8>,
    body: Vec<u8>,
}

/// Unpacks a stored value written by [`encode_entry`].
///
/// Returns `None` when the value is too short or claims a metadata length that
/// does not fit, which means the value was not written by this adapter.
fn decode_entry(stored: &[u8]) -> Option<StoredEntry> {
    let header_len = GENERATION_BYTES + METADATA_LENGTH_BYTES;
    if stored.len() < header_len {
        return None;
    }

    let generation_bytes: [u8; GENERATION_BYTES] =
        stored.get(..GENERATION_BYTES)?.try_into().ok()?;
    let generation = u64::from_be_bytes(generation_bytes);

    let length_bytes: [u8; METADATA_LENGTH_BYTES] =
        stored.get(GENERATION_BYTES..header_len)?.try_into().ok()?;
    let metadata_len = usize::try_from(u32::from_be_bytes(length_bytes)).ok()?;

    let metadata_end = header_len.checked_add(metadata_len)?;
    let metadata = stored.get(header_len..metadata_end)?.to_vec();
    let body = stored.get(metadata_end..)?.to_vec();

    Some(StoredEntry {
        generation,
        metadata,
        body,
    })
}

/// Persistent-store backend for the Edge Cookie identity graph.
pub struct AxumEcKvStore {
    store: Arc<dyn PlatformKvStore>,
    store_name: String,
}

impl AxumEcKvStore {
    /// Creates a backend over an already-opened platform key-value store.
    ///
    /// `store_name` is the operator-facing name from `ec.ec_store`, used in log
    /// and error messages so they match the Fastly adapter's. The bytes live in
    /// this adapter's single `redb` database whatever the name says.
    #[must_use]
    pub fn new(store: Arc<dyn PlatformKvStore>, store_name: impl Into<String>) -> Self {
        Self {
            store,
            store_name: store_name.into(),
        }
    }

    fn namespaced(key: &str) -> String {
        format!("{KEY_PREFIX}{key}")
    }

    fn kv_error(&self, message: String) -> Report<TrustedServerError> {
        Report::new(TrustedServerError::KvStore {
            store_name: self.store_name.clone(),
            message,
        })
    }

    /// Reads a stored entry, returning its generation, metadata and body.
    ///
    /// Runs the store's future to completion on the calling thread. Every
    /// `PersistentKvStore` method has a fully synchronous body behind its
    /// `async fn`, so the future is ready on its first poll and this never
    /// parks the thread.
    fn read(&self, key: &str) -> Result<Option<StoredEntry>, Report<TrustedServerError>> {
        let stored = futures::executor::block_on(self.store.get_bytes(&Self::namespaced(key)))
            .map_err(|err| self.kv_error(format!("Failed to read key: {err}")))?;

        let Some(stored) = stored else {
            return Ok(None);
        };

        decode_entry(&stored).map_or_else(
            || {
                Err(self.kv_error(
                    "Stored entry is not in this adapter's format and cannot be decoded".to_owned(),
                ))
            },
            |entry| Ok(Some(entry)),
        )
    }
}

impl EcKvStore for AxumEcKvStore {
    fn store_name(&self) -> &str {
        &self.store_name
    }

    fn lookup(&self, key: &str) -> Result<Option<EcKvLookup>, Report<TrustedServerError>> {
        Ok(self.read(key)?.map(|entry| EcKvLookup {
            body: entry.body,
            metadata: Some(entry.metadata),
            generation: entry.generation,
        }))
    }

    fn insert(
        &self,
        key: &str,
        write: EcKvWrite<'_>,
    ) -> Result<EcKvWriteOutcome, Report<TrustedServerError>> {
        // Held across the read and the write so two requests cannot both see
        // the same generation and both decide their precondition holds.
        let _ordering = write_lock();

        let existing_generation = self.read(key)?.map(|entry| entry.generation);

        match write.mode {
            EcKvWriteMode::Add if existing_generation.is_some() => {
                return Ok(EcKvWriteOutcome::PreconditionFailed);
            }
            EcKvWriteMode::IfGenerationMatch(expected) if existing_generation != Some(expected) => {
                return Ok(EcKvWriteOutcome::PreconditionFailed);
            }
            EcKvWriteMode::Add | EcKvWriteMode::Overwrite | EcKvWriteMode::IfGenerationMatch(_) => {
            }
        }

        let generation = existing_generation.unwrap_or(0).saturating_add(1);
        let value = encode_entry(generation, write.metadata, write.body);

        futures::executor::block_on(self.store.put_bytes_with_ttl(
            &Self::namespaced(key),
            bytes::Bytes::from(value),
            write.ttl,
        ))
        .map_err(|err| self.kv_error(format!("Failed to write entry: {err}")))?;

        Ok(EcKvWriteOutcome::Written)
    }

    fn count_keys_with_prefix(
        &self,
        prefix: &str,
        limit: u32,
    ) -> Result<u32, Report<TrustedServerError>> {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        if limit == 0 {
            return Ok(0);
        }

        let namespaced = Self::namespaced(prefix);
        let mut cursor: Option<String> = None;
        let mut counted = 0_usize;

        loop {
            let remaining = limit - counted;
            let page = futures::executor::block_on(self.store.list_keys_page(
                &namespaced,
                cursor.as_deref(),
                remaining,
            ))
            .map_err(|err| {
                self.kv_error(format!(
                    "Failed to list keys with prefix '{}': {err}",
                    prefix.get(..8).unwrap_or(prefix)
                ))
            })?;

            counted = counted.saturating_add(page.keys.len());
            cursor = page.cursor;

            if counted >= limit || cursor.is_none() {
                break;
            }
        }

        Ok(u32::try_from(counted).unwrap_or(u32::MAX))
    }

    fn delete(&self, key: &str) -> Result<(), Report<TrustedServerError>> {
        futures::executor::block_on(self.store.delete(&Self::namespaced(key)))
            .map_err(|err| self.kv_error(format!("Failed to delete key: {err}")))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    /// Counter making each test database file unique within a run.
    static NEXT_STORE: AtomicU64 = AtomicU64::new(0);

    fn test_store() -> AxumEcKvStore {
        let sequence = NEXT_STORE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("trusted-server-ec-kv-{}", std::process::id()))
            .join(format!("store-{sequence}.redb"));
        let _ = std::fs::remove_file(&path);
        let store = crate::platform::open_kv_store(&path).expect("should open a temporary store");
        AxumEcKvStore::new(store, "ec_identity_store")
    }

    fn write(mode: EcKvWriteMode) -> EcKvWrite<'static> {
        EcKvWrite {
            body: "{\"ec_id\":\"abc\"}",
            metadata: "{\"v\":1}",
            ttl: Duration::from_secs(3600),
            mode,
        }
    }

    #[test]
    fn a_missing_key_reads_as_absent() {
        let store = test_store();

        assert!(
            store.lookup("missing").expect("should read").is_none(),
            "an absent key must not look like a stored entry"
        );
    }

    #[test]
    fn an_added_entry_round_trips_with_its_metadata() {
        let store = test_store();

        let outcome = store
            .insert("id-1", write(EcKvWriteMode::Add))
            .expect("should write");
        assert_eq!(
            outcome,
            EcKvWriteOutcome::Written,
            "the first Add for a key must be written"
        );

        let found = store
            .lookup("id-1")
            .expect("should read")
            .expect("should find the entry just written");
        assert_eq!(
            found.body, b"{\"ec_id\":\"abc\"}",
            "the body must come back byte for byte"
        );
        assert_eq!(
            found.metadata.as_deref(),
            Some(b"{\"v\":1}".as_slice()),
            "the metadata column must survive the round trip"
        );
        assert_eq!(found.generation, 1, "a new key starts at generation 1");
    }

    #[test]
    fn adding_over_an_existing_key_fails_its_precondition() {
        let store = test_store();
        store
            .insert("id-1", write(EcKvWriteMode::Add))
            .expect("should write the first time");

        let outcome = store
            .insert("id-1", write(EcKvWriteMode::Add))
            .expect("should not error");

        assert_eq!(
            outcome,
            EcKvWriteOutcome::PreconditionFailed,
            "Add must refuse to overwrite, so two requests cannot both claim a new id"
        );
    }

    #[test]
    fn overwrite_replaces_the_entry_and_moves_the_generation_on() {
        let store = test_store();
        store
            .insert("id-1", write(EcKvWriteMode::Add))
            .expect("should write");

        store
            .insert("id-1", write(EcKvWriteMode::Overwrite))
            .expect("should overwrite");

        let found = store
            .lookup("id-1")
            .expect("should read")
            .expect("should still find the entry");
        assert_eq!(
            found.generation, 2,
            "each write must move the generation on, or compare-and-swap cannot detect a race"
        );
    }

    #[test]
    fn a_matching_generation_writes_and_a_stale_one_does_not() {
        let store = test_store();
        store
            .insert("id-1", write(EcKvWriteMode::Add))
            .expect("should write");

        let matched = store
            .insert("id-1", write(EcKvWriteMode::IfGenerationMatch(1)))
            .expect("should not error");
        assert_eq!(
            matched,
            EcKvWriteOutcome::Written,
            "a write against the current generation must be applied"
        );

        let stale = store
            .insert("id-1", write(EcKvWriteMode::IfGenerationMatch(1)))
            .expect("should not error");
        assert_eq!(
            stale,
            EcKvWriteOutcome::PreconditionFailed,
            "a write against a generation that has moved on must be refused"
        );
    }

    #[test]
    fn a_generation_match_on_an_absent_key_is_refused() {
        let store = test_store();

        let outcome = store
            .insert("id-1", write(EcKvWriteMode::IfGenerationMatch(1)))
            .expect("should not error");

        assert_eq!(
            outcome,
            EcKvWriteOutcome::PreconditionFailed,
            "there is no generation 1 to match when the key does not exist"
        );
    }

    #[test]
    fn delete_removes_the_entry() {
        let store = test_store();
        store
            .insert("id-1", write(EcKvWriteMode::Add))
            .expect("should write");

        store.delete("id-1").expect("should delete");

        assert!(
            store.lookup("id-1").expect("should read").is_none(),
            "a deleted entry must read as absent"
        );
    }

    #[test]
    fn deleting_an_absent_key_is_not_an_error() {
        let store = test_store();

        store
            .delete("never-written")
            .expect("deleting an absent key must succeed, matching the Fastly backend");
    }

    #[test]
    fn prefix_counting_sees_only_matching_keys() {
        let store = test_store();
        for key in ["cluster/a", "cluster/b", "other/c"] {
            store
                .insert(key, write(EcKvWriteMode::Add))
                .expect("should write");
        }

        assert_eq!(
            store
                .count_keys_with_prefix("cluster/", 10)
                .expect("should count"),
            2,
            "only the two keys under the prefix should be counted"
        );
    }

    #[test]
    fn prefix_counting_stops_at_the_limit() {
        let store = test_store();
        for key in ["cluster/a", "cluster/b", "cluster/c"] {
            store
                .insert(key, write(EcKvWriteMode::Add))
                .expect("should write");
        }

        assert_eq!(
            store
                .count_keys_with_prefix("cluster/", 2)
                .expect("should count"),
            2,
            "the cluster heuristic only needs to know whether the limit is reached"
        );
    }

    #[test]
    fn a_zero_limit_counts_nothing() {
        let store = test_store();
        store
            .insert("cluster/a", write(EcKvWriteMode::Add))
            .expect("should write");

        assert_eq!(
            store
                .count_keys_with_prefix("cluster/", 0)
                .expect("should count"),
            0,
            "a zero limit must not scan the store"
        );
    }

    #[test]
    fn an_undecodable_value_is_reported_rather_than_read_as_absent() {
        let store = test_store();
        futures::executor::block_on(
            store
                .store
                .put_bytes("ec/id-1", bytes::Bytes::from_static(b"short")),
        )
        .expect("should write a raw value");

        assert!(
            store.lookup("id-1").is_err(),
            "a value this adapter did not write must be an error, not a silent miss"
        );
    }

    #[test]
    fn entries_are_namespaced_away_from_other_platform_keys() {
        let store = test_store();
        store
            .insert("id-1", write(EcKvWriteMode::Add))
            .expect("should write");

        let raw = futures::executor::block_on(store.store.get_bytes("id-1"))
            .expect("should read the unprefixed key");

        assert!(
            raw.is_none(),
            "identity entries must not collide with another user of the same store"
        );
    }
}
