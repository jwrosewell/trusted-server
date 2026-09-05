//! Edge Cookie identity store for the Axum adapter, backed by `redb`.
//!
//! [`EcKvStore`] is a different trait from
//! [`PlatformKvStore`](trusted_server_core::platform::PlatformKvStore), and the
//! identity graph goes through this one. It is also **synchronous**, because
//! the Fastly SDK it was first written against is synchronous, so this cannot
//! be a wrapper over `EdgeZero`'s `PersistentKvStore`, whose API is `async`.
//! Blocking on that future inside the runtime that is serving the request is
//! the kind of shortcut that passes every test and deadlocks under load.
//!
//! `redb` is itself synchronous, so this implements the trait against it
//! directly. Operations are single embedded reads and writes, on the same
//! terms as the Fastly store's own blocking calls.
//!
//! # Why a second database file
//!
//! `redb` takes an exclusive lock on a file, so this cannot share the one
//! `EdgeZero`'s platform store already holds open. A separate file is also the
//! shape the Fastly adapter uses, where identity has its own named store, and
//! the two have genuinely different lifetimes: a response cache is per
//! instance and disposable, an identity graph is neither.
//!
//! # What is stored
//!
//! One row per key, holding the body, the metadata, a generation counter and
//! an expiry. The generation is what makes the compare-and-set write mode
//! real: `redb` gives an ACID write transaction, so the read of the current
//! generation and the write that depends on it cannot interleave with another
//! request.
//!
//! An expired row is treated as absent on read and overwritten on write,
//! rather than swept on a timer. A row that is never read again costs one
//! entry until the file is compacted, which is the same trade `EdgeZero`'s own
//! store makes.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use error_stack::{Report, ResultExt as _};
use redb::{Database, ReadableDatabase as _, ReadableTable as _, TableDefinition};
use trusted_server_core::ec::kv_backend::{
    EcKvLookup, EcKvStore, EcKvWrite, EcKvWriteMode, EcKvWriteOutcome,
};
use trusted_server_core::error::TrustedServerError;

/// Key to (body, metadata, generation, expiry in milliseconds since the epoch).
///
/// The metadata is stored as an empty slice rather than an `Option`, because
/// the trait's own `EcKvLookup::metadata` is `None` for absent and the empty
/// case round-trips to the same answer.
type EcRow = (&'static [u8], &'static [u8], u64, Option<u128>);

const EC_TABLE: TableDefinition<&str, EcRow> = TableDefinition::new("ec_identity");

/// The store name reported in logs and errors.
const STORE_NAME: &str = "ec_identity_store";

/// Edge Cookie identity store backed by a local `redb` database.
#[derive(Debug)]
pub struct AxumEcKvStore {
    database: Database,
}

impl AxumEcKvStore {
    /// Opens the identity database, creating the file and its parent
    /// directory when they do not exist.
    ///
    /// # Errors
    ///
    /// Returns [`TrustedServerError::KvStore`] when the directory cannot be
    /// created or the database cannot be opened, which includes a file another
    /// process already holds, because `redb` locks exclusively.
    pub fn open(path: &Path) -> Result<Self, Report<TrustedServerError>> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).change_context(TrustedServerError::KvStore {
                store_name: STORE_NAME.to_owned(),
                message: format!("Failed to create the directory {}", parent.display()),
            })?;
        }

        let database = Database::create(path).change_context(TrustedServerError::KvStore {
            store_name: STORE_NAME.to_owned(),
            message: format!("Failed to open the identity database at {}", path.display()),
        })?;

        // Create the table once at open, so a read on a fresh database does not
        // fail for a table that has never been written.
        let write = database
            .begin_write()
            .change_context(Self::error("begin"))?;
        {
            write
                .open_table(EC_TABLE)
                .change_context(Self::error("open the table"))?;
        }
        write.commit().change_context(Self::error("commit"))?;

        Ok(Self { database })
    }

    fn error(what: &str) -> TrustedServerError {
        TrustedServerError::KvStore {
            store_name: STORE_NAME.to_owned(),
            message: format!("Failed to {what} on the identity store"),
        }
    }

    /// Milliseconds since the epoch, or zero if the clock is before it.
    fn now_millis() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_millis())
    }

    /// Whether a stored expiry has passed.
    ///
    /// A row with no expiry never expires. A clock before the epoch reports
    /// not expired, so a nonsense clock cannot delete live identity.
    fn is_expired(expires_at: Option<u128>) -> bool {
        expires_at.is_some_and(|expiry| Self::now_millis() >= expiry)
    }
}

impl EcKvStore for AxumEcKvStore {
    fn store_name(&self) -> &str {
        STORE_NAME
    }

    fn lookup(&self, key: &str) -> Result<Option<EcKvLookup>, Report<TrustedServerError>> {
        let read = self
            .database
            .begin_read()
            .change_context(Self::error("begin a read"))?;
        let table = read
            .open_table(EC_TABLE)
            .change_context(Self::error("open the table"))?;

        let Some(row) = table.get(key).change_context(Self::error("read a key"))? else {
            return Ok(None);
        };

        let (body, metadata, generation, expires_at) = row.value();
        if Self::is_expired(expires_at) {
            return Ok(None);
        }

        Ok(Some(EcKvLookup {
            body: body.to_vec(),
            metadata: (!metadata.is_empty()).then(|| metadata.to_vec()),
            generation,
        }))
    }

    fn insert(
        &self,
        key: &str,
        write: EcKvWrite<'_>,
    ) -> Result<EcKvWriteOutcome, Report<TrustedServerError>> {
        let transaction = self
            .database
            .begin_write()
            .change_context(Self::error("begin a write"))?;
        let outcome = {
            let mut table = transaction
                .open_table(EC_TABLE)
                .change_context(Self::error("open the table"))?;

            // The current row, treating an expired one as absent so a stale
            // entry cannot fail an Add or satisfy a generation match.
            let current = table
                .get(key)
                .change_context(Self::error("read a key"))?
                .map(|row| {
                    let (_, _, generation, expires_at) = row.value();
                    (generation, expires_at)
                })
                .filter(|(_, expires_at)| !Self::is_expired(*expires_at));

            let permitted = match (write.mode, current) {
                (EcKvWriteMode::Add, Some(_)) => false,
                (EcKvWriteMode::IfGenerationMatch(expected), Some((generation, _))) => {
                    generation == expected
                }
                // A generation match against a key that is not there cannot
                // succeed: there is no generation to match.
                (EcKvWriteMode::IfGenerationMatch(_), None) => false,
                (EcKvWriteMode::Add | EcKvWriteMode::Overwrite, _) => true,
            };

            if permitted {
                let generation = current.map_or(1, |(generation, _)| generation.saturating_add(1));
                let expires_at = Some(Self::now_millis().saturating_add(write.ttl.as_millis()));
                table
                    .insert(
                        key,
                        (
                            write.body.as_bytes(),
                            write.metadata.as_bytes(),
                            generation,
                            expires_at,
                        ),
                    )
                    .change_context(Self::error("write a key"))?;
                EcKvWriteOutcome::Written
            } else {
                EcKvWriteOutcome::PreconditionFailed
            }
        };

        transaction
            .commit()
            .change_context(Self::error("commit a write"))?;
        Ok(outcome)
    }

    fn count_keys_with_prefix(
        &self,
        prefix: &str,
        limit: u32,
    ) -> Result<u32, Report<TrustedServerError>> {
        let read = self
            .database
            .begin_read()
            .change_context(Self::error("begin a read"))?;
        let table = read
            .open_table(EC_TABLE)
            .change_context(Self::error("open the table"))?;

        let mut counted = 0;
        for row in table
            .range(prefix..)
            .change_context(Self::error("scan a prefix"))?
        {
            let (key, value) = row.change_context(Self::error("read a row"))?;
            // The range is ordered, so the first key past the prefix ends it.
            if !key.value().starts_with(prefix) {
                break;
            }
            let (_, _, _, expires_at) = value.value();
            if Self::is_expired(expires_at) {
                continue;
            }
            counted += 1;
            if counted >= limit {
                break;
            }
        }
        Ok(counted)
    }

    fn delete(&self, key: &str) -> Result<(), Report<TrustedServerError>> {
        let transaction = self
            .database
            .begin_write()
            .change_context(Self::error("begin a write"))?;
        {
            let mut table = transaction
                .open_table(EC_TABLE)
                .change_context(Self::error("open the table"))?;
            table
                .remove(key)
                .change_context(Self::error("delete a key"))?;
        }
        transaction
            .commit()
            .change_context(Self::error("commit a delete"))?;
        Ok(())
    }
}

/// The file backing the identity store for a named store.
///
/// Resolution matches the platform store's: an explicit path wins, otherwise
/// `.edgezero/<store name>.redb`, so an appliance can move durable identity out
/// of the working directory with one variable.
#[must_use]
pub fn ec_identity_path(store_name: &str) -> std::path::PathBuf {
    std::env::var("TRUSTED_SERVER_EC_STORE_PATH")
        .ok()
        .map(std::path::PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new(".edgezero").join(format!("{store_name}.redb")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;

    fn store() -> (AxumEcKvStore, tempfile::TempDir) {
        let directory = tempfile::tempdir().expect("should make a temporary directory");
        let store = AxumEcKvStore::open(&directory.path().join("ec.redb"))
            .expect("should open the identity store");
        (store, directory)
    }

    fn write(body: &str, mode: EcKvWriteMode) -> EcKvWrite<'_> {
        EcKvWrite {
            body,
            metadata: "",
            ttl: Duration::from_secs(60),
            mode,
        }
    }

    #[test]
    fn a_written_entry_reads_back() {
        let (store, _dir) = store();

        store
            .insert("k", write("body", EcKvWriteMode::Overwrite))
            .expect("should write");
        let found = store
            .lookup("k")
            .expect("should read")
            .expect("should exist");

        assert_eq!(found.body, b"body", "should return the body it stored");
        assert_eq!(found.generation, 1, "a first write starts the generation");
    }

    #[test]
    fn a_missing_key_is_absent_rather_than_an_error() {
        let (store, _dir) = store();

        assert!(
            store.lookup("nothing").expect("should read").is_none(),
            "an absent key must not be an error, or every new visitor fails"
        );
    }

    #[test]
    fn add_refuses_to_overwrite_an_existing_entry() {
        let (store, _dir) = store();
        store
            .insert("k", write("first", EcKvWriteMode::Add))
            .expect("should write");

        let outcome = store
            .insert("k", write("second", EcKvWriteMode::Add))
            .expect("should report the precondition rather than fail");

        assert_eq!(
            outcome,
            EcKvWriteOutcome::PreconditionFailed,
            "Add is what stops two requests both claiming a new identifier"
        );
        assert_eq!(
            store
                .lookup("k")
                .expect("should read")
                .expect("exists")
                .body,
            b"first",
            "the refused write must not have changed the value"
        );
    }

    #[test]
    fn a_generation_match_applies_only_against_the_generation_it_names() {
        let (store, _dir) = store();
        store
            .insert("k", write("first", EcKvWriteMode::Overwrite))
            .expect("should write");

        let stale = store
            .insert("k", write("stale", EcKvWriteMode::IfGenerationMatch(99)))
            .expect("should report the precondition");
        assert_eq!(
            stale,
            EcKvWriteOutcome::PreconditionFailed,
            "a write against a generation that is not current must not land"
        );

        let current = store
            .insert("k", write("second", EcKvWriteMode::IfGenerationMatch(1)))
            .expect("should write");
        assert_eq!(
            current,
            EcKvWriteOutcome::Written,
            "the current generation should apply"
        );
        assert_eq!(
            store
                .lookup("k")
                .expect("should read")
                .expect("exists")
                .generation,
            2,
            "a successful write moves the generation on"
        );
    }

    #[test]
    fn a_generation_match_against_an_absent_key_cannot_succeed() {
        let (store, _dir) = store();

        let outcome = store
            .insert("k", write("body", EcKvWriteMode::IfGenerationMatch(1)))
            .expect("should report the precondition");

        assert_eq!(
            outcome,
            EcKvWriteOutcome::PreconditionFailed,
            "there is no generation to match, so this must not create the key"
        );
    }

    #[test]
    fn an_expired_entry_reads_as_absent() {
        let (store, _dir) = store();
        store
            .insert(
                "k",
                EcKvWrite {
                    body: "body",
                    metadata: "",
                    ttl: Duration::from_millis(0),
                    mode: EcKvWriteMode::Overwrite,
                },
            )
            .expect("should write");

        assert!(
            store.lookup("k").expect("should read").is_none(),
            "an entry past its lifetime must not be served"
        );
    }

    #[test]
    fn an_expired_entry_does_not_block_a_fresh_add() {
        let (store, _dir) = store();
        store
            .insert(
                "k",
                EcKvWrite {
                    body: "old",
                    metadata: "",
                    ttl: Duration::from_millis(0),
                    mode: EcKvWriteMode::Overwrite,
                },
            )
            .expect("should write");

        let outcome = store
            .insert("k", write("new", EcKvWriteMode::Add))
            .expect("should write");

        assert_eq!(
            outcome,
            EcKvWriteOutcome::Written,
            "a lapsed entry must not permanently reserve its key"
        );
    }

    #[test]
    fn metadata_round_trips_and_absent_metadata_stays_absent() {
        let (store, _dir) = store();

        store
            .insert(
                "with",
                EcKvWrite {
                    body: "b",
                    metadata: "m",
                    ttl: Duration::from_secs(60),
                    mode: EcKvWriteMode::Overwrite,
                },
            )
            .expect("should write");
        store
            .insert("without", write("b", EcKvWriteMode::Overwrite))
            .expect("should write");

        assert_eq!(
            store
                .lookup("with")
                .expect("should read")
                .expect("exists")
                .metadata,
            Some(b"m".to_vec()),
            "metadata should survive the round trip"
        );
        assert_eq!(
            store
                .lookup("without")
                .expect("should read")
                .expect("exists")
                .metadata,
            None,
            "empty metadata should read back as absent, not as an empty value"
        );
    }

    #[test]
    fn counting_a_prefix_counts_that_prefix_and_stops_at_the_limit() {
        let (store, _dir) = store();
        for key in ["p:1", "p:2", "p:3", "q:1"] {
            store
                .insert(key, write("b", EcKvWriteMode::Overwrite))
                .expect("should write");
        }

        assert_eq!(
            store
                .count_keys_with_prefix("p:", 10)
                .expect("should count"),
            3,
            "should count only the keys under the prefix"
        );
        assert_eq!(
            store.count_keys_with_prefix("p:", 2).expect("should count"),
            2,
            "the limit is what stops a cluster check reading the whole store"
        );
    }

    #[test]
    fn counting_a_prefix_ignores_expired_entries() {
        let (store, _dir) = store();
        store
            .insert("p:live", write("b", EcKvWriteMode::Overwrite))
            .expect("should write");
        store
            .insert(
                "p:gone",
                EcKvWrite {
                    body: "b",
                    metadata: "",
                    ttl: Duration::from_millis(0),
                    mode: EcKvWriteMode::Overwrite,
                },
            )
            .expect("should write");

        assert_eq!(
            store
                .count_keys_with_prefix("p:", 10)
                .expect("should count"),
            1,
            "a lapsed entry must not inflate a cluster count"
        );
    }

    #[test]
    fn a_deleted_key_is_gone() {
        let (store, _dir) = store();
        store
            .insert("k", write("b", EcKvWriteMode::Overwrite))
            .expect("should write");

        store.delete("k").expect("should delete");

        assert!(
            store.lookup("k").expect("should read").is_none(),
            "a withdrawal has to actually remove the row"
        );
    }

    #[test]
    fn deleting_a_key_that_is_not_there_is_not_an_error() {
        let (store, _dir) = store();

        store
            .delete("never-existed")
            .expect("deleting an absent key should succeed");
    }

    #[test]
    fn a_second_open_of_the_same_file_is_refused() {
        let directory = tempfile::tempdir().expect("should make a temporary directory");
        let path = directory.path().join("ec.redb");
        let _held = AxumEcKvStore::open(&path).expect("should open");

        let second = AxumEcKvStore::open(&path);

        // This is why the identity store gets a file of its own rather than
        // sharing the platform store's. The module documentation says `redb`
        // locks exclusively, and this is what makes that claim checkable
        // rather than asserted.
        assert!(
            second.is_err(),
            "a second open of a held database must be refused, or the separate-file              design this store depends on has no reason to exist"
        );
    }

    #[test]
    fn identity_survives_reopening_the_database() {
        let directory = tempfile::tempdir().expect("should make a temporary directory");
        let path = directory.path().join("ec.redb");
        {
            let store = AxumEcKvStore::open(&path).expect("should open");
            store
                .insert("k", write("body", EcKvWriteMode::Overwrite))
                .expect("should write");
        }

        let reopened = AxumEcKvStore::open(&path).expect("should reopen");

        assert_eq!(
            reopened
                .lookup("k")
                .expect("should read")
                .expect("should still exist")
                .body,
            b"body",
            "an appliance restart must not lose every visitor's identity"
        );
    }
}
