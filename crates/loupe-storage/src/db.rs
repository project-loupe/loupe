use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;
use thiserror::Error;

use crate::migrations::{apply_pending, current_schema_version};
use crate::secrets::MasterKey;

#[derive(Debug, Error)]
pub enum Error {
	#[error(transparent)]
	Sqlite(#[from] rusqlite::Error),
	#[error("database contains unknown job kinds {0:?}; refusing startup")]
	UnknownJobKinds(Vec<String>),
	#[error(transparent)]
	Validation(#[from] loupe_core::text::Error),
	#[error("conflict: {0:?}")]
	Conflict(crate::Conflict),
	#[error("ownership mismatch: {0:?}")]
	Ownership(crate::Ownership),
	#[error("{0:?} {1} not found")]
	NotFound(crate::Entity, i64),
	#[error(transparent)]
	UnknownPaths(crate::inventory::UnknownPaths),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Owning handle to the SQLite database. We use a single `Mutex<Connection>`
/// rather than a connection pool — the bkb-ingest experience is that
/// rusqlite's WAL-mode single-writer model copes fine with our query
/// volume, and a pool adds dependencies (`r2d2_sqlite`) we'd rather not
/// pay for. Swap in Postgres at the seam if multi-instance deployment
/// becomes necessary.
///
/// The connection is opened against the SQLCipher-bundled SQLite, so
/// the underlying file is sealed under the [`MasterKey`] handed to
/// [`Db::open`] / [`Db::open_in_memory`]. `PRAGMA key` runs *before*
/// any other query so a wrong-key open fails at the first read rather
/// than silently returning corrupt data.
pub struct Db {
	conn: Mutex<Connection>,
}

impl Db {
	/// Open (or create) a database at `path`, sealed under `key`,
	/// and run any unapplied migrations to the current schema
	/// version. WAL mode is enabled so reads don't block writes.
	pub fn open(path: impl AsRef<Path>, key: &MasterKey) -> Result<Self> {
		let conn = Connection::open(path)?;
		Self::bootstrap(conn, key)
	}

	/// In-memory database. Useful in tests and for the `--ephemeral` mode
	/// of the server. Tests should pass [`MasterKey::for_tests`].
	pub fn open_in_memory(key: &MasterKey) -> Result<Self> {
		let conn = Connection::open_in_memory()?;
		Self::bootstrap(conn, key)
	}

	fn bootstrap(conn: Connection, key: &MasterKey) -> Result<Self> {
		Self::bootstrap_with_migration(conn, key, apply_pending)
	}

	// Keep configuration and connection disposal on the real startup path
	// when migration tests inject failures at transactional boundaries.
	pub(crate) fn bootstrap_with_migration(
		mut conn: Connection, key: &MasterKey,
		migrate: impl FnOnce(&mut Connection) -> rusqlite::Result<()>,
	) -> Result<Self> {
		// PRAGMA key MUST run before any other statement that touches
		// pages: SQLCipher decrypts pages on read, so an unkeyed read
		// against an encrypted file returns "file is not a database".
		conn.pragma_update(None, "key", format!("x'{}'", key.to_hex()))?;
		conn.pragma_update(None, "journal_mode", "WAL")?;
		conn.pragma_update(None, "foreign_keys", "ON")?;
		conn.pragma_update(None, "synchronous", "NORMAL")?;
		migrate(&mut conn)?;
		// Foreign keys do not retroactively validate rows inserted with
		// enforcement disabled. Check on every boot, not just during v3.
		// NOT EXISTS rather than NOT IN: a NULL in the lookup would make
		// `NOT IN` evaluate to NULL for every row and pass everything.
		let unknown = conn
			.prepare(
				"SELECT DISTINCT kind FROM jobs j
				  WHERE NOT EXISTS (SELECT 1 FROM job_kinds k WHERE k.kind = j.kind)
				  ORDER BY kind",
			)?
			.query_map([], |row| row.get::<_, String>(0))?
			.collect::<rusqlite::Result<Vec<_>>>()?;
		if !unknown.is_empty() {
			return Err(Error::UnknownJobKinds(unknown));
		}
		crate::scheduler::ensure_state(&conn)?;
		Ok(Self { conn: Mutex::new(conn) })
	}

	/// Run a closure with exclusive access to the underlying connection.
	pub fn with_conn<R>(&self, f: impl FnOnce(&mut Connection) -> Result<R>) -> Result<R> {
		let mut guard = self.conn.lock().expect("loupe-storage db mutex poisoned");
		f(&mut guard)
	}

	/// Highest applied migration version.
	pub fn schema_version(&self) -> Result<u32> {
		self.with_conn(|c| Ok(current_schema_version(c)?))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::migrations::LATEST_SCHEMA_VERSION;

	#[test]
	fn fresh_in_memory_db_is_at_latest_version() {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		assert_eq!(db.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
	}

	#[test]
	fn reopening_does_not_re_apply_migrations() {
		// Reopening a memory db isn't possible, so simulate by running
		// `apply_pending` twice on the same connection.
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		db.with_conn(|c| {
			crate::migrations::apply_pending(c)?;
			crate::migrations::apply_pending(c)?;
			Ok(())
		})
		.unwrap();
		assert_eq!(db.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
	}

	#[test]
	fn startup_rejects_unknown_job_kinds_on_an_already_migrated_db() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("loupe.sqlite");
		let key = MasterKey::for_tests();
		let db = Db::open(&path, &key).unwrap();
		db.with_conn(|conn| {
			conn.pragma_update(None, "foreign_keys", false)?;
			conn.execute_batch(
				"INSERT INTO registered_repos
                (id, clone_url, host, owner, repo, reporting, created_at)
                VALUES (1, 'u', 'github.com', 'o', 'r', '{\"kind\":\"manual\"}', 0);
                INSERT INTO jobs (repo_id, kind, state, enqueued_at)
                VALUES (1, 'bogus-b', 'queued', 0), (1, 'bogus-a', 'failed', 0),
                       (1, 'scan', 'queued', 0), (1, 'verify', 'succeeded', 0),
                       (1, 'survey', 'queued', 0), (1, 'drilldown', 'queued', 0);",
			)?;
			Ok(())
		})
		.unwrap();
		drop(db);
		let error = match Db::open(&path, &key) {
			Err(error) => error,
			Ok(_) => {
				panic!("startup must reject unknown kinds even when schema v3 is already applied")
			},
		};
		let message = error.to_string();
		assert!(message.contains("bogus-a") && message.contains("bogus-b"), "{message}");
		assert!(
			!message.contains("survey") && !message.contains("drilldown"),
			"known kinds must not be diagnosed as unknown: {message}"
		);
		// Repair only the invalid rows and prove that every seeded kind opens.
		let conn = Connection::open(&path).unwrap();
		conn.pragma_update(None, "key", format!("x'{}'", key.to_hex())).unwrap();
		conn.execute("DELETE FROM jobs WHERE kind IN ('bogus-a', 'bogus-b')", []).unwrap();
		drop(conn);
		let db = Db::open(&path, &key).unwrap();
		assert_eq!(db.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
	}

	#[test]
	fn startup_kind_guard_is_not_disabled_by_a_nullable_lookup() {
		// Exercise validation independently of the new NOT NULL constraint.
		// This is the original lookup shape, with a NULL row that would poison
		// NOT IN. The migration injection keeps the production DDL unchanged.
		for unknown in [false, true] {
			let result = Db::bootstrap_with_migration(
				Connection::open_in_memory().unwrap(),
				&MasterKey::for_tests(),
				|conn| {
					conn.execute_batch(
						"CREATE TABLE job_kinds (kind TEXT PRIMARY KEY);
                         INSERT INTO job_kinds VALUES ('scan'), (NULL);
                         CREATE TABLE jobs (kind TEXT NOT NULL);
                         INSERT INTO jobs VALUES ('scan');",
					)?;
					if unknown {
						conn.execute("INSERT INTO jobs VALUES ('bogus')", [])?;
					}
					Ok(())
				},
			);
			if unknown {
				match result {
					Err(Error::UnknownJobKinds(kinds)) => assert_eq!(kinds, ["bogus"]),
					Err(other) => panic!("expected unknown-kind rejection, got {other}"),
					Ok(_) => panic!("a NULL lookup row must not disable unknown-kind rejection"),
				}
			} else {
				assert!(result.is_ok(), "known job kinds must still open with a NULL lookup row");
			}
		}
	}

	#[test]
	fn opening_with_wrong_key_errors() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("loupe.sqlite");
		let key_a = MasterKey::from_bytes([0xAAu8; 32]);
		let key_b = MasterKey::from_bytes([0xBBu8; 32]);
		// Create + close.
		{
			let _db = Db::open(&path, &key_a).unwrap();
		}
		// Reopen with the wrong key — first migration query must fail.
		let err = match Db::open(&path, &key_b) {
			Err(e) => e,
			Ok(_) => panic!("wrong-key open must error"),
		};
		let msg = format!("{err:#}");
		assert!(
			msg.contains("not a database") || msg.contains("file is encrypted"),
			"expected SQLCipher cipher error, got: {msg}"
		);
	}

	#[test]
	fn raw_db_file_does_not_contain_inserted_plaintext() {
		// On-disk evidence that SQLCipher is sealing the page bytes —
		// not just our DAOs being polite about not exposing rows.
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("loupe.sqlite");
		let key = MasterKey::for_tests();
		let needle = b"verysecretvalue_loupe_test";
		{
			let db = Db::open(&path, &key).unwrap();
			db.with_conn(|c| {
				Ok(crate::secrets::insert(
					c,
					crate::secrets::SecretKind::GithubPat,
					"x",
					needle,
					0,
				)?)
			})
			.unwrap();
		}
		let raw = std::fs::read(&path).unwrap();
		assert!(
			!raw.windows(needle.len()).any(|w| w == needle),
			"plaintext leaked into encrypted db file on disk"
		);
	}
}
