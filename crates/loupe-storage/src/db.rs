use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::migrations::{apply_pending_with_finalizer, current_schema_version};
use crate::secrets::MasterKey;

pub enum Error {
	Migration(crate::migrations::MigrationFailure),
	Sqlite(rusqlite::Error),
	UnknownJobKinds(usize),
	Validation(loupe_core::text::Error),
	Conflict(crate::Conflict),
	Ownership(crate::Ownership),
	NotFound(crate::Entity, i64),
	UnknownPaths(crate::inventory::UnknownPaths),
	ScopeDenied,
	ReportReceipt,
	DatabaseUnavailable,
}

impl From<crate::migrations::MigrationFailure> for Error {
	fn from(error: crate::migrations::MigrationFailure) -> Self {
		Self::Migration(error)
	}
}
impl From<rusqlite::Error> for Error {
	fn from(error: rusqlite::Error) -> Self {
		Self::Sqlite(error)
	}
}
impl From<loupe_core::text::Error> for Error {
	fn from(error: loupe_core::text::Error) -> Self {
		Self::Validation(error)
	}
}

// SQLite diagnostics can include bound FTS input and arbitrary conversion
// causes. Preserve the structured variant for internal decisions, but expose
// only a closed category through every standard diagnostic interface.
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Sqlite(_) => f.write_str("database operation failed"),
			Self::Migration(failure) => std::fmt::Display::fmt(failure, f),
			Self::UnknownJobKinds(count) => {
				write!(f, "database contains {count} unknown job kinds; refusing startup")
			},
			Self::Validation(error) => std::fmt::Display::fmt(error, f),
			Self::Conflict(conflict) => write!(f, "conflict: {conflict:?}"),
			Self::Ownership(relation) => write!(f, "ownership mismatch: {relation:?}"),
			Self::NotFound(entity, id) => write!(f, "{entity:?} {id} not found"),
			Self::UnknownPaths(paths) => std::fmt::Display::fmt(paths, f),
			Self::ScopeDenied => f.write_str("repository access denied"),
			Self::ReportReceipt => f.write_str("report completion binding mismatch"),
			Self::DatabaseUnavailable => f.write_str("database unavailable"),
		}
	}
}

impl std::fmt::Debug for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Sqlite(_) => f.write_str("Sqlite([redacted])"),
			Self::Migration(failure) => f.debug_tuple("Migration").field(failure).finish(),
			Self::UnknownJobKinds(count) => f.debug_tuple("UnknownJobKinds").field(count).finish(),
			Self::Validation(error) => f.debug_tuple("Validation").field(error).finish(),
			Self::Conflict(conflict) => f.debug_tuple("Conflict").field(conflict).finish(),
			Self::Ownership(relation) => f.debug_tuple("Ownership").field(relation).finish(),
			Self::NotFound(entity, id) => {
				f.debug_tuple("NotFound").field(entity).field(id).finish()
			},
			Self::UnknownPaths(paths) => f.debug_tuple("UnknownPaths").field(paths).finish(),
			Self::ScopeDenied => f.write_str("ScopeDenied"),
			Self::ReportReceipt => f.write_str("ReportReceipt"),
			Self::DatabaseUnavailable => f.write_str("DatabaseUnavailable"),
		}
	}
}

pub type Result<T> = std::result::Result<T, Error>;

/// Owning handle to the SQLite database. Clones share one locked connection,
/// serializing transaction callbacks across the process.
///
/// The connection is opened against the SQLCipher-bundled SQLite, so
/// the underlying file is sealed under the [`MasterKey`] handed to
/// [`Db::open`] / [`Db::open_in_memory`]. `PRAGMA key` runs *before*
/// any other query so a wrong-key open fails at the first read rather
/// than silently returning corrupt data.
///
/// SQL callbacks are private to storage, including when test support is enabled.
/// ```compile_fail,E0624
/// fn raw(db: &loupe_storage::Db) {
///     let _ = db.with_conn(|connection| {
///         connection.execute_batch("SELECT 1")?;
///         Ok(())
///     });
/// }
/// ```
pub struct Db {
	conn: Mutex<Connection>,
	pub(crate) identity: Arc<DbIdentity>,
}

pub(crate) struct DbIdentity;

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
		Self::bootstrap_with_migration(conn, key, |conn| {
			apply_pending_with_finalizer(conn, Self::finalize)
		})
	}

	// Keep configuration and connection disposal on the real startup path
	// when migration tests inject failures at transactional boundaries.
	pub(crate) fn bootstrap_with_migration(
		mut conn: Connection, key: &MasterKey, migrate: impl FnOnce(&mut Connection) -> Result<()>,
	) -> Result<Self> {
		// PRAGMA key MUST run before any other statement that touches
		// pages: SQLCipher decrypts pages on read, so an unkeyed read
		// against an encrypted file returns "file is not a database".
		let sqlcipher_key = key.sqlcipher_key();
		conn.pragma_update(None, "key", sqlcipher_key.expose())?;
		conn.pragma_update(None, "journal_mode", "WAL")?;
		conn.pragma_update(None, "foreign_keys", "ON")?;
		conn.pragma_update(None, "synchronous", "NORMAL")?;
		migrate(&mut conn)?;
		Ok(Self { conn: Mutex::new(conn), identity: Arc::new(DbIdentity) })
	}

	fn finalize(conn: &Connection, upgrading: bool) -> Result<()> {
		// Foreign keys do not retroactively validate rows inserted with
		// enforcement disabled. Check on every boot, not just during v3.
		// NOT EXISTS rather than NOT IN: a NULL in the lookup would make
		// `NOT IN` evaluate to NULL for every row and pass everything.
		let unknown: Option<i64> = conn.query_row(
			"SELECT MIN(rowid) FROM jobs j
				  WHERE NOT EXISTS (SELECT 1 FROM job_kinds k WHERE k.kind = j.kind)",
			[],
			|row| row.get(0),
		)?;
		if let Some(rowid) = unknown {
			return Err(crate::migrations::MigrationFailure::new(
				crate::migrations::MigrationStage::Finalize,
				crate::migrations::MigrationReason::UnknownJobKind,
			)
			.at("jobs", "kind", Some(rowid))
			.into());
		}
		crate::scheduler::ensure_state(conn)?;
		if upgrading {
			crate::migrations::admission::validate(conn)?;
		}
		Ok(())
	}

	/// Run a closure with exclusive access to the underlying connection.
	pub(crate) fn with_conn<R>(&self, f: impl FnOnce(&mut Connection) -> Result<R>) -> Result<R> {
		let mut guard = self.conn.lock().map_err(|_| Error::DatabaseUnavailable)?;
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
	fn sqlite_error_debug_does_not_repeat_scoped_query_input() {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		let operator = crate::test_support::operator_ingress();
		let query = crate::findings::SearchQuery::syntax(
			crate::test_support::text("private_fts_marker:word").unwrap(),
		);
		let error = crate::scope::with_operator_repository(
			&db,
			&operator,
			crate::scope::OperatorTarget::Repository(1),
			|scope| crate::findings::search(scope, &query, 1),
		)
		.unwrap_err();
		assert!(matches!(error, Error::Sqlite(_)), "exercise an actual SQLite FTS error");
		for diagnostic in [format!("{error:?}"), format!("{error:#?}")] {
			assert!(
				!diagnostic.contains("private_fts_marker"),
				"storage error Debug must not repeat scoped query content: {diagnostic}"
			);
		}
	}

	#[test]
	fn sqlite_error_display_and_sources_do_not_repeat_scoped_query_input() {
		use std::error::Error as _;
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		let query = crate::findings::SearchQuery::syntax(
			crate::test_support::text("private_fts_marker:word").unwrap(),
		);
		let error = crate::scope::with_operator_repository(
			&db,
			&crate::test_support::operator_ingress(),
			crate::scope::OperatorTarget::Repository(1),
			|scope| crate::findings::search(scope, &query, 1),
		)
		.unwrap_err();
		assert!(matches!(error, Error::Sqlite(_)));
		for diagnostic in [error.to_string(), format!("{error:#}")] {
			assert!(
				!diagnostic.contains("private_fts_marker"),
				"storage error Display must not repeat scoped query content: {diagnostic}"
			);
		}
		assert!(
			error.source().is_none(),
			"SQLite causes must not escape the storage diagnostic boundary"
		);
		let wrapped = anyhow::Error::new(error);
		assert!(!format!("{wrapped:#}").contains("private_fts_marker"));
	}

	#[test]
	fn sqlite_conversion_error_sources_are_closed() {
		use std::error::Error as _;
		let sqlite = rusqlite::Error::FromSqlConversionFailure(
			0,
			rusqlite::types::Type::Text,
			"private_conversion_marker".into(),
		);
		let error = Error::from(sqlite);
		assert!(error.source().is_none(), "arbitrary SQLite conversion causes must be closed");
		for diagnostic in
			[format!("{error:?}"), format!("{error:#?}"), error.to_string(), format!("{error:#}")]
		{
			assert!(!diagnostic.contains("private_conversion_marker"));
		}
	}

	#[test]
	fn poisoned_database_lock_returns_a_closed_error_instead_of_panicking() {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			let _ = db.with_conn::<()>(|_| panic!("synthetic transaction panic"));
		}));
		assert!(poison.is_err());
		let next = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| db.schema_version()));
		assert!(next.is_ok(), "a poisoned database must return a closed error without panicking");
		assert!(next.unwrap().is_err());
	}

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
		assert!(
			matches!(
				error,
				Error::Migration(crate::migrations::MigrationFailure {
					reason: crate::migrations::MigrationReason::UnknownJobKind,
					table: Some("jobs"),
					column: Some("kind"),
					rowid: Some(1),
					..
				})
			),
			"{error}"
		);
		assert!(!format!("{error:?}").contains("bogus"));
		assert!(
			!message.contains("survey") && !message.contains("drilldown"),
			"known kinds must not be diagnosed as unknown: {message}"
		);
		// Repair only the invalid rows and prove that every seeded kind opens.
		let conn = Connection::open(&path).unwrap();
		conn.pragma_update(None, "key", key.sqlcipher_key().expose()).unwrap();
		conn.execute("DELETE FROM jobs WHERE kind IN ('bogus-a', 'bogus-b')", []).unwrap();
		drop(conn);
		let db = Db::open(&path, &key).unwrap();
		assert_eq!(db.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
	}

	#[test]
	fn startup_kind_guard_is_not_disabled_by_a_nullable_lookup() {
		// Exercise validation independently of the NOT NULL constraint.
		// The fixture permits a NULL row that would poison
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
					Db::finalize(conn, false)
				},
			);
			if unknown {
				match result {
					Err(Error::Migration(failure)) => {
						assert_eq!(
							failure.reason,
							crate::migrations::MigrationReason::UnknownJobKind
						);
						assert_eq!(failure.rowid, Some(2));
					},
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
		let id = {
			let db = Db::open(&path, &key_a).unwrap();
			db.with_conn(|c| {
				Ok(crate::secrets::insert(
					c,
					crate::secrets::SecretKind::GithubPat,
					"reopen",
					b"fake_reopen_pat",
					1,
				)?)
			})
			.unwrap()
		};
		// Reopen with the wrong key — first migration query must fail.
		let err = match Db::open(&path, &key_b) {
			Err(e) => e,
			Ok(_) => panic!("wrong-key open must error"),
		};
		assert_eq!(err.to_string(), "database operation failed");
		let Error::Sqlite(sqlite) = err else {
			panic!("wrong-key open must retain the structured SQLCipher error");
		};
		let msg = sqlite.to_string();
		assert!(
			msg.contains("not a database") || msg.contains("file is encrypted"),
			"expected SQLCipher cipher error, got: {msg}"
		);
		// A correct-key reopen must still recover real content after the failed open.
		let reopened = Db::open(&path, &key_a).unwrap();
		let value = reopened.with_conn(|c| Ok(crate::secrets::read(c, id)?)).unwrap().unwrap();
		assert_eq!(value.expose(), b"fake_reopen_pat");
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
