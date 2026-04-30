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

	fn bootstrap(mut conn: Connection, key: &MasterKey) -> Result<Self> {
		// PRAGMA key MUST run before any other statement that touches
		// pages: SQLCipher decrypts pages on read, so an unkeyed read
		// against an encrypted file returns "file is not a database".
		conn.pragma_update(None, "key", format!("x'{}'", key.to_hex()))?;
		conn.pragma_update(None, "journal_mode", "WAL")?;
		conn.pragma_update(None, "foreign_keys", "ON")?;
		conn.pragma_update(None, "synchronous", "NORMAL")?;
		apply_pending(&mut conn)?;
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
