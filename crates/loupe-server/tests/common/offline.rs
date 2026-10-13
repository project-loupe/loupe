//! Test-owned encrypted fixtures for schema states unreachable through public APIs.
//!
//! The file is owned by this test's TempDir, initialized by the real migrations,
//! and encrypted with the synthetic MasterKey::for_tests key. Offline edits
//! require every cloned Db handle to have been dropped. Deliberate external
//! corruption may instead use an independent transaction while the original
//! server keeps its quotas, timers, identity caches, and notification state.
//! Neither path accesses the connection owned by a production Db.

use std::sync::Arc;

use loupe_storage::secrets::MasterKey;
use loupe_storage::Db;

pub struct OfflineDatabase {
	directory: tempfile::TempDir,
	db: Option<Arc<Db>>,
}

impl OfflineDatabase {
	pub fn new() -> Self {
		let mut fixture = Self { directory: tempfile::tempdir().unwrap(), db: None };
		drop(fixture.open());
		fixture
	}

	pub fn path(&self) -> std::path::PathBuf {
		self.directory.path().join("fixture.sqlite")
	}

	pub fn open(&mut self) -> Arc<Db> {
		if self.db.is_none() {
			self.db = Some(Arc::new(Db::open(self.path(), &MasterKey::for_tests()).unwrap()));
		}
		self.db.as_ref().unwrap().clone()
	}

	pub fn edit<T>(
		&mut self, body: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<T>,
	) -> T {
		if let Some(db) = self.db.take() {
			let db = match Arc::try_unwrap(db) {
				Ok(db) => db,
				Err(db) => {
					self.db = Some(db);
					panic!("offline fixture edits require all server and test Db handles to be dropped");
				},
			};
			drop(db);
		}
		let conn = rusqlite::Connection::open(self.path()).unwrap();
		let key = MasterKey::for_tests().to_hex();
		conn.pragma_update(None, "key", format!("x'{}'", key.expose())).unwrap();
		conn.pragma_update(None, "foreign_keys", "ON").unwrap();
		let result = body(&conn).unwrap();
		conn.close().unwrap();
		result
	}

	/// Simulate external on-disk corruption without replacing the running server.
	/// Only this fixture's private temporary file and synthetic key are used.
	/// The IMMEDIATE transaction serializes authored mutations with real route
	/// transactions and is committed before the caller sends its next request.
	/// This never obtains or exports the connection owned by a production Db.
	pub fn external_corruption<T>(
		&self, body: impl FnOnce(&rusqlite::Connection) -> loupe_storage::Result<T>,
	) -> loupe_storage::Result<T> {
		let mut conn = rusqlite::Connection::open(self.path())?;
		let key = MasterKey::for_tests().to_hex();
		conn.pragma_update(None, "key", format!("x'{}'", key.expose()))?;
		conn.pragma_update(None, "foreign_keys", "ON")?;
		let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
		let result = body(&tx)?;
		tx.commit()?;
		Ok(result)
	}
}
