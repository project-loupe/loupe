use rusqlite::config::DbConfig;
use rusqlite::{Connection, TransactionBehavior};

use super::v3::Step;
use super::{
	read_current_version, set_version, Migration, MigrationFailure as Failure,
	MigrationReason as Reason, MigrationResult, MigrationStage as Stage, Probe,
};

pub(super) fn apply_with_finalizer(
	conn: &mut Connection, migrations: &[Migration],
	finalize: impl FnOnce(&Connection, bool) -> crate::Result<()>, probe: &mut Probe<'_>,
) -> crate::Result<()> {
	let latest = migrations.last().map_or(0, Migration::version);
	let mut source = None;
	let result = (|| {
		let mut guard = ForeignKeys::disable(conn)?;
		// Read the marker only after excluding other writers. Every pending
		// step, startup check, and both markers belong to this transaction.
		let tx = guard
			.conn
			.transaction_with_behavior(TransactionBehavior::Immediate)
			.map_err(|e| Failure::sqlite(Stage::AcquireLock, e))?;
		let current = read_current_version(&tx).map_err(|_| {
			Failure::new(Stage::ReadVersion, Reason::InvalidVersion).at(
				"schema_meta",
				"version",
				None,
			)
		})?;
		source = Some(current);
		if current > latest {
			return Err(Failure::new(Stage::ReadVersion, Reason::NewerSchema));
		}
		for migration in migrations.iter().filter(|m| m.version() > current) {
			match migration {
				Migration::Sql { sql, .. } => {
					tx.execute_batch(sql).map_err(|e| Failure::sqlite(Stage::Sql, e))?
				},
				Migration::Structural { run, .. } => run(&tx, probe)?,
			}
		}
		finalize(&tx, current < latest).map_err(Failure::finalizer)?;
		if current < latest {
			probe(Step::ForeignKeyCheck, &tx)
				.map_err(|e| Failure::sqlite(Stage::ForeignKeyCheck, e))?;
			validate_foreign_keys(&tx)?;
			probe(Step::IntegrityCheck, &tx)
				.map_err(|e| Failure::sqlite(Stage::IntegrityCheck, e))?;
			validate_integrity(&tx)?;
			set_version(&tx, latest).map_err(|e| Failure::sqlite(Stage::WriteVersion, e))?;
		}
		// Also repair a stale mirror atomically when the schema is current.
		tx.pragma_update(None, "user_version", latest)
			.map_err(|e| Failure::sqlite(Stage::WriteVersion, e))?;
		probe(Step::Restore, &tx).map_err(|e| Failure::sqlite(Stage::RestoreForeignKeys, e))?;
		// PRAGMA foreign_keys is a no-op in a transaction. The pinned SQLite
		// db_config API applies this setting immediately, and can be checked
		// before COMMIT. There is no fallible operation after a successful commit.
		restore_foreign_keys(&tx, guard.prior)?;
		guard.restored = true;
		probe(Step::Commit, &tx).map_err(|e| Failure::sqlite(Stage::Commit, e))?;
		tx.commit().map_err(|e| Failure::sqlite(Stage::Commit, e))
	})();
	result.map_err(|failure| failure.contextualize(source, latest).into())
}

fn validate_foreign_keys(conn: &Connection) -> MigrationResult {
	let inspect = || -> rusqlite::Result<Option<(String, Option<i64>)>> {
		let mut statement = conn.prepare("PRAGMA foreign_key_check")?;
		let mut rows = statement.query([])?;
		rows.next()?.map(|row| Ok((row.get(0)?, row.get(1)?))).transpose()
	};
	if let Some((table, rowid)) =
		inspect().map_err(|e| Failure::sqlite(Stage::ForeignKeyCheck, e))?
	{
		let mut failure = Failure::new(Stage::ForeignKeyCheck, Reason::ForeignKeyViolation);
		// Only code-owned names are diagnostic metadata. Unrecognized schema
		// identifiers are untrusted text and must not reach Display or Debug.
		failure.table = super::admission::known_table(&table);
		failure.rowid = rowid;
		return Err(failure);
	}
	Ok(())
}

fn validate_integrity(conn: &Connection) -> MigrationResult {
	let inspect = || -> rusqlite::Result<bool> {
		let mut statement = conn.prepare("PRAGMA integrity_check")?;
		let mut rows = statement.query([])?;
		let ok = rows.next()?.is_some_and(|row| row.get::<_, String>(0).is_ok_and(|s| s == "ok"));
		Ok(ok && rows.next()?.is_none())
	};
	if !inspect().map_err(|e| Failure::sqlite(Stage::IntegrityCheck, e))? {
		return Err(Failure::new(Stage::IntegrityCheck, Reason::IntegrityViolation));
	}
	Ok(())
}

struct ForeignKeys<'a> {
	conn: &'a mut Connection,
	prior: bool,
	restored: bool,
}

impl<'a> ForeignKeys<'a> {
	fn disable(conn: &'a mut Connection) -> MigrationResult<Self> {
		if !conn.is_autocommit() {
			return Err(Failure::new(Stage::AcquireLock, Reason::Database));
		}
		let prior = conn
			.db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY)
			.map_err(|e| Failure::sqlite(Stage::AcquireLock, e))?;
		let guard = Self { conn, prior, restored: false };
		let enabled = guard
			.conn
			.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY, false)
			.map_err(|e| Failure::sqlite(Stage::AcquireLock, e))?;
		if enabled {
			return Err(Failure::new(Stage::AcquireLock, Reason::ForeignKeySetting));
		}
		Ok(guard)
	}
}

fn restore_foreign_keys(conn: &Connection, prior: bool) -> MigrationResult {
	conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY, prior)
		.map_err(|e| Failure::sqlite(Stage::RestoreForeignKeys, e))?;
	let enabled = conn
		.db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY)
		.map_err(|e| Failure::sqlite(Stage::RestoreForeignKeys, e))?;
	if enabled != prior {
		return Err(Failure::new(Stage::RestoreForeignKeys, Reason::ForeignKeySetting));
	}
	Ok(())
}

impl Drop for ForeignKeys<'_> {
	fn drop(&mut self) {
		if !self.restored {
			// Transaction drops first on both errors and panics. Best effort
			// restoration never turns an aborted upgrade into reported success.
			let _ = self.conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY, self.prior);
		}
	}
}
