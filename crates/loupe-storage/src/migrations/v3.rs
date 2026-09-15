//! One-off, offline jobs rebuild. No published schema is modified in place.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use super::{migration_error, set_version};

mod schema;

// Spell out every historical column. New columns deliberately take NULL;
// neither generated review knowledge nor legacy job kinds are backfilled.
const LEGACY_COLUMNS: &str = "id, repo_id, kind, state, incremental, since_sha,
    head_sha, parent_job_id, target_finding_id, worker_id, lease_expires_at, attempts,
    enqueued_at, started_at, finished_at, error, job_capability_hash";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
	PreCheck,
	Seed,
	Tables,
	Copy,
	VerifyCopy,
	Replace,
	Indexes,
	ForeignKeyCheck,
	IntegrityCheck,
	Commit,
	Restore,
}

pub(super) fn run(conn: &mut Connection) -> rusqlite::Result<()> {
	run_with_probe(conn, &mut |_step, _conn| Ok(()))
}

// The connection argument lets tests corrupt the uncommitted copy, rather
// than merely simulate an error from a check that might not actually run.
pub(super) fn run_with_probe(
	conn: &mut Connection, probe: &mut impl FnMut(Step, &Connection) -> rusqlite::Result<()>,
) -> rusqlite::Result<()> {
	// SQLite cannot change FK enforcement inside a transaction, so this
	// happens first; the pre-checks below are read-only and do not care.
	let mut guard = ForeignKeys::disable(conn)?;
	let result = (|| {
		// IMMEDIATE takes the write lock before the pre-checks, so a writer
		// the operator failed to stop cannot lease a job between the count
		// and the first DDL and be copied into v3.
		let tx = guard.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
		probe(Step::PreCheck, &tx)?;
		let leased: i64 =
			tx.query_row("SELECT COUNT(*) FROM jobs WHERE state = 'leased'", [], |r| r.get(0))?;
		if leased != 0 {
			return Err(migration_error(format!(
				"schema v3 upgrade refused: {leased} leased job(s); wait for in-flight work to finish or cancel it, then stop the old server and all workers before retrying. Database remains at schema v2 (including upgrades starting at v1)"
			)));
		}
		let unknown = tx
			.prepare(
				"SELECT DISTINCT kind FROM jobs WHERE kind NOT IN ('scan', 'verify') ORDER BY kind",
			)?
			.query_map([], |row| row.get::<_, String>(0))?
			.collect::<rusqlite::Result<Vec<_>>>()?;
		if !unknown.is_empty() {
			return Err(migration_error(format!(
				"schema v3 upgrade refused: unknown legacy job kinds {unknown:?}; database remains at schema v2 (including upgrades starting at v1)"
			)));
		}
		tx.execute_batch(schema::JOB_KINDS)?;
		probe(Step::Seed, &tx)?;
		for sql in schema::NEW_TABLES {
			tx.execute_batch(sql)?;
		}
		probe(Step::Tables, &tx)?;
		tx.execute_batch(schema::JOBS_NEW)?;
		tx.execute_batch(&format!(
			"INSERT INTO jobs_new ({LEGACY_COLUMNS}) SELECT {LEGACY_COLUMNS} FROM jobs;"
		))?;
		probe(Step::Copy, &tx)?;
		probe(Step::VerifyCopy, &tx)?;
		let equal_counts: bool = tx.query_row(
			"SELECT (SELECT COUNT(*) FROM jobs) = (SELECT COUNT(*) FROM jobs_new)",
			[],
			|r| r.get(0),
		)?;
		let equal_rows: bool = tx.query_row(&format!(
			"SELECT NOT EXISTS (SELECT {LEGACY_COLUMNS} FROM jobs EXCEPT SELECT {LEGACY_COLUMNS} FROM jobs_new)
             AND NOT EXISTS (SELECT {LEGACY_COLUMNS} FROM jobs_new EXCEPT SELECT {LEGACY_COLUMNS} FROM jobs)"
		), [], |r| r.get(0))?;
		if !equal_counts || !equal_rows {
			return Err(migration_error(
				"schema v3: legacy jobs copy differs; upgrade rolled back to v2",
			));
		}
		tx.execute_batch("DROP TABLE jobs; ALTER TABLE jobs_new RENAME TO jobs;")?;
		probe(Step::Replace, &tx)?;
		for (name, sql) in schema::JOB_INDEXES {
			if let Err(error) = tx.execute_batch(sql) {
				let mut context =
					format!("schema v3: cannot create {name}; upgrade rolled back to v2");
				if *name == "idx_jobs_active_verify" {
					let duplicate: Option<i64> = tx.query_row(
						"SELECT target_finding_id FROM jobs
                         WHERE target_finding_id IS NOT NULL AND state IN ('queued','leased') AND kind = 'verify'
                         GROUP BY target_finding_id HAVING COUNT(*) > 1 ORDER BY target_finding_id LIMIT 1",
						[], |r| r.get(0),
					).optional()?;
					if let Some(finding) = duplicate {
						context.push_str(&format!(
							"; finding {finding} has duplicate active verify jobs: restart the old server, cancel one of its queued verify jobs, then stop the server and workers and retry"
						));
					}
				}
				return Err(match error {
					rusqlite::Error::SqliteFailure(code, message) => {
						rusqlite::Error::SqliteFailure(
							code,
							Some(format!("{context}: {}", message.unwrap_or_default())),
						)
					},
					other => migration_error(format!("{context}: {other}")),
				});
			}
		}
		probe(Step::Indexes, &tx)?;
		probe(Step::ForeignKeyCheck, &tx)?;
		let mut statement = tx.prepare("PRAGMA foreign_key_check")?;
		let mut violations = statement.query([])?;
		if let Some(row) = violations.next()? {
			let table: String = row.get(0)?;
			let rowid: Option<i64> = row.get(1)?;
			let parent: String = row.get(2)?;
			return Err(migration_error(format!(
				"schema v3 foreign_key_check failed: {table} row {rowid:?} references {parent}; upgrade rolled back to v2"
			)));
		}
		drop(violations);
		drop(statement);
		probe(Step::IntegrityCheck, &tx)?;
		let integrity = tx
			.prepare("PRAGMA integrity_check")?
			.query_map([], |r| r.get::<_, String>(0))?
			.collect::<rusqlite::Result<Vec<_>>>()?;
		if integrity != ["ok"] {
			return Err(migration_error(format!(
				"schema v3 integrity_check failed: {integrity:?}; upgrade rolled back to v2"
			)));
		}
		set_version(&tx, 3)?;
		tx.pragma_update(None, "user_version", 3)?;
		probe(Step::Commit, &tx)?;
		tx.commit()
	})();
	// On an ordinary error the transaction has already rolled back. After
	// commit, restoration is the only operation left in the v3 body.
	probe(Step::Restore, guard.conn).and_then(|()| guard.finish())?;
	result
}

struct ForeignKeys<'a> {
	conn: &'a mut Connection,
	prior: bool,
	restored: bool,
}

impl<'a> ForeignKeys<'a> {
	fn disable(conn: &'a mut Connection) -> rusqlite::Result<Self> {
		if !conn.is_autocommit() {
			return Err(migration_error("schema v3 must run outside a transaction"));
		}
		let prior = conn.pragma_query_value(None, "foreign_keys", |r| r.get(0))?;
		let guard = Self { conn, prior, restored: false };
		guard.conn.pragma_update(None, "foreign_keys", false)?;
		let enabled: bool = guard.conn.pragma_query_value(None, "foreign_keys", |r| r.get(0))?;
		if enabled {
			return Err(migration_error("schema v3 could not disable foreign keys"));
		}
		Ok(guard)
	}

	fn finish(&mut self) -> rusqlite::Result<()> {
		self.conn.pragma_update(None, "foreign_keys", self.prior)?;
		let enabled: bool = self.conn.pragma_query_value(None, "foreign_keys", |r| r.get(0))?;
		if enabled != self.prior {
			return Err(migration_error(
				"schema v3 could not restore foreign keys; discard this connection",
			));
		}
		self.restored = true;
		Ok(())
	}
}

impl Drop for ForeignKeys<'_> {
	fn drop(&mut self) {
		if !self.restored {
			// Best effort on unwind or an explicit restoration failure only.
			// The caller receives restoration errors through finish(), never
			// a successfully constructed Db with foreign keys silently off.
			let _ = self.conn.pragma_update(None, "foreign_keys", self.prior);
		}
	}
}
