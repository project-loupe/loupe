//! One-off, offline jobs rebuild inside the framework's upgrade transaction.

use rusqlite::{Connection, OptionalExtension};

use super::{
	MigrationFailure as Failure, MigrationReason as Reason, MigrationResult,
	MigrationStage as Stage, Probe,
};

mod schema;

// Spell out every historical column. New columns deliberately take NULL;
// neither generated review knowledge nor legacy job kinds are backfilled.
const LEGACY_COLUMNS: &str = "id, repo_id, kind, state, incremental, since_sha,
    head_sha, parent_job_id, target_finding_id, worker_id, lease_expires_at, attempts,
    enqueued_at, started_at, finished_at, error, job_capability_hash";

// debug-ok: migration steps are closed host operation names without stored row content.
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

pub(super) fn run(conn: &Connection, probe: &mut Probe<'_>) -> MigrationResult {
	let mut stage = Stage::PreCheck;
	let result = (|| -> crate::Result<()> {
		probe(Step::PreCheck, conn)?;
		let leased: Option<i64> = conn
			.query_row("SELECT id FROM jobs WHERE state = 'leased' ORDER BY id LIMIT 1", [], |r| {
				r.get(0)
			})
			.optional()?;
		if let Some(rowid) = leased {
			return Err(Failure::new(stage, Reason::LeasedJobs)
				.at("jobs", "state", Some(rowid))
				.into());
		}
		let unknown: Option<i64> = conn.query_row(
			"SELECT id FROM jobs WHERE kind NOT IN ('scan', 'verify') OR kind IS NULL ORDER BY id LIMIT 1",
			[], |r| r.get(0),
		).optional()?;
		if let Some(rowid) = unknown {
			return Err(Failure::new(stage, Reason::UnknownJobKind)
				.at("jobs", "kind", Some(rowid))
				.into());
		}
		stage = Stage::Seed;
		conn.execute_batch(schema::JOB_KINDS)?;
		probe(Step::Seed, conn)?;
		stage = Stage::Tables;
		for sql in schema::NEW_TABLES {
			conn.execute_batch(sql)?;
		}
		probe(Step::Tables, conn)?;
		conn.execute_batch(schema::JOBS_NEW)?;
		stage = Stage::Copy;
		conn.execute_batch(&format!(
			"INSERT INTO jobs_new ({LEGACY_COLUMNS}) SELECT {LEGACY_COLUMNS} FROM jobs;"
		))?;
		probe(Step::Copy, conn)?;
		stage = Stage::VerifyCopy;
		probe(Step::VerifyCopy, conn)?;
		let equal_counts: bool = conn.query_row(
			"SELECT (SELECT COUNT(*) FROM jobs) = (SELECT COUNT(*) FROM jobs_new)",
			[],
			|r| r.get(0),
		)?;
		let equal_rows: bool = conn.query_row(&format!(
			"SELECT NOT EXISTS (SELECT {LEGACY_COLUMNS} FROM jobs EXCEPT SELECT {LEGACY_COLUMNS} FROM jobs_new)
             AND NOT EXISTS (SELECT {LEGACY_COLUMNS} FROM jobs_new EXCEPT SELECT {LEGACY_COLUMNS} FROM jobs)"
		), [], |r| r.get(0))?;
		if !equal_counts || !equal_rows {
			let mut failure = Failure::new(stage, Reason::CopyMismatch);
			failure.table = Some("jobs");
			return Err(failure.into());
		}
		stage = Stage::Replace;
		conn.execute_batch("DROP TABLE jobs; ALTER TABLE jobs_new RENAME TO jobs;")?;
		probe(Step::Replace, conn)?;
		stage = Stage::Indexes;
		for (name, sql) in schema::JOB_INDEXES {
			if let Err(error) = conn.execute_batch(sql) {
				if *name == "idx_jobs_active_verify" {
					let duplicate: Option<i64> = conn.query_row(
						"SELECT MIN(id) FROM jobs
                         WHERE target_finding_id IS NOT NULL AND state IN ('queued','leased') AND kind = 'verify'
                         GROUP BY target_finding_id HAVING COUNT(*) > 1 ORDER BY MIN(id) LIMIT 1",
						[], |r| r.get(0),
					).optional()?;
					if let Some(rowid) = duplicate {
						return Err(Failure::new(stage, Reason::DuplicateVerify)
							.at("jobs", "target_finding_id", Some(rowid))
							.into());
					}
				}
				return Err(error.into());
			}
		}
		probe(Step::Indexes, conn)?;
		Ok(())
	})();
	result.map_err(|error| match error {
		crate::Error::Migration(failure) => failure,
		crate::Error::Sqlite(error) => Failure::sqlite(stage, error),
		_ => Failure::new(stage, Reason::InvalidData),
	})
}

// Exercise the production framework as well as the structural body. Probes
// can mutate the uncommitted copy, so validation tests cover real bad data.
#[cfg(test)]
pub(super) fn run_with_probe(conn: &mut Connection, probe: &mut Probe<'_>) -> crate::Result<()> {
	super::apply_with_finalizer(conn, &super::MIGRATIONS[..3], |_, _| Ok(()), probe)
}
