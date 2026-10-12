//! Give every historical finding a stable identity for report completion.

use rusqlite::Connection;

use super::{MigrationFailure, MigrationReason, MigrationResult, MigrationStage, Probe};
use crate::report_identity;

pub(super) fn run(conn: &Connection, _probe: &mut Probe<'_>) -> MigrationResult {
	run_with_identity(conn, &mut report_identity::generate)
}

fn run_with_identity(
	conn: &Connection, next: &mut impl FnMut() -> rusqlite::Result<[u8; report_identity::BYTES]>,
) -> MigrationResult {
	let failure = |error| {
		MigrationFailure::sqlite(MigrationStage::Copy, error).at(
			"findings",
			"report_identity",
			None,
		)
	};
	// NULL permits the append-only column addition. Backfill completes before
	// commit, and DAO insertion/loading separately requires a valid token.
	conn.execute_batch(
		"ALTER TABLE findings ADD COLUMN report_identity BLOB
		 CHECK (report_identity IS NULL OR
		        (typeof(report_identity)='blob' AND length(report_identity)=16));
		 CREATE UNIQUE INDEX idx_findings_report_identity ON findings(report_identity);",
	)
	.map_err(failure)?;
	{
		let mut select = conn.prepare("SELECT id FROM findings ORDER BY id").map_err(failure)?;
		let mut rows = select.query([]).map_err(failure)?;
		let mut update =
			conn.prepare("UPDATE findings SET report_identity=?1 WHERE id=?2").map_err(failure)?;
		while let Some(row) = rows.next().map_err(failure)? {
			let id: i64 = row.get(0).map_err(failure)?;
			let identity = next().map_err(|_| {
				MigrationFailure::new(MigrationStage::Copy, MigrationReason::Entropy).at(
					"findings",
					"report_identity",
					Some(id),
				)
			})?;
			update.execute((identity.as_slice(), id)).map_err(|error| {
				let mut error = failure(error);
				error.rowid = Some(id);
				error.reason = MigrationReason::IdentityBackfill;
				error
			})?;
		}
	}
	conn.execute_batch(
		"CREATE TRIGGER findings_report_identity_immutable
		 BEFORE UPDATE OF report_identity ON findings
		 WHEN OLD.report_identity IS NOT NULL AND NEW.report_identity IS NOT OLD.report_identity
		 BEGIN SELECT RAISE(ABORT, 'finding report identity is immutable'); END;",
	)
	.map_err(failure)?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::migrations::{apply_migrations, apply_pending, fixtures, MIGRATIONS};

	#[test]
	fn identity_failure_after_v3_rebuild_rolls_back_every_pending_version() {
		fn fail(conn: &Connection, _: &mut Probe<'_>) -> MigrationResult {
			let mut calls = 0;
			run_with_identity(conn, &mut || {
				calls += 1;
				if calls == 2 {
					Err(rusqlite::Error::InvalidQuery)
				} else {
					Ok([7; report_identity::BYTES])
				}
			})
		}
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("upgrade.sqlite");
		let mut conn = fixtures::open(&path);
		fixtures::v1(&mut conn);
		conn.execute("UPDATE jobs SET state='leased' WHERE id=3", []).unwrap();
		let schema = fixtures::schema(&conn);
		let rows = crate::migrations::admission_tests::snapshot(&conn);
		let migrations = [
			crate::migrations::Migration::Sql {
				version: 2,
				sql: crate::migrations::V2_JOB_CAPABILITIES,
			},
			crate::migrations::Migration::Structural {
				version: 3,
				run: crate::migrations::v3::run,
			},
			crate::migrations::Migration::Sql { version: 4, sql: crate::migrations::V4_GITHUB_APP },
			crate::migrations::Migration::Structural { version: 5, run: fail },
		];
		let error = apply_migrations(&mut conn, &migrations).unwrap_err();
		assert!(matches!(
			error,
			crate::Error::Migration(MigrationFailure {
				source_version: Some(1),
				target_version: 5,
				rowid: Some(2),
				reason: MigrationReason::Entropy,
				..
			})
		));
		drop(conn);
		let conn = fixtures::open(&path);
		assert_eq!(fixtures::markers(&conn), (1, 1));
		assert_eq!(fixtures::schema(&conn), schema);
		assert_eq!(crate::migrations::admission_tests::snapshot(&conn), rows);
		drop(conn);
		assert_eq!(
			crate::Db::open(&path, &crate::secrets::MasterKey::for_tests())
				.unwrap()
				.schema_version()
				.unwrap(),
			6
		);
	}

	#[test]
	fn identity_failure_rolls_back_backfill_schema_and_version() {
		for collide in [false, true] {
			let mut conn = Connection::open_in_memory().unwrap();
			fixtures::v1(&mut conn);
			apply_migrations(&mut conn, &MIGRATIONS[..4]).unwrap();
			let before_schema = fixtures::schema(&conn);
			let before_rows = fixtures::rows(&conn, "SELECT * FROM findings ORDER BY id");
			let mut calls = 0;
			let error = {
				let tx = conn.transaction().unwrap();
				let error = run_with_identity(&tx, &mut || {
					calls += 1;
					if calls == 2 && !collide {
						return Err(rusqlite::Error::InvalidQuery);
					}
					Ok([7; report_identity::BYTES])
				})
				.expect_err("entropy failure or token collision must abort the migration");
				drop(tx);
				error
			};
			assert_eq!(calls, 2, "failure must follow an actual first backfill write");
			if collide {
				assert_eq!(error.sqlite_code, Some(rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE));
			} else {
				assert_eq!(error.reason, MigrationReason::Entropy);
			}
			assert_eq!(error.rowid, Some(2));
			assert!(conn.is_autocommit());
			assert_eq!(fixtures::markers(&conn), (4, 4));
			assert_eq!(fixtures::schema(&conn), before_schema);
			assert_eq!(fixtures::rows(&conn, "SELECT * FROM findings ORDER BY id"), before_rows);
			apply_pending(&mut conn).unwrap();
			assert_eq!(fixtures::markers(&conn), (6, 6));
		}
	}
}
