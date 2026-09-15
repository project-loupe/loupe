use std::panic::{catch_unwind, AssertUnwindSafe};

use super::fixtures::*;
use super::v3::{run_with_probe, Step};
use super::*;
use crate::secrets::MasterKey;
use crate::Db;

#[test]
fn v3_precommit_failures_reopen_as_complete_v2_and_retry() {
	for step in [
		Step::PreCheck,
		Step::Seed,
		Step::Tables,
		Step::Copy,
		Step::VerifyCopy,
		Step::Replace,
		Step::Indexes,
		Step::ForeignKeyCheck,
		Step::IntegrityCheck,
		Step::Commit,
	] {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("loupe.sqlite");
		let mut conn = open(&path);
		settled(&mut conn);
		let before = schema(&conn);
		let jobs = rows(&conn, "SELECT * FROM jobs ORDER BY id");
		let legacy: Vec<_> = LEGACY_TABLES
			.iter()
			.map(|t| rows(&conn, &format!("SELECT * FROM {t} ORDER BY id")))
			.collect();
		let error = run_with_probe(&mut conn, &mut |at, _conn| {
			if at == step {
				Err(migration_error(format!("injected {step:?}")))
			} else {
				Ok(())
			}
		})
		.expect_err("precommit failure must abort the migration");
		assert!(error.to_string().contains("injected"), "{step:?}: {error}");
		assert!(fk_enabled(&conn));
		drop(conn);
		let mut conn = open(&path);
		assert_eq!(markers(&conn), (2, 2), "{step:?}");
		assert_eq!(schema(&conn), before, "{step:?}");
		assert_eq!(rows(&conn, "SELECT * FROM jobs ORDER BY id"), jobs, "{step:?}");
		for (table, before) in LEGACY_TABLES.iter().zip(legacy) {
			assert_eq!(
				rows(&conn, &format!("SELECT * FROM {table} ORDER BY id")),
				before,
				"{step:?}: {table}"
			);
		}
		assert!(fk_enabled(&conn));
		apply_pending(&mut conn).unwrap();
		assert_eq!(markers(&conn), (3, 3));
	}
}

#[test]
fn v3_exact_copy_check_detects_equal_length_corruption() {
	for sql in [
		"UPDATE jobs_new SET since_sha = head_sha, head_sha = since_sha WHERE id = 1",
		"UPDATE jobs_new SET job_capability_hash = zeroblob(32) WHERE id = 1",
	] {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("loupe.sqlite");
		let mut conn = open(&path);
		settled(&mut conn);
		let before = schema(&conn);
		let jobs = rows(&conn, "SELECT * FROM jobs ORDER BY id");
		let error = run_with_probe(&mut conn, &mut |step, conn| {
			if step == Step::VerifyCopy {
				conn.execute_batch(sql)?;
				// These are exactly the aggregates the earlier plan proposed.
				for column in ["since_sha", "head_sha", "job_capability_hash"] {
					assert_eq!(rows(conn, &format!("SELECT COUNT(*), COUNT({column}), TOTAL(LENGTH({column})) FROM jobs")),
						rows(conn, &format!("SELECT COUNT(*), COUNT({column}), TOTAL(LENGTH({column})) FROM jobs_new")));
				}
			}
			Ok(())
		}).expect_err("same-length corruption must fail exact copy verification");
		assert!(error.to_string().contains("legacy jobs copy differs"), "{error}");
		assert!(fk_enabled(&conn));
		drop(conn);
		let mut conn = open(&path);
		assert_eq!(markers(&conn), (2, 2));
		assert_eq!(schema(&conn), before);
		assert_eq!(rows(&conn, "SELECT * FROM jobs ORDER BY id"), jobs);
		apply_pending(&mut conn).unwrap();
	}
}

#[test]
fn v3_validators_reject_injected_fk_and_check_violations() {
	for (at, sql, diagnostic) in [
		(Step::ForeignKeyCheck, "UPDATE jobs SET repo_id = 999 WHERE id = 1", "foreign_key_check"),
		(Step::IntegrityCheck, "PRAGMA ignore_check_constraints = ON; UPDATE jobs SET token_budget = 0 WHERE id = 1; PRAGMA ignore_check_constraints = OFF;", "integrity_check"),
	] {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("loupe.sqlite");
		let mut conn = open(&path);
		settled(&mut conn);
		let before = schema(&conn);
		let error = run_with_probe(&mut conn, &mut |step, conn| {
			if step == at { conn.execute_batch(sql)?; }
			Ok(())
		}).expect_err("validation must run before committing schema v3");
		assert!(error.to_string().contains(diagnostic), "{error}");
		drop(conn);
		let mut conn = open(&path);
		assert_eq!(markers(&conn), (2, 2));
		assert_eq!(schema(&conn), before);
		apply_pending(&mut conn).unwrap();
	}
}

#[test]
fn v3_restoration_failure_rejects_bootstrap_but_keeps_complete_v3() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("loupe.sqlite");
	let mut conn = open(&path);
	settled(&mut conn);
	drop(conn);
	let result = Db::bootstrap_with_migration(
		Connection::open(&path).unwrap(),
		&MasterKey::for_tests(),
		|conn| {
			run_with_probe(conn, &mut |step, _conn| {
				if step == Step::Restore {
					Err(migration_error("injected FK restoration failure"))
				} else {
					Ok(())
				}
			})
		},
	);
	let Err(error) = result else {
		panic!("restoration failure must not construct a Db");
	};
	assert!(error.to_string().contains("FK restoration failure"), "{error}");
	let conn = open(&path);
	assert_eq!(markers(&conn), (3, 3));
	assert!(fk_enabled(&conn));
	let expected = schema(&conn);
	let mut fresh = Connection::open_in_memory().unwrap();
	apply_pending(&mut fresh).unwrap();
	assert_eq!(expected, schema(&fresh), "restoration failure must leave the entire v3 schema");
	assert!(rows(&conn, "PRAGMA foreign_key_check").is_empty());
	drop(conn);
	let db = Db::open(&path, &MasterKey::for_tests()).unwrap();
	db.with_conn(|conn| {
		assert_eq!(schema(conn), expected);
		assert_eq!(markers(conn), (3, 3));
		assert!(fk_enabled(conn));
		Ok(())
	})
	.unwrap();
}

#[test]
fn v3_panic_restores_the_prior_fk_setting() {
	for prior in [false, true] {
		for step in [Step::Copy, Step::Restore] {
			let mut conn = Connection::open_in_memory().unwrap();
			settled(&mut conn);
			conn.pragma_update(None, "foreign_keys", prior).unwrap();
			let before = schema(&conn);
			let result = catch_unwind(AssertUnwindSafe(|| {
				run_with_probe(&mut conn, &mut |at, _conn| {
					assert_ne!(at, step, "injected panic");
					Ok(())
				})
			}));
			assert!(result.is_err(), "probe must panic");
			assert!(conn.is_autocommit());
			assert_eq!(fk_enabled(&conn), prior);
			if step == Step::Copy {
				assert_eq!(markers(&conn), (2, 2));
				assert_eq!(schema(&conn), before);
			} else {
				assert_eq!(markers(&conn), (3, 3));
			}
		}
	}
}

#[test]
fn v3_success_and_error_restore_both_prior_fk_settings() {
	for prior in [false, true] {
		for fail in [false, true] {
			let mut conn = Connection::open_in_memory().unwrap();
			settled(&mut conn);
			conn.pragma_update(None, "foreign_keys", prior).unwrap();
			let result = run_with_probe(&mut conn, &mut |step, _| {
				if fail && step == Step::Copy {
					Err(migration_error("injected failure"))
				} else {
					Ok(())
				}
			});
			assert_eq!(result.is_err(), fail);
			assert!(conn.is_autocommit());
			assert_eq!(fk_enabled(&conn), prior);
		}
	}
}

#[test]
fn v3_real_commit_failure_rolls_back_and_restores_foreign_keys() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("loupe.sqlite");
	let mut conn = open(&path);
	settled(&mut conn);
	// A reader in rollback-journal mode permits DDL but prevents COMMIT
	// from acquiring its exclusive lock. This exercises SQLite's own error,
	// not a probe returning an error just before an otherwise good commit.
	conn.pragma_update(None, "journal_mode", "DELETE").unwrap();
	conn.busy_timeout(std::time::Duration::ZERO).unwrap();
	let reader = Connection::open(&path).unwrap();
	reader.pragma_update(None, "key", format!("x'{}'", MasterKey::for_tests().to_hex())).unwrap();
	reader.execute_batch("BEGIN; SELECT * FROM jobs;").unwrap();
	let before = schema(&conn);
	let mut reached_commit = false;
	let error = run_with_probe(&mut conn, &mut |step, _| {
		if step == Step::Commit {
			reached_commit = true;
		}
		Ok(())
	})
	.expect_err("SQLite must refuse COMMIT while a reader holds the file");
	assert!(reached_commit, "failure must occur at COMMIT, not during DDL: {error}");
	assert_eq!(error.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseBusy));
	assert!(fk_enabled(&conn));
	assert!(conn.is_autocommit());
	drop(reader);
	drop(conn);
	let mut conn = open(&path);
	assert_eq!(markers(&conn), (2, 2));
	assert_eq!(schema(&conn), before);
	apply_pending(&mut conn).unwrap();
	assert_eq!(markers(&conn), (3, 3));
}

#[test]
fn v1_upgrade_and_v3_refusal_leave_committed_capability_migration() {
	for refuse in [false, true] {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("loupe.sqlite");
		let mut conn = open(&path);
		v1(&mut conn);
		conn.execute_batch("UPDATE jobs SET state = 'leased', worker_id = 1, lease_expires_at = 100 WHERE id IN (2, 3);").unwrap();
		fn fail_precheck(conn: &mut Connection) -> rusqlite::Result<()> {
			assert_eq!(markers(conn), (2, 2));
			run_with_probe(conn, &mut |step, _conn| {
				if step == Step::PreCheck {
					Err(migration_error("injected pre-check failure"))
				} else {
					Ok(())
				}
			})
		}
		if refuse {
			apply_migrations(
				&mut conn,
				&[
					Migration::Sql { version: 1, sql: V1_INITIAL },
					Migration::Sql { version: 2, sql: V2_JOB_CAPABILITIES },
					Migration::Structural { version: 3, run: fail_precheck },
				],
			)
			.unwrap_err();
		} else {
			apply_pending(&mut conn).unwrap();
		}
		drop(conn);
		let mut conn = open(&path);
		let version = if refuse { 2 } else { 3 };
		assert_eq!(markers(&conn), (version, version));
		assert_eq!(rows(&conn, "SELECT state, worker_id, lease_expires_at, job_capability_hash, finished_at FROM jobs WHERE id = 2"),
			vec![vec!["succeeded".to_owned().into(), rusqlite::types::Value::Null, rusqlite::types::Value::Null, rusqlite::types::Value::Null, 6.into()]]);
		assert_eq!(rows(&conn, "SELECT state, worker_id, lease_expires_at, attempts, started_at, finished_at, error, head_sha FROM jobs WHERE id = 3"),
			vec![vec!["queued".to_owned().into(), rusqlite::types::Value::Null, rusqlite::types::Value::Null, 0.into(), rusqlite::types::Value::Null, rusqlite::types::Value::Null, rusqlite::types::Value::Null, rusqlite::types::Value::Null]]);
		if refuse {
			let mut expected = Connection::open_in_memory().unwrap();
			settled(&mut expected);
			assert_eq!(schema(&conn), schema(&expected));
			apply_pending(&mut conn).unwrap();
			assert_eq!(markers(&conn), (3, 3));
		}
	}
}

#[test]
fn v3_precheck_holds_the_write_lock_against_a_late_writer() {
	// The runbook asks operators to stop every writer, but the migration
	// must not depend on that: a writer that leases a job between the
	// leased-job count and the first DDL would otherwise be copied into v3.
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("loupe.sqlite");
	let mut conn = open(&path);
	settled(&mut conn);
	let late_writer = open(&path);
	late_writer.busy_timeout(std::time::Duration::ZERO).unwrap();
	run_with_probe(&mut conn, &mut |step, _conn| {
		if step == Step::PreCheck {
			let attempt = late_writer.execute(
				"UPDATE jobs SET state = 'leased', worker_id = 1, lease_expires_at = 1000 WHERE id = 7",
				[],
			);
			let error = attempt.expect_err("pre-check must already hold the write lock");
			assert_eq!(
				error.sqlite_error_code(),
				Some(rusqlite::ErrorCode::DatabaseBusy),
				"{error}"
			);
		}
		Ok(())
	})
	.unwrap();
	assert_eq!(markers(&conn), (3, 3));
	assert_eq!(
		rows(&conn, "SELECT state, worker_id FROM jobs WHERE id = 7"),
		vec![vec!["queued".to_owned().into(), rusqlite::types::Value::Null]]
	);
}
