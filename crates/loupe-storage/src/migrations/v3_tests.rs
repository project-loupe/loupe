use super::fixtures::*;
use super::*;
use crate::secrets::MasterKey;
use crate::{jobs, Db};

#[test]
fn v3_preserves_encrypted_legacy_data_and_claims() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("loupe.sqlite");
	let mut conn = open(&path);
	settled(&mut conn);
	let legacy_indexes = rows(&conn, "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'jobs' ORDER BY name");
	let legacy_jobs = rows(&conn, &format!("SELECT {LEGACY_COLUMNS} FROM jobs ORDER BY id"));
	let legacy_rows: Vec<_> = LEGACY_TABLES
		.iter()
		.map(|table| rows(&conn, &format!("SELECT * FROM {table} ORDER BY id")))
		.collect();
	drop(conn);
	let db = Db::open(&path, &MasterKey::for_tests()).unwrap();
	assert_eq!(db.schema_version().unwrap(), 3, "B1 must install schema v3");
	db.with_conn(|conn| {
		assert_eq!(markers(conn), (3, 3));
		assert!(fk_enabled(conn));
		assert_eq!(rows(conn, "SELECT name, sql FROM sqlite_master WHERE name IN ('idx_jobs_queued', 'idx_jobs_lease', 'idx_jobs_repo', 'idx_jobs_capability') ORDER BY name"), legacy_indexes);
		for job in rows(conn, "SELECT * FROM jobs ORDER BY id") {
			assert_eq!(job.len(), 30, "17 legacy columns plus 13 nullable additions");
			assert!(job[17..].iter().all(|value| *value == rusqlite::types::Value::Null), "legacy jobs must not acquire synthetic phase context");
		}
		assert_eq!(
			rows(conn, &format!("SELECT {LEGACY_COLUMNS} FROM jobs ORDER BY id")),
			legacy_jobs
		);
		for (table, before) in LEGACY_TABLES.iter().zip(&legacy_rows) {
			assert_eq!(
				&rows(conn, &format!("SELECT * FROM {table} ORDER BY id")),
				before,
				"{table} changed"
			);
		}
		assert_eq!(
			rows(
				conn,
				"SELECT rowid FROM findings_fts WHERE findings_fts MATCH 'sentinel' ORDER BY rowid"
			)
			.len(),
			6
		);
		assert_eq!(
			rows(conn, "SELECT f.id FROM findings f JOIN jobs j ON f.job_id = j.id").len(),
			6
		);
		assert_eq!(
			rows(conn, "SELECT j.id FROM jobs j JOIN jobs p ON j.parent_job_id = p.id").len(),
			6
		);
		assert_eq!(
			rows(
				conn,
				"SELECT v.id FROM finding_verifications v JOIN findings f ON v.finding_id = f.id"
			)
			.len(),
			3
		);
		assert_eq!(
			conn.execute(
				"INSERT OR IGNORE INTO findings
            (repo_id, job_id, scanner_id, severity, title, description, fingerprint, created_at)
            VALUES (1, 1, 'scanner', 'high', 'duplicate', 'ignored', 'fingerprint-1', 100)",
				[]
			)?,
			0
		);
		let scan = jobs::lease_next(conn, 1, false, 100, 600, &[0xa1; 32])?.unwrap();
		assert_eq!(scan.id, 7);
		let verify = jobs::lease_next(conn, 1, true, 100, 600, &[0xa2; 32])?.unwrap();
		assert_eq!(verify.id, 8);
		Ok(())
	})
	.unwrap();
	drop(db);
	// Leases only block the migration, not reopening an already upgraded DB.
	let db = Db::open(&path, &MasterKey::for_tests()).unwrap();
	assert_eq!(db.schema_version().unwrap(), 3);
}

#[test]
fn v3_refuses_busy_unknown_and_duplicate_verify_without_changes() {
	for (mutate, expected) in [
		(busy as fn(&Connection), "leased"),
		(unknown_kind, "bogus"),
		(duplicate_verify, "idx_jobs_active_verify"),
	] {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("loupe.sqlite");
		let mut conn = open(&path);
		settled(&mut conn);
		mutate(&conn);
		let before = schema(&conn);
		let jobs = rows(&conn, "SELECT * FROM jobs ORDER BY id");
		let err = apply_pending(&mut conn).expect_err("unsafe v3 upgrade must be refused");
		assert!(err.to_string().contains(expected), "{err}");
		if expected == "idx_jobs_active_verify" {
			assert!(err.to_string().contains("finding 2"), "{err}");
			assert!(err.to_string().contains("cancel"), "{err}");
		}
		assert!(fk_enabled(&conn));
		drop(conn);
		let conn = open(&path);
		assert_eq!(markers(&conn), (2, 2));
		assert_eq!(schema(&conn), before);
		assert_eq!(rows(&conn, "SELECT * FROM jobs ORDER BY id"), jobs);
		assert!(fk_enabled(&conn));
	}
}

#[test]
fn v3_installs_all_tables_indexes_and_job_kinds() {
	let mut conn = Connection::open_in_memory().unwrap();
	let prior_fk = fk_enabled(&conn);
	apply_pending(&mut conn).unwrap();
	assert_eq!(markers(&conn), (3, 3), "B1 must install schema v3");
	for table in [
		"job_kinds",
		"review_campaigns",
		"review_generations",
		"generation_inventory",
		"review_units",
		"job_assigned_review_units",
		"review_unit_results",
		"leads",
		"lead_observations",
		"job_checkpoints",
		"job_terminal_receipts",
		"finding_review_details",
		"verification_attempt_details",
		"proof_artifact_blobs",
		"proof_artifacts",
		"staged_proof_artifacts",
		"proof_executions",
		"verification_proofs",
		"verification_proof_artifacts",
		"verification_proof_executions",
	] {
		conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
	}
	for index in [
		"idx_jobs_queued",
		"idx_jobs_lease",
		"idx_jobs_repo",
		"idx_jobs_capability",
		"idx_jobs_repo_id_id",
		"idx_jobs_active_drilldown",
		"idx_jobs_active_verify",
		"idx_jobs_scheduler",
		"idx_campaigns_repo",
		"idx_campaigns_one_active",
		"idx_generations_one_active",
		"idx_generations_repo",
		"idx_units_sched",
		"idx_unit_results_unit",
		"idx_leads_identity",
		"idx_leads_sched",
		"idx_findings_repo_id_id",
		"idx_finding_verifications_finding_id_id",
	] {
		let exists: bool = conn
			.query_row(
				"SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?1)",
				[index],
				|r| r.get(0),
			)
			.unwrap();
		assert!(exists, "missing {index}");
	}
	let kinds: Vec<(String, i64)> = conn
		.prepare("SELECT kind, legacy FROM job_kinds ORDER BY kind")
		.unwrap()
		.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
		.unwrap()
		.collect::<rusqlite::Result<_>>()
		.unwrap();
	assert_eq!(
		kinds,
		[("drilldown".into(), 0), ("scan".into(), 1), ("survey".into(), 0), ("verify".into(), 0)]
	);
	assert_eq!(fk_enabled(&conn), prior_fk, "raw connection's prior FK setting must be retained");
}

#[test]
fn legacy_retry_conflicts_instead_of_tripping_the_active_verify_index() {
	// The settled fixture holds a failed verify (job 6) and a queued verify
	// (job 8) for finding 2; the migration admits that on purpose. Retrying
	// job 6 must answer with the endpoint's usual Conflict, not surface the
	// new partial unique index as an internal error.
	let mut conn = Connection::open_in_memory().unwrap();
	settled(&mut conn);
	apply_pending(&mut conn).unwrap();
	let outcome = jobs::retry_failed(&mut conn, 6, 100, 700)
		.expect("retry on migrated legacy data must not fail with a raw constraint error");
	match outcome {
		jobs::RetryOutcome::Conflict(message) => {
			assert!(
				message.contains("job 8"),
				"conflict must name the active verify job: {message}"
			);
		},
		other => panic!("expected Conflict, got {other:?}"),
	}
	assert_eq!(
		rows(&conn, "SELECT state FROM jobs WHERE id = 6"),
		vec![vec!["failed".to_owned().into()]]
	);
	assert_eq!(
		rows(&conn, "SELECT state FROM jobs WHERE id = 8"),
		vec![vec!["queued".to_owned().into()]]
	);
}

#[test]
fn job_kinds_rejects_a_null_kind() {
	// A non-INTEGER PRIMARY KEY admits NULL in SQLite unless NOT NULL is
	// spelled out, and a NULL kind would make the startup `NOT IN` guard
	// pass every unknown kind silently.
	let mut conn = Connection::open_in_memory().unwrap();
	apply_pending(&mut conn).unwrap();
	let error = conn
		.execute("INSERT INTO job_kinds (kind, legacy) VALUES (NULL, 0)", [])
		.expect_err("job_kinds must not admit a NULL kind");
	assert_eq!(
		error.sqlite_error().map(|e| e.extended_code),
		Some(rusqlite::ffi::SQLITE_CONSTRAINT_NOTNULL),
		"{error}"
	);
}
