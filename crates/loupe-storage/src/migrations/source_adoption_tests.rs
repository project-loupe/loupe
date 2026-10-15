//! Atomic source-metadata and finding-identity migrations preserve existing
//! content bytes while adding the required columns and constraints.
use rusqlite::Connection;

use super::{apply_migrations, apply_pending, current_schema_version, fixtures, MIGRATIONS};

const CONTENT_TABLES: &[&str] = &[
	"findings",
	"finding_verifications",
	"review_units",
	"review_unit_results",
	"leads",
	"lead_observations",
	"finding_review_details",
	"verification_attempt_details",
	"proof_artifacts",
	"staged_proof_artifacts",
	"proof_executions",
	"verification_proofs",
];

fn historical() -> Connection {
	let mut conn = Connection::open_in_memory().unwrap();
	fixtures::v1(&mut conn);
	apply_migrations(&mut conn, &MIGRATIONS[..4]).unwrap();
	assert_eq!(current_schema_version(&conn).unwrap(), 4);
	conn
}

#[test]
fn atomic_m_historical_bytes_and_version_mirror_control() {
	let mut conn = historical();
	let exact = "cafe\u{301}\r\n\t trailing  \n\n\n";
	conn.execute(
		"UPDATE findings SET description=?1, patch_unified=?2, poc_unified=?3 WHERE id=1",
		(exact, "--- a/x\r\n+++ b/x\r\n\t final without newline", ""),
	)
	.unwrap();
	let before = fixtures::rows(
		&conn,
		"SELECT id, repo_id, job_id, scanner_id, title, description, patch_unified, poc_unified, fingerprint, approved_by_cn, rejected_by_cn FROM findings ORDER BY id",
	);
	apply_pending(&mut conn).unwrap();
	assert_eq!(
		fixtures::rows(&conn, "SELECT id, repo_id, job_id, scanner_id, title, description, patch_unified, poc_unified, fingerprint, approved_by_cn, rejected_by_cn FROM findings ORDER BY id"),
		before,
		"source adoption must preserve every existing selected byte and row identity"
	);
	let version = current_schema_version(&conn).unwrap();
	let mirror: u32 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
	assert_eq!(version, mirror);
	apply_pending(&mut conn).unwrap();
	assert_eq!(current_schema_version(&conn).unwrap(), version);
}

/// Snapshot named v4 columns, so appended metadata cannot hide
/// changes to existing content, audit fields, NULLs, IDs, digests or links.
fn legacy_snapshot(conn: &Connection, table: &str) -> (String, Vec<Vec<rusqlite::types::Value>>) {
	let (sql, rows) = fixtures::snapshot(conn, table);
	assert!(!rows.is_empty(), "retention control must actually populate {table}");
	(sql, rows)
}

#[test]
fn atomic_m_twelve_content_groups_and_excluded_fields_survive_reopen() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("content.sqlite");
	let mut conn = fixtures::open(&path);
	fixtures::v1(&mut conn);
	apply_migrations(&mut conn, &MIGRATIONS[..4]).unwrap();
	super::ownership_tests::seed_two_projects(&conn);
	// Row 11 has populated optional groups; row 12 retains their NULLs. The
	// revision and policy values deliberately differ from the submitted content.
	let single = "Cafe\u{301} same  ";
	let prose = "Cafe\u{301}\r\n\t same  \n\n\n";
	let json = r#"{ "same": "Cafe\u0301", "nested": [null, "same"] }"#;
	let updates = [
		("findings", "title=?1, description=?2, patch_unified=?2, poc_unified='', patch_notes=?2, approved_by_cn=?1, rejected_by_cn=NULL, patch_proposed_by_cn='audit-proposer'", "id=11"),
		("finding_verifications", "notes=?2", "id=11"),
		("review_units", "title=?1, objective=?2, priority_proposal=?3, source_refs='[{\"path\":\"src/cafe\\u0301.rs\"}]', depends_on='[12]', closure_criteria=?2, semantic_context=?3, client_review_unit_key='audit-key', defer_reason=?2, stale_reason='audit-stale'", "review_unit_id=11"),
		("review_unit_results", "inspected_refs='[]', counterevidence=?2, proof_gaps=?2, result_payload=?3, commit_sha='revision-result', invalidated_reason='audit-invalidated'", "review_unit_result_id=11"),
		("leads", "priority_proposal=?3, identity_family=?1, identity_anchor=?1, identity_instance_key=?1, anchored_payload=?3, commit_sha='revision-lead', defer_reason=?2, retry_condition='audit-retry'", "lead_id=11"),
		("lead_observations", "observation_payload=?3, commit_sha='revision-observation'", "lead_observation_id=11"),
		("finding_review_details", "identity_family=?1, identity_anchor=?1, identity_instance_key=?1, l2_argument=?3, counterevidence=?2, assumptions_gaps=?2, reviewed_commit_sha='revision-review'", "finding_id=11"),
		("verification_attempt_details", "checkout_commit_sha='revision-attempt', e2e_rationale=?2, blocker=?2, retry_condition=?2", "verification_id=11"),
		("proof_artifacts", "media_type='text/plain; charset=utf-8', label=?1, original_name=?1", "proof_artifact_id=11"),
		("staged_proof_artifacts", "media_type='application/octet-stream', label=?1, original_name=?1", "staged_proof_artifact_id=11"),
		("proof_executions", "target_commit_sha='revision-execution', argv='[\"command\",\"Cafe\\u0301\"]', working_dir='src/café', env_names=?3, fixture_artifact_ids='[11]', limits='{\"host_policy\":7}', term_signal=9, stderr_artifact_id=11", "proof_execution_id=11"),
		("verification_proofs", "pinned_commit_sha='revision-proof', manifest=?3", "verification_proof_id=11"),
	];
	assert_eq!(updates.len(), CONTENT_TABLES.len());
	for ((table, assignments, predicate), expected) in updates.iter().zip(CONTENT_TABLES) {
		assert_eq!(table, expected);
		// Named bindings are present in every statement through the always-true
		// predicate; this fixture preserves differing policies without a parser.
		let sql = format!("UPDATE {table} SET {assignments} WHERE {predicate} AND ?1 IS NOT NULL AND ?2 IS NOT NULL AND ?3 IS NOT NULL");
		assert_eq!(conn.execute(&sql, (single, prose, json)).unwrap(), 1, "{table}");
	}
	assert_eq!(fixtures::rows(&conn, "SELECT e2e_rationale,blocker,retry_condition FROM verification_attempt_details WHERE verification_id=12"), vec![vec![rusqlite::types::Value::Null; 3]]);
	assert_eq!(fixtures::rows(&conn, "SELECT target_commit_sha,limits,working_dir FROM proof_executions WHERE proof_execution_id=11"), vec![vec![rusqlite::types::Value::Text("revision-execution".into()), rusqlite::types::Value::Text("{\"host_policy\":7}".into()), rusqlite::types::Value::Text("src/café".into())]]);
	let mut snapshots: Vec<_> =
		CONTENT_TABLES.iter().map(|table| legacy_snapshot(&conn, table)).collect();
	// These are deliberately outside the content-source subset, including the
	// opaque binary object and host recipe/audit values.
	for table in [
		"review_generations",
		"review_campaigns",
		"generation_inventory",
		"job_assigned_review_units",
		"proof_artifact_blobs",
		"verification_proof_artifacts",
		"verification_proof_executions",
		"job_terminal_receipts",
		"jobs",
		"registered_repos",
	] {
		snapshots.push(legacy_snapshot(&conn, table));
	}
	let fts = fixtures::rows(
		&conn,
		"SELECT rowid FROM findings_fts WHERE findings_fts MATCH 'sentinel' ORDER BY rowid",
	);
	assert_eq!(fts.len(), 6);
	apply_pending(&mut conn).unwrap();
	drop(conn);
	let mut conn = fixtures::open(&path);
	apply_pending(&mut conn).unwrap();
	for (sql, before) in snapshots {
		assert_eq!(fixtures::rows(&conn, &sql), before, "historical row changed: {sql}");
	}
	assert_eq!(
		fixtures::rows(
			&conn,
			"SELECT rowid FROM findings_fts WHERE findings_fts MATCH 'sentinel' ORDER BY rowid"
		),
		fts
	);
	assert!(fixtures::fk_enabled(&conn));
	assert!(fixtures::rows(&conn, "PRAGMA foreign_key_check").is_empty());
}

#[test]
fn atomic_m_deadline_note_requires_the_exact_mixed_host_tuple() {
	use crate::findings::{
		is_deadline_dismissed_without_terminal_verdict, reap_stale_validating,
		VALIDATING_DEADLINE_EXPIRED_NOTE,
	};
	let mut conn = historical();
	// The retained historical tuple is exercised through the current DAO;
	// install its required schema without changing any pre-existing values.
	apply_pending(&mut conn).unwrap();
	conn.execute("DELETE FROM finding_verifications", []).unwrap();
	conn.execute("UPDATE findings SET state='validating',validating_deadline=100 WHERE id=1", [])
		.unwrap();
	conn.execute("UPDATE findings SET validating_deadline=NULL WHERE id<>1", []).unwrap();
	assert_eq!(reap_stale_validating(&mut conn, 200).unwrap(), 1);
	let actual: (Option<i64>, String, Option<String>) = conn
		.query_row(
			"SELECT job_id,verdict,notes FROM finding_verifications WHERE finding_id=1",
			[],
			|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
		)
		.unwrap();
	assert_eq!(
		actual,
		(None, "inconclusive".into(), Some(VALIDATING_DEADLINE_EXPIRED_NOTE.into()))
	);
	assert!(is_deadline_dismissed_without_terminal_verdict(&conn, 1).unwrap());
	for (job, verdict, notes, expected) in [
		(None, "inconclusive", Some(VALIDATING_DEADLINE_EXPIRED_NOTE), true),
		(Some(2), "inconclusive", Some(VALIDATING_DEADLINE_EXPIRED_NOTE), false),
		(None, "inconclusive", Some("validating_deadline expired "), false),
		(None, "inconclusive", Some("submitted reason"), false),
		(None, "inconclusive", None, false),
		(None, "confirmed", Some(VALIDATING_DEADLINE_EXPIRED_NOTE), false),
		(None, "dismissed", Some(VALIDATING_DEADLINE_EXPIRED_NOTE), false),
	] {
		conn.execute("DELETE FROM finding_verifications WHERE finding_id=2", []).unwrap();
		conn.execute("INSERT INTO finding_verifications(finding_id,job_id,verdict,notes,created_at) VALUES(2,?1,?2,?3,0)", (job, verdict, notes)).unwrap();
		assert_eq!(
			is_deadline_dismissed_without_terminal_verdict(&conn, 2).unwrap(),
			expected,
			"{job:?}/{verdict}/{notes:?}"
		);
	}
	conn.execute("INSERT INTO finding_verifications(finding_id,job_id,verdict,notes,created_at) VALUES(1,2,'confirmed','submitted confirmation',0)", []).unwrap();
	assert!(
		!is_deadline_dismissed_without_terminal_verdict(&conn, 1).unwrap(),
		"real terminal verdict overrides the exact host tuple"
	);
}

#[test]
fn atomic_m_source_columns_cover_only_designated_tables() {
	let mut conn = historical();
	apply_pending(&mut conn).unwrap();
	let mut actual: Vec<String> = conn
		.prepare("SELECT m.name FROM sqlite_master m JOIN pragma_table_info(m.name) p WHERE m.type='table' AND p.name='source' ORDER BY m.name")
		.unwrap()
		.query_map([], |row| row.get(0))
		.unwrap()
		.collect::<rusqlite::Result<_>>()
		.unwrap();
	let mut expected: Vec<_> = CONTENT_TABLES.iter().map(|s| (*s).to_owned()).collect();
	actual.sort();
	expected.sort();
	assert_eq!(
		actual, expected,
		"atomic M must add precisely the twelve designated source columns"
	);
	for table in CONTENT_TABLES {
		let (required, default): (bool, String) = conn
			.query_row(
				"SELECT [notnull], dflt_value FROM pragma_table_info(?1) WHERE name='source'",
				[table],
				|row| Ok((row.get(0)?, row.get(1)?)),
			)
			.unwrap();
		assert!(required, "source must be mandatory on {table}");
		assert_eq!(default, "'agent'", "historical source classification on {table}");
	}
	assert_eq!(current_schema_version(&conn).unwrap(), 6);
	assert_eq!(
		conn.query_row("SELECT count(*) FROM findings WHERE source='agent'", [], |r| r
			.get::<_, usize>(0))
			.unwrap(),
		6
	);
}

#[test]
fn atomic_m_finding_identity_is_backfilled_once_and_unique() {
	let mut conn = historical();
	apply_pending(&mut conn).unwrap();
	let exists: bool = conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM pragma_table_info('findings') WHERE name='report_identity')",
		[], |r| r.get(0),
	).unwrap();
	assert!(exists, "atomic M must retain a report identity independent of recyclable SQL IDs");
	let before = fixtures::rows(&conn, "SELECT id, report_identity FROM findings ORDER BY id");
	assert_eq!(before.len(), 6);
	let (count, unique, valid): (usize, usize, usize) = conn.query_row(
		"SELECT count(*), count(DISTINCT report_identity), sum(typeof(report_identity)='blob' AND length(report_identity)=16) FROM findings",
		[], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
	).unwrap();
	assert_eq!((count, unique, valid), (6, 6, 6));
	apply_pending(&mut conn).unwrap();
	assert_eq!(
		fixtures::rows(&conn, "SELECT id, report_identity FROM findings ORDER BY id"),
		before
	);
}

#[test]
fn atomic_m_report_identity_cannot_be_replaced_or_reused() {
	let mut conn = historical();
	apply_pending(&mut conn).unwrap();
	let exists: bool = conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM pragma_table_info('findings') WHERE name='report_identity')",
		[], |row| row.get(0),
	).unwrap();
	assert!(exists, "report identity must exist before its immutability can be enforced");
	let identities = fixtures::rows(&conn, "SELECT id, report_identity FROM findings ORDER BY id");
	let id: Vec<u8> = conn
		.query_row("SELECT report_identity FROM findings WHERE id=1", [], |row| row.get(0))
		.unwrap();
	// Repeating the same identity is harmless; neither clearing it nor changing
	// its bytes may retarget an in-flight report receipt to another row.
	assert_eq!(
		conn.execute("UPDATE findings SET report_identity=?1 WHERE id=1", [&id]).unwrap(),
		1
	);
	for sql in [
		"UPDATE findings SET report_identity=NULL WHERE id=1",
		"UPDATE findings SET report_identity=zeroblob(16) WHERE id=1",
		"UPDATE findings SET report_identity=x'01' WHERE id=1",
		"UPDATE findings SET report_identity='sixteen-byte-key' WHERE id=1",
	] {
		assert!(conn.execute(sql, []).is_err(), "report identity update must fail: {sql}");
	}
	assert!(conn.execute(
		"INSERT INTO findings (repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,verification_required,created_at,report_identity)
		 SELECT repo_id,job_id,scanner_id,severity,title,description,'identity-collision',state,verification_required,created_at,report_identity FROM findings WHERE id=1", [],
	).is_err(), "a different finding cannot reuse an existing identity");
	assert_eq!(
		fixtures::rows(&conn, "SELECT id, report_identity FROM findings ORDER BY id"),
		identities
	);
}
