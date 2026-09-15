//! Generated, encrypted historical databases; no opaque binary fixtures.

use std::path::Path;

use rusqlite::types::Value;
use rusqlite::{params, Connection};

use super::{apply_migrations, Migration, V1_INITIAL, V2_JOB_CAPABILITIES};
use crate::secrets::MasterKey;

pub(super) const LEGACY_COLUMNS: &str = "id, repo_id, kind, state, incremental, since_sha,
    head_sha, parent_job_id, target_finding_id, worker_id, lease_expires_at, attempts,
    enqueued_at, started_at, finished_at, error, job_capability_hash";

pub(super) const LEGACY_TABLES: &[&str] = &[
	"registered_repos",
	"workers",
	"secrets",
	"findings",
	"finding_verifications",
	"scan_history",
];

pub(super) fn rows(conn: &Connection, sql: &str) -> Vec<Vec<Value>> {
	let mut statement = conn.prepare(sql).unwrap();
	let width = statement.column_count();
	statement
		.query_map([], |row| (0..width).map(|i| row.get(i)).collect())
		.unwrap()
		.collect::<rusqlite::Result<_>>()
		.unwrap()
}

pub(super) fn schema(conn: &Connection) -> Vec<Vec<Value>> {
	rows(conn, "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")
}

pub(super) fn markers(conn: &Connection) -> (u32, u32) {
	(
		super::current_schema_version(conn).unwrap(),
		conn.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap(),
	)
}

pub(super) fn fk_enabled(conn: &Connection) -> bool {
	conn.pragma_query_value(None, "foreign_keys", |row| row.get(0)).unwrap()
}

pub(super) fn open(path: &Path) -> Connection {
	let conn = Connection::open(path).unwrap();
	conn.pragma_update(None, "key", format!("x'{}'", MasterKey::for_tests().to_hex())).unwrap();
	conn.pragma_update(None, "journal_mode", "WAL").unwrap();
	conn.pragma_update(None, "foreign_keys", true).unwrap();
	conn
}

pub(super) fn v1(conn: &mut Connection) {
	apply_migrations(conn, &[Migration::Sql { version: 1, sql: V1_INITIAL }]).unwrap();
	conn.execute_batch(
		r#"
INSERT INTO secrets VALUES (1, 'github_pat', 'fixture', x'0001ff', 11);
INSERT INTO workers VALUES (1, 'active', 'worker', x'01', 1, 2, NULL),
                           (2, 'revoked', 'admin', x'02', 3, 4, 5);
INSERT INTO registered_repos
    (id, clone_url, host, owner, repo, default_branch, scan_interval_seconds,
     scanner_config, reporting, verification_enabled, require_approval,
     last_scanned_sha, last_scanned_at, created_at, disabled_at)
VALUES (1, 'https://github.com/a/a', 'github.com', 'a', 'a', 'main', 600,
        '{ "source_extensions": ["rs"], "future_field": {"x":true} }',
        '{"kind":"manual"}', 1, NULL, 'old-head', 9, 1, NULL),
       (2, 'https://github.com/b/b', 'github.com', 'b', 'b', NULL, NULL,
        '{}', '{"kind":"manual"}', 0, 0, NULL, NULL, 2, NULL),
       (3, 'https://github.com/c/c', 'github.com', 'c', 'c', 'dev', 900,
        '{"unknown":42}', '{"kind":"manual"}', 1, 1, 'other-head', 10, 3, 11);
INSERT INTO jobs
    (id, repo_id, kind, state, incremental, since_sha, head_sha, parent_job_id,
     target_finding_id, worker_id, lease_expires_at, attempts, enqueued_at,
     started_at, finished_at, error)
VALUES (1, 1, 'scan', 'succeeded', 1, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', NULL, NULL, 1, NULL, 2, 1, 2, 3, NULL),
       (2, 1, 'verify', 'succeeded', 0, NULL, 'verified', 1, 4, 1, NULL, 1, 4, 5, 6, NULL),
       (3, 1, 'scan', 'failed', 0, NULL, NULL, 1, NULL, 2, NULL, 3, 7, 8, 9, 'failure'),
       (4, 1, 'verify', 'cancelled', 0, NULL, NULL, 1, 5, NULL, NULL, 0, 10, NULL, 11, 'cancelled'),
       (5, 1, 'scan', 'cancelled', 0, NULL, NULL, NULL, NULL, NULL, NULL, 0, 12, NULL, 13, ''),
       (6, 1, 'verify', 'failed', 0, NULL, NULL, 1, 2, 1, NULL, 3, 14, 15, 16, 'retry'),
       (7, 1, 'scan', 'queued', 1, 'base', NULL, 1, NULL, NULL, NULL, 0, 17, NULL, NULL, NULL),
       (8, 1, 'verify', 'queued', 0, NULL, NULL, 1, 2, NULL, NULL, 0, 18, NULL, NULL, NULL);
"#,
	)
	.unwrap();
	for (offset, state) in
		["pending", "validating", "awaiting_approval", "confirmed", "dismissed", "reported"]
			.iter()
			.enumerate()
	{
		let id = i64::try_from(offset).unwrap() + 1;
		conn.execute(
			"INSERT INTO findings
             (id, repo_id, job_id, scanner_id, severity, title, description, file_path,
              line_start, line_end, cwe, patch_unified, poc_unified, fingerprint, state,
              verification_required, validating_deadline, created_at, confirmed_at,
              dismissed_at, reported_at, approved_at, approved_by_cn, rejected_at,
              rejected_by_cn, patch_proposed_at, patch_proposed_by_cn, patch_notes)
             VALUES (?1, 1, 1, 'scanner', 'high', 'sentinel vulnerability', 'description',
                     'src/lib.rs', 12, 14, 'CWE-20', 'patch', 'legacy poc', ?2, ?3,
                     1, 300, 20, 21, 22, 23, 24, 'admin', 25, 'rejector', 26, 'verifier', 'notes')",
			params![id, format!("fingerprint-{id}"), state],
		)
		.unwrap();
	}
	conn.execute_batch(
		"INSERT INTO finding_verifications VALUES
        (1, 4, 2, 'confirmed', 'recorded verdict', 50),
        (2, 5, 4, 'dismissed', 'counterargument', 51),
        (3, 2, NULL, 'inconclusive', 'reaper', 52);
        INSERT INTO scan_history VALUES (1, 1, 1, 'head', 'base', 6, 123, 53);",
	)
	.unwrap();
}

pub(super) fn settled(conn: &mut Connection) {
	v1(conn);
	apply_migrations(
		conn,
		&[
			Migration::Sql { version: 1, sql: V1_INITIAL },
			Migration::Sql { version: 2, sql: V2_JOB_CAPABILITIES },
		],
	)
	.unwrap();
	for (id, byte) in [(1, 0x11_u8), (6, 0x66), (8, 0x88)] {
		conn.execute(
			"UPDATE jobs SET job_capability_hash = ?1 WHERE id = ?2",
			params![&[byte; 32], id],
		)
		.unwrap();
	}
}

pub(super) fn busy(conn: &Connection) {
	conn.execute(
		"INSERT INTO jobs
        (id, repo_id, kind, state, worker_id, lease_expires_at, job_capability_hash, enqueued_at)
        VALUES (9, 1, 'scan', 'leased', 1, 1000, ?1, 19)",
		[&[0x99_u8; 32]],
	)
	.unwrap();
}

pub(super) fn duplicate_verify(conn: &Connection) {
	conn.execute_batch(
		"INSERT INTO jobs (id, repo_id, kind, state, target_finding_id, enqueued_at)
        VALUES (9, 1, 'verify', 'queued', 2, 19);",
	)
	.unwrap();
}

pub(super) fn unknown_kind(conn: &Connection) {
	conn.pragma_update(None, "ignore_check_constraints", true).unwrap();
	conn.execute("UPDATE jobs SET kind = 'bogus' WHERE id = 1", []).unwrap();
	conn.pragma_update(None, "ignore_check_constraints", false).unwrap();
}
