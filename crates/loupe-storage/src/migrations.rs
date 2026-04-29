//! Embedded SQL migrations.
//!
//! Each entry in [`MIGRATIONS`] is `(version, sql)`. On startup we read
//! `schema_meta.version`, apply any newer migrations in a single
//! transaction, then bump the row. Migrations must be append-only —
//! never edit the SQL of a published version, only add a new one.

use rusqlite::{params, Connection};

/// One migration step. Versions are dense (1, 2, 3, ...) and applied in
/// ascending order.
struct Migration {
	version: u32,
	sql: &'static str,
}

/// The full migration list. New migrations are appended here.
const MIGRATIONS: &[Migration] = &[Migration { version: 1, sql: V1_INITIAL }];

/// The highest version this build knows about.
pub const LATEST_SCHEMA_VERSION: u32 = {
	// Computed at compile time so a forgotten bump is impossible.
	let mut max = 0u32;
	let mut i = 0;
	while i < MIGRATIONS.len() {
		if MIGRATIONS[i].version > max {
			max = MIGRATIONS[i].version;
		}
		i += 1;
	}
	max
};

/// Apply any migrations whose version is higher than `schema_meta.version`.
/// The bootstrap migration (`v0 → v1`) creates `schema_meta` itself.
pub fn apply_pending(conn: &mut Connection) -> rusqlite::Result<()> {
	let current = read_current_version(conn)?;
	let tx = conn.transaction()?;
	for m in MIGRATIONS {
		if m.version <= current {
			continue;
		}
		tx.execute_batch(m.sql)?;
		tx.execute(
			"INSERT INTO schema_meta (id, version, applied_at) VALUES (1, ?1, strftime('%s','now'))
			 ON CONFLICT(id) DO UPDATE SET version = excluded.version, applied_at = excluded.applied_at",
			params![m.version],
		)?;
	}
	tx.commit()?;
	Ok(())
}

/// Highest applied migration version — `0` if `schema_meta` doesn't yet exist.
pub fn current_schema_version(conn: &Connection) -> rusqlite::Result<u32> {
	read_current_version(conn)
}

fn read_current_version(conn: &Connection) -> rusqlite::Result<u32> {
	let exists: bool = conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_meta')",
		[],
		|r| r.get(0),
	)?;
	if !exists {
		return Ok(0);
	}
	let v: Option<u32> =
		conn.query_row("SELECT version FROM schema_meta WHERE id = 1", [], |r| r.get(0)).ok();
	Ok(v.unwrap_or(0))
}

/// v1 — initial schema.
///
/// Every substantive table carries a `record_version` column so JSON-blob
/// shape changes don't force a global migration; readers branch on the
/// version when interpreting.
const V1_INITIAL: &str = r#"
CREATE TABLE schema_meta (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    version     INTEGER NOT NULL,
    applied_at  INTEGER NOT NULL
);

CREATE TABLE secrets (
    id              INTEGER PRIMARY KEY,
    record_version  INTEGER NOT NULL DEFAULT 1,
    kind            TEXT    NOT NULL,
    label           TEXT    NOT NULL,
    nonce           BLOB    NOT NULL,
    ciphertext      BLOB    NOT NULL,
    created_at      INTEGER NOT NULL,
    UNIQUE(kind, label)
);

CREATE TABLE workers (
    id                INTEGER PRIMARY KEY,
    record_version    INTEGER NOT NULL DEFAULT 1,
    name              TEXT    NOT NULL UNIQUE,
    kind              TEXT    NOT NULL DEFAULT 'worker'
                            CHECK (kind IN ('worker', 'admin')),
    cert_fingerprint  BLOB    NOT NULL UNIQUE,
    created_at        INTEGER NOT NULL,
    last_seen_at      INTEGER,
    revoked_at        INTEGER
);

CREATE TABLE registered_repos (
    id                      INTEGER PRIMARY KEY,
    record_version          INTEGER NOT NULL DEFAULT 1,
    clone_url               TEXT    NOT NULL UNIQUE,
    host                    TEXT    NOT NULL,
    owner                   TEXT    NOT NULL,
    repo                    TEXT    NOT NULL,
    default_branch          TEXT,
    scan_interval_seconds   INTEGER,
    scanner_config          TEXT    NOT NULL DEFAULT '{}',
    reporting               TEXT    NOT NULL,
    -- When non-zero, findings from this repo must be confirmed by a
    -- verifier-capable worker before they're dispatched. Default off
    -- so the simple regex / first-pass LLM scanners don't pay an
    -- extra round-trip for repos that don't have a verifier worker
    -- pool to pick the verify jobs up.
    verification_enabled    INTEGER NOT NULL DEFAULT 0,
    last_scanned_sha        TEXT,
    last_scanned_at         INTEGER,
    created_at              INTEGER NOT NULL,
    disabled_at             INTEGER
);
CREATE INDEX idx_repos_due
    ON registered_repos(last_scanned_at)
    WHERE scan_interval_seconds IS NOT NULL AND disabled_at IS NULL;

CREATE TABLE jobs (
    id                  INTEGER PRIMARY KEY,
    record_version      INTEGER NOT NULL DEFAULT 1,
    repo_id             INTEGER NOT NULL REFERENCES registered_repos(id) ON DELETE CASCADE,
    kind                TEXT    NOT NULL CHECK (kind IN ('scan', 'verify')),
    state               TEXT    NOT NULL CHECK (state IN ('queued','leased','succeeded','failed','cancelled')),
    incremental         INTEGER NOT NULL DEFAULT 0,
    since_sha           TEXT,
    head_sha            TEXT,
    parent_job_id       INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
    target_finding_id   INTEGER,
    worker_id           INTEGER REFERENCES workers(id) ON DELETE SET NULL,
    lease_expires_at    INTEGER,
    attempts            INTEGER NOT NULL DEFAULT 0,
    enqueued_at         INTEGER NOT NULL,
    started_at          INTEGER,
    finished_at         INTEGER,
    error               TEXT
);
CREATE INDEX idx_jobs_queued ON jobs(state, enqueued_at);
CREATE INDEX idx_jobs_lease  ON jobs(state, lease_expires_at);
CREATE INDEX idx_jobs_repo   ON jobs(repo_id);

CREATE TABLE findings (
    id                      INTEGER PRIMARY KEY,
    record_version          INTEGER NOT NULL DEFAULT 1,
    repo_id                 INTEGER NOT NULL REFERENCES registered_repos(id) ON DELETE CASCADE,
    job_id                  INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    scanner_id              TEXT    NOT NULL,
    severity                TEXT    NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    title                   TEXT    NOT NULL,
    description             TEXT    NOT NULL,
    file_path               TEXT,
    line_start              INTEGER,
    line_end                INTEGER,
    cwe                     TEXT,
    patch_unified           TEXT,
    poc_unified             TEXT,
    fingerprint             TEXT    NOT NULL,
    state                   TEXT    NOT NULL DEFAULT 'pending'
                                CHECK (state IN ('pending','validating','confirmed','dismissed','reported')),
    verification_required   INTEGER NOT NULL DEFAULT 1,
    validating_deadline     INTEGER,
    created_at              INTEGER NOT NULL,
    confirmed_at            INTEGER,
    dismissed_at            INTEGER,
    reported_at             INTEGER,
    UNIQUE(repo_id, fingerprint)
);
CREATE INDEX idx_findings_job   ON findings(job_id);
CREATE INDEX idx_findings_state ON findings(state);

CREATE TABLE finding_verifications (
    id              INTEGER PRIMARY KEY,
    record_version  INTEGER NOT NULL DEFAULT 1,
    finding_id      INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    job_id          INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    verdict         TEXT    NOT NULL CHECK (verdict IN ('confirmed','dismissed','inconclusive')),
    notes           TEXT,
    created_at      INTEGER NOT NULL
);
CREATE INDEX idx_verifications_finding ON finding_verifications(finding_id);

CREATE TABLE scan_history (
    id              INTEGER PRIMARY KEY,
    record_version  INTEGER NOT NULL DEFAULT 1,
    repo_id         INTEGER NOT NULL REFERENCES registered_repos(id) ON DELETE CASCADE,
    job_id          INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    head_sha        TEXT    NOT NULL,
    base_sha        TEXT,
    finding_count   INTEGER NOT NULL,
    duration_ms     INTEGER NOT NULL,
    finished_at     INTEGER NOT NULL
);
CREATE INDEX idx_history_repo ON scan_history(repo_id, finished_at DESC);
"#;

#[cfg(test)]
mod tests {
	use rusqlite::Connection;

	use super::*;

	fn fresh() -> Connection {
		let mut c = Connection::open_in_memory().unwrap();
		apply_pending(&mut c).unwrap();
		c
	}

	#[test]
	fn fresh_db_reaches_latest_version() {
		let c = fresh();
		assert_eq!(current_schema_version(&c).unwrap(), LATEST_SCHEMA_VERSION);
	}

	#[test]
	fn applying_migrations_twice_is_a_no_op() {
		let mut c = fresh();
		// schema_meta.applied_at recorded once on the first apply; a second
		// pass must not change the version (and must not error).
		let v_before = current_schema_version(&c).unwrap();
		apply_pending(&mut c).unwrap();
		let v_after = current_schema_version(&c).unwrap();
		assert_eq!(v_before, v_after);
	}

	#[test]
	fn every_substantive_table_carries_record_version() {
		// `schema_meta` is exempt — it tracks migrations itself.
		let c = fresh();
		let mut stmt = c
			.prepare(
				"SELECT name FROM sqlite_master \
				 WHERE type='table' \
				   AND name NOT LIKE 'sqlite_%' \
				   AND name <> 'schema_meta'",
			)
			.unwrap();
		let tables: Vec<String> =
			stmt.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
		assert!(!tables.is_empty(), "no substantive tables found");
		for table in tables {
			let has: bool = c
				.query_row(
					&format!("SELECT EXISTS(SELECT 1 FROM pragma_table_info('{table}') WHERE name='record_version')"),
					[],
					|r| r.get(0),
				)
				.unwrap();
			assert!(has, "table {table} is missing record_version");
		}
	}

	#[test]
	fn finding_state_check_constraint_rejects_bogus_value() {
		let c = fresh();
		// Seed dependencies: a repo and a scan job.
		c.execute(
			"INSERT INTO registered_repos
			   (clone_url, host, owner, repo, scanner_config, reporting, created_at)
			 VALUES ('u', 'github.com', 'o', 'r', '{}', '{\"kind\":\"github_issue\",\"target_owner\":\"o\",\"target_repo\":\"r\",\"pat_secret_id\":1}', 0)",
			[],
		)
		.unwrap();
		c.execute(
			"INSERT INTO jobs (repo_id, kind, state, enqueued_at) VALUES (1, 'scan', 'queued', 0)",
			[],
		)
		.unwrap();
		let bad = c.execute(
			"INSERT INTO findings (repo_id, job_id, scanner_id, severity, title, description, fingerprint, state, created_at)
			 VALUES (1, 1, 's', 'low', 't', 'd', 'fp1', 'wibble', 0)",
			[],
		);
		assert!(bad.is_err(), "expected CHECK constraint to reject 'wibble' state");
	}

	#[test]
	fn finding_fingerprint_dedup_per_repo() {
		let c = fresh();
		c.execute(
			"INSERT INTO registered_repos
			   (clone_url, host, owner, repo, scanner_config, reporting, created_at)
			 VALUES ('u', 'github.com', 'o', 'r', '{}', '{\"kind\":\"github_issue\",\"target_owner\":\"o\",\"target_repo\":\"r\",\"pat_secret_id\":1}', 0)",
			[],
		)
		.unwrap();
		c.execute(
			"INSERT INTO jobs (repo_id, kind, state, enqueued_at) VALUES (1, 'scan', 'queued', 0)",
			[],
		)
		.unwrap();
		c.execute(
			"INSERT INTO findings (repo_id, job_id, scanner_id, severity, title, description, fingerprint, created_at)
			 VALUES (1, 1, 's', 'low', 't', 'd', 'fp-dup', 0)",
			[],
		)
		.unwrap();
		let dup = c.execute(
			"INSERT INTO findings (repo_id, job_id, scanner_id, severity, title, description, fingerprint, created_at)
			 VALUES (1, 1, 's', 'low', 't', 'd', 'fp-dup', 0)",
			[],
		);
		assert!(dup.is_err(), "expected UNIQUE(repo_id, fingerprint) to reject duplicate");
	}
}
