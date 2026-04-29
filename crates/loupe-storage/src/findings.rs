//! DAO for the `findings` table.

use loupe_core::{Finding, Severity};
use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRow {
	pub id: i64,
	pub repo_id: i64,
	pub job_id: i64,
	pub scanner_id: String,
	pub severity: Severity,
	pub title: String,
	pub description: String,
	pub file_path: Option<String>,
	pub line_start: Option<u32>,
	pub line_end: Option<u32>,
	pub cwe: Option<String>,
	pub patch_unified: Option<String>,
	pub poc_unified: Option<String>,
	pub fingerprint: String,
	pub state: String,
	pub verification_required: bool,
	pub created_at: i64,
}

/// Insert a finding produced by a scan job. Idempotent on
/// `UNIQUE(repo_id, fingerprint)`: a duplicate insert returns `None`
/// rather than erroring, so the worker can retry safely.
///
/// `verification_required` controls whether the finding starts in
/// `validating` (the verify flow will confirm or dismiss it) or goes
/// straight through. The state column itself is still left at the
/// schema default `'pending'`; the complete handler is what flips it.
pub fn insert_or_ignore(
	conn: &Connection, repo_id: i64, job_id: i64, f: &Finding, verification_required: bool,
	now: i64,
) -> rusqlite::Result<Option<i64>> {
	let n = conn.execute(
		"INSERT OR IGNORE INTO findings
		   (repo_id, job_id, scanner_id, severity, title, description,
		    file_path, line_start, line_end, cwe, patch_unified,
		    poc_unified, fingerprint, verification_required, created_at)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
		params![
			repo_id,
			job_id,
			&f.scanner_id,
			f.severity.as_str(),
			&f.title,
			&f.description,
			&f.file_path,
			f.line_start,
			f.line_end,
			&f.cwe,
			&f.patch_unified,
			&f.poc_unified,
			&f.fingerprint,
			verification_required as i64,
			now,
		],
	)?;
	Ok(if n > 0 { Some(conn.last_insert_rowid()) } else { None })
}

pub fn list_for_job(conn: &Connection, job_id: i64) -> rusqlite::Result<Vec<FindingRow>> {
	let mut stmt = conn.prepare(
		"SELECT id, repo_id, job_id, scanner_id, severity, title, description,
		        file_path, line_start, line_end, cwe, patch_unified,
		        poc_unified, fingerprint, state, verification_required, created_at
		 FROM findings WHERE job_id = ?1 ORDER BY id ASC",
	)?;
	let rows = stmt.query_map(params![job_id], row_to_finding)?;
	rows.collect()
}

/// Reap findings whose `validating_deadline` has elapsed without
/// enough verdicts to flip state. Each reaped finding gets a
/// system-issued `inconclusive` verdict in `finding_verifications`
/// (with `job_id = NULL`) and transitions to `dismissed`. Returns the
/// number of findings reaped.
pub fn reap_stale_validating(conn: &mut Connection, now: i64) -> rusqlite::Result<usize> {
	let tx = conn.transaction()?;
	let stale: Vec<i64> = {
		let mut stmt = tx.prepare(
			"SELECT id FROM findings
			 WHERE state = 'validating'
			   AND validating_deadline IS NOT NULL
			   AND validating_deadline < ?1",
		)?;
		let rows = stmt.query_map([now], |r| r.get::<_, i64>(0))?;
		rows.collect::<rusqlite::Result<Vec<i64>>>()?
	};
	for fid in &stale {
		tx.execute(
			"INSERT INTO finding_verifications
			   (finding_id, job_id, verdict, notes, created_at)
			 VALUES (?1, NULL, 'inconclusive', 'validating_deadline expired', ?2)",
			(fid, now),
		)?;
		tx.execute(
			"UPDATE findings SET state = 'dismissed', dismissed_at = ?1
			 WHERE id = ?2 AND state = 'validating'",
			(now, fid),
		)?;
	}
	tx.commit()?;
	Ok(stale.len())
}

/// List findings for one repo, most recent first. `limit` caps the
/// page size (callers should pass something reasonable, e.g. 100).
pub fn list_for_repo(
	conn: &Connection, repo_id: i64, limit: i64,
) -> rusqlite::Result<Vec<FindingRow>> {
	let mut stmt = conn.prepare(
		"SELECT id, repo_id, job_id, scanner_id, severity, title, description,
		        file_path, line_start, line_end, cwe, patch_unified,
		        poc_unified, fingerprint, state, verification_required, created_at
		 FROM findings WHERE repo_id = ?1 ORDER BY id DESC LIMIT ?2",
	)?;
	let rows = stmt.query_map(params![repo_id, limit], row_to_finding)?;
	rows.collect()
}

/// Fetch one finding by id. Returns `None` if it doesn't exist.
pub fn get(conn: &Connection, id: i64) -> rusqlite::Result<Option<FindingRow>> {
	conn.query_row(
		"SELECT id, repo_id, job_id, scanner_id, severity, title, description,
		        file_path, line_start, line_end, cwe, patch_unified,
		        poc_unified, fingerprint, state, verification_required, created_at
		 FROM findings WHERE id = ?1",
		params![id],
		row_to_finding,
	)
	.optional()
}

pub fn get_for_repo(
	conn: &Connection, repo_id: i64, fingerprint: &str,
) -> rusqlite::Result<Option<FindingRow>> {
	conn.query_row(
		"SELECT id, repo_id, job_id, scanner_id, severity, title, description,
		        file_path, line_start, line_end, cwe, patch_unified,
		        poc_unified, fingerprint, state, verification_required, created_at
		 FROM findings WHERE repo_id = ?1 AND fingerprint = ?2",
		params![repo_id, fingerprint],
		row_to_finding,
	)
	.optional()
}

fn row_to_finding(row: &rusqlite::Row) -> rusqlite::Result<FindingRow> {
	let sev_str: String = row.get(4)?;
	let severity = sev_str.parse::<Severity>().map_err(|e| {
		rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, e.into())
	})?;
	Ok(FindingRow {
		id: row.get(0)?,
		repo_id: row.get(1)?,
		job_id: row.get(2)?,
		scanner_id: row.get(3)?,
		severity,
		title: row.get(5)?,
		description: row.get(6)?,
		file_path: row.get(7)?,
		line_start: row.get::<_, Option<i64>>(8)?.map(|v| v as u32),
		line_end: row.get::<_, Option<i64>>(9)?.map(|v| v as u32),
		cwe: row.get(10)?,
		patch_unified: row.get(11)?,
		poc_unified: row.get(12)?,
		fingerprint: row.get(13)?,
		state: row.get(14)?,
		verification_required: row.get::<_, i64>(15)? != 0,
		created_at: row.get(16)?,
	})
}

#[cfg(test)]
mod tests {
	use loupe_core::{ReportingDestination, Severity};

	use super::*;
	use crate::jobs::{self, NewJob};
	use crate::repos::{self, NewRepo};
	use crate::secrets::{self, SecretKind};
	use crate::Db;

	fn fixture() -> (Db, i64, i64) {
		let db = Db::open_in_memory().unwrap();
		let secret_id = db
			.with_conn(|c| Ok(secrets::insert_plaintext(c, SecretKind::GithubPat, "p", b"x", 0)?))
			.unwrap();
		let repo_id = db
			.with_conn(|c| {
				Ok(repos::insert(
					c,
					&NewRepo {
						clone_url: "https://github.com/a/b.git".into(),
						host: "github.com".into(),
						owner: "a".into(),
						repo: "b".into(),
						default_branch: None,
						scan_interval_seconds: None,
						scanner_config: serde_json::Value::Null,
						reporting: ReportingDestination::GithubIssue {
							target_owner: "a".into(),
							target_repo: "t".into(),
							pat_secret_id: secret_id,
						},
						verification_enabled: false,
					},
					0,
				)?)
			})
			.unwrap();
		let job_id = db
			.with_conn(|c| {
				Ok(jobs::enqueue(
					c,
					&NewJob {
						repo_id,
						kind: loupe_core::JobKind::Scan,
						incremental: false,
						since_sha: None,
						parent_job_id: None,
						target_finding_id: None,
					},
					0,
				)?)
			})
			.unwrap();
		(db, repo_id, job_id)
	}

	fn sample(fingerprint: &str) -> Finding {
		Finding {
			scanner_id: "regex".into(),
			severity: Severity::High,
			title: "AWS access key".into(),
			description: "Found AKIA...".into(),
			file_path: Some("src/x.rs".into()),
			line_start: Some(1),
			line_end: Some(1),
			cwe: Some("CWE-798".into()),
			patch_unified: None,
			poc_unified: None,
			fingerprint: fingerprint.into(),
		}
	}

	#[test]
	fn insert_then_list_round_trip() {
		let (db, repo_id, job_id) = fixture();
		let f = sample("fp1");
		let id = db
			.with_conn(|c| Ok(insert_or_ignore(c, repo_id, job_id, &f, false, 100)?))
			.unwrap()
			.unwrap();
		let listed = db.with_conn(|c| Ok(list_for_job(c, job_id)?)).unwrap();
		assert_eq!(listed.len(), 1);
		assert_eq!(listed[0].id, id);
		assert_eq!(listed[0].severity, Severity::High);
		assert_eq!(listed[0].fingerprint, "fp1");
	}

	#[test]
	fn reap_stale_validating_dismisses_expired_findings() {
		let (db, repo_id, job_id) = fixture();
		let f = sample("fp-stale");
		let id = db
			.with_conn(|c| Ok(insert_or_ignore(c, repo_id, job_id, &f, true, 0)?))
			.unwrap()
			.unwrap();
		// Push the finding into 'validating' with a deadline in the past.
		db.with_conn(|c| {
			c.execute(
				"UPDATE findings
				   SET state = 'validating', validating_deadline = 100
				 WHERE id = ?1",
				[id],
			)?;
			Ok(())
		})
		.unwrap();

		let n = db.with_conn(|c| Ok(reap_stale_validating(c, 200)?)).unwrap();
		assert_eq!(n, 1);

		// Finding flipped to dismissed; verifications row landed with
		// the timeout reason and a NULL job_id.
		let (state, dismissed_at): (String, Option<i64>) = db
			.with_conn(|c| {
				Ok(c.query_row(
					"SELECT state, dismissed_at FROM findings WHERE id = ?1",
					[id],
					|r| Ok((r.get(0)?, r.get(1)?)),
				)?)
			})
			.unwrap();
		assert_eq!(state, "dismissed");
		assert_eq!(dismissed_at, Some(200));

		let (count, with_null_job): (i64, i64) = db
			.with_conn(|c| {
				Ok(c.query_row(
					"SELECT COUNT(*), SUM(CASE WHEN job_id IS NULL THEN 1 ELSE 0 END)
					 FROM finding_verifications WHERE finding_id = ?1",
					[id],
					|r| Ok((r.get(0)?, r.get(1)?)),
				)?)
			})
			.unwrap();
		assert_eq!(count, 1);
		assert_eq!(with_null_job, 1, "reaper-issued row must have job_id = NULL");
	}

	#[test]
	fn reap_stale_validating_skips_confirmed_findings() {
		let (db, repo_id, job_id) = fixture();
		let f = sample("fp-confirmed");
		let id = db
			.with_conn(|c| Ok(insert_or_ignore(c, repo_id, job_id, &f, true, 0)?))
			.unwrap()
			.unwrap();
		db.with_conn(|c| {
			c.execute(
				"UPDATE findings
				   SET state = 'confirmed', validating_deadline = 100
				 WHERE id = ?1",
				[id],
			)?;
			Ok(())
		})
		.unwrap();
		let n = db.with_conn(|c| Ok(reap_stale_validating(c, 200)?)).unwrap();
		assert_eq!(
			n, 0,
			"confirmed findings must not be touched by the validating-deadline reaper"
		);
	}

	#[test]
	fn duplicate_fingerprint_is_idempotent() {
		let (db, repo_id, job_id) = fixture();
		let f = sample("dup");
		let first =
			db.with_conn(|c| Ok(insert_or_ignore(c, repo_id, job_id, &f, false, 100)?)).unwrap();
		let second =
			db.with_conn(|c| Ok(insert_or_ignore(c, repo_id, job_id, &f, false, 200)?)).unwrap();
		assert!(first.is_some());
		assert!(second.is_none(), "second insert must be ignored");
		assert_eq!(db.with_conn(|c| Ok(list_for_job(c, job_id)?)).unwrap().len(), 1);
	}
}
