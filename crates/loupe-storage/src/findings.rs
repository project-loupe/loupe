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
