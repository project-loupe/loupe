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
	pub approved_at: Option<i64>,
	pub approved_by_cn: Option<String>,
	pub rejected_at: Option<i64>,
	pub rejected_by_cn: Option<String>,
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

/// Column list for `row_to_finding`. Centralised so adding a column
/// is one edit, not four.
const FINDING_COLUMNS: &str = "id, repo_id, job_id, scanner_id, severity, title, description,
        file_path, line_start, line_end, cwe, patch_unified,
        poc_unified, fingerprint, state, verification_required, created_at,
        approved_at, approved_by_cn, rejected_at, rejected_by_cn";

pub fn list_for_job(conn: &Connection, job_id: i64) -> rusqlite::Result<Vec<FindingRow>> {
	let mut stmt = conn.prepare(&format!(
		"SELECT {FINDING_COLUMNS}
		 FROM findings WHERE job_id = ?1 ORDER BY id ASC"
	))?;
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
	let mut stmt = conn.prepare(&format!(
		"SELECT {FINDING_COLUMNS}
		 FROM findings WHERE repo_id = ?1 ORDER BY id DESC LIMIT ?2"
	))?;
	let rows = stmt.query_map(params![repo_id, limit], row_to_finding)?;
	rows.collect()
}

/// Full-text search over a repo's findings. Matches on `title`,
/// `description`, and `file_path` via the `findings_fts` FTS5
/// virtual table; results ranked by BM25 with `title` weighted most
/// heavily, `file_path` moderately, `description` as long-form
/// context. Returns up to `limit` rows.
///
/// `query` is raw FTS5 query syntax. Callers handing in free-form
/// operator/agent keywords should run them through
/// [`sanitize_fts_query`] first — that strips FTS5 operators,
/// double-quotes each token, and gives "every token must appear"
/// semantics, which is what an agent calling
/// `query_prior_findings(keywords=...)` reasonably expects.
pub fn search(
	conn: &Connection, repo_id: i64, query: &str, limit: i64,
) -> rusqlite::Result<Vec<FindingRow>> {
	// FINDING_COLUMNS is unqualified; the FTS join puts a second
	// `title` / `description` / `file_path` in scope (the FTS5
	// virtual table proxies them) so the planner can't tell which
	// is which without a qualifier. Prefix each column with
	// `findings.` for this query specifically.
	let qualified_cols = FINDING_COLUMNS
		.split(',')
		.map(|c| format!("findings.{}", c.trim()))
		.collect::<Vec<_>>()
		.join(", ");
	let sql = format!(
		"SELECT {qualified_cols}
		 FROM findings_fts
		 JOIN findings ON findings.id = findings_fts.rowid
		 WHERE findings_fts MATCH ?1
		   AND findings.repo_id = ?2
		 ORDER BY bm25(findings_fts, 5.0, 1.0, 2.0)
		 LIMIT ?3"
	);
	let mut stmt = conn.prepare(&sql)?;
	let rows = stmt.query_map(params![query, repo_id, limit], row_to_finding)?;
	rows.collect()
}

/// Filter a candidate-fingerprint list to those already present on
/// `repo_id`. Used by the worker-side dedup stage: between
/// discovery and validation, the scanner asks "which of these
/// fingerprints have we already recorded?", drops the matches, and
/// only pays validation LLM cost on genuinely-new candidates.
///
/// Empty input returns an empty set; this is the natural answer
/// when discovery produced zero candidates (or every one was below
/// the dedup threshold). The query packs the list into a single
/// `IN (?, ?, …)` clause — for the few-tens-of-fingerprints scale
/// per scan, that's well under SQLite's max-bind-parameter limit
/// (999 by default).
pub fn known_fingerprints(
	conn: &Connection, repo_id: i64, candidates: &[String],
) -> rusqlite::Result<std::collections::HashSet<String>> {
	if candidates.is_empty() {
		return Ok(std::collections::HashSet::new());
	}
	// `repeat_n` is stable since 1.82; we target 1.75. `repeat(...).take(n)` is the equivalent.
	let placeholders = std::iter::repeat("?").take(candidates.len()).collect::<Vec<_>>().join(",");
	let sql = format!(
		"SELECT fingerprint FROM findings \
		 WHERE repo_id = ? AND fingerprint IN ({placeholders})",
	);
	let mut stmt = conn.prepare(&sql)?;
	let mut binds: Vec<rusqlite::types::Value> = Vec::with_capacity(candidates.len() + 1);
	binds.push(repo_id.into());
	for fp in candidates {
		binds.push(fp.clone().into());
	}
	let rows =
		stmt.query_map(rusqlite::params_from_iter(binds.iter()), |r| r.get::<_, String>(0))?;
	rows.collect::<rusqlite::Result<std::collections::HashSet<String>>>()
}

/// Turn a free-form keyword string into a safe FTS5 MATCH query.
///
/// Splits on whitespace; drops tokens of length < 2; strips
/// characters that would otherwise act as FTS5 operators (`"`, `*`,
/// `:`, `(`, `)`, `'`); double-quotes each remaining token to
/// neutralise any residual special meaning; joins with spaces. The
/// resulting query means "every token must appear" — the obvious
/// behaviour for "search by these keywords." Empty input (or input
/// where everything got dropped) returns an empty string; callers
/// should treat that as "no usable terms" and skip the query.
pub fn sanitize_fts_query(input: &str) -> String {
	input
		.split_whitespace()
		.map(|t| t.replace(['"', '*', ':', '(', ')', '\''], "").trim().to_owned())
		.filter(|t| t.len() >= 2)
		.map(|t| format!("\"{t}\""))
		.collect::<Vec<_>>()
		.join(" ")
}

/// Fetch one finding by id. Returns `None` if it doesn't exist.
pub fn get(conn: &Connection, id: i64) -> rusqlite::Result<Option<FindingRow>> {
	conn.query_row(
		&format!("SELECT {FINDING_COLUMNS} FROM findings WHERE id = ?1"),
		params![id],
		row_to_finding,
	)
	.optional()
}

pub fn get_for_repo(
	conn: &Connection, repo_id: i64, fingerprint: &str,
) -> rusqlite::Result<Option<FindingRow>> {
	conn.query_row(
		&format!("SELECT {FINDING_COLUMNS} FROM findings WHERE repo_id = ?1 AND fingerprint = ?2"),
		params![repo_id, fingerprint],
		row_to_finding,
	)
	.optional()
}

/// Outcome of an `approve`/`reject` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcome {
	/// The finding was in `awaiting_approval` and got transitioned.
	Applied,
	/// The finding exists but isn't in `awaiting_approval` (already
	/// approved, rejected, or never gated). Caller decides whether
	/// that's a 404 or a 409.
	NotPending,
	/// No finding with that id.
	NotFound,
}

/// Park a freshly-`confirmed` finding in `awaiting_approval` because
/// the repo (or server default) requires human sign-off before
/// dispatch. No-op if the finding isn't in `confirmed`.
pub fn transition_to_awaiting_approval(conn: &Connection, finding_id: i64) -> rusqlite::Result<()> {
	conn.execute(
		"UPDATE findings SET state = 'awaiting_approval'
		 WHERE id = ?1 AND state = 'confirmed'",
		[finding_id],
	)?;
	Ok(())
}

/// Approve a finding. Stamps `approved_at`/`approved_by_cn` and
/// transitions `awaiting_approval → confirmed` so the dispatcher can
/// pick it up. Idempotent on already-approved rows: re-running on a
/// `confirmed` row returns `NotPending` rather than re-stamping.
pub fn approve(
	conn: &Connection, id: i64, by_cn: &str, now: i64,
) -> rusqlite::Result<ApprovalOutcome> {
	let n = conn.execute(
		"UPDATE findings
		    SET state = 'confirmed', approved_at = ?1, approved_by_cn = ?2
		  WHERE id = ?3 AND state = 'awaiting_approval'",
		params![now, by_cn, id],
	)?;
	Ok(if n > 0 {
		ApprovalOutcome::Applied
	} else {
		match get(conn, id)? {
			Some(_) => ApprovalOutcome::NotPending,
			None => ApprovalOutcome::NotFound,
		}
	})
}

/// Reject a finding sitting in `awaiting_approval`. Transitions to
/// terminal `dismissed` with `rejected_at`/`rejected_by_cn` stamped.
/// `dismissed_at` is also stamped so dashboards that group on
/// `dismissed_at` don't need to special-case the rejection path.
pub fn reject(
	conn: &Connection, id: i64, by_cn: &str, now: i64,
) -> rusqlite::Result<ApprovalOutcome> {
	let n = conn.execute(
		"UPDATE findings
		    SET state = 'dismissed', dismissed_at = ?1,
		        rejected_at = ?1, rejected_by_cn = ?2
		  WHERE id = ?3 AND state = 'awaiting_approval'",
		params![now, by_cn, id],
	)?;
	Ok(if n > 0 {
		ApprovalOutcome::Applied
	} else {
		match get(conn, id)? {
			Some(_) => ApprovalOutcome::NotPending,
			None => ApprovalOutcome::NotFound,
		}
	})
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
		approved_at: row.get(17)?,
		approved_by_cn: row.get(18)?,
		rejected_at: row.get(19)?,
		rejected_by_cn: row.get(20)?,
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
		let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
		let secret_id =
			db.with_conn(|c| Ok(secrets::insert(c, SecretKind::GithubPat, "p", b"x", 0)?)).unwrap();
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
						require_approval: None,
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
	fn fts_search_matches_title_and_description() {
		let (db, repo_id, job_id) = fixture();
		// Three findings, deliberately distinct in title + description so
		// we can exercise tokenization, ranking, and per-repo isolation.
		let mut a = sample("fp-a");
		a.title = "Integer underflow in claim_for_id".into();
		a.description = "checked_sub returns None; payment is blocked".into();
		a.file_path = Some("src/payment/bolt11.rs".into());
		let mut b = sample("fp-b");
		b.title = "Unbounded allocation in handle_open_channel".into();
		b.description = "peer-controlled count drives a Vec::with_capacity".into();
		b.file_path = Some("src/peer/handler.rs".into());
		let mut c = sample("fp-c");
		c.title = "Race in closing_signed".into();
		c.description = "two threads can apply opposite fee updates".into();
		c.file_path = Some("src/channel/closing.rs".into());
		for f in &[&a, &b, &c] {
			db.with_conn(|conn| Ok(insert_or_ignore(conn, repo_id, job_id, f, false, 0)?)).unwrap();
		}

		// Single-keyword match.
		let q = sanitize_fts_query("underflow");
		let hits = db.with_conn(|c| Ok(search(c, repo_id, &q, 10)?)).unwrap();
		assert_eq!(hits.len(), 1);
		assert!(hits[0].title.contains("Integer underflow"));

		// Multi-keyword AND: must hit a row that contains both.
		let q = sanitize_fts_query("vec capacity");
		let hits = db.with_conn(|c| Ok(search(c, repo_id, &q, 10)?)).unwrap();
		assert_eq!(hits.len(), 1);
		assert!(hits[0].title.contains("Unbounded allocation"));

		// Path-component match (file_path is one of the indexed
		// columns).
		let q = sanitize_fts_query("closing.rs");
		let hits = db.with_conn(|c| Ok(search(c, repo_id, &q, 10)?)).unwrap();
		assert_eq!(hits.len(), 1);
		assert!(hits[0].title.contains("Race"));

		// No matches → empty Vec, not an error.
		let q = sanitize_fts_query("no-such-token-anywhere");
		let hits = db.with_conn(|c| Ok(search(c, repo_id, &q, 10)?)).unwrap();
		assert!(hits.is_empty());
	}

	#[test]
	fn fts_search_is_repo_scoped() {
		// Build a second repo in the same DB, plant a finding with the
		// same searchable terms in both, and confirm the search filter
		// keeps results in their lane.
		let (db, repo_id_a, job_id_a) = fixture();
		let secret_id = db
			.with_conn(|c| Ok(secrets::insert(c, SecretKind::GithubPat, "p2", b"x", 0)?))
			.unwrap();
		let repo_id_b = db
			.with_conn(|c| {
				Ok(repos::insert(
					c,
					&repos::NewRepo {
						clone_url: "https://github.com/c/d.git".into(),
						host: "github.com".into(),
						owner: "c".into(),
						repo: "d".into(),
						default_branch: None,
						scan_interval_seconds: None,
						scanner_config: serde_json::Value::Null,
						reporting: ReportingDestination::GithubIssue {
							target_owner: "c".into(),
							target_repo: "t".into(),
							pat_secret_id: secret_id,
						},
						verification_enabled: false,
						require_approval: None,
					},
					0,
				)?)
			})
			.unwrap();
		let job_id_b = db
			.with_conn(|c| {
				Ok(jobs::enqueue(
					c,
					&jobs::NewJob {
						repo_id: repo_id_b,
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

		let mut f_a = sample("fa");
		f_a.title = "shared keyword overflow".into();
		let mut f_b = sample("fb");
		f_b.title = "shared keyword overflow".into();

		db.with_conn(|c| Ok(insert_or_ignore(c, repo_id_a, job_id_a, &f_a, false, 0)?)).unwrap();
		db.with_conn(|c| Ok(insert_or_ignore(c, repo_id_b, job_id_b, &f_b, false, 0)?)).unwrap();

		let q = sanitize_fts_query("overflow");
		let hits_a = db.with_conn(|c| Ok(search(c, repo_id_a, &q, 10)?)).unwrap();
		assert_eq!(hits_a.len(), 1, "search must filter by repo_id; got {hits_a:?}");
		assert_eq!(hits_a[0].repo_id, repo_id_a);
		let hits_b = db.with_conn(|c| Ok(search(c, repo_id_b, &q, 10)?)).unwrap();
		assert_eq!(hits_b.len(), 1);
		assert_eq!(hits_b[0].repo_id, repo_id_b);
	}

	#[test]
	fn fts_search_survives_a_delete() {
		// Trigger sanity: inserting then deleting a finding leaves
		// the FTS index empty for that row, so a subsequent search
		// returns nothing instead of stale hits.
		let (db, repo_id, job_id) = fixture();
		let mut f = sample("fp-del");
		f.title = "very specific deletable phrase".into();
		let id = db
			.with_conn(|c| Ok(insert_or_ignore(c, repo_id, job_id, &f, false, 0)?))
			.unwrap()
			.unwrap();
		// Search hits.
		let q = sanitize_fts_query("deletable phrase");
		assert_eq!(db.with_conn(|c| Ok(search(c, repo_id, &q, 10)?)).unwrap().len(), 1);
		// Delete the finding.
		db.with_conn(|c| {
			c.execute("DELETE FROM findings WHERE id = ?1", [id])?;
			Ok(())
		})
		.unwrap();
		// Search now empty — the trigger reaped the FTS row.
		assert!(db.with_conn(|c| Ok(search(c, repo_id, &q, 10)?)).unwrap().is_empty());
	}

	#[test]
	fn known_fingerprints_filters_to_present_only() {
		let (db, repo_id, job_id) = fixture();
		// Plant two findings under repo_id with distinct fingerprints.
		let mut a = sample("fp-aaa");
		a.title = "alpha".into();
		let mut b = sample("fp-bbb");
		b.title = "beta".into();
		for f in &[&a, &b] {
			db.with_conn(|c| Ok(insert_or_ignore(c, repo_id, job_id, f, false, 0)?)).unwrap();
		}

		// Mix planted + novel candidates.
		let candidates: Vec<String> =
			["fp-aaa", "fp-novel", "fp-bbb", "also-novel"].iter().map(|s| s.to_string()).collect();
		let known = db.with_conn(|c| Ok(known_fingerprints(c, repo_id, &candidates)?)).unwrap();
		assert_eq!(known.len(), 2);
		assert!(known.contains("fp-aaa"));
		assert!(known.contains("fp-bbb"));
		assert!(!known.contains("fp-novel"));

		// Empty input → empty set, no query at all.
		let empty: Vec<String> = vec![];
		let known = db.with_conn(|c| Ok(known_fingerprints(c, repo_id, &empty)?)).unwrap();
		assert!(known.is_empty());
	}

	#[test]
	fn known_fingerprints_is_repo_scoped() {
		// A fingerprint planted on repo A should not be reported as
		// "known" for repo B.
		let (db, repo_id_a, job_id_a) = fixture();
		let secret_id = db
			.with_conn(|c| Ok(secrets::insert(c, SecretKind::GithubPat, "p2", b"x", 0)?))
			.unwrap();
		let repo_id_b = db
			.with_conn(|c| {
				Ok(repos::insert(
					c,
					&repos::NewRepo {
						clone_url: "https://github.com/x/y.git".into(),
						host: "github.com".into(),
						owner: "x".into(),
						repo: "y".into(),
						default_branch: None,
						scan_interval_seconds: None,
						scanner_config: serde_json::Value::Null,
						reporting: ReportingDestination::GithubIssue {
							target_owner: "x".into(),
							target_repo: "t".into(),
							pat_secret_id: secret_id,
						},
						verification_enabled: false,
						require_approval: None,
					},
					0,
				)?)
			})
			.unwrap();
		// Seed only repo A.
		let mut f = sample("shared-fp");
		f.title = "x".into();
		db.with_conn(|c| Ok(insert_or_ignore(c, repo_id_a, job_id_a, &f, false, 0)?)).unwrap();

		let candidates = vec!["shared-fp".to_string()];
		let known_b = db.with_conn(|c| Ok(known_fingerprints(c, repo_id_b, &candidates)?)).unwrap();
		assert!(known_b.is_empty(), "fingerprint on repo A must not match repo B");
	}

	#[test]
	fn sanitize_fts_query_strips_operators_and_quotes_tokens() {
		assert_eq!(sanitize_fts_query("foo bar"), "\"foo\" \"bar\"");
		// Operators / quotes / colons get stripped, then the cleaned
		// token is double-quoted as a literal.
		assert_eq!(sanitize_fts_query("foo* (bar:baz)"), "\"foo\" \"barbaz\"");
		// Single-character tokens are dropped.
		assert_eq!(sanitize_fts_query("a underflow b"), "\"underflow\"");
		// All-empty after sanitisation → empty string. Callers can
		// detect this and skip the query.
		assert_eq!(sanitize_fts_query("'\" *: ()"), "");
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
