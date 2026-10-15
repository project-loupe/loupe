//! DAO for the `findings` table.

use loupe_core::text::policy::*;
use loupe_core::text::{BoundedText, RepoPath};
use loupe_core::{
	initial_finding_state, roll_up_verdicts, Finding, FindingState, FindingTransition, Severity,
	StateTransitionError, VerdictRollup,
};
use loupe_provenance::{Agent, Db as DbSource, Source};
use rusqlite::{params, Connection, OptionalExtension};

pub const VALIDATING_DEADLINE_EXPIRED_NOTE: &str = "validating_deadline expired";

pub fn get(scope: &crate::scope::RepoScope<'_>, id: i64) -> crate::Result<Option<FindingRow>> {
	Ok(scope
		.conn
		.query_row(
			&format!("SELECT {FINDING_COLUMNS} FROM findings WHERE id=?1 AND repo_id=?2"),
			params![id, scope.repo_id],
			row_to_finding,
		)
		.optional()?)
}

pub fn list_for_repo(
	scope: &crate::scope::RepoScope<'_>, limit: i64,
) -> crate::Result<Vec<FindingRow>> {
	Ok(list_for_repo_raw(scope.conn, scope.repo_id, limit)?)
}

pub fn list_for_job(
	scope: &crate::scope::RepoScope<'_>, job: i64,
) -> crate::Result<Vec<FindingRow>> {
	let mut stmt = scope.conn.prepare(&format!(
		"SELECT {FINDING_COLUMNS} FROM findings WHERE job_id=?1 AND repo_id=?2 ORDER BY id"
	))?;
	Ok(stmt
		.query_map(params![job, scope.repo_id], row_to_finding)?
		.collect::<rusqlite::Result<_>>()?)
}

pub fn search<S: Source>(
	scope: &crate::scope::RepoScope<'_>, query: &SearchQuery<S>, limit: i64,
) -> crate::Result<Vec<FindingRow>> {
	Ok(search_raw(scope.conn, scope.repo_id, query, limit)?)
}

/// Worker submission derives both repository and producing job from the live lease.
pub fn submit(
	scope: &crate::scope::AssignmentScope<'_>, finding: &Finding<Agent>,
) -> crate::Result<Option<i64>> {
	if scope.job.kind != loupe_core::JobKind::Scan {
		return Err(crate::Error::ScopeDenied);
	}
	let repo = crate::repos::get(&scope.repo)?.ok_or(crate::Error::ScopeDenied)?;
	Ok(insert_or_ignore(
		scope.repo.conn,
		scope.repo.repo_id,
		scope.job.id,
		finding,
		repo.verification_enabled,
		scope.lease.now,
	)?)
}

/// The two real verification writers. The fixed deadline tuple never acquires
/// an Agent prose label merely because it shares a SQL column with submissions.
pub enum VerificationInput<'a> {
	Submitted { job_id: i64, verdict: &'a loupe_core::Verdict<Agent> },
	DeadlineExpired,
}
pub(crate) fn insert_verification(
	conn: &Connection, repo_id: i64, finding_id: i64, input: VerificationInput<'_>, now: i64,
) -> rusqlite::Result<i64> {
	let (job_id, outcome, notes) = match input {
		VerificationInput::Submitted { job_id, verdict } => {
			let (outcome, notes) = match verdict {
				loupe_core::Verdict::Confirmed { notes, .. } => {
					("confirmed", notes.as_ref().map(BoundedText::expose))
				},
				loupe_core::Verdict::Dismissed { notes } => {
					("dismissed", notes.as_ref().map(BoundedText::expose))
				},
				loupe_core::Verdict::Inconclusive { reason, .. } => {
					("inconclusive", Some(reason.expose()))
				},
			};
			(Some(job_id), outcome, notes)
		},
		VerificationInput::DeadlineExpired => {
			(None, "inconclusive", Some(VALIDATING_DEADLINE_EXPIRED_NOTE))
		},
	};
	let changed = conn.execute("INSERT INTO finding_verifications(finding_id,job_id,verdict,notes,created_at,source) SELECT ?1,?2,?3,?4,?5,'agent' WHERE EXISTS(SELECT 1 FROM findings WHERE id=?1 AND repo_id=?6) AND (?2 IS NULL OR EXISTS(SELECT 1 FROM jobs WHERE id=?2 AND repo_id=?6 AND target_finding_id=?1 AND kind='verify'))", params![finding_id,job_id,outcome,notes,now,repo_id])?;
	if changed == 0 {
		return Err(rusqlite::Error::QueryReturnedNoRows);
	}
	Ok(conn.last_insert_rowid())
}

pub struct SearchText;
impl loupe_core::text::TextPolicy for SearchText {
	const FIELD: &'static str = "finding_search";
	const MAX_BYTES: usize = LEGACY_TEXT_MAX_BYTES;
	const MAX_CHARS: usize = LEGACY_TEXT_MAX_BYTES;
	const MULTILINE: bool = true;
	const ALLOW_CR: bool = true;
	const ALLOW_EMPTY: bool = true;
	const NORMALIZATION: loupe_core::text::Normalization = loupe_core::text::Normalization::Exact;
	const WHITESPACE: loupe_core::text::Whitespace = loupe_core::text::Whitespace::Significant;
}
/// Named FTS egress retains the actual admitted keyword or syntax owner.
pub struct SearchQuery<S: Source> {
	input: BoundedText<SearchText, S>,
	keywords: Option<String>,
}
impl<S: Source> SearchQuery<S> {
	pub fn keywords(input: BoundedText<SearchText, S>) -> Self {
		let keywords = Some(sanitize_fts_query(input.expose()));
		Self { input, keywords }
	}
	pub fn syntax(input: BoundedText<SearchText, S>) -> Self {
		Self { input, keywords: None }
	}
	fn expose(&self) -> &str {
		self.keywords.as_deref().unwrap_or_else(|| self.input.expose())
	}
	pub fn is_empty(&self) -> bool {
		self.expose().is_empty()
	}
}

/// Immutable row identity used by report-scope binding, never a wire field.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FindingIdentity([u8; crate::report_identity::BYTES]);
impl FindingIdentity {
	pub fn scope_bytes(&self) -> &[u8; crate::report_identity::BYTES] {
		&self.0
	}
}
impl std::fmt::Debug for FindingIdentity {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("FindingIdentity([redacted])")
	}
}

// debug-ok: all finding text and row identity delegate to redacted owners; other fields are IDs, times and closed states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRow {
	pub id: i64,
	pub repo_id: i64,
	pub job_id: i64,
	pub scanner_id: BoundedText<ScannerIdText, Agent>,
	pub severity: Severity,
	pub title: BoundedText<FindingTitle, Agent>,
	pub description: BoundedText<FindingDescription, Agent>,
	pub file_path: Option<RepoPath<Agent>>,
	pub line_start: Option<u32>,
	pub line_end: Option<u32>,
	pub cwe: Option<BoundedText<CweText, Agent>>,
	pub patch_unified: Option<BoundedText<PatchUnified, Agent>>,
	pub poc_unified: Option<BoundedText<PocUnified, Agent>>,
	pub fingerprint: BoundedText<FindingFingerprintText, Agent>,
	pub state: FindingState,
	pub verification_required: bool,
	pub created_at: i64,
	pub approved_at: Option<i64>,
	pub approved_by_cn: Option<BoundedText<AuditName, DbSource>>,
	pub rejected_at: Option<i64>,
	pub rejected_by_cn: Option<BoundedText<AuditName, DbSource>>,
	pub patch_proposed_at: Option<i64>,
	pub patch_proposed_by_cn: Option<BoundedText<AuditName, DbSource>>,
	pub patch_notes: Option<BoundedText<PatchNotes, Agent>>,
	report_identity: FindingIdentity,
}

impl FindingRow {
	pub fn report_identity(&self) -> FindingIdentity {
		self.report_identity
	}
	pub fn into_finding(self) -> Finding<Agent> {
		Finding {
			scanner_id: self.scanner_id,
			severity: self.severity,
			title: self.title,
			description: self.description,
			file_path: self.file_path,
			line_start: self.line_start,
			line_end: self.line_end,
			cwe: self.cwe,
			patch_unified: self.patch_unified,
			poc_unified: self.poc_unified,
			fingerprint: self.fingerprint,
		}
	}
}

/// Insert a finding produced by a scan job. Idempotent on
/// `UNIQUE(repo_id, fingerprint)`: a duplicate insert returns `None`
/// rather than erroring, so the worker can retry safely.
///
/// `verification_required` controls whether the finding starts in
/// `validating` (the verify flow will confirm or dismiss it) or goes
/// straight through. Inserted rows start as `pending`; the complete
/// handler is what flips them.
pub(crate) fn insert_or_ignore(
	conn: &Connection, repo_id: i64, job_id: i64, f: &Finding<Agent>, verification_required: bool,
	now: i64,
) -> rusqlite::Result<Option<i64>> {
	insert_with_identity(
		conn,
		repo_id,
		job_id,
		f,
		verification_required,
		now,
		crate::report_identity::generate,
	)
}

fn insert_with_identity(
	conn: &Connection, repo_id: i64, job_id: i64, f: &Finding<Agent>, verification_required: bool,
	now: i64, generate: impl FnOnce() -> rusqlite::Result<[u8; crate::report_identity::BYTES]>,
) -> rusqlite::Result<Option<i64>> {
	let initial_state = initial_finding_state(FindingTransition::ScanAccepted)
		.map_err(sql_state_transition_error)?;
	let report_identity = generate()?;
	let n = conn.execute(
		"INSERT INTO findings
		   (repo_id, job_id, scanner_id, severity, title, description,
		    file_path, line_start, line_end, cwe, patch_unified,
		    poc_unified, fingerprint, state, verification_required, created_at, report_identity, source)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, 'agent')
		 ON CONFLICT(repo_id, fingerprint) DO NOTHING",
		params![
			repo_id,
			job_id,
			f.scanner_id.expose(),
			f.severity.as_str(),
			f.title.expose(),
			f.description.expose(),
			f.file_path.as_ref().map(RepoPath::expose),
			f.line_start,
			f.line_end,
			f.cwe.as_ref().map(BoundedText::expose),
			f.patch_unified.as_ref().map(BoundedText::expose),
			f.poc_unified.as_ref().map(BoundedText::expose),
			f.fingerprint.expose(),
			initial_state.as_str(),
			verification_required as i64,
			now,
			report_identity.as_slice(),
		],
	)?;
	Ok(if n > 0 { Some(conn.last_insert_rowid()) } else { None })
}

/// Column list for `row_to_finding`. Centralised so adding a column
/// is one edit, not four.
pub(crate) const FINDING_COLUMNS: &str =
	"id, repo_id, job_id, scanner_id, severity, title, description,
        file_path, line_start, line_end, cwe, patch_unified,
        poc_unified, fingerprint, state, verification_required, created_at,
        approved_at, approved_by_cn, rejected_at, rejected_by_cn,
        patch_proposed_at, patch_proposed_by_cn, patch_notes, report_identity, source";

#[cfg(test)]
pub(crate) fn list_for_job_raw(
	conn: &Connection, job_id: i64,
) -> rusqlite::Result<Vec<FindingRow>> {
	let mut stmt = conn.prepare(&format!(
		"SELECT {FINDING_COLUMNS}
		 FROM findings WHERE job_id = ?1 ORDER BY id ASC"
	))?;
	let rows = stmt.query_map(params![job_id], row_to_finding)?;
	rows.collect()
}

pub(crate) fn transition_scan_findings_after_success(
	conn: &Connection, repo_id: i64, job_id: i64, require_approval: bool, validating_deadline: i64,
	now: i64,
) -> rusqlite::Result<usize> {
	let source_state = FindingState::Pending;
	let auto_transition = if require_approval {
		FindingTransition::ScanAwaitApproval
	} else {
		FindingTransition::ScanAutoConfirm
	};
	let auto_target = source_state.apply(auto_transition).map_err(sql_state_transition_error)?;
	let verify_target = source_state
		.apply(FindingTransition::ScanRequireVerification)
		.map_err(sql_state_transition_error)?;

	let auto_count = if require_approval {
		conn.execute(
			"UPDATE findings
			   SET state = ?1
			 WHERE job_id = ?2 AND verification_required = 0 AND state = ?3 AND repo_id=?4",
			(auto_target.as_str(), job_id, source_state.as_str(), repo_id),
		)?
	} else {
		conn.execute(
			"UPDATE findings
			   SET state = ?1, confirmed_at = ?2
			 WHERE job_id = ?3 AND verification_required = 0 AND state = ?4 AND repo_id=?5",
			(auto_target.as_str(), now, job_id, source_state.as_str(), repo_id),
		)?
	};
	let verify_count = conn.execute(
		"UPDATE findings
		   SET state = ?1, validating_deadline = ?2
		 WHERE job_id = ?3 AND verification_required = 1 AND state = ?4 AND repo_id=?5",
		(verify_target.as_str(), validating_deadline, job_id, source_state.as_str(), repo_id),
	)?;
	Ok(auto_count + verify_count)
}

pub(crate) fn delete_pending_for_job(
	conn: &Connection, repo_id: i64, job_id: i64,
) -> rusqlite::Result<usize> {
	conn.execute(
		"DELETE FROM findings WHERE job_id = ?1 AND state = ?2 AND repo_id=?3",
		(job_id, FindingState::Pending.as_str(), repo_id),
	)
}

/// Reap findings whose `validating_deadline` has elapsed without
/// enough verdicts to flip state. Each reaped finding gets a
/// system-issued `inconclusive` verdict in `finding_verifications`
/// (with `job_id = NULL`) and transitions to `dismissed`. Returns the
/// number of findings reaped.
pub(crate) fn reap_stale_validating(conn: &mut Connection, now: i64) -> rusqlite::Result<usize> {
	let source_state = FindingState::Validating;
	let target_state = source_state
		.apply(FindingTransition::DeadlineExpire)
		.map_err(sql_state_transition_error)?;
	let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
	let stale: Vec<(i64, i64)> = {
		let mut stmt = tx.prepare(
			"SELECT id,repo_id FROM findings
			 WHERE state = ?2
			   AND validating_deadline IS NOT NULL
			   AND validating_deadline < ?1",
		)?;
		let rows = stmt.query_map((now, source_state.as_str()), |r| Ok((r.get(0)?, r.get(1)?)))?;
		rows.collect::<rusqlite::Result<_>>()?
	};
	for (fid, repo) in &stale {
		insert_verification(&tx, *repo, *fid, VerificationInput::DeadlineExpired, now)?;
		tx.execute(
			"UPDATE findings SET state = ?1, dismissed_at = ?2
			 WHERE id = ?3 AND state = ?4 AND repo_id=?5",
			(target_state.as_str(), now, fid, source_state.as_str(), repo),
		)?;
	}
	tx.commit()?;
	Ok(stale.len())
}

pub(crate) fn roll_up_verdicts_for_finding(
	conn: &Connection, repo_id: i64, finding_id: i64, terminal_inconclusive: bool,
	require_approval: bool, now: i64,
) -> rusqlite::Result<Option<FindingState>> {
	let current =
		get_selected(conn, repo_id, finding_id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?.state;
	let has_dismissed: bool = conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM finding_verifications
		                 WHERE finding_id = ?1 AND verdict = 'dismissed' AND EXISTS(SELECT 1 FROM findings WHERE id=?1 AND repo_id=?2))",
		[finding_id,repo_id],
		|r| r.get(0),
	)?;
	let has_confirmed: bool = conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM finding_verifications
		                 WHERE finding_id = ?1 AND verdict = 'confirmed' AND EXISTS(SELECT 1 FROM findings WHERE id=?1 AND repo_id=?2))",
		[finding_id,repo_id],
		|r| r.get(0),
	)?;
	let next = roll_up_verdicts(
		current,
		VerdictRollup { has_confirmed, has_dismissed, terminal_inconclusive, require_approval },
	)
	.map_err(sql_state_transition_error)?;
	let Some(next_state) = next else { return Ok(None) };
	let stamp_clause = match next_state {
		FindingState::Confirmed => ", confirmed_at = ?2",
		FindingState::Dismissed => ", dismissed_at = ?2",
		_ => "",
	};
	conn.execute(
		&format!("UPDATE findings SET state = ?1{stamp_clause} WHERE id = ?3 AND repo_id=?4"),
		(next_state.as_str(), now, finding_id, repo_id),
	)?;
	Ok(Some(next_state))
}

pub(crate) fn is_deadline_dismissed_without_terminal_verdict(
	conn: &Connection, finding_id: i64,
) -> rusqlite::Result<bool> {
	conn.query_row(
		"SELECT
		    EXISTS(
		      SELECT 1 FROM finding_verifications
		       WHERE finding_id = ?1
		         AND job_id IS NULL
		         AND verdict = 'inconclusive'
		         AND notes = ?2
		    )
		    AND NOT EXISTS(
		      SELECT 1 FROM finding_verifications
		       WHERE finding_id = ?1
		         AND verdict IN ('confirmed', 'dismissed')
		    )",
		(finding_id, VALIDATING_DEADLINE_EXPIRED_NOTE),
		|r| r.get(0),
	)
}

pub(crate) fn retry_verification(
	conn: &Connection, repo_id: i64, finding_id: i64, validating_deadline: i64,
) -> rusqlite::Result<bool> {
	let Some(row) = get_selected(conn, repo_id, finding_id)? else { return Ok(false) };
	let target_state = row
		.state
		.apply(FindingTransition::RetryVerification)
		.map_err(sql_state_transition_error)?;
	let updated = conn.execute(
		"UPDATE findings
		   SET state = ?1,
		       dismissed_at = NULL,
		       validating_deadline = ?2
		 WHERE id = ?3 AND state = ?4 AND repo_id=?5",
		(target_state.as_str(), validating_deadline, finding_id, row.state.as_str(), repo_id),
	)?;
	Ok(updated > 0)
}

/// List findings for one repo, most recent first. `limit` caps the
/// page size (callers should pass something reasonable, e.g. 100).
pub(crate) fn list_for_repo_raw(
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
pub(crate) fn search_raw<S: Source>(
	conn: &Connection, repo_id: i64, query: &SearchQuery<S>, limit: i64,
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
	let rows = stmt.query_map(params![query.expose(), repo_id, limit], row_to_finding)?;
	rows.collect()
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
pub(crate) fn get_raw(conn: &Connection, id: i64) -> rusqlite::Result<Option<FindingRow>> {
	conn.query_row(
		&format!("SELECT {FINDING_COLUMNS} FROM findings WHERE id = ?1"),
		params![id],
		row_to_finding,
	)
	.optional()
}

pub(crate) fn get_selected(
	conn: &Connection, repo: i64, id: i64,
) -> rusqlite::Result<Option<FindingRow>> {
	conn.query_row(
		&format!("SELECT {FINDING_COLUMNS} FROM findings WHERE id=?1 AND repo_id=?2"),
		params![id, repo],
		row_to_finding,
	)
	.optional()
}

/// Outcome of an `attach_proposed_patch` call.
// debug-ok: attachment outcomes are closed variants without patch content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchAttachOutcome {
	/// The row had no patch yet; we wrote one and stamped the audit.
	Attached,
	/// A patch was already on the row (a prior verifier got there
	/// first, or a human attached one out-of-band). The new patch is
	/// dropped — first-writer-wins keeps a single canonical proposal
	/// per finding without forcing the route to special-case the race.
	AlreadyPresent,
}

/// Stamp `patch_unified` (plus the rationale and audit columns) on a
/// finding, only if it doesn't already have a patch attached. The
/// atomic guard (`WHERE id = ?1 AND patch_unified IS NULL`) makes
/// concurrent verifier verdicts race-safe: whichever verdict commits
/// first wins the slot; later writes silently no-op
/// (`AlreadyPresent`).
///
/// `notes` is the verifier's 1–2 sentence rationale ("what the fix
/// does and why this is the minimal correct change"); surfaced to
/// human reviewers via `loupectl finding show` and embedded into
/// auto-filed GitHub issues alongside the diff.
///
/// Caller is responsible for having already validated that the
/// verdict was `confirmed` — this function does not check verdict
/// state. Pairing it with the verdict-insert in the same tx (see
/// `routes/jobs.rs::submit_verdict`) is what enforces the invariant
/// that a patch can only ride on a confirmed verdict.
pub(crate) fn attach_proposed_patch(
	conn: &Connection, repo_id: i64, finding_id: i64,
	patch_unified: &BoundedText<PatchUnified, Agent>, notes: &BoundedText<PatchNotes, Agent>,
	by_cn: &BoundedText<WorkerName, DbSource>, now: i64,
) -> rusqlite::Result<PatchAttachOutcome> {
	let n = conn.execute(
		"UPDATE findings
		    SET patch_unified = ?1, patch_notes = ?2,
		        patch_proposed_by_cn = ?3, patch_proposed_at = ?4
		  WHERE id = ?5 AND patch_unified IS NULL AND repo_id=?6",
		params![patch_unified.expose(), notes.expose(), by_cn.expose(), now, finding_id, repo_id],
	)?;
	Ok(if n > 0 { PatchAttachOutcome::Attached } else { PatchAttachOutcome::AlreadyPresent })
}

/// Outcome of an `approve`/`reject` call.
// debug-ok: approval outcomes are closed variants without finding content.
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

/// Approve a finding. Stamps `approved_at`/`approved_by_cn` and
/// transitions `awaiting_approval → confirmed` so the dispatcher can
/// pick it up. Idempotent on already-approved rows: re-running on a
/// `confirmed` row returns `NotPending` rather than re-stamping.
pub(crate) fn approve(
	conn: &Connection, repo_id: i64, id: i64, by_cn: &BoundedText<WorkerName, DbSource>, now: i64,
) -> rusqlite::Result<ApprovalOutcome> {
	let target_state = FindingState::AwaitingApproval
		.apply(FindingTransition::Approve)
		.map_err(sql_state_transition_error)?;
	let n = conn.execute(
		"UPDATE findings
		    SET state = ?1, approved_at = ?2, approved_by_cn = ?3
		  WHERE id = ?4 AND state = ?5 AND repo_id=?6",
		params![
			target_state.as_str(),
			now,
			by_cn.expose(),
			id,
			FindingState::AwaitingApproval.as_str(),
			repo_id
		],
	)?;
	Ok(if n > 0 {
		ApprovalOutcome::Applied
	} else {
		match get_selected(conn, repo_id, id)? {
			Some(_) => ApprovalOutcome::NotPending,
			None => ApprovalOutcome::NotFound,
		}
	})
}

pub fn reject(
	scope: &crate::scope::RepoScope<'_>, id: i64, by_cn: &BoundedText<WorkerName, DbSource>,
	now: i64,
) -> crate::Result<ApprovalOutcome> {
	scope.require_operator()?;
	let target_state = FindingState::AwaitingApproval
		.apply(FindingTransition::Reject)
		.map_err(sql_state_transition_error)?;
	let changed = scope.conn.execute("UPDATE findings SET state=?1,dismissed_at=?2,rejected_at=?2,rejected_by_cn=?3 WHERE id=?4 AND state=?5 AND repo_id=?6",
		params![target_state.as_str(),now,by_cn.expose(),id,FindingState::AwaitingApproval.as_str(),scope.repo_id])?;
	Ok(if changed != 0 {
		ApprovalOutcome::Applied
	} else if get(scope, id)?.is_some() {
		ApprovalOutcome::NotPending
	} else {
		ApprovalOutcome::NotFound
	})
}

fn sql_state_transition_error(error: StateTransitionError) -> rusqlite::Error {
	rusqlite::Error::InvalidParameterName(error.to_string())
}

pub(crate) fn row_to_finding(row: &rusqlite::Row) -> rusqlite::Result<FindingRow> {
	crate::ingress::require_agent_source(row, 25)?;
	let identity = match row.get_ref(24)? {
		rusqlite::types::ValueRef::Blob(bytes) => {
			<[u8; crate::report_identity::BYTES]>::try_from(bytes)
				.map_err(|_| crate::review::invalid_scalar(24))?
		},
		_ => return Err(crate::review::invalid_scalar(24)),
	};
	let severity = crate::review::parsed(row, 4)?;
	Ok(FindingRow {
		report_identity: FindingIdentity(identity),
		id: row.get(0)?,
		repo_id: row.get(1)?,
		job_id: row.get(2)?,
		scanner_id: crate::ingress::scanner(row, 3)?,
		severity,
		title: crate::ingress::finding_title(row, 5)?,
		description: crate::ingress::description(row, 6)?,
		file_path: crate::ingress::optional_finding_path(row, 7)?,
		line_start: row.get::<_, Option<i64>>(8)?.map(|v| v as u32),
		line_end: row.get::<_, Option<i64>>(9)?.map(|v| v as u32),
		cwe: crate::ingress::optional_cwe(row, 10)?,
		patch_unified: crate::ingress::optional_patch(row, 11)?,
		poc_unified: crate::ingress::optional_poc(row, 12)?,
		fingerprint: crate::ingress::fingerprint(row, 13)?,
		state: crate::review::parsed(row, 14)?,
		verification_required: row.get::<_, i64>(15)? != 0,
		created_at: row.get(16)?,
		approved_at: row.get(17)?,
		approved_by_cn: crate::ingress::optional_audit(row, 18)?,
		rejected_at: row.get(19)?,
		rejected_by_cn: crate::ingress::optional_audit(row, 20)?,
		patch_proposed_at: row.get(21)?,
		patch_proposed_by_cn: crate::ingress::optional_audit(row, 22)?,
		patch_notes: crate::ingress::optional_patch_notes(row, 23)?,
	})
}

pub(crate) fn validate_stored_rows(conn: &Connection) -> crate::Result<()> {
	crate::migrations::admission::scan(conn, "findings", FINDING_COLUMNS, row_to_finding)?;
	crate::migrations::admission::scan(
		conn,
		"findings",
		"validating_deadline,confirmed_at,dismissed_at,reported_at",
		|_| Ok::<_, rusqlite::Error>(()),
	)
}

pub(crate) fn validate_stored_verifications(conn: &Connection) -> crate::Result<()> {
	crate::migrations::admission::scan(
		conn,
		"finding_verifications",
		"id,finding_id,job_id,verdict,notes,created_at,source",
		|r| {
			crate::ingress::require_agent_source(r, 6)?;
			let verdict: String = r.get(3)?;
			match verdict.as_str() {
				"confirmed" | "dismissed" => {
					if !matches!(r.get_ref(4)?, rusqlite::types::ValueRef::Null) {
						crate::ingress::verdict_notes(r, 4)?;
					}
				},
				"inconclusive" => {
					if !matches!(r.get_ref(4)?, rusqlite::types::ValueRef::Null) {
						crate::ingress::verdict_reason(r, 4)?;
					}
				},
				_ => return Err(crate::review::invalid_scalar(3)),
			}
			Ok(())
		},
	)
}

pub(crate) fn validate_stored_history(conn: &Connection) -> crate::Result<()> {
	crate::migrations::admission::scan(
		conn,
		"scan_history",
		"id,repo_id,job_id,head_sha,base_sha,finding_count,duration_ms,finished_at",
		|r| {
			crate::ingress::revision(r, 3)?;
			crate::ingress::optional_revision(r, 4)?;
			Ok::<_, rusqlite::Error>(())
		},
	)
}

#[cfg(test)]
pub(crate) mod tests {
	use loupe_core::{ReportingDestination, Severity};

	use super::*;
	use crate::jobs::{self, NewJob};
	use crate::repos::{self, NewRepo};
	use crate::secrets::{self, SecretKind};
	use crate::Db;

	pub(crate) fn fixture() -> (Db, i64, i64) {
		let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
		let secret_id =
			db.with_conn(|c| Ok(secrets::insert(c, SecretKind::GithubPat, "p", b"x", 0)?)).unwrap();
		let repo_id = db
			.with_conn(|c| {
				Ok(repos::insert(
					c,
					&NewRepo {
						clone_url: crate::test_support::db_text("https://github.com/a/b.git")
							.unwrap(),
						host: crate::test_support::db_text("github.com").unwrap(),
						owner: crate::test_support::db_text("a").unwrap(),
						repo: crate::test_support::db_text("b").unwrap(),
						default_branch: None,
						scan_interval_seconds: None,
						scanner_config: crate::test_support::scanner(serde_json::Value::Null),
						reporting: ReportingDestination::GithubIssue {
							target_owner: crate::test_support::db_text("a").unwrap(),
							target_repo: crate::test_support::db_text("t").unwrap(),
							pat_secret_id: Some(secret_id),
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
				jobs::enqueue_raw(
					c,
					&NewJob {
						repo_id,
						kind: loupe_core::JobKind::<loupe_provenance::Db>::Scan,
						incremental: false,
						since_sha: None,
						parent_job_id: None,
						target_finding_id: None,
					},
					0,
				)
			})
			.unwrap();
		(db, repo_id, job_id)
	}

	pub(crate) fn sample(fingerprint: &str) -> Finding<loupe_provenance::Agent> {
		Finding {
			scanner_id: crate::test_support::text("regex").unwrap(),
			severity: Severity::High,
			title: crate::test_support::text("AWS access key").unwrap(),
			description: crate::test_support::text("Found AKIA...").unwrap(),
			file_path: Some(crate::test_support::path("src/x.rs").unwrap()),
			line_start: Some(1),
			line_end: Some(1),
			cwe: Some(crate::test_support::text("CWE-798").unwrap()),
			patch_unified: None,
			poc_unified: None,
			fingerprint: crate::test_support::text(fingerprint).unwrap(),
		}
	}

	#[test]
	fn verdict_summary_is_scoped_and_independent_of_insertion_order() {
		// EXISTS-based aggregation depends on presence, not verdict order/count.
		// Insert each complete multiset before one rollup; terminal states are
		// deliberately not revisited as individual verdicts arrive.
		let (db, repo_id, job_id) = fixture();
		let permutations = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
		let cases = [
			(
				["confirmed", "dismissed", "inconclusive"],
				false,
				false,
				Some(FindingState::Dismissed),
			),
			(
				["confirmed", "inconclusive", "confirmed"],
				false,
				false,
				Some(FindingState::Confirmed),
			),
			(
				["confirmed", "inconclusive", "confirmed"],
				false,
				true,
				Some(FindingState::AwaitingApproval),
			),
			(
				["confirmed", "inconclusive", "confirmed"],
				true,
				false,
				Some(FindingState::Dismissed),
			),
			(["inconclusive", "inconclusive", "inconclusive"], false, false, None),
			(
				["inconclusive", "inconclusive", "inconclusive"],
				true,
				true,
				Some(FindingState::Dismissed),
			),
		];
		db.with_conn(|conn| {
			// Both positive verdict kinds on another finding must be ignored.
			let foreign = insert_or_ignore(conn, repo_id, job_id, &sample("foreign-rollup"), true, 0)?.unwrap();
			for verdict in ["confirmed", "dismissed"] {
				conn.execute("INSERT INTO finding_verifications (finding_id, verdict, created_at) VALUES (?1, ?2, 0)", (foreign, verdict))?;
			}
			for (case, (verdicts, terminal, approval, expected)) in cases.into_iter().enumerate() {
				for (permutation, order) in permutations.into_iter().enumerate() {
					let finding = sample(&format!("rollup-{case}-{permutation}"));
					let id = insert_or_ignore(conn, repo_id, job_id, &finding, true, 0)?.unwrap();
					conn.execute("UPDATE findings SET state = 'validating' WHERE id = ?1", [id])?;
					for index in order {
						conn.execute("INSERT INTO finding_verifications (finding_id, verdict, created_at) VALUES (?1, ?2, 0)", (id, verdicts[index]))?;
					}
					assert_eq!(roll_up_verdicts_for_finding(conn, repo_id, id, terminal, approval, 42)?, expected,
						"SQL verdict summary changed with permutation {order:?} in case {case}");
					let (state, confirmed_at, dismissed_at): (String, Option<i64>, Option<i64>) = conn.query_row(
						"SELECT state, confirmed_at, dismissed_at FROM findings WHERE id = ?1", [id],
						|row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
					assert_eq!(state, expected.unwrap_or(FindingState::Validating).as_str());
					assert_eq!(confirmed_at, (expected == Some(FindingState::Confirmed)).then_some(42));
					assert_eq!(dismissed_at, (expected == Some(FindingState::Dismissed)).then_some(42));
				}
			}
			Ok(())
		}).unwrap();
	}

	#[test]
	fn insert_then_list_round_trip() {
		let (db, repo_id, job_id) = fixture();
		let f = sample("fp1");
		let id = db
			.with_conn(|c| Ok(insert_or_ignore(c, repo_id, job_id, &f, false, 100)?))
			.unwrap()
			.unwrap();
		let listed = db.with_conn(|c| Ok(list_for_job_raw(c, job_id)?)).unwrap();
		assert_eq!(listed.len(), 1);
		assert_eq!(listed[0].id, id);
		assert_eq!(listed[0].severity, Severity::High);
		assert_eq!(listed[0].fingerprint.expose(), "fp1");
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
		a.title = crate::test_support::text("Integer underflow in claim_for_id").unwrap();
		a.description =
			crate::test_support::text("checked_sub returns None; payment is blocked").unwrap();
		a.file_path = Some(crate::test_support::path("src/payment/bolt11.rs").unwrap());
		let mut b = sample("fp-b");
		b.title = crate::test_support::text("Unbounded allocation in handle_open_channel").unwrap();
		b.description =
			crate::test_support::text("peer-controlled count drives a Vec::with_capacity").unwrap();
		b.file_path = Some(crate::test_support::path("src/peer/handler.rs").unwrap());
		let mut c = sample("fp-c");
		c.title = crate::test_support::text("Race in closing_signed").unwrap();
		c.description =
			crate::test_support::text("two threads can apply opposite fee updates").unwrap();
		c.file_path = Some(crate::test_support::path("src/channel/closing.rs").unwrap());
		for f in &[&a, &b, &c] {
			db.with_conn(|conn| Ok(insert_or_ignore(conn, repo_id, job_id, f, false, 0)?)).unwrap();
		}

		// Single-keyword match.
		let q = SearchQuery::keywords(crate::test_support::text("underflow").unwrap());
		let hits = db.with_conn(|c| Ok(search_raw(c, repo_id, &q, 10)?)).unwrap();
		assert_eq!(hits.len(), 1);
		assert!(hits[0].title.expose().contains("Integer underflow"));

		// Multi-keyword AND: must hit a row that contains both.
		let q = SearchQuery::keywords(crate::test_support::text("vec capacity").unwrap());
		let hits = db.with_conn(|c| Ok(search_raw(c, repo_id, &q, 10)?)).unwrap();
		assert_eq!(hits.len(), 1);
		assert!(hits[0].title.expose().contains("Unbounded allocation"));

		// Path-component match (file_path is one of the indexed
		// columns).
		let q = SearchQuery::keywords(crate::test_support::text("closing.rs").unwrap());
		let hits = db.with_conn(|c| Ok(search_raw(c, repo_id, &q, 10)?)).unwrap();
		assert_eq!(hits.len(), 1);
		assert!(hits[0].title.expose().contains("Race"));

		// No matches → empty Vec, not an error.
		let q = SearchQuery::keywords(crate::test_support::text("no-such-token-anywhere").unwrap());
		let hits = db.with_conn(|c| Ok(search_raw(c, repo_id, &q, 10)?)).unwrap();
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
						clone_url: crate::test_support::db_text("https://github.com/c/d.git")
							.unwrap(),
						host: crate::test_support::db_text("github.com").unwrap(),
						owner: crate::test_support::db_text("c").unwrap(),
						repo: crate::test_support::db_text("d").unwrap(),
						default_branch: None,
						scan_interval_seconds: None,
						scanner_config: crate::test_support::scanner(serde_json::Value::Null),
						reporting: ReportingDestination::GithubIssue {
							target_owner: crate::test_support::db_text("c").unwrap(),
							target_repo: crate::test_support::db_text("t").unwrap(),
							pat_secret_id: Some(secret_id),
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
				jobs::enqueue_raw(
					c,
					&jobs::NewJob {
						repo_id: repo_id_b,
						kind: loupe_core::JobKind::<loupe_provenance::Db>::Scan,
						incremental: false,
						since_sha: None,
						parent_job_id: None,
						target_finding_id: None,
					},
					0,
				)
			})
			.unwrap();

		let mut f_a = sample("fa");
		f_a.title = crate::test_support::text("shared keyword overflow").unwrap();
		let mut f_b = sample("fb");
		f_b.title = crate::test_support::text("shared keyword overflow").unwrap();

		db.with_conn(|c| Ok(insert_or_ignore(c, repo_id_a, job_id_a, &f_a, false, 0)?)).unwrap();
		db.with_conn(|c| Ok(insert_or_ignore(c, repo_id_b, job_id_b, &f_b, false, 0)?)).unwrap();

		let q = SearchQuery::keywords(crate::test_support::text("overflow").unwrap());
		let hits_a = db.with_conn(|c| Ok(search_raw(c, repo_id_a, &q, 10)?)).unwrap();
		assert_eq!(hits_a.len(), 1, "search must filter by repo_id; got {hits_a:?}");
		assert_eq!(hits_a[0].repo_id, repo_id_a);
		let hits_b = db.with_conn(|c| Ok(search_raw(c, repo_id_b, &q, 10)?)).unwrap();
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
		f.title = crate::test_support::text("very specific deletable phrase").unwrap();
		let id = db
			.with_conn(|c| Ok(insert_or_ignore(c, repo_id, job_id, &f, false, 0)?))
			.unwrap()
			.unwrap();
		// Search hits.
		let q = SearchQuery::keywords(crate::test_support::text("deletable phrase").unwrap());
		assert_eq!(db.with_conn(|c| Ok(search_raw(c, repo_id, &q, 10)?)).unwrap().len(), 1);
		// Delete the finding.
		db.with_conn(|c| {
			c.execute("DELETE FROM findings WHERE id = ?1", [id])?;
			Ok(())
		})
		.unwrap();
		// Search now empty — the trigger reaped the FTS row.
		assert!(db.with_conn(|c| Ok(search_raw(c, repo_id, &q, 10)?)).unwrap().is_empty());
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
	fn attach_proposed_patch_writes_when_slot_is_empty() {
		let (db, repo_id, job_id) = fixture();
		let f = sample("fp-attach");
		let id = db
			.with_conn(|c| Ok(insert_or_ignore(c, repo_id, job_id, &f, false, 100)?))
			.unwrap()
			.unwrap();

		let outcome = db
			.with_conn(|c| {
				Ok(attach_proposed_patch(
					c,
					repo_id,
					id,
					&crate::test_support::text("--- a/x\n+++ b/x\n@@\n-old\n+new\n").unwrap(),
					&crate::test_support::text("swap operator").unwrap(),
					&crate::test_support::db_text("alice").unwrap(),
					200,
				)?)
			})
			.unwrap();
		assert_eq!(outcome, PatchAttachOutcome::Attached);

		let row = db.with_conn(|c| Ok(get_raw(c, id)?)).unwrap().unwrap();
		assert_eq!(
			row.patch_unified.as_ref().map(loupe_core::text::BoundedText::expose),
			Some("--- a/x\n+++ b/x\n@@\n-old\n+new\n")
		);
		assert_eq!(
			row.patch_notes.as_ref().map(loupe_core::text::BoundedText::expose),
			Some("swap operator")
		);
		assert_eq!(
			row.patch_proposed_by_cn.as_ref().map(loupe_core::text::BoundedText::expose),
			Some("alice")
		);
		assert_eq!(row.patch_proposed_at, Some(200));
	}

	#[test]
	fn attach_proposed_patch_is_first_writer_wins() {
		// Race semantics: a second verifier confirming the same finding
		// after the first one already attached a patch must NOT
		// overwrite the existing diff. The audit columns also stay
		// pinned to the first writer so a later reader can't be misled
		// about provenance.
		let (db, repo_id, job_id) = fixture();
		let f = sample("fp-race");
		let id = db
			.with_conn(|c| Ok(insert_or_ignore(c, repo_id, job_id, &f, false, 100)?))
			.unwrap()
			.unwrap();

		let first = db
			.with_conn(|c| {
				Ok(attach_proposed_patch(
					c,
					repo_id,
					id,
					&crate::test_support::text("first patch").unwrap(),
					&crate::test_support::text("first reason").unwrap(),
					&crate::test_support::db_text("alice").unwrap(),
					200,
				)?)
			})
			.unwrap();
		assert_eq!(first, PatchAttachOutcome::Attached);
		let second = db
			.with_conn(|c| {
				Ok(attach_proposed_patch(
					c,
					repo_id,
					id,
					&crate::test_support::text("second patch").unwrap(),
					&crate::test_support::text("second reason").unwrap(),
					&crate::test_support::db_text("bob").unwrap(),
					300,
				)?)
			})
			.unwrap();
		assert_eq!(second, PatchAttachOutcome::AlreadyPresent);

		let row = db.with_conn(|c| Ok(get_raw(c, id)?)).unwrap().unwrap();
		assert_eq!(
			row.patch_unified.as_ref().map(loupe_core::text::BoundedText::expose),
			Some("first patch")
		);
		assert_eq!(
			row.patch_notes.as_ref().map(loupe_core::text::BoundedText::expose),
			Some("first reason")
		);
		assert_eq!(
			row.patch_proposed_by_cn.as_ref().map(loupe_core::text::BoundedText::expose),
			Some("alice")
		);
		assert_eq!(row.patch_proposed_at, Some(200));
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
		assert_eq!(db.with_conn(|c| Ok(list_for_job_raw(c, job_id)?)).unwrap().len(), 1);
	}
}

#[cfg(test)]
#[path = "findings_identity_tests.rs"]
mod atomic_m_identity_tests;
