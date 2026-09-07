//! Findings inspection + approval routes:
//!
//! - `GET  /v1/repos/:id/findings`           → recent findings for a repo
//! - `GET  /v1/repos/:id/findings/search?q=` → FTS5 keyword search
//! - `GET  /v1/findings/:id`                 → full detail for one finding
//! - `POST /v1/findings/:id/approve`         → release a held finding
//! - `POST /v1/findings/:id/retry-report`    → retry a confirmed finding
//! - `POST /v1/findings/:id/reject`          → terminally dismiss a held finding
//!
//! The list / approve / reject routes are admin-only — they sit
//! behind `require_admin`. `search` and `get` are callable by admins,
//! and by workers only while the worker holds an active lease for the
//! finding's repo. The worker-side MCP server (running as a child of
//! `loupe-worker`) uses those routes for `query_prior_findings` and
//! `get_finding_by_id`, so the lease check prevents a compromised
//! agent from exploring finding history outside its current repo.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use loupe_core::{FindingState, JobKind, ReportingDestination};
use loupe_proto::{
	FindingDetail, FindingSummary, ListFindingsResponse, RetryVerifyRequest, RetryVerifyResponse,
	PROTOCOL_VERSION,
};
use loupe_storage::findings::{self, ApprovalOutcome, FindingRow};
use loupe_storage::jobs::NewJob;
use loupe_storage::{jobs, repos};
use serde::Deserialize;

use crate::auth::AuthedWorker;
use crate::job_capability;
use crate::state::AppState;

/// How many findings the listing endpoint returns by default.
const LIST_DEFAULT_LIMIT: i64 = 100;

/// Default cap on `search` results. The agent typically only needs
/// the top handful of "is this a duplicate of any prior finding?"
/// candidates, not a full repo dump.
const SEARCH_DEFAULT_LIMIT: i64 = 20;
/// Hard ceiling on `search` to keep a single tool call from
/// downloading every finding on a repo.
const SEARCH_MAX_LIMIT: i64 = 100;

#[derive(Debug)]
struct VerifyRetryCandidate {
	finding_id: i64,
	repo_id: i64,
	parent_job_id: i64,
}

fn now_secs() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

fn authorize_prior_finding_repo(
	state: &AppState, authed: &AuthedWorker, headers: &HeaderMap, repo_id: i64,
) -> Result<(), (StatusCode, String)> {
	if authed.is_admin() {
		return Ok(());
	}
	let now = now_secs();
	let authorized = job_capability::authorize(state, authed, headers, now)?;
	if authorized.row.repo_id == repo_id {
		Ok(())
	} else {
		Err(job_capability::forbidden())
	}
}

pub async fn list_for_repo(
	State(state): State<AppState>, Path(repo_id): Path<i64>, Query(qp): Query<ListQuery>,
) -> Result<Json<ListFindingsResponse>, (StatusCode, String)> {
	let limit = positive_limit(qp.limit)?.unwrap_or(LIST_DEFAULT_LIMIT);
	let rows = state
		.db
		.with_conn(|c| Ok(findings::list_for_repo(c, repo_id, limit)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("listing findings: {e}")))?;
	Ok(Json(ListFindingsResponse {
		protocol_version: PROTOCOL_VERSION,
		findings: rows.into_iter().map(row_to_summary).collect(),
	}))
}

/// Query string for `GET /v1/repos/:id/findings`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
	#[serde(default)]
	pub limit: Option<i64>,
}

fn positive_limit(limit: Option<i64>) -> Result<Option<i64>, (StatusCode, String)> {
	if matches!(limit, Some(n) if n <= 0) {
		return Err((StatusCode::BAD_REQUEST, "limit must be positive".into()));
	}
	Ok(limit)
}

/// Query string for `GET /v1/repos/:id/findings/search`.
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
	pub q: String,
	#[serde(default)]
	pub limit: Option<i64>,
}

/// `GET /v1/repos/:id/findings/search?q=<keywords>&limit=<n>`. FTS5
/// keyword search over title, description, file_path. Open to admins
/// and to workers with an active lease for `:id`; the MCP server's
/// `query_prior_findings` tool calls this from inside the worker.
/// Free-form `q` is run through `findings::sanitize_fts_query`
/// server-side, so the caller doesn't need to know FTS5 syntax.
pub async fn search(
	State(state): State<AppState>, Extension(authed): Extension<AuthedWorker>,
	Path(repo_id): Path<i64>, Query(qp): Query<SearchQuery>, headers: HeaderMap,
) -> Result<Json<ListFindingsResponse>, (StatusCode, String)> {
	authorize_prior_finding_repo(&state, &authed, &headers, repo_id)?;
	let limit = qp.limit.unwrap_or(SEARCH_DEFAULT_LIMIT).clamp(1, SEARCH_MAX_LIMIT);
	let sanitized = findings::sanitize_fts_query(&qp.q);
	if sanitized.is_empty() {
		// No usable terms — return empty rather than running an
		// invalid FTS5 query that errors out.
		return Ok(Json(ListFindingsResponse {
			protocol_version: PROTOCOL_VERSION,
			findings: vec![],
		}));
	}
	let rows = state
		.db
		.with_conn(|c| Ok(findings::search(c, repo_id, &sanitized, limit)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("searching findings: {e}")))?;
	Ok(Json(ListFindingsResponse {
		protocol_version: PROTOCOL_VERSION,
		findings: rows.into_iter().map(row_to_summary).collect(),
	}))
}

pub async fn get(
	State(state): State<AppState>, Extension(authed): Extension<AuthedWorker>, Path(id): Path<i64>,
	headers: HeaderMap,
) -> Result<Json<FindingDetail>, (StatusCode, String)> {
	let authorized_repo = if authed.is_admin() {
		None
	} else {
		Some(job_capability::authorize(&state, &authed, &headers, now_secs())?.row.repo_id)
	};
	let row = state
		.db
		.with_conn(|c| Ok(findings::get(c, id)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("get finding: {e}")))?
		.ok_or((StatusCode::NOT_FOUND, format!("no finding with id {id}")))?;
	if authorized_repo.is_some_and(|repo_id| repo_id != row.repo_id) {
		// Return the same 404 a nonexistent id yields so a leased
		// worker cannot use the status code to probe which finding ids
		// exist in a repository it does not hold a capability for.
		return Err((StatusCode::NOT_FOUND, format!("no finding with id {id}")));
	}
	Ok(Json(row_to_detail(row)))
}

/// `POST /v1/findings/retry-verify` — admin-only
/// recovery for findings that still need verifier work but are no
/// longer represented correctly in the queue.
///
/// Recovery has three explicit arms:
///
/// 1. deadline-dismissed findings: `dismissed` only because the
///    validating-deadline reaper inserted its system inconclusive row;
/// 2. legacy stranded pending findings: `pending` rows whose scan job
///    is already terminal;
/// 3. stranded validating findings: `validating` rows with no active
///    verify job.
///
/// All arms exclude terminal verifier verdicts, so findings actively
/// dismissed by a verifier are not revived. Verifier-produced
/// inconclusive rows are excluded unless `include_inconclusive` is set;
/// the reaper's system inconclusive marker (`job_id = NULL`) remains
/// recoverable without that flag.
pub async fn retry_verify(
	State(state): State<AppState>, Json(req): Json<RetryVerifyRequest>,
) -> Result<Json<RetryVerifyResponse>, (StatusCode, String)> {
	if req.protocol_version != PROTOCOL_VERSION {
		return Err((
			StatusCode::BAD_REQUEST,
			format!("unsupported protocol_version {}", req.protocol_version),
		));
	}
	if let Some(limit) = req.limit
		&& limit <= 0
	{
		return Err((StatusCode::BAD_REQUEST, "limit must be positive".into()));
	}
	let now = now_secs();
	let mut response = state
		.db
		.with_conn(|c| {
			let tx = c.transaction()?;
			let limit = req.limit.unwrap_or(-1);
			let candidates = {
				// Keep the three recovery modes in one query so the
				// repo/limit ordering is global rather than per-arm.
				// Active queued/leased verify jobs are counted later and
				// not mutated, which prevents duplicate verifier work.
				let mut stmt = tx.prepare(
					"SELECT f.id, f.repo_id, f.job_id
						   FROM findings f
						  WHERE f.verification_required = 1
						    AND (?1 IS NULL OR f.repo_id = ?1)
						    AND (
						      (
						        f.state = 'dismissed'
						        AND EXISTS (
						          SELECT 1 FROM finding_verifications v
						           WHERE v.finding_id = f.id
						             AND v.job_id IS NULL
						             AND v.verdict = 'inconclusive'
						             AND v.notes = ?4
						        )
						      )
						      OR (
						        f.state = 'pending'
						        AND EXISTS (
						          SELECT 1 FROM jobs j
						           WHERE j.id = f.job_id
						             AND j.kind = 'scan'
						             AND j.state IN ('succeeded', 'failed', 'cancelled')
						             AND j.finished_at IS NOT NULL
						        )
						      )
						      OR f.state = 'validating'
						    )
						    AND NOT EXISTS (
						      SELECT 1 FROM finding_verifications v
						       WHERE v.finding_id = f.id
						         AND v.verdict IN ('confirmed', 'dismissed')
						    )
						    AND (
						      ?3 = 1
						      OR NOT EXISTS (
						        SELECT 1 FROM finding_verifications v
						         WHERE v.finding_id = f.id
						           AND v.job_id IS NOT NULL
						           AND v.verdict = 'inconclusive'
						      )
						    )
						  ORDER BY COALESCE(f.validating_deadline, f.created_at), f.id
						  LIMIT ?2",
				)?;
				let mut rows = stmt.query((
					req.repo_id,
					limit,
					req.include_inconclusive as i64,
					findings::VALIDATING_DEADLINE_EXPIRED_NOTE,
				))?;
				let mut out = Vec::new();
				while let Some(r) = rows.next()? {
					out.push(VerifyRetryCandidate {
						finding_id: r.get(0)?,
						repo_id: r.get(1)?,
						parent_job_id: r.get(2)?,
					});
				}
				out
			};

			let mut out = RetryVerifyResponse {
				protocol_version: PROTOCOL_VERSION,
				dry_run: req.dry_run,
				matched: candidates.len() as u64,
				revived: 0,
				requeued_jobs: 0,
				created_jobs: 0,
				left_queued_or_leased: 0,
			};

			for candidate in candidates {
				let active_verify: bool = tx.query_row(
					"SELECT EXISTS(
					   SELECT 1 FROM jobs
					    WHERE kind = 'verify'
					      AND target_finding_id = ?1
					      AND state IN ('queued','leased')
					)",
					[candidate.finding_id],
					|r| r.get(0),
				)?;

				if active_verify {
					out.left_queued_or_leased += 1;
					continue;
				} else {
					out.revived += 1;
					let failed_job_id: Option<i64> = {
						let mut stmt = tx.prepare(
							"SELECT id FROM jobs
							  WHERE kind = 'verify'
							    AND target_finding_id = ?1
							    AND state = 'failed'
							  ORDER BY enqueued_at DESC, id DESC
							  LIMIT 1",
						)?;
						let mut rows = stmt.query([candidate.finding_id])?;
						match rows.next()? {
							Some(r) => Some(r.get(0)?),
							None => None,
						}
					};

					if let Some(job_id) = failed_job_id {
						out.requeued_jobs += 1;
						if !req.dry_run {
							jobs::requeue_failed(&tx, job_id, now)?;
						}
					} else {
						out.created_jobs += 1;
						if !req.dry_run {
							jobs::enqueue(
								&tx,
								&NewJob {
									repo_id: candidate.repo_id,
									kind: JobKind::Verify,
									incremental: false,
									since_sha: None,
									parent_job_id: Some(candidate.parent_job_id),
									target_finding_id: Some(candidate.finding_id),
								},
								now,
							)?;
						}
					}
				}

				if !req.dry_run {
					findings::retry_verification(
						&tx,
						candidate.finding_id,
						now + super::jobs::DEFAULT_VALIDATING_BUDGET_SECS,
					)?;
				}
			}

			if req.dry_run {
				tx.rollback()?;
			} else {
				tx.commit()?;
			}
			Ok(out)
		})
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("retry verify: {e}")))?;

	if !response.dry_run && response.requeued_jobs + response.created_jobs > 0 {
		state.job_arrived.notify_waiters();
	}
	response.protocol_version = PROTOCOL_VERSION;
	Ok(Json(response))
}

/// `POST /v1/findings/:id/approve` — admin only. Transitions a
/// finding sitting in `awaiting_approval` into `confirmed` and runs
/// the dispatcher, so the operator's click immediately fires the
/// reporter. Stamps `approved_at` + `approved_by_cn` (the admin
/// client cert's worker.name). 404 if the finding doesn't exist;
/// 409 if the finding exists but isn't in `awaiting_approval` (e.g.
/// already approved, already dispatched, or never gated).
pub async fn approve(
	State(state): State<AppState>, Extension(authed): Extension<AuthedWorker>, Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	let cn = authed.worker.name.clone();
	let outcome = state
		.db
		.with_conn(|c| Ok(findings::approve(c, id, &cn, now)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("approve finding: {e}")))?;
	match outcome {
		ApprovalOutcome::Applied => {
			if let Err(e) = super::jobs::dispatch_finding(&state, id, now).await {
				tracing::warn!(
					finding_id = id,
					error = %super::jobs::format_error_chain(&e),
					"dispatch on approve failed"
				);
			}
			Ok(StatusCode::NO_CONTENT)
		},
		ApprovalOutcome::NotPending => {
			Err((StatusCode::CONFLICT, format!("finding {id} is not awaiting approval")))
		},
		ApprovalOutcome::NotFound => {
			Err((StatusCode::NOT_FOUND, format!("no finding with id {id}")))
		},
	}
}

/// `POST /v1/findings/:id/retry-report` — admin only. Retries external
/// reporting for a finding that is already `confirmed`. Already
/// `reported` findings are idempotent no-ops.
pub async fn retry_report(
	State(state): State<AppState>, Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
	let now = now_secs();
	let row = state
		.db
		.with_conn(|c| Ok(findings::get(c, id)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("get finding: {e}")))?
		.ok_or((StatusCode::NOT_FOUND, format!("no finding with id {id}")))?;

	match row.state {
		FindingState::Reported => return Ok(StatusCode::NO_CONTENT),
		FindingState::Confirmed => {},
		_ => return Err((StatusCode::CONFLICT, format!("finding {id} is not confirmed"))),
	}

	let repo = state
		.db
		.with_conn(|c| Ok(repos::get(c, row.repo_id)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("get repo: {e}")))?
		.ok_or((StatusCode::INTERNAL_SERVER_ERROR, "finding repo is missing".to_owned()))?;
	if matches!(repo.reporting, ReportingDestination::Manual) {
		return Err((
			StatusCode::CONFLICT,
			format!("repo {} does not have reporting configured", repo.id),
		));
	}

	match super::jobs::dispatch_finding(&state, id, now).await {
		Ok(()) => Ok(StatusCode::NO_CONTENT),
		Err(e) => {
			let error = super::jobs::format_error_chain(&e);
			tracing::warn!(finding_id = id, error = %error, "retry report failed");
			Err((StatusCode::INTERNAL_SERVER_ERROR, format!("retry report: {error}")))
		},
	}
}

/// `POST /v1/findings/:id/reject` — admin only. Transitions a held
/// finding into terminal `dismissed` with `rejected_at` +
/// `rejected_by_cn` stamped. Distinct from a verifier-issued
/// `dismiss` (which leaves `rejected_*` NULL), so dashboards can
/// tell the two apart later.
pub async fn reject(
	State(state): State<AppState>, Extension(authed): Extension<AuthedWorker>, Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	let cn = authed.worker.name.clone();
	let outcome = state
		.db
		.with_conn(|c| Ok(findings::reject(c, id, &cn, now)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("reject finding: {e}")))?;
	match outcome {
		ApprovalOutcome::Applied => Ok(StatusCode::NO_CONTENT),
		ApprovalOutcome::NotPending => {
			Err((StatusCode::CONFLICT, format!("finding {id} is not awaiting approval")))
		},
		ApprovalOutcome::NotFound => {
			Err((StatusCode::NOT_FOUND, format!("no finding with id {id}")))
		},
	}
}

fn row_to_summary(r: FindingRow) -> FindingSummary {
	FindingSummary {
		id: r.id,
		repo_id: r.repo_id,
		job_id: r.job_id,
		scanner_id: r.scanner_id,
		severity: r.severity,
		title: r.title,
		file_path: r.file_path,
		line_start: r.line_start,
		fingerprint: r.fingerprint,
		state: r.state,
		verification_required: r.verification_required,
		created_at: r.created_at,
		approved_at: r.approved_at,
		approved_by_cn: r.approved_by_cn,
		rejected_at: r.rejected_at,
		rejected_by_cn: r.rejected_by_cn,
	}
}

fn row_to_detail(r: FindingRow) -> FindingDetail {
	FindingDetail {
		protocol_version: PROTOCOL_VERSION,
		id: r.id,
		repo_id: r.repo_id,
		job_id: r.job_id,
		scanner_id: r.scanner_id,
		severity: r.severity,
		title: r.title,
		description: r.description,
		file_path: r.file_path,
		line_start: r.line_start,
		line_end: r.line_end,
		cwe: r.cwe,
		patch_unified: r.patch_unified,
		poc_unified: r.poc_unified,
		fingerprint: r.fingerprint,
		state: r.state,
		verification_required: r.verification_required,
		created_at: r.created_at,
		approved_at: r.approved_at,
		approved_by_cn: r.approved_by_cn,
		rejected_at: r.rejected_at,
		rejected_by_cn: r.rejected_by_cn,
	}
}
