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
use axum::http::StatusCode;
use axum::Json;
use loupe_core::{FindingState, ReportingDestination};
use loupe_proto::{FindingDetail, FindingSummary, ListFindingsResponse, PROTOCOL_VERSION};
use loupe_storage::findings::{self, ApprovalOutcome, FindingRow};
use loupe_storage::{jobs, repos};
use serde::Deserialize;

use crate::auth::AuthedWorker;
use crate::state::AppState;

/// How many findings the listing endpoint returns by default. Operators
/// who need to page further should narrow by repo and follow up via
/// `loupectl finding get <id>` for individual rows.
const LIST_LIMIT: i64 = 100;

/// Default cap on `search` results. The agent typically only needs
/// the top handful of "is this a duplicate of any prior finding?"
/// candidates, not a full repo dump.
const SEARCH_DEFAULT_LIMIT: i64 = 20;
/// Hard ceiling on `search` to keep a single tool call from
/// downloading every finding on a repo.
const SEARCH_MAX_LIMIT: i64 = 100;

fn now_secs() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

fn authorize_prior_finding_repo(
	state: &AppState, authed: &AuthedWorker, repo_id: i64,
) -> Result<(), (StatusCode, String)> {
	if authed.is_admin() {
		return Ok(());
	}
	let now = now_secs();
	let allowed = state
		.db
		.with_conn(|c| Ok(jobs::worker_has_active_lease_for_repo(c, authed.id(), repo_id, now)?))
		.map_err(|e| {
			(StatusCode::INTERNAL_SERVER_ERROR, format!("checking worker repo lease: {e}"))
		})?;
	if allowed {
		Ok(())
	} else {
		Err((
			StatusCode::FORBIDDEN,
			format!("worker does not hold an active lease for repo {repo_id}"),
		))
	}
}

pub async fn list_for_repo(
	State(state): State<AppState>, Path(repo_id): Path<i64>,
) -> Result<Json<ListFindingsResponse>, (StatusCode, String)> {
	let rows = state
		.db
		.with_conn(|c| Ok(findings::list_for_repo(c, repo_id, LIST_LIMIT)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("listing findings: {e}")))?;
	Ok(Json(ListFindingsResponse {
		protocol_version: PROTOCOL_VERSION,
		findings: rows.into_iter().map(row_to_summary).collect(),
	}))
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
	Path(repo_id): Path<i64>, Query(qp): Query<SearchQuery>,
) -> Result<Json<ListFindingsResponse>, (StatusCode, String)> {
	authorize_prior_finding_repo(&state, &authed, repo_id)?;
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
) -> Result<Json<FindingDetail>, (StatusCode, String)> {
	let row = state
		.db
		.with_conn(|c| Ok(findings::get(c, id)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("get finding: {e}")))?
		.ok_or((StatusCode::NOT_FOUND, format!("no finding with id {id}")))?;
	authorize_prior_finding_repo(&state, &authed, row.repo_id)?;
	Ok(Json(row_to_detail(row)))
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
