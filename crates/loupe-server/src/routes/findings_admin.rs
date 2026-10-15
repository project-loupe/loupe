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
use loupe_core::{FindingState, ReportingDestination};
use loupe_proto::{
	FindingDetail, FindingSummary, ListFindingsResponse, RetryVerifyResponse, PROTOCOL_VERSION,
};
use loupe_provenance::{Agent, Db};
use loupe_storage::findings::{self, ApprovalOutcome, FindingRow};
use loupe_storage::repos;
use loupe_storage::scope::{self, OperatorTarget, RepoScope};
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

fn now_secs() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

fn read_scope<T>(
	state: &AppState, authed: &AuthedWorker, headers: &HeaderMap, target: OperatorTarget,
	body: impl for<'tx> FnOnce(&RepoScope<'tx>) -> loupe_storage::Result<T>,
) -> Result<T, (StatusCode, String)> {
	if let Some(operator) = authed.operator_ingress() {
		return scope::with_operator_repository(&state.db, &operator, target, body)
			.map_err(read_error);
	}
	let now = now_secs();
	use loupe_core::security_event::{CapabilityDenial, Operation, RequestedTarget};
	let (operation, requested) = match target {
		OperatorTarget::Repository(id) => {
			(Operation::SearchFindings, RequestedTarget::Repository(id))
		},
		OperatorTarget::Finding(id) => (Operation::ReadFinding, RequestedTarget::Finding(id)),
		OperatorTarget::Job(id) => (Operation::ReadFinding, RequestedTarget::Job(id)),
	};
	let authorized = job_capability::authorize(state, authed, headers, now, operation, requested)?;
	scope::with_active_lease(&state.db, authorized.active_lease(authed.id(), now), |scope| {
		if let OperatorTarget::Repository(repo) = target
			&& scope.repo().repository_id() != repo
		{
			job_capability::denied(
				authed,
				Some(&authorized.row),
				operation,
				requested,
				CapabilityDenial::RepositoryMismatch,
			);
			return Err(loupe_storage::Error::ScopeDenied);
		}
		body(scope.repo())
	})
	.map_err(read_error)?
	.ok_or_else(|| {
		job_capability::denied(
			authed,
			Some(&authorized.row),
			operation,
			requested,
			CapabilityDenial::LeaseInvalidated,
		);
		job_capability::forbidden()
	})
}

fn read_error(error: loupe_storage::Error) -> (StatusCode, String) {
	match error {
		loupe_storage::Error::NotFound(loupe_storage::Entity::Finding, id) => {
			(StatusCode::NOT_FOUND, format!("no finding with id {id}"))
		},
		loupe_storage::Error::ScopeDenied => job_capability::forbidden(),
		other => (StatusCode::INTERNAL_SERVER_ERROR, format!("reading findings: {other}")),
	}
}

pub async fn list_for_repo(
	State(state): State<AppState>, Path(repo_id): Path<i64>, Query(qp): Query<ListQuery>,
	Extension(authed): Extension<AuthedWorker>,
) -> Result<Json<ListFindingsResponse<Agent, Db>>, (StatusCode, String)> {
	let limit = positive_limit(qp.limit)?.unwrap_or(LIST_DEFAULT_LIMIT);
	let rows = read_scope(
		&state,
		&authed,
		&HeaderMap::new(),
		OperatorTarget::Repository(repo_id),
		|scope| findings::list_for_repo(scope, limit),
	)?;
	Ok(Json(ListFindingsResponse {
		protocol_version: PROTOCOL_VERSION,
		findings: rows.into_iter().map(row_to_summary).collect(),
	}))
}

/// Query string for `GET /v1/repos/:id/findings`.
// debug-ok: this list query contains only an optional numeric limit.
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
pub use crate::ingress::query::SearchQuery;

/// `GET /v1/repos/:id/findings/search?q=<keywords>&limit=<n>`. FTS5
/// keyword search over title, description, file_path. Open to admins
/// and to workers with an active lease for `:id`; the MCP server's
/// `query_prior_findings` tool calls this from inside the worker.
/// Free-form `q` is run through `findings::sanitize_fts_query`
/// server-side, so the caller doesn't need to know FTS5 syntax.
pub async fn search(
	State(state): State<AppState>, Extension(authed): Extension<AuthedWorker>,
	Path(repo_id): Path<i64>, qp: SearchQuery, headers: HeaderMap,
) -> Result<Json<ListFindingsResponse<Agent, Db>>, (StatusCode, String)> {
	let limit = qp.limit.unwrap_or(SEARCH_DEFAULT_LIMIT).clamp(1, SEARCH_MAX_LIMIT);
	let sanitized = qp.q;
	let rows =
		read_scope(&state, &authed, &headers, OperatorTarget::Repository(repo_id), |scope| {
			if sanitized.is_empty() {
				Ok(Vec::new())
			} else {
				sanitized.search(scope, limit)
			}
		})?;
	Ok(Json(ListFindingsResponse {
		protocol_version: PROTOCOL_VERSION,
		findings: rows.into_iter().map(row_to_summary).collect(),
	}))
}

pub async fn get(
	State(state): State<AppState>, Extension(authed): Extension<AuthedWorker>, Path(id): Path<i64>,
	headers: HeaderMap,
) -> Result<Json<FindingDetail<Agent, Db>>, (StatusCode, String)> {
	let row = read_scope(&state, &authed, &headers, OperatorTarget::Finding(id), |scope| {
		findings::get(scope, id)
	})?
	.ok_or((StatusCode::NOT_FOUND, format!("no finding with id {id}")))?;
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
	State(state): State<AppState>, Extension(operator): Extension<AuthedWorker>,
	body: crate::ingress::OperatorJson,
) -> Result<Json<RetryVerifyResponse>, (StatusCode, String)> {
	let req = crate::ingress::registry::RetryVerifyDecoder::decode(body)?;
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
	let response = loupe_storage::recovery::retry_verification_candidates(
		&state.db,
		&operator.require_operator()?,
		&loupe_storage::recovery::RecoveryRequest {
			repo_id: req.repo_id,
			limit: req.limit,
			include_inconclusive: req.include_inconclusive,
			dry_run: req.dry_run,
		},
		now,
		super::jobs::DEFAULT_VALIDATING_BUDGET_SECS,
	)
	.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("retry verify: {e}")))?;

	if !response.dry_run && response.requeued_jobs + response.created_jobs > 0 {
		state.job_arrived.notify_waiters();
	}
	Ok(Json(RetryVerifyResponse {
		protocol_version: PROTOCOL_VERSION,
		dry_run: response.dry_run,
		matched: response.matched,
		revived: response.revived,
		requeued_jobs: response.requeued_jobs,
		created_jobs: response.created_jobs,
		left_queued_or_leased: response.left_queued_or_leased,
	}))
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
	let cn = authed.name().to_owned();
	let ingress =
		authed.operator_ingress().ok_or((StatusCode::FORBIDDEN, "admin required".into()))?;
	let (outcome, preparation) = loupe_storage::scope::with_operator_repository(
		&state.db,
		&ingress,
		loupe_storage::scope::OperatorTarget::Finding(id),
		|scope| loupe_storage::reports::approve(scope, id, &cn, now),
	)
	.map_err(|e| match e {
		loupe_storage::Error::NotFound(loupe_storage::Entity::Finding, _) => {
			(StatusCode::NOT_FOUND, format!("no finding with id {id}"))
		},
		error => (StatusCode::INTERNAL_SERVER_ERROR, format!("approve finding: {error}")),
	})?;
	match outcome {
		ApprovalOutcome::Applied => {
			if let Err(e) = super::jobs::dispatch_prepared(
				&state,
				preparation,
				super::jobs::DispatchScope::Finding(id),
				now,
			)
			.await
			{
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
	State(state): State<AppState>, Extension(authed): Extension<AuthedWorker>, Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
	let now = now_secs();
	let ingress =
		authed.operator_ingress().ok_or((StatusCode::FORBIDDEN, "admin required".into()))?;
	let preparation = loupe_storage::scope::with_operator_repository(
		&state.db,
		&ingress,
		loupe_storage::scope::OperatorTarget::Finding(id),
		|scope| {
			let row = findings::get(scope, id)?
				.ok_or(loupe_storage::Error::NotFound(loupe_storage::Entity::Finding, id))?;
			match row.state {
				FindingState::Reported => {
					return Ok(Ok(loupe_storage::reports::Preparation::NoReport))
				},
				FindingState::Confirmed => {},
				_ => {
					return Ok(Err((
						StatusCode::CONFLICT,
						format!("finding {id} is not confirmed"),
					)))
				},
			}
			let repo = repos::get(scope)?.ok_or(loupe_storage::Error::ScopeDenied)?;
			if matches!(repo.reporting, ReportingDestination::Manual) {
				return Ok(Err((
					StatusCode::CONFLICT,
					format!("repo {} does not have reporting configured", repo.id),
				)));
			}
			Ok(Ok(loupe_storage::reports::prepare_operator(scope, id)?))
		},
	)
	.map_err(read_error)??;
	match super::jobs::dispatch_prepared(
		&state,
		preparation,
		super::jobs::DispatchScope::Finding(id),
		now,
	)
	.await
	{
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
	let cn = authed.name().to_owned();
	let outcome = scope::with_operator_repository(
		&state.db,
		&authed.require_operator()?,
		OperatorTarget::Finding(id),
		|scope| findings::reject(scope, id, &cn, now),
	)
	.map_err(read_error)?;
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

fn row_to_summary(r: FindingRow) -> FindingSummary<Agent, Db> {
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

fn row_to_detail(r: FindingRow) -> FindingDetail<Agent, Db> {
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
