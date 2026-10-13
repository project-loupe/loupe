//! Worker-side job lifecycle routes plus admin enqueue/list/inspect.
//!
//! State machine implemented here:
//!
//! ```text
//! queued ──lease──► leased ──complete(succeeded)──► succeeded
//!   ▲                │
//!   │                ├─ complete(failed) ──► failed
//!   │                │
//!   └── reaper (attempts < MAX) ◄── lease_expires_at < now
//! ```
//!
//! Findings batches are accepted for `kind = scan` jobs only; verdict
//! submissions are accepted for `kind = verify` only. Both checks live
//! in this module so a buggy verifier scanner can't insert findings
//! that themselves trigger verification.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::{Extension, Json};
use loupe_core::{JobKind, JobState};
use loupe_proto::{
	CompleteOutcome, HeartbeatResponse, JobCapability, JobInfo, LeaseEnvelope, LeasePayload,
	LeaseResponse, ScanResponse, LLM_CODE_REVIEW_SCANNER_ID, PROTOCOL_VERSION,
};
use loupe_provenance::{Agent, Db, Operator};
use loupe_storage::jobs::{self, JobRow, QueuedJob, DEFAULT_LEASE_SECONDS};
use loupe_storage::{findings, reports, repos, scope};
use serde::Deserialize;

use crate::auth::AuthedWorker;
use crate::state::AppState;
use crate::{job_capability, reporters};

pub(crate) enum Route {
	Findings,
	LlmFinding,
	Verdict,
}

pub(crate) fn route_admits_kind<S: loupe_provenance::Source>(
	route: Route, kind: &JobKind<S>,
) -> bool {
	match route {
		Route::Findings | Route::LlmFinding => matches!(kind, JobKind::Scan),
		Route::Verdict => matches!(kind, JobKind::Verify),
	}
}

fn now_secs() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

fn check_version(version: u16) -> Result<(), (StatusCode, String)> {
	if version == PROTOCOL_VERSION {
		Ok(())
	} else {
		Err((StatusCode::BAD_REQUEST, format!("unsupported protocol_version {version}")))
	}
}

fn job_to_info(row: &JobRow) -> JobInfo<Db> {
	JobInfo {
		job_id: row.id,
		repo_id: row.repo_id,
		kind: row.kind.clone(),
		state: row.state,
		incremental: row.incremental,
		since_sha: row.since_sha.clone(),
		head_sha: row.head_sha.clone(),
		parent_job_id: row.parent_job_id,
		target_finding_id: row.target_finding_id,
		attempts: row.attempts,
		enqueued_at: row.enqueued_at,
		worker_id: row.worker_id,
		lease_expires_at: row.lease_expires_at,
		started_at: row.started_at,
		finished_at: row.finished_at,
		error: row.error.clone(),
	}
}

#[derive(Deserialize)]
pub struct ListQuery {
	#[serde(default)]
	pub limit: Option<i64>,
	/// Comma-separated `JobState` values; a job matches if it is in any of
	/// them. Accepts a list because "finished" spans three states, and an
	/// operator view wants them in one query rather than three.
	#[serde(default)]
	pub state: Option<String>,
	#[serde(default)]
	pub kind: Option<String>,
}
impl std::fmt::Debug for ListQuery {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("ListQuery([redacted])")
	}
}

/// Parse the `state=` filter. Rejects unknown values loudly rather than
/// silently returning everything — a typo'd filter that looks like it
/// worked is worse than an error.
pub fn parse_states(raw: Option<&str>) -> Result<Vec<JobState>, (StatusCode, String)> {
	let Some(raw) = raw else {
		return Ok(Vec::new());
	};
	let mut states = Vec::new();
	for token in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
		let state: JobState = token.parse().map_err(|_| {
			(
				StatusCode::BAD_REQUEST,
				format!(
					"unknown job state {token:?}; expected any of \
					 queued, leased, succeeded, failed, cancelled"
				),
			)
		})?;
		if !states.contains(&state) {
			states.push(state);
		}
	}
	if states.is_empty() {
		return Err((StatusCode::BAD_REQUEST, "state must name at least one job state".into()));
	}
	Ok(states)
}

pub fn parse_kind(raw: Option<&str>) -> Result<Option<JobKind<Operator>>, (StatusCode, String)> {
	raw.map(|k| {
		let kind = match k {
			"scan" => JobKind::Scan,
			"verify" => JobKind::Verify,
			"survey" => JobKind::Survey,
			"drilldown" => JobKind::Drilldown,
			_ => {
				return Err((
					StatusCode::BAD_REQUEST,
					format!("unknown job kind {k:?}; expected scan, verify, survey or drilldown"),
				))
			},
		};
		Ok(kind)
	})
	.transpose()
}

/// `POST /v1/repos/:id/scan` — admin enqueues a scan job for `id`.
pub async fn enqueue_scan(
	State(state): State<AppState>, Path(repo_id): Path<i64>,
	Extension(operator): Extension<AuthedWorker>, body: crate::ingress::OperatorJson,
) -> Result<(StatusCode, Json<ScanResponse>), (StatusCode, String)> {
	let req = crate::ingress::registry::EnqueueScanDecoder::decode(body)?;
	check_version(req.protocol_version)?;
	let now = now_secs();

	let job_id = scope::with_operator_repository(
		&state.db,
		&operator.require_operator()?,
		scope::OperatorTarget::Repository(repo_id),
		|scope| {
			let Some(repo) = repos::get(scope)? else {
				return Ok(None);
			};
			let since_sha = if req.incremental { repo.last_scanned_sha } else { None };
			Ok(Some(jobs::enqueue(
				scope,
				&QueuedJob {
					kind: JobKind::Scan,
					incremental: req.incremental,
					since_sha,
					parent_job_id: None,
					target_finding_id: None,
				},
				now,
			)?))
		},
	)
	.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("enqueue: {e}")))?
	.ok_or((StatusCode::NOT_FOUND, format!("no repo with id {repo_id}")))?;

	state.job_arrived.notify_waiters();
	Ok((StatusCode::CREATED, Json(ScanResponse { protocol_version: PROTOCOL_VERSION, job_id })))
}

/// `GET /v1/jobs` — admin lists jobs (most recent first). `state` and
/// `kind` narrow the result server-side so a caller watching one part of
/// the queue doesn't have to pull the whole table and filter locally.
pub async fn list(
	State(state): State<AppState>, Extension(operator): Extension<AuthedWorker>,
	crate::ingress::query::OperatorJobQuery(filter): crate::ingress::query::OperatorJobQuery,
) -> Result<Json<Vec<JobInfo<Db>>>, (StatusCode, String)> {
	let rows = jobs::catalog(&state.db, &operator.require_operator()?, &filter)
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("list jobs: {e}")))?;
	Ok(Json(rows.iter().map(job_to_info).collect()))
}

/// `GET /v1/jobs/:id` — admin gets one job.
pub async fn get(
	State(state): State<AppState>, Path(id): Path<i64>,
	Extension(operator): Extension<AuthedWorker>,
) -> Result<Json<JobInfo<Db>>, (StatusCode, String)> {
	let row = scope::with_operator_repository(
		&state.db,
		&operator.require_operator()?,
		scope::OperatorTarget::Job(id),
		|scope| jobs::get(scope, id),
	)
	.map_err(|e| match e {
		loupe_storage::Error::NotFound(loupe_storage::Entity::Job, _) => {
			(StatusCode::NOT_FOUND, format!("no job with id {id}"))
		},
		other => (StatusCode::INTERNAL_SERVER_ERROR, format!("get job: {other}")),
	})?
	.ok_or_else(|| (StatusCode::NOT_FOUND, format!("no job with id {id}")))?;
	Ok(Json(job_to_info(&row)))
}

/// `POST /v1/jobs/:id/retry` — admin requeues a failed job.
///
/// This is intentionally scoped to `failed` jobs. Queued/leased jobs
/// are already in flight, and terminal succeeded jobs should not be
/// run twice through the same row. Failed verify jobs also require the
/// target finding to still be `validating`; if a verifier already
/// produced a terminal finding state, or the validating deadline
/// reaper dismissed it, an operator should make that state transition
/// deliberately rather than revive it by accident.
pub async fn retry(
	State(state): State<AppState>, Path(id): Path<i64>,
	Extension(operator): Extension<AuthedWorker>,
) -> Result<Json<JobInfo<Db>>, (StatusCode, String)> {
	let now = now_secs();
	let result = loupe_storage::recovery::retry_job(
		&state.db,
		&operator.require_operator()?,
		id,
		now,
		now + DEFAULT_VALIDATING_BUDGET_SECS,
	)
	.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("retry job: {e}")))?;

	match result {
		jobs::RetryOutcome::Retried(row) => {
			state.job_arrived.notify_waiters();
			Ok(Json(job_to_info(&row)))
		},
		jobs::RetryOutcome::NotFound => {
			Err((StatusCode::NOT_FOUND, format!("no job with id {id}")))
		},
		jobs::RetryOutcome::Conflict(msg) => Err((StatusCode::CONFLICT, msg)),
		jobs::RetryOutcome::UnsupportedKind => {
			Err((StatusCode::CONFLICT, "unsupported job kind".into()))
		},
	}
}

/// `POST /v1/jobs/:id/cancel` — admin cancels queued or leased work.
pub async fn cancel(
	State(state): State<AppState>, Path(id): Path<i64>,
	Extension(operator): Extension<AuthedWorker>,
) -> Result<Json<JobInfo<Db>>, (StatusCode, String)> {
	let now = now_secs();
	let outcome =
		loupe_storage::recovery::cancel_job(&state.db, &operator.require_operator()?, id, now)
			.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("cancel job: {e}")))?;
	match outcome {
		jobs::CancelOutcome::Cancelled(row) => Ok(Json(job_to_info(&row))),
		jobs::CancelOutcome::NotFound => {
			Err((StatusCode::NOT_FOUND, format!("no job with id {id}")))
		},
		jobs::CancelOutcome::NotCancellable(state) => {
			Err((StatusCode::CONFLICT, format!("job {id} is {state:?}, not queued or leased")))
		},
		jobs::CancelOutcome::UnsupportedKind => {
			Err((StatusCode::CONFLICT, "unsupported job kind".into()))
		},
	}
}

/// Maximum wait the server will honour on a single long-poll, even if
/// the client asked for longer. Picked under the typical proxy idle
/// timeout so we never hold a connection long enough for an
/// intermediary to kill it.
const MAX_LEASE_WAIT_SECS: u32 = 60;

/// How long a finding can sit in `validating` before the deadline
/// reaper steps in. This budget starts when verify jobs are enqueued,
/// not when a verifier leases them, so it must tolerate queue backlogs.
/// Seven days keeps unverified findings from being silently dismissed
/// during verifier outages while still bounding invisible stale state.
pub(crate) const DEFAULT_VALIDATING_BUDGET_SECS: i64 = 7 * 24 * 60 * 60;

/// `POST /v1/jobs/lease` — worker pulls the next available job. Honours
/// `wait_seconds` for server-side long-polling: when the queue is empty
/// the server waits on `state.job_arrived` for up to that many seconds
/// (capped) before returning `Empty`. `wait_seconds = 0` is the
/// non-blocking poll-and-return-empty behavior.
pub async fn lease(
	State(state): State<AppState>, Extension(worker): Extension<AuthedWorker>,
	body: crate::ingress::WorkerJson,
) -> Result<axum::response::Response, (StatusCode, String)> {
	let req = crate::ingress::jobs::LeaseRequestDecoder::decode(body)?;
	check_version(req.protocol_version)?;
	// Any `verify:*` capability makes the worker eligible for verify jobs;
	// the tag suffix does not restrict which findings it can verify.
	let accepts_verify = req.capabilities.iter().any(|c| c.expose().starts_with("verify:"));

	if let Some(env) = try_lease(&state, worker.id(), accepts_verify)? {
		return super::credential_response::lease(&LeaseResponse::Lease(Box::new(env)));
	}
	if req.wait_seconds == 0 {
		return super::credential_response::lease(&LeaseResponse::Empty {
			protocol_version: PROTOCOL_VERSION,
		});
	}

	let wait = std::time::Duration::from_secs(req.wait_seconds.min(MAX_LEASE_WAIT_SECS) as u64);
	let deadline = tokio::time::Instant::now() + wait;
	loop {
		// Subscribe to notify *before* the lease check so we can't
		// miss a notify_waiters fired between our two attempts.
		let notified = state.job_arrived.notified();
		tokio::pin!(notified);

		if let Some(env) = try_lease(&state, worker.id(), accepts_verify)? {
			return super::credential_response::lease(&LeaseResponse::Lease(Box::new(env)));
		}

		let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
		if remaining.is_zero() {
			return super::credential_response::lease(&LeaseResponse::Empty {
				protocol_version: PROTOCOL_VERSION,
			});
		}
		tokio::select! {
			_ = &mut notified => {
				// New job — loop and try the lease again.
			}
			_ = tokio::time::sleep(remaining) => {
				return super::credential_response::lease(&LeaseResponse::Empty { protocol_version: PROTOCOL_VERSION });
			}
		}
	}
}

/// One non-blocking lease attempt. `None` means no eligible job is
/// queued. `accepts_verify` gates verify-kind jobs.
fn try_lease(
	state: &AppState, worker_id: i64, accepts_verify: bool,
) -> Result<Option<LeaseEnvelope<Agent, Db>>, (StatusCode, String)> {
	let now = now_secs();
	let (job_capability, job_capability_hash) = job_capability::issue();
	let kinds: Vec<JobKind<Db>> =
		if accepts_verify { vec![JobKind::Scan, JobKind::Verify] } else { vec![JobKind::Scan] };
	let row = crate::review::scheduler::claim_for_worker(
		state,
		worker_id,
		&kinds,
		now,
		&job_capability_hash,
	)
	.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("lease: {e}")))?;
	let Some(row) = row else { return Ok(None) };
	let env = build_lease_envelope(row, job_capability)
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("envelope: {e}")))?;
	Ok(Some(env))
}

fn build_lease_envelope(
	selected: loupe_storage::scheduler::ClaimedLease, job_capability: JobCapability,
) -> anyhow::Result<LeaseEnvelope<Agent, Db>> {
	let repo = selected.repository;
	let row = selected.claimed.job;
	// No clone-side credential is stored separately. We deliberately do
	// not ship the reporting PAT to the worker.
	let github_pat = None;

	let payload = match row.kind {
		JobKind::Scan => LeasePayload::Scan { since_sha: row.since_sha.clone() },
		JobKind::Verify => {
			let target_id = row
				.target_finding_id
				.ok_or_else(|| anyhow::anyhow!("verify job missing target_finding_id"))?;
			let finding_row = selected
				.target
				.ok_or_else(|| anyhow::anyhow!("verify target finding not found"))?;
			if finding_row.repo_id != row.repo_id {
				anyhow::bail!(
					"verify target finding {} belongs to repo {}, not job repo {}",
					target_id,
					finding_row.repo_id,
					row.repo_id
				);
			}
			let reviewed_sha = selected.reviewed_revision;
			let finding = finding_row.into_finding();
			LeasePayload::Verify { finding_id: target_id, finding: Box::new(finding), reviewed_sha }
		},
		JobKind::Survey | JobKind::Drilldown | JobKind::Unknown(_) => {
			anyhow::bail!("unsupported job kind in legacy lease envelope");
		},
	};

	Ok(LeaseEnvelope {
		protocol_version: PROTOCOL_VERSION,
		job_id: row.id,
		job_capability,
		repo_id: repo.id,
		repo: loupe_core::RepoSpec {
			host: repo.host.clone(),
			owner: repo.owner.clone(),
			repo: repo.repo.clone(),
			clone_url: repo.clone_url.clone(),
			branch: repo.default_branch.clone(),
		},
		head_branch: repo.default_branch,
		lease_expires_at: row.lease_expires_at.unwrap_or(0),
		scanner_config: repo.scanner_config,
		github_pat,
		payload,
	})
}

/// `POST /v1/jobs/:id/heartbeat` — worker extends its lease.
pub async fn heartbeat(
	State(state): State<AppState>, Extension(worker): Extension<AuthedWorker>,
	Path(job_id): Path<i64>, headers: HeaderMap, body: crate::ingress::WorkerBody,
) -> Result<Json<HeartbeatResponse>, (StatusCode, String)> {
	if let Some(req) = crate::ingress::jobs::HeartbeatDecoder::decode(body)? {
		check_version(req.protocol_version)?;
	}
	let now = now_secs();
	let authorized = job_capability::authorize_for_job(
		&state,
		&worker,
		&headers,
		job_id,
		now,
		loupe_core::security_event::Operation::Heartbeat,
	)?;
	let lease_until =
		scope::with_active_lease(&state.db, authorized.active_lease(worker.id(), now), |scope| {
			jobs::extend_lease(scope, DEFAULT_LEASE_SECONDS)
		})
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("heartbeat: {e}")))?
		.flatten()
		.ok_or_else(|| {
			authorized
				.deny(&worker, loupe_core::security_event::CapabilityDenial::LeaseInvalidated);
			(StatusCode::FORBIDDEN, "lease not held by this worker".to_owned())
		})?;
	Ok(Json(HeartbeatResponse {
		protocol_version: PROTOCOL_VERSION,
		lease_expires_at: lease_until,
	}))
}

/// `POST /v1/jobs/:id/findings` — worker submits a batch (scan jobs only).
pub async fn submit_findings(
	State(state): State<AppState>, Extension(worker): Extension<AuthedWorker>,
	Path(job_id): Path<i64>, headers: HeaderMap, body: crate::ingress::WorkerJson,
) -> Result<StatusCode, (StatusCode, String)> {
	let batch = crate::ingress::jobs::FindingsBatchDecoder::decode(body)?;
	check_version(batch.protocol_version)?;
	let now = now_secs();

	let authorized = job_capability::authorize_for_job(
		&state,
		&worker,
		&headers,
		job_id,
		now,
		loupe_core::security_event::Operation::SubmitFindings,
	)?;
	let row = &authorized.row;
	if !route_admits_kind(Route::Findings, &row.kind) {
		authorized.deny(&worker, loupe_core::security_event::CapabilityDenial::UnsupportedJobKind);
		return Err((StatusCode::BAD_REQUEST, "verify-kind jobs cannot post findings".into()));
	}
	if batch
		.findings
		.iter()
		.any(|finding| finding.scanner_id.expose() == LLM_CODE_REVIEW_SCANNER_ID)
	{
		authorized
			.deny(&worker, loupe_core::security_event::CapabilityDenial::StrictEndpointRequired);
		return Err((
			StatusCode::BAD_REQUEST,
			"LLM findings must use the strict /llm-findings endpoint".into(),
		));
	}

	let submitted =
		scope::with_active_lease(&state.db, authorized.active_lease(worker.id(), now), |scope| {
			let repo = repos::get(scope.repo())?.ok_or(loupe_storage::Error::ScopeDenied)?;
			for finding in &batch.findings {
				if let Err(error) =
					validate_report_size(&repo, finding, scope.job().head_sha.as_ref())
				{
					report_budget_event(repo.id, Some(scope.job().id), Some(worker.id()));
					return Ok(Err(error));
				}
			}
			for finding in &batch.findings {
				findings::submit(scope, finding)?;
			}
			Ok(Ok(()))
		})
		.map_err(|e| storage_write_error("submit findings", e))?;
	submitted.ok_or_else(|| authorized.lease_invalidated(&worker))??;
	Ok(StatusCode::NO_CONTENT)
}

fn storage_write_error(context: &str, error: loupe_storage::Error) -> (StatusCode, String) {
	use loupe_storage::Error;
	let status = match &error {
		Error::Validation(_) | Error::UnknownPaths(_) => StatusCode::BAD_REQUEST,
		Error::Conflict(_) => StatusCode::CONFLICT,
		Error::Ownership(_) => StatusCode::FORBIDDEN,
		Error::ScopeDenied => StatusCode::FORBIDDEN,
		Error::ReportReceipt => StatusCode::CONFLICT,
		Error::NotFound(_, _) => StatusCode::NOT_FOUND,
		Error::Sqlite(_)
		| Error::Migration(_)
		| Error::UnknownJobKinds(_)
		| Error::DatabaseUnavailable => StatusCode::INTERNAL_SERVER_ERROR,
	};
	(status, format!("{context}: {error}"))
}

fn validate_report_size(
	repo: &repos::RepoRow, finding: &loupe_core::Finding<Agent>,
	reviewed_revision: Option<
		&loupe_core::text::BoundedText<loupe_core::text::policy::RevisionText, Db>,
	>,
) -> Result<(), (StatusCode, String)> {
	validate_report_with_patch(repo, finding, reviewed_revision, None)
}

fn validate_report_with_patch(
	repo: &repos::RepoRow, finding: &loupe_core::Finding<Agent>,
	reviewed_revision: Option<
		&loupe_core::text::BoundedText<loupe_core::text::policy::RevisionText, Db>,
	>,
	patch: Option<&loupe_core::text::BoundedText<loupe_core::text::policy::PatchUnified, Agent>>,
) -> Result<(), (StatusCode, String)> {
	if matches!(repo.reporting, loupe_core::ReportingDestination::GithubIssue { .. }) {
		loupe_core::report_limits::validate_report_content(
			finding.description.expose(),
			finding.poc_unified.as_ref().map(|v| v.expose()),
			patch.or(finding.patch_unified.as_ref()).map(|v| v.expose()),
		)
		.map_err(|error| (StatusCode::BAD_REQUEST, error))?;
		let mut view = reporters::render::ReportView::new(i64::MAX, finding, reviewed_revision);
		if let Some(patch) = patch {
			view = view.with_patch(patch);
		}
		reporters::github::validate_view(repo, view)
			.map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
	}
	Ok(())
}

/// `POST /v1/jobs/:id/llm-findings` — strict host-side MCP broker path.
pub async fn submit_llm_finding(
	State(state): State<AppState>, Extension(worker): Extension<AuthedWorker>,
	Path(job_id): Path<i64>, headers: HeaderMap, body: crate::ingress::WorkerJson,
) -> Result<StatusCode, (StatusCode, String)> {
	let submission = crate::ingress::jobs::LlmFindingDecoder::decode(body)?;
	check_version(submission.protocol_version)?;
	let now = now_secs();
	let authorized = job_capability::authorize_for_job(
		&state,
		&worker,
		&headers,
		job_id,
		now,
		loupe_core::security_event::Operation::SubmitLlmFinding,
	)?;
	let row = &authorized.row;
	if !route_admits_kind(Route::LlmFinding, &row.kind) {
		authorized.deny(&worker, loupe_core::security_event::CapabilityDenial::UnsupportedJobKind);
		return Err((StatusCode::BAD_REQUEST, "verify-kind jobs cannot post findings".into()));
	}
	submission.validate().map_err(|error| (StatusCode::BAD_REQUEST, error))?;
	let finding = submission.into_finding();
	let submitted =
		scope::with_active_lease(&state.db, authorized.active_lease(worker.id(), now), |scope| {
			let repo = repos::get(scope.repo())?.ok_or(loupe_storage::Error::ScopeDenied)?;
			if let Err(error) = validate_report_size(&repo, &finding, scope.job().head_sha.as_ref())
			{
				report_budget_event(repo.id, Some(scope.job().id), Some(worker.id()));
				return Ok(Err(error));
			}
			findings::submit(scope, &finding)?;
			Ok(Ok(()))
		})
		.map_err(|error| storage_write_error("submit LLM finding", error))?;
	submitted.ok_or_else(|| authorized.lease_invalidated(&worker))??;
	Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/jobs/:id/verdict` — worker submits a verdict (verify jobs only).
pub async fn submit_verdict(
	State(state): State<AppState>, Extension(worker): Extension<AuthedWorker>,
	Path(job_id): Path<i64>, headers: HeaderMap, body: crate::ingress::WorkerJson,
) -> Result<StatusCode, (StatusCode, String)> {
	let submission = crate::ingress::jobs::VerdictSubmissionDecoder::decode(body)?;
	check_version(submission.protocol_version)?;
	let now = now_secs();

	let authorized = job_capability::authorize_for_job(
		&state,
		&worker,
		&headers,
		job_id,
		now,
		loupe_core::security_event::Operation::SubmitVerdict,
	)?;
	let row = &authorized.row;
	if !route_admits_kind(Route::Verdict, &row.kind) {
		authorized.deny(&worker, loupe_core::security_event::CapabilityDenial::UnsupportedJobKind);
		return Err((StatusCode::BAD_REQUEST, "scan-kind jobs cannot post verdicts".into()));
	}
	let target_finding_id = row.target_finding_id.ok_or_else(|| {
		authorized
			.deny(&worker, loupe_core::security_event::CapabilityDenial::MissingAssignedTarget);
		(StatusCode::BAD_REQUEST, "verify job missing target finding".into())
	})?;

	let terminal_inconclusive =
		matches!(&submission.verdict, loupe_core::Verdict::Inconclusive { terminal: true, .. });
	// Patches only ride on Confirmed verdicts (pinned by the
	// `Verdict` type itself); pull the diff out here so the closure
	// below can borrow it cleanly without re-matching on the variant.
	let patch_to_attach = match &submission.verdict {
		loupe_core::Verdict::Confirmed { patch: Some(p), .. } => Some((&p.patch_unified, &p.notes)),
		_ => None,
	};
	let by_cn = worker.name().to_owned();
	let server_default = state.require_approval_default;
	// Insert the verdict + apply the rollup policy in a single
	// transaction so a concurrent verdict from a second verifier
	// can't catch us mid-state-flip and observe "confirmed AND
	// dismissed" simultaneously.
	let (_, preparation) =
		scope::with_active_lease(&state.db, authorized.active_lease(worker.id(), now), |scope| {
			let repo = repos::get(scope.repo())?.ok_or(loupe_storage::Error::ScopeDenied)?;
			if let Some((patch_unified, _)) = patch_to_attach {
				let Some(finding) = findings::get(scope.repo(), target_finding_id)? else {
					return Ok(Err((StatusCode::NOT_FOUND, "target finding missing".into())));
				};
				let revision =
					jobs::get(scope.repo(), finding.job_id)?.and_then(|job| job.head_sha);
				if let Err(error) = validate_report_with_patch(
					&repo,
					&finding.into_finding(),
					revision.as_ref(),
					Some(patch_unified),
				) {
					report_budget_event(repo.id, Some(scope.job().id), Some(worker.id()));
					return Ok(Err(error));
				}
			}
			Ok(Ok(reports::submit_verdict(
				scope,
				&submission.verdict,
				&by_cn,
				terminal_inconclusive,
				server_default,
			)?))
		})
		.map_err(|e| storage_write_error("submit verdict", e))?
		.ok_or_else(|| authorized.lease_invalidated(&worker))??;

	if let Err(e) =
		dispatch_prepared(&state, preparation, DispatchScope::Finding(target_finding_id), now).await
	{
		tracing::warn!(
			finding_id = target_finding_id,
			error = %format_error_chain(&e),
			"dispatch on verdict-confirm failed"
		);
	}
	Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/jobs/:id/complete` — worker terminates the job. On
/// success of a scan, persists `last_scanned_sha` so the next
/// incremental run knows where to pick up.
pub async fn complete(
	State(state): State<AppState>, Extension(worker): Extension<AuthedWorker>,
	Path(job_id): Path<i64>, headers: HeaderMap, body: crate::ingress::WorkerJson,
) -> Result<StatusCode, (StatusCode, String)> {
	let req = crate::ingress::jobs::CompleteDecoder::decode(body)?;
	check_version(req.protocol_version)?;
	let new_state = match req.outcome {
		CompleteOutcome::Succeeded => JobState::Succeeded,
		CompleteOutcome::Failed => JobState::Failed,
	};
	let now = now_secs();

	let authorized = job_capability::authorize_for_job(
		&state,
		&worker,
		&headers,
		job_id,
		now,
		loupe_core::security_event::Operation::CompleteJob,
	)?;
	let job = &authorized.row;
	// Same set the storage guards use; the two must never drift apart.
	if !jobs::RUNTIME_KINDS.contains(&job.kind) {
		return Err((StatusCode::BAD_REQUEST, "unsupported job kind".into()));
	}
	if matches!(new_state, JobState::Succeeded) {
		match job.kind {
			JobKind::Scan => {
				if req
					.head_sha
					.as_ref()
					.map(|v| v.expose().trim())
					.filter(|sha| !sha.is_empty())
					.is_none()
				{
					return Err((
						StatusCode::BAD_REQUEST,
						"successful scan completion requires non-empty head_sha".into(),
					));
				}
			},
			JobKind::Verify => {
				let has_verdict = scope::with_active_lease(
					&state.db,
					authorized.active_lease(worker.id(), now),
					jobs::has_verdict,
				)
				.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("check verdict: {e}")))?
				.ok_or_else(|| authorized.lease_invalidated(&worker))?;
				if !has_verdict {
					return Err((
						StatusCode::CONFLICT,
						"successful verify completion requires a submitted verdict".into(),
					));
				}
			},
			JobKind::Survey | JobKind::Drilldown | JobKind::Unknown(_) => {
				return Err((StatusCode::BAD_REQUEST, "unsupported job kind".into()));
			},
		}
	}

	let preparation =
		scope::with_active_lease(&state.db, authorized.active_lease(worker.id(), now), |scope| {
			reports::complete_assignment(
				scope,
				new_state,
				req.head_sha.as_ref(),
				req.error.as_ref(),
				state.require_approval_default,
				now + DEFAULT_VALIDATING_BUDGET_SECS,
			)
		})
		.map_err(|e: loupe_storage::Error| {
			(StatusCode::INTERNAL_SERVER_ERROR, format!("complete: {e}"))
		})?
		.ok_or((StatusCode::CONFLICT, "lease reaped before complete".into()))?;

	if matches!(new_state, JobState::Succeeded) && job.kind == JobKind::Scan {
		// Wake long-pollers in case any verify jobs were just enqueued
		// (also covers the auto-confirmed-only case — extra notify is
		// harmless).
		state.job_arrived.notify_waiters();
		if let Err(e) =
			dispatch_prepared(&state, preparation, DispatchScope::Job(job.id), now).await
		{
			// Dispatch failures don't roll back the job. Confirmed
			// findings remain retryable via the admin retry-report route.
			tracing::warn!(job_id = job.id, error = %format_error_chain(&e), "dispatch failed");
		}
	}
	Ok(StatusCode::NO_CONTENT)
}

pub(super) fn format_error_chain(error: &anyhow::Error) -> String {
	let mut causes = error.chain();
	let Some(first) = causes.next() else {
		return error.to_string();
	};
	let mut rendered = first.to_string();
	for cause in causes {
		rendered.push_str(": ");
		rendered.push_str(&cause.to_string());
	}
	rendered
}

// debug-ok: report selection contains only a closed target kind and integer row ID.
#[derive(Debug, Clone, Copy)]
pub(super) enum DispatchScope {
	Finding(i64),
	Job(i64),
}

fn report_budget_event(repo_id: i64, job_id: Option<i64>, worker_id: Option<i64>) {
	use loupe_core::security_event::{emit, BudgetResource, EventContext, SecurityEvent};
	emit(SecurityEvent::BudgetExhausted {
		context: EventContext { repo_id: Some(repo_id), job_id, worker_id, ..Default::default() },
		resource: BudgetResource::ReportOutput,
		used: None,
		limit: None,
	});
}

fn report_dispatch_error(error: &anyhow::Error, repo_id: i64, origin: DispatchScope) {
	if error.is::<reporters::render::ReportError>() || reporters::email::is_budget_error(error) {
		let job_id = match origin {
			DispatchScope::Job(id) => Some(id),
			DispatchScope::Finding(_) => None,
		};
		report_budget_event(repo_id, job_id, None);
	}
}

/// All database selection has committed before this asynchronous operation.
pub(super) async fn dispatch_prepared(
	state: &AppState, preparation: reports::Preparation, origin: DispatchScope, now: i64,
) -> anyhow::Result<()> {
	use loupe_core::ReportingDestination;

	use crate::reporters::Reporter;
	let mut batch = match preparation {
		reports::Preparation::NoReport => return Ok(()),
		reports::Preparation::Unavailable(error) => return Err(error.into()),
		reports::Preparation::Ready(batch) => batch,
	};
	if let ReportingDestination::GithubIssue { target_owner, pat_secret_id: None, .. } =
		&batch.repository().reporting
	{
		state.check_github_app_target_owner(target_owner).map_err(anyhow::Error::msg)?;
	}
	if matches!(batch.repository().reporting, ReportingDestination::GithubIssue { .. }) {
		for index in 0..batch.entries().len() {
			let id = batch.entries()[index].id();
			let delivered =
				state.github_reporter.dispatch_entry(&batch, index).await.inspect_err(|error| {
					report_dispatch_error(error, batch.repository().id, origin)
				})?;
			batch.mark_one(&state.db, id, now)?;
			match origin {
				DispatchScope::Finding(_) => tracing::info!(
					finding_id = id,
					external_id = delivered.external_id.as_deref(),
					"dispatched finding"
				),
				DispatchScope::Job(job_id) => tracing::info!(
					job_id,
					finding_id = id,
					external_id = delivered.external_id.as_deref(),
					"dispatched finding"
				),
			}
		}
	} else {
		let delivered = state
			.email_reporter
			.dispatch(&batch)
			.await
			.inspect_err(|error| report_dispatch_error(error, batch.repository().id, origin))?;
		batch.mark_all(&state.db, now)?;
		match origin {
			DispatchScope::Finding(finding_id) => tracing::info!(
				finding_id,
				external_id = delivered.external_id.as_deref(),
				"dispatched finding"
			),
			DispatchScope::Job(job_id) => tracing::info!(
				job_id,
				count = batch.entries().len(),
				external_id = delivered.external_id.as_deref(),
				"dispatched findings"
			),
		}
	}
	Ok(())
}

#[cfg(test)]
#[path = "report_delivery_tests.rs"]
mod report_delivery_tests;

#[cfg(test)]
mod storage_error_tests {
	use super::*;
	#[test]
	fn domain_errors_keep_their_http_meaning() {
		use loupe_storage::{Conflict, Entity, Error, Ownership};
		for (error, status) in [
			(Error::Conflict(Conflict::Checkpoint), StatusCode::CONFLICT),
			(Error::Ownership(Ownership::LeadJob), StatusCode::FORBIDDEN),
			(Error::NotFound(Entity::Job, 1), StatusCode::NOT_FOUND),
			(
				Error::Validation(loupe_core::text::Error::new(
					"title",
					loupe_core::text::Rule::Empty,
				)),
				StatusCode::BAD_REQUEST,
			),
			(Error::UnknownJobKinds(0), StatusCode::INTERNAL_SERVER_ERROR),
		] {
			assert_eq!(
				storage_write_error("submit", error).0,
				status,
				"preserve typed storage failure status"
			);
		}
	}
}

#[cfg(test)]
mod route_kind_tests {
	use super::*;

	#[test]
	fn submission_routes_accept_only_their_runtime_kind() {
		for kind in [
			JobKind::Scan,
			JobKind::Verify,
			JobKind::Survey,
			JobKind::Drilldown,
			JobKind::Unknown(crate::test_support::text("verify")),
		] {
			assert_eq!(route_admits_kind(Route::Findings, &kind), kind == JobKind::Scan);
			assert_eq!(route_admits_kind(Route::LlmFinding, &kind), kind == JobKind::Scan);
			assert_eq!(route_admits_kind(Route::Verdict, &kind), kind == JobKind::Verify);
		}
	}
}
