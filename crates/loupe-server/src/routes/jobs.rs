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
use axum::http::StatusCode;
use axum::{Extension, Json};
use loupe_core::{JobKind, JobState};
use loupe_proto::{
	CompleteOutcome, CompleteRequest, FindingsBatch, HeartbeatResponse, JobInfo, LeaseEnvelope,
	LeasePayload, LeaseRequest, LeaseResponse, ScanRequest, ScanResponse, VerdictSubmission,
	PROTOCOL_VERSION,
};
use loupe_storage::jobs::{self, JobRow, NewJob, DEFAULT_LEASE_SECONDS};
use loupe_storage::{findings, repos};

use crate::auth::AuthedWorker;
use crate::state::AppState;

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

fn job_to_info(row: &JobRow) -> JobInfo {
	JobInfo {
		job_id: row.id,
		repo_id: row.repo_id,
		kind: row.kind,
		state: row.state,
		incremental: row.incremental,
		since_sha: row.since_sha.clone(),
		head_sha: row.head_sha.clone(),
		parent_job_id: row.parent_job_id,
		target_finding_id: row.target_finding_id,
		attempts: row.attempts,
		enqueued_at: row.enqueued_at,
	}
}

/// `POST /v1/repos/:id/scan` — admin enqueues a scan job for `id`.
pub async fn enqueue_scan(
	State(state): State<AppState>, Path(repo_id): Path<i64>, Json(req): Json<ScanRequest>,
) -> Result<(StatusCode, Json<ScanResponse>), (StatusCode, String)> {
	check_version(req.protocol_version)?;
	let now = now_secs();

	let repo = state
		.db
		.with_conn(|c| Ok(repos::get(c, repo_id)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("get repo: {e}")))?
		.ok_or((StatusCode::NOT_FOUND, format!("no repo with id {repo_id}")))?;

	let since_sha = if req.incremental { repo.last_scanned_sha.clone() } else { None };
	let job_id = state
		.db
		.with_conn(|c| {
			Ok(jobs::enqueue(
				c,
				&NewJob {
					repo_id: repo.id,
					kind: JobKind::Scan,
					incremental: req.incremental,
					since_sha,
					parent_job_id: None,
					target_finding_id: None,
				},
				now,
			)?)
		})
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("enqueue: {e}")))?;

	Ok((StatusCode::CREATED, Json(ScanResponse { protocol_version: PROTOCOL_VERSION, job_id })))
}

/// `GET /v1/jobs` — admin lists jobs (most recent first).
pub async fn list(
	State(state): State<AppState>,
) -> Result<Json<Vec<JobInfo>>, (StatusCode, String)> {
	let rows = state
		.db
		.with_conn(|c| Ok(jobs::list(c)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("list jobs: {e}")))?;
	Ok(Json(rows.iter().map(job_to_info).collect()))
}

/// `GET /v1/jobs/:id` — admin gets one job.
pub async fn get(
	State(state): State<AppState>, Path(id): Path<i64>,
) -> Result<Json<JobInfo>, (StatusCode, String)> {
	let row = state
		.db
		.with_conn(|c| Ok(jobs::get(c, id)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("get job: {e}")))?
		.ok_or_else(|| (StatusCode::NOT_FOUND, format!("no job with id {id}")))?;
	Ok(Json(job_to_info(&row)))
}

/// `POST /v1/jobs/lease` — worker pulls the next available job.
/// Returns `LeaseResponse::Empty` if the queue is empty.
pub async fn lease(
	State(state): State<AppState>, Extension(worker): Extension<AuthedWorker>,
	Json(req): Json<LeaseRequest>,
) -> Result<Json<LeaseResponse>, (StatusCode, String)> {
	check_version(req.protocol_version)?;
	let _ = req.capabilities; // capability matching lands with the verifier dispatcher in M2.
	let now = now_secs();

	let row = state
		.db
		.with_conn(|c| Ok(jobs::lease_next(c, worker.id(), now, DEFAULT_LEASE_SECONDS)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("lease: {e}")))?;

	let Some(row) = row else {
		return Ok(Json(LeaseResponse::Empty { protocol_version: PROTOCOL_VERSION }));
	};

	let envelope = build_lease_envelope(&state, &row)
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("envelope: {e}")))?;
	Ok(Json(LeaseResponse::Lease(Box::new(envelope))))
}

fn build_lease_envelope(state: &AppState, row: &JobRow) -> anyhow::Result<LeaseEnvelope> {
	let repo = state
		.db
		.with_conn(|c| Ok(repos::get(c, row.repo_id)?))?
		.ok_or_else(|| anyhow::anyhow!("repo {} for leased job not found", row.repo_id))?;
	// For now no clone-side PAT is stored separately; M2 wires this in.
	// (We deliberately do not ship the reporting PAT to the worker.)
	let github_pat: Option<String> = None;

	let payload = match row.kind {
		JobKind::Scan => LeasePayload::Scan { since_sha: row.since_sha.clone() },
		JobKind::Verify => {
			let target_id = row
				.target_finding_id
				.ok_or_else(|| anyhow::anyhow!("verify job missing target_finding_id"))?;
			let finding_row = state
				.db
				.with_conn(|c| Ok(findings::list_for_job(c, row.parent_job_id.unwrap_or(0))?))?
				.into_iter()
				.find(|f| f.id == target_id)
				.ok_or_else(|| anyhow::anyhow!("verify target finding not found"))?;
			let finding = loupe_core::Finding {
				scanner_id: finding_row.scanner_id,
				severity: finding_row.severity,
				title: finding_row.title,
				description: finding_row.description,
				file_path: finding_row.file_path,
				line_start: finding_row.line_start,
				line_end: finding_row.line_end,
				cwe: finding_row.cwe,
				patch_unified: finding_row.patch_unified,
				fingerprint: finding_row.fingerprint,
			};
			LeasePayload::Verify { finding_id: target_id, finding }
		},
	};

	Ok(LeaseEnvelope {
		protocol_version: PROTOCOL_VERSION,
		job_id: row.id,
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
	Path(job_id): Path<i64>,
) -> Result<Json<HeartbeatResponse>, (StatusCode, String)> {
	let now = now_secs();
	let lease_until = state
		.db
		.with_conn(|c| Ok(jobs::heartbeat(c, job_id, worker.id(), now, DEFAULT_LEASE_SECONDS)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("heartbeat: {e}")))?
		.ok_or_else(|| (StatusCode::FORBIDDEN, "lease not held by this worker".to_owned()))?;
	Ok(Json(HeartbeatResponse {
		protocol_version: PROTOCOL_VERSION,
		lease_expires_at: lease_until,
	}))
}

/// `POST /v1/jobs/:id/findings` — worker submits a batch (scan jobs only).
pub async fn submit_findings(
	State(state): State<AppState>, Extension(worker): Extension<AuthedWorker>,
	Path(job_id): Path<i64>, Json(batch): Json<FindingsBatch>,
) -> Result<StatusCode, (StatusCode, String)> {
	check_version(batch.protocol_version)?;
	let now = now_secs();

	let row = state
		.db
		.with_conn(|c| Ok(jobs::get(c, job_id)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("get job: {e}")))?
		.ok_or((StatusCode::FORBIDDEN, "no leased scan job for this worker".into()))?;
	if row.state != JobState::Leased || row.worker_id != Some(worker.id()) {
		return Err((StatusCode::FORBIDDEN, "no leased job for this worker".into()));
	}
	if row.kind != JobKind::Scan {
		return Err((StatusCode::BAD_REQUEST, "verify-kind jobs cannot post findings".into()));
	}

	state
		.db
		.with_conn(|c| {
			let tx = c.transaction()?;
			for f in &batch.findings {
				findings::insert_or_ignore(&tx, row.repo_id, row.id, f, now)?;
			}
			tx.commit()?;
			Ok(())
		})
		.map_err(|e: loupe_storage::Error| {
			(StatusCode::INTERNAL_SERVER_ERROR, format!("submit findings: {e}"))
		})?;
	Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/jobs/:id/verdict` — worker submits a verdict (verify jobs only).
pub async fn submit_verdict(
	State(state): State<AppState>, Extension(worker): Extension<AuthedWorker>,
	Path(job_id): Path<i64>, Json(submission): Json<VerdictSubmission>,
) -> Result<StatusCode, (StatusCode, String)> {
	check_version(submission.protocol_version)?;
	let now = now_secs();

	let row = state
		.db
		.with_conn(|c| Ok(jobs::get(c, job_id)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("get job: {e}")))?
		.ok_or((StatusCode::FORBIDDEN, "no leased verify job for this worker".into()))?;
	if row.state != JobState::Leased || row.worker_id != Some(worker.id()) {
		return Err((StatusCode::FORBIDDEN, "no leased job for this worker".into()));
	}
	if row.kind != JobKind::Verify {
		return Err((StatusCode::BAD_REQUEST, "scan-kind jobs cannot post verdicts".into()));
	}
	let target_finding_id = row
		.target_finding_id
		.ok_or((StatusCode::BAD_REQUEST, "verify job missing target finding".into()))?;

	let (verdict_str, notes) = match &submission.verdict {
		loupe_core::Verdict::Confirmed { notes } => ("confirmed", notes.clone()),
		loupe_core::Verdict::Dismissed { notes } => ("dismissed", notes.clone()),
		loupe_core::Verdict::Inconclusive { reason } => ("inconclusive", Some(reason.clone())),
	};
	state
		.db
		.with_conn(|c| {
			c.execute(
				"INSERT INTO finding_verifications
				   (finding_id, job_id, verdict, notes, created_at)
				 VALUES (?1, ?2, ?3, ?4, ?5)",
				(target_finding_id, row.id, verdict_str, &notes, now),
			)?;
			Ok(())
		})
		.map_err(|e: loupe_storage::Error| {
			(StatusCode::INTERNAL_SERVER_ERROR, format!("submit verdict: {e}"))
		})?;
	Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/jobs/:id/complete` — worker terminates the job. On
/// success of a scan, persists `last_scanned_sha` so the next
/// incremental run knows where to pick up.
pub async fn complete(
	State(state): State<AppState>, Extension(worker): Extension<AuthedWorker>,
	Path(job_id): Path<i64>, Json(req): Json<CompleteRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
	check_version(req.protocol_version)?;
	let new_state = match req.outcome {
		CompleteOutcome::Succeeded => JobState::Succeeded,
		CompleteOutcome::Failed => JobState::Failed,
	};
	let now = now_secs();

	let job = state
		.db
		.with_conn(|c| Ok(jobs::get(c, job_id)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("get job: {e}")))?
		.ok_or((StatusCode::FORBIDDEN, "no leased job for this worker".into()))?;
	if job.state != JobState::Leased || job.worker_id != Some(worker.id()) {
		return Err((StatusCode::FORBIDDEN, "no leased job for this worker".into()));
	}

	state
		.db
		.with_conn(|c| {
			let tx = c.transaction()?;
			let updated = jobs::complete(
				&tx,
				job_id,
				worker.id(),
				new_state,
				req.head_sha.as_deref(),
				req.error.as_deref(),
				now,
			)?;
			if !updated {
				// Lease was reaped between our read and write — bail
				// without touching scan_history.
				return Ok(false);
			}
			if matches!(new_state, JobState::Succeeded) && job.kind == JobKind::Scan {
				if let Some(sha) = req.head_sha.as_deref() {
					tx.execute(
						"UPDATE registered_repos
						   SET last_scanned_sha = ?1, last_scanned_at = ?2
						 WHERE id = ?3",
						(sha, now, job.repo_id),
					)?;
				}
				tx.execute(
					"INSERT INTO scan_history
					   (repo_id, job_id, head_sha, base_sha, finding_count, duration_ms, finished_at)
					 SELECT ?1, ?2, ?3, ?4,
					        (SELECT COUNT(*) FROM findings WHERE job_id = ?2),
					        ?5, ?6",
					(
						job.repo_id,
						job_id,
						req.head_sha.as_deref().unwrap_or(""),
						job.since_sha.clone(),
						job.started_at.map(|s| (now - s) * 1_000).unwrap_or(0),
						now,
					),
				)?;
			}
			tx.commit()?;
			Ok(true)
		})
		.map_err(|e: loupe_storage::Error| {
			(StatusCode::INTERNAL_SERVER_ERROR, format!("complete: {e}"))
		})?
		.then_some(())
		.ok_or((StatusCode::CONFLICT, "lease reaped before complete".into()))?;
	Ok(StatusCode::NO_CONTENT)
}
