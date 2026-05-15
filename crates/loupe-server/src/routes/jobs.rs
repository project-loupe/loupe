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

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use loupe_core::{FindingState, JobKind, JobState};
use loupe_proto::{
	CompleteOutcome, CompleteRequest, FindingsBatch, HeartbeatRequest, HeartbeatResponse, JobInfo,
	LeaseEnvelope, LeasePayload, LeaseRequest, LeaseResponse, ScanRequest, ScanResponse,
	VerdictSubmission, PROTOCOL_VERSION,
};
use loupe_storage::jobs::{self, JobRow, NewJob, DEFAULT_LEASE_SECONDS};
use loupe_storage::{findings, repos, secrets};

use crate::auth::AuthedWorker;
use crate::reporters;
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

	state.job_arrived.notify_waiters();
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

/// Maximum wait the server will honour on a single long-poll, even if
/// the client asked for longer. Picked under the typical proxy idle
/// timeout so we never hold a connection long enough for an
/// intermediary to kill it.
const MAX_LEASE_WAIT_SECS: u32 = 60;

/// How long a finding can sit in `validating` before the deadline
/// reaper steps in. 1 hour is a healthy budget for an LLM verifier;
/// large enough to absorb queue backpressure, small enough that a
/// stuck finding doesn't sit invisible for days.
const DEFAULT_VALIDATING_BUDGET_SECS: i64 = 3_600;

/// `POST /v1/jobs/lease` — worker pulls the next available job. Honours
/// `wait_seconds` for server-side long-polling: when the queue is empty
/// the server waits on `state.job_arrived` for up to that many seconds
/// (capped) before returning `Empty`. `wait_seconds = 0` is the
/// historical poll-and-return-empty behaviour.
pub async fn lease(
	State(state): State<AppState>, Extension(worker): Extension<AuthedWorker>,
	Json(req): Json<LeaseRequest>,
) -> Result<Json<LeaseResponse>, (StatusCode, String)> {
	check_version(req.protocol_version)?;
	// A worker is eligible for verify jobs iff it advertised at least
	// one `verify:*` capability. Fine-grained tag matching (e.g.
	// `verify:secrets` only matches secret-flavoured verify jobs) is a
	// follow-up; today we only have one tag in flight.
	let accepts_verify = req.capabilities.iter().any(|c| c.starts_with("verify:"));

	if let Some(env) = try_lease(&state, worker.id(), accepts_verify)? {
		return Ok(Json(LeaseResponse::Lease(Box::new(env))));
	}
	if req.wait_seconds == 0 {
		return Ok(Json(LeaseResponse::Empty { protocol_version: PROTOCOL_VERSION }));
	}

	let wait = std::time::Duration::from_secs(req.wait_seconds.min(MAX_LEASE_WAIT_SECS) as u64);
	let deadline = tokio::time::Instant::now() + wait;
	loop {
		// Subscribe to notify *before* the lease check so we can't
		// miss a notify_waiters fired between our two attempts.
		let notified = state.job_arrived.notified();
		tokio::pin!(notified);

		if let Some(env) = try_lease(&state, worker.id(), accepts_verify)? {
			return Ok(Json(LeaseResponse::Lease(Box::new(env))));
		}

		let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
		if remaining.is_zero() {
			return Ok(Json(LeaseResponse::Empty { protocol_version: PROTOCOL_VERSION }));
		}
		tokio::select! {
			_ = &mut notified => {
				// New job — loop and try the lease again.
			}
			_ = tokio::time::sleep(remaining) => {
				return Ok(Json(LeaseResponse::Empty { protocol_version: PROTOCOL_VERSION }));
			}
		}
	}
}

/// One non-blocking lease attempt. `None` means no eligible job is
/// queued. `accepts_verify` gates verify-kind jobs.
fn try_lease(
	state: &AppState, worker_id: i64, accepts_verify: bool,
) -> Result<Option<LeaseEnvelope>, (StatusCode, String)> {
	let now = now_secs();
	let row = state
		.db
		.with_conn(|c| {
			Ok(jobs::lease_next(c, worker_id, accepts_verify, now, DEFAULT_LEASE_SECONDS)?)
		})
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("lease: {e}")))?;
	let Some(row) = row else { return Ok(None) };
	let env = build_lease_envelope(state, &row)
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("envelope: {e}")))?;
	Ok(Some(env))
}

fn build_lease_envelope(state: &AppState, row: &JobRow) -> anyhow::Result<LeaseEnvelope> {
	let repo = state
		.db
		.with_conn(|c| Ok(repos::get(c, row.repo_id)?))?
		.ok_or_else(|| anyhow::anyhow!("repo {} for leased job not found", row.repo_id))?;
	// No clone-side credential is stored separately. We deliberately do
	// not ship the reporting PAT to the worker.
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
				poc_unified: finding_row.poc_unified,
				fingerprint: finding_row.fingerprint,
			};
			LeasePayload::Verify { finding_id: target_id, finding }
		},
	};

	Ok(LeaseEnvelope {
		protocol_version: PROTOCOL_VERSION,
		job_id: row.id,
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
	Path(job_id): Path<i64>, body: Bytes,
) -> Result<Json<HeartbeatResponse>, (StatusCode, String)> {
	if !body.is_empty() {
		let req: HeartbeatRequest = serde_json::from_slice(&body)
			.map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid heartbeat body: {e}")))?;
		check_version(req.protocol_version)?;
	}
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

	// Look up the repo's verification policy so the inserted findings
	// carry the right verification_required flag.
	let repo = state
		.db
		.with_conn(|c| Ok(repos::get(c, row.repo_id)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("get repo: {e}")))?
		.ok_or((StatusCode::INTERNAL_SERVER_ERROR, "repo for leased job missing".to_owned()))?;
	let verification_required = repo.verification_enabled;

	state
		.db
		.with_conn(|c| {
			let tx = c.transaction()?;
			for f in &batch.findings {
				findings::insert_or_ignore(
					&tx,
					row.repo_id,
					row.id,
					f,
					verification_required,
					now,
				)?;
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
		loupe_core::Verdict::Confirmed { notes, .. } => ("confirmed", notes.clone()),
		loupe_core::Verdict::Dismissed { notes } => ("dismissed", notes.clone()),
		loupe_core::Verdict::Inconclusive { reason } => ("inconclusive", Some(reason.clone())),
	};
	// Patches only ride on Confirmed verdicts (pinned by the
	// `Verdict` type itself); pull the diff out here so the closure
	// below can borrow it cleanly without re-matching on the variant.
	let patch_to_attach: Option<(&str, &str)> = match &submission.verdict {
		loupe_core::Verdict::Confirmed { patch: Some(p), .. } => {
			Some((p.patch_unified.as_str(), p.notes.as_str()))
		},
		_ => None,
	};
	let by_cn = worker.worker.name.clone();
	// Resolve effective approval mode for this finding's repo before
	// the tx so the rollup can route a `confirmed` verdict either to
	// `confirmed` (immediate dispatch) or `awaiting_approval` (parked
	// for human sign-off).
	let server_default = state.require_approval_default;
	let require_approval = state
		.db
		.with_conn(|c| Ok(repos::get(c, row.repo_id)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("get repo: {e}")))?
		.map(|r| r.effective_require_approval(server_default))
		.unwrap_or(false);
	// Insert the verdict + apply the rollup policy in a single
	// transaction so a concurrent verdict from a second verifier
	// can't catch us mid-state-flip and observe "confirmed AND
	// dismissed" simultaneously.
	let new_state: Option<&str> = state
		.db
		.with_conn(|c| {
			let tx = c.transaction()?;
			tx.execute(
				"INSERT INTO finding_verifications
				   (finding_id, job_id, verdict, notes, created_at)
				 VALUES (?1, ?2, ?3, ?4, ?5)",
				(target_finding_id, row.id, verdict_str, &notes, now),
			)?;
			// Attach a verifier-proposed patch (when Confirmed and one
			// was supplied) inside the same tx as the verdict insert,
			// so by the time `dispatch_finding` runs after tx.commit
			// the GitHub reporter sees the patch in the row. The
			// storage layer's NULL-check guards against a second
			// verifier overwriting an earlier patch — first writer
			// wins, the audit columns pin provenance to that writer.
			if let Some((patch_unified, patch_notes)) = patch_to_attach {
				let _ = loupe_storage::findings::attach_proposed_patch(
					&tx,
					target_finding_id,
					patch_unified,
					patch_notes,
					&by_cn,
					now,
				)?;
			}
			// Bail out early if the finding was already terminal — a
			// concurrent reaper or earlier verdict beat us here.
			let current: String = tx.query_row(
				"SELECT state FROM findings WHERE id = ?1",
				[target_finding_id],
				|r| r.get(0),
			)?;
			if current != "validating" {
				tx.commit()?;
				return Ok(None);
			}
			// Default rollup policy:
			//   any 'dismissed'  ⇒ dismissed
			//   else any 'confirmed' ⇒ confirmed
			//   else stay 'validating' (waiting for more verdicts or
			//        the deadline reaper).
			let any_dismissed: bool = tx.query_row(
				"SELECT EXISTS(SELECT 1 FROM finding_verifications
				                 WHERE finding_id = ?1 AND verdict = 'dismissed')",
				[target_finding_id],
				|r| r.get(0),
			)?;
			let next_state: Option<&'static str> = if any_dismissed {
				Some("dismissed")
			} else {
				let any_confirmed: bool = tx.query_row(
					"SELECT EXISTS(SELECT 1 FROM finding_verifications
					                 WHERE finding_id = ?1 AND verdict = 'confirmed')",
					[target_finding_id],
					|r| r.get(0),
				)?;
				if any_confirmed {
					if require_approval {
						Some("awaiting_approval")
					} else {
						Some("confirmed")
					}
				} else {
					None
				}
			};
			if let Some(s) = next_state {
				// `awaiting_approval` doesn't stamp anything yet —
				// `approved_at` lands later when the operator approves.
				let stamp_clause = match s {
					"confirmed" => ", confirmed_at = ?2",
					"dismissed" => ", dismissed_at = ?2",
					_ => "",
				};
				tx.execute(
					&format!("UPDATE findings SET state = ?1{stamp_clause} WHERE id = ?3"),
					(s, now, target_finding_id),
				)?;
			}
			tx.commit()?;
			Ok(next_state)
		})
		.map_err(|e: loupe_storage::Error| {
			(StatusCode::INTERNAL_SERVER_ERROR, format!("submit verdict: {e}"))
		})?;

	if matches!(new_state, Some("confirmed")) {
		if let Err(e) = dispatch_finding(&state, target_finding_id, now).await {
			tracing::warn!(
				finding_id = target_finding_id,
				error = %format_error_chain(&e),
				"dispatch on verdict-confirm failed"
			);
		}
	}
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

	// Resolve effective approval mode once, outside the tx, so the
	// state-transition SQL can branch on it. `dispatch_for_job` later
	// also reads the repo, but that's a separate call path.
	let server_default = state.require_approval_default;
	let require_approval = if matches!(new_state, JobState::Succeeded) && job.kind == JobKind::Scan
	{
		state
			.db
			.with_conn(|c| Ok(repos::get(c, job.repo_id)?))
			.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("get repo: {e}")))?
			.map(|r| r.effective_require_approval(server_default))
			.unwrap_or(false)
	} else {
		false
	};
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

				// Transition each finding produced by this scan. The
				// auto-pass branch (verification_required = 0) lands on
				// either `confirmed` (dispatcher picks up later) or
				// `awaiting_approval` (parked until a human runs
				// `loupectl finding approve`), driven by the repo's
				// effective `require_approval`. `confirmed_at` is only
				// stamped on the `confirmed` path — `awaiting_approval`
				// stamps `approved_at` later when (and if) approved.
				if require_approval {
					tx.execute(
						"UPDATE findings
						   SET state = 'awaiting_approval'
						 WHERE job_id = ?1 AND verification_required = 0 AND state = 'pending'",
						[job_id],
					)?;
				} else {
					tx.execute(
						"UPDATE findings
						   SET state = 'confirmed', confirmed_at = ?1
						 WHERE job_id = ?2 AND verification_required = 0 AND state = 'pending'",
						(now, job_id),
					)?;
				}
				tx.execute(
					"UPDATE findings
					   SET state = 'validating', validating_deadline = ?1
					 WHERE job_id = ?2 AND verification_required = 1 AND state = 'pending'",
					(now + DEFAULT_VALIDATING_BUDGET_SECS, job_id),
				)?;

				// Enqueue one verify job per finding now in 'validating'
				// for this scan. We use a stand-alone INSERT…SELECT so
				// the verify-job rows go in inside the same transaction
				// as the state flips.
				tx.execute(
					"INSERT INTO jobs
					   (repo_id, kind, state, incremental, parent_job_id,
					    target_finding_id, enqueued_at)
					 SELECT ?1, 'verify', 'queued', 0, ?2, id, ?3
					 FROM findings
					 WHERE job_id = ?2 AND state = 'validating'",
					(job.repo_id, job_id, now),
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

	if matches!(new_state, JobState::Succeeded) && job.kind == JobKind::Scan {
		// Wake long-pollers in case any verify jobs were just enqueued
		// (also covers the auto-confirmed-only case — extra notify is
		// harmless).
		state.job_arrived.notify_waiters();
		if let Err(e) = dispatch_for_job(&state, job.repo_id, job.id, now).await {
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

/// Dispatch a single finding that has just transitioned to `confirmed`
/// (typical caller: the verdict handler after a verify worker confirms
/// it, or the approval handler after a human signs off). Skips
/// findings that aren't in the right state — defends against
/// double-dispatch races.
pub(super) async fn dispatch_finding(
	state: &AppState, finding_id: i64, now: i64,
) -> anyhow::Result<()> {
	let row = state
		.db
		.with_conn(|c| Ok(findings::get(c, finding_id)?))?
		.ok_or_else(|| anyhow::anyhow!("finding {finding_id} disappeared before dispatch"))?;
	if row.state != FindingState::Confirmed {
		anyhow::bail!("finding {finding_id} is not confirmed; current state is {}", row.state);
	}
	let repo = state.db.with_conn(|c| Ok(repos::get(c, row.repo_id)?))?.ok_or_else(|| {
		anyhow::anyhow!("repo {} for finding {} missing", row.repo_id, finding_id)
	})?;
	dispatch_confirmed_rows(state, &repo, vec![row], DispatchScope::Finding(finding_id), now)
		.await?;
	Ok(())
}

/// After a scan succeeds, ferry its (auto-confirmed) findings through
/// the appropriate reporter. Marks `findings.reported_at` on success
/// so later scans that re-emit the same fingerprint don't re-notify
/// (UNIQUE(repo_id, fingerprint) already prevents the row insert;
/// reported_at is the "we told someone" stamp).
async fn dispatch_for_job(
	state: &AppState, repo_id: i64, job_id: i64, now: i64,
) -> anyhow::Result<()> {
	let repo = state
		.db
		.with_conn(|c| Ok(repos::get(c, repo_id)?))?
		.ok_or_else(|| anyhow::anyhow!("repo {repo_id} disappeared before dispatch"))?;
	let rows = state.db.with_conn(|c| Ok(findings::list_for_job(c, job_id)?))?;
	dispatch_confirmed_rows(state, &repo, rows, DispatchScope::Job(job_id), now).await?;
	Ok(())
}

#[derive(Debug, Clone, Copy)]
enum DispatchScope {
	Finding(i64),
	Job(i64),
}

async fn dispatch_confirmed_rows(
	state: &AppState, repo: &repos::RepoRow, rows: Vec<findings::FindingRow>, scope: DispatchScope,
	now: i64,
) -> anyhow::Result<()> {
	use loupe_core::ReportingDestination;

	let confirmed_rows: Vec<_> =
		rows.into_iter().filter(|r| r.state == FindingState::Confirmed).collect();
	if confirmed_rows.is_empty() {
		return Ok(());
	}
	let ids: Vec<i64> = confirmed_rows.iter().map(|r| r.id).collect();
	let findings_for_report: Vec<_> = confirmed_rows.into_iter().map(finding_from_row).collect();

	if matches!(repo.reporting, ReportingDestination::Manual) {
		match scope {
			DispatchScope::Finding(finding_id) => tracing::info!(
				finding_id,
				"manual mode: finding left confirmed without external dispatch"
			),
			DispatchScope::Job(job_id) => tracing::info!(
				job_id,
				count = ids.len(),
				"manual mode: findings left confirmed without external dispatch"
			),
		}
		return Ok(());
	}

	let pat = reporter_secret(state, repo)?;
	let reporter =
		reporters::select(repo, state.github_reporter.clone(), state.email_reporter.clone())
			.ok_or_else(|| anyhow::anyhow!("no reporter for destination kind"))?;
	let receipt = reporter.dispatch(repo, &findings_for_report, &pat).await?;
	match scope {
		DispatchScope::Finding(finding_id) => tracing::info!(
			finding_id,
			external_id = receipt.external_id.as_deref(),
			"dispatched finding"
		),
		DispatchScope::Job(job_id) => tracing::info!(
			job_id,
			count = findings_for_report.len(),
			external_id = receipt.external_id.as_deref(),
			"dispatched findings"
		),
	}

	mark_reported(state, &ids, now)?;
	Ok(())
}

fn reporter_secret(state: &AppState, repo: &repos::RepoRow) -> anyhow::Result<String> {
	use loupe_core::ReportingDestination;

	match &repo.reporting {
		ReportingDestination::GithubIssue { pat_secret_id, .. } => {
			let bytes = state
				.db
				.with_conn(|c| Ok(secrets::read(c, *pat_secret_id)?))?
				.ok_or_else(|| anyhow::anyhow!("pat secret {pat_secret_id} not found"))?;
			String::from_utf8(bytes).map_err(|e| anyhow::anyhow!("pat is not utf-8: {e}"))
		},
		ReportingDestination::Email { .. } => Ok(String::new()),
		ReportingDestination::Manual => unreachable!("Manual handled before reporter_secret"),
	}
}

fn finding_from_row(row: findings::FindingRow) -> loupe_core::Finding {
	loupe_core::Finding {
		scanner_id: row.scanner_id,
		severity: row.severity,
		title: row.title,
		description: row.description,
		file_path: row.file_path,
		line_start: row.line_start,
		line_end: row.line_end,
		cwe: row.cwe,
		patch_unified: row.patch_unified,
		poc_unified: row.poc_unified,
		fingerprint: row.fingerprint,
	}
}

fn mark_reported(state: &AppState, ids: &[i64], now: i64) -> anyhow::Result<usize> {
	let n = state.db.with_conn(|c| {
		let tx = c.transaction()?;
		let mut n = 0usize;
		for id in ids {
			n += tx.execute(
				"UPDATE findings SET reported_at = ?1, state = 'reported'
				 WHERE id = ?2 AND state = 'confirmed'",
				(now, id),
			)?;
		}
		tx.commit()?;
		Ok(n)
	})?;
	Ok(n)
}
