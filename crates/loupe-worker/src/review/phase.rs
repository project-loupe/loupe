//! What every phase handler shares: one agent invocation against the
//! phase's catalog, ended by the sealed receipt the agent produced or a
//! `complete{failed}` carrying a fixed host reason.

use std::future::Future;
use std::sync::Arc;
use std::time::SystemTime;

use loupe_proto::review_lease::ReviewLimits;
use loupe_proto::{JobCapability, LeaseEnvelope, LeasePayload};
use loupe_provenance::{Agent, Server};
use tokio_util::sync::CancellationToken;

use super::deadline::phase_timeout;
use super::failure::{report, FailureReason};
use super::prepare::at;
use crate::canary::JobSecurity;
use crate::llm::prompt::{JobToolBoundary, Prompt, PromptError};
use crate::llm::{LlmBackend, LlmRequest};
use crate::mcp::PhaseTools;
use crate::runner::{CheckedOutWorktree, PhaseHeartbeat, Runner};

/// How an attempt ended when it did not fail.
pub(super) enum Ended {
	Sealed,
	/// The server deferred the pin and already ended the job.
	Deferred,
}

/// What a failure report needs from the lease, read before preparation
/// consumes it.
pub(super) struct Lease {
	job_id: i64,
	capability: JobCapability,
	hard_deadline: SystemTime,
}

impl Lease {
	/// `None` for a lease that is not a phase lease.
	pub(super) fn new(env: &LeaseEnvelope<Agent, Server>) -> Option<Self> {
		let limits = limits(&env.payload)?;
		Some(Self::with_deadline(env, at(limits.hard_deadline_at)))
	}

	/// A lease whose hard deadline has passed, so its failure is reported
	/// once and never retried.
	pub(super) fn expired(env: &LeaseEnvelope<Agent, Server>) -> Self {
		Self::with_deadline(env, SystemTime::UNIX_EPOCH)
	}

	fn with_deadline(env: &LeaseEnvelope<Agent, Server>, hard_deadline: SystemTime) -> Self {
		Self { job_id: env.job_id, capability: env.job_capability.clone(), hard_deadline }
	}
}

/// The deadlines and quotas of a phase lease; `None` for any other lease.
pub(crate) fn limits(payload: &LeasePayload<Agent, Server>) -> Option<&ReviewLimits> {
	match payload {
		LeasePayload::ReviewSurvey(lease) => Some(&lease.provenance.limits),
		LeasePayload::ReviewDrilldown(lease) => Some(&lease.provenance.limits),
		_ => None,
	}
}

/// Run `attempt` for the `name` phase to its end, reporting a failure
/// itself. The legacy completion is never sent for a phase lease.
pub(super) async fn run(
	runner: &Runner, name: &'static str, lease: Lease,
	attempt: impl Future<Output = Result<Ended, FailureReason>>, cancel: &CancellationToken,
	security: &JobSecurity, heartbeat: &PhaseHeartbeat,
) {
	let Lease { job_id, capability, hard_deadline } = lease;
	let ended = if cancel.is_cancelled() { Err(FailureReason::Cancelled) } else { attempt.await };
	let reason = match ended {
		Ok(Ended::Sealed) => {
			debug_assert!(
				heartbeat.stop_token().is_cancelled(),
				"a sealed attempt must not heartbeat"
			);
			tracing::info!(job_id, "{name} finalized");
			return;
		},
		Ok(Ended::Deferred) => {
			tracing::info!(job_id, "{name} pin deferred; the server ended the job");
			return;
		},
		Err(_) if security.is_quarantined() => FailureReason::Quarantined,
		Err(FailureReason::AuthorityLost) => FailureReason::AuthorityLost,
		Err(_) if cancel.is_cancelled() => FailureReason::Cancelled,
		Err(reason) => reason,
	};
	match report(runner, job_id, &capability, hard_deadline, heartbeat, reason).await {
		Ok(control) => {
			tracing::warn!(job_id, reason = reason.text(), state = ?control.state, "{name} failed");
		},
		Err(_) => tracing::warn!(job_id, reason = reason.text(), "{name} failure report failed"),
	}
}

/// The prepared attempt an agent is launched into.
pub(super) struct Launch<'a> {
	pub worktree: &'a CheckedOutWorktree,
	pub repo_id: i64,
	pub job_capability: &'a JobCapability,
	pub limits: &'a ReviewLimits,
}

/// Launch the agent once against `tools` and read how it ended. A sealed
/// receipt is the attempt's success whatever the agent did after.
pub(super) async fn invoke(
	backend: &Arc<dyn LlmBackend>, launch: Launch<'_>, tools: PhaseTools,
	prompt: impl FnOnce(SystemTime) -> Result<Prompt, PromptError>, security: &Arc<JobSecurity>,
	cancel: CancellationToken,
) -> Result<Ended, FailureReason> {
	let now = tools.phase().now();
	let timeout = phase_timeout(launch.limits, now).ok_or(FailureReason::HardDeadline)?;
	let prompt = prompt(now).map_err(|_| FailureReason::PromptFailed)?;
	let tool_boundary = JobToolBoundary::new().map_err(|_| FailureReason::PromptFailed)?;
	let state = tools.clone();
	let request = LlmRequest {
		sandbox_workdir: launch.worktree.sandbox_path(),
		security: security.clone(),
		tool_boundary,
		prompt,
		workdir: launch.worktree.path().to_owned(),
		timeout,
		cancel,
		repo_id: Some(launch.repo_id),
		mcp_scope: crate::mcp::McpScope::Phase(tools),
		token_budget: launch.limits.token_budget,
		job_capability: Some(launch.job_capability.clone()),
	};
	let _ = backend.run(request).await;
	if state.sealed() {
		return Ok(Ended::Sealed);
	}
	let phase = state.phase();
	Err(if phase.authority_lost() {
		FailureReason::AuthorityLost
	} else if phase.hard_deadline_reached() {
		FailureReason::HardDeadline
	} else {
		FailureReason::AgentExited
	})
}
