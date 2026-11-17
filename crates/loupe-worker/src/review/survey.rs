//! The survey handler: prepare the attempt, run one agent invocation against
//! the survey catalog, and end with the sealed receipt the agent produced or
//! a `complete{failed}` carrying a fixed host reason.

use std::sync::Arc;

use loupe_proto::review_lease::ReviewLimits;
use loupe_proto::LeaseEnvelope;
use loupe_provenance::{Agent, Server};
use tokio_util::sync::CancellationToken;

use super::deadline::survey_timeout;
use super::failure::{report, FailureReason};
use super::prepare::{at, prepare, Preparation, PreparedSurvey};
use super::prompts::survey_prompt;
use super::session::{Clock, SurveySession};
use crate::canary::JobSecurity;
use crate::llm::{LlmBackend, LlmRequest};
use crate::mcp::McpMode;
use crate::runner::{PhaseHeartbeat, Runner};

/// How an attempt ended when it did not fail.
enum Ended {
	Sealed,
	Deferred,
}

/// Run one survey lease to its end, reporting a failure itself. The legacy
/// completion is never sent for a survey.
pub(crate) async fn run(
	runner: &Runner, backend: &Arc<dyn LlmBackend>, env: LeaseEnvelope<Agent, Server>,
	limits: &ReviewLimits, cancel: CancellationToken, security: Arc<JobSecurity>,
	heartbeat: PhaseHeartbeat,
) {
	let clock = runner.survey_clock();
	let job_id = env.job_id;
	let capability = env.job_capability.clone();
	let hard_deadline = at(limits.hard_deadline_at);
	let ended = attempt(runner, backend, clock, env, &cancel, &security, &heartbeat).await;
	let reason = match ended {
		Ok(Ended::Sealed) => {
			debug_assert!(
				heartbeat.stop_token().is_cancelled(),
				"a sealed attempt must not heartbeat"
			);
			tracing::info!(job_id, "survey finalized");
			return;
		},
		Ok(Ended::Deferred) => {
			tracing::info!(job_id, "survey pin deferred; the server ended the job");
			return;
		},
		Err(_) if security.is_quarantined() => FailureReason::Quarantined,
		Err(FailureReason::AuthorityLost) => FailureReason::AuthorityLost,
		Err(_) if cancel.is_cancelled() => FailureReason::Cancelled,
		Err(reason) => reason,
	};
	match report(runner, job_id, &capability, hard_deadline, &heartbeat, reason).await {
		Ok(control) => {
			tracing::warn!(job_id, reason = reason.text(), state = ?control.state, "survey failed");
		},
		Err(_) => tracing::warn!(job_id, reason = reason.text(), "survey failure report failed"),
	}
}

async fn attempt(
	runner: &Runner, backend: &Arc<dyn LlmBackend>, clock: &Clock,
	env: LeaseEnvelope<Agent, Server>, cancel: &CancellationToken, security: &Arc<JobSecurity>,
	heartbeat: &PhaseHeartbeat,
) -> Result<Ended, FailureReason> {
	if cancel.is_cancelled() {
		return Err(FailureReason::Cancelled);
	}
	let prepared = match prepare(runner, env, security, cancel).await {
		Ok(Preparation::Ready(prepared)) => prepared,
		Ok(Preparation::Deferred) => return Ok(Ended::Deferred),
		Err(error) => return Err(FailureReason::from_prepare(&error)),
	};
	let agent_cancel = cancel.child_token();
	let session = Arc::new(
		SurveySession::from_prepared(&prepared, clock.clone(), agent_cancel.clone())
			.with_heartbeat(heartbeat.stop_token()),
	);
	let request = launch(&prepared, &session, security, agent_cancel)?;
	// A sealed receipt is the attempt's success whatever the agent did after.
	let _ = backend.run(request).await;
	if session.receipt().is_some() {
		return Ok(Ended::Sealed);
	}
	Err(if session.authority_lost() {
		FailureReason::AuthorityLost
	} else if session.hard_deadline_reached() {
		FailureReason::HardDeadline
	} else {
		FailureReason::AgentExited
	})
}

fn launch(
	prepared: &PreparedSurvey, session: &Arc<SurveySession>, security: &Arc<JobSecurity>,
	cancel: CancellationToken,
) -> Result<LlmRequest, FailureReason> {
	let now = session.now();
	let timeout = survey_timeout(&prepared.limits, now).ok_or(FailureReason::HardDeadline)?;
	let prompt = survey_prompt(prepared, now).map_err(|_| FailureReason::PromptFailed)?;
	let tool_boundary =
		crate::llm::prompt::JobToolBoundary::new().map_err(|_| FailureReason::PromptFailed)?;
	Ok(LlmRequest {
		sandbox_workdir: prepared.worktree.sandbox_path(),
		security: security.clone(),
		tool_boundary,
		prompt,
		workdir: prepared.worktree.path().to_owned(),
		timeout,
		cancel,
		repo_id: Some(prepared.repo_id),
		mcp_mode: McpMode::Survey,
		phase: Some(crate::mcp::PhaseTools::Survey(session.clone())),
		token_budget: prepared.limits.token_budget,
		job_capability: Some(prepared.job_capability.clone()),
	})
}
