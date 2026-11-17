//! The survey handler: prepare the attempt, then run one agent invocation
//! against the survey catalog.

use std::sync::Arc;

use loupe_proto::LeaseEnvelope;
use loupe_provenance::{Agent, Server};
use tokio_util::sync::CancellationToken;

use super::failure::FailureReason;
use super::phase::{self, Ended, Launch, Lease};
use super::prepare::{prepare, Preparation};
use super::prompts::survey_prompt;
use super::session::SurveySession;
use crate::canary::JobSecurity;
use crate::llm::LlmBackend;
use crate::mcp::PhaseTools;
use crate::runner::{PhaseHeartbeat, Runner};

/// Run one survey lease to its end, reporting a failure itself.
pub(crate) async fn run(
	runner: &Runner, backend: &Arc<dyn LlmBackend>, env: LeaseEnvelope<Agent, Server>,
	cancel: CancellationToken, security: Arc<JobSecurity>, heartbeat: PhaseHeartbeat,
) {
	let lease = Lease::new(&env);
	let attempt = attempt(runner, backend, env, &cancel, &security, &heartbeat);
	phase::run(runner, "survey", lease, attempt, &cancel, &security, &heartbeat).await;
}

async fn attempt(
	runner: &Runner, backend: &Arc<dyn LlmBackend>, env: LeaseEnvelope<Agent, Server>,
	cancel: &CancellationToken, security: &Arc<JobSecurity>, heartbeat: &PhaseHeartbeat,
) -> Result<Ended, FailureReason> {
	let prepared = match prepare(runner, env, security, cancel).await {
		Ok(Preparation::Ready(prepared)) => prepared,
		Ok(Preparation::Deferred) => return Ok(Ended::Deferred),
		Err(error) => return Err(FailureReason::from_prepare(&error)),
	};
	let agent_cancel = cancel.child_token();
	let session = Arc::new(
		SurveySession::from_prepared(&prepared, runner.phase_clock().clone(), agent_cancel.clone())
			.with_heartbeat(heartbeat.stop_token()),
	);
	let launch = Launch {
		worktree: &prepared.worktree,
		repo_id: prepared.repo_id,
		job_capability: &prepared.job_capability,
		limits: &prepared.limits,
	};
	let prompt = |now| survey_prompt(&prepared, now);
	phase::invoke(backend, launch, PhaseTools::Survey(session), prompt, security, agent_cancel)
		.await
}
