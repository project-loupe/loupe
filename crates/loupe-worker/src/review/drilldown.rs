//! The drilldown handler: check out and pin the generation commit, then run
//! one agent invocation against the drilldown catalog.

use std::sync::Arc;

use loupe_proto::LeaseEnvelope;
use loupe_provenance::{Agent, Server};
use tokio_util::sync::CancellationToken;

use super::failure::FailureReason;
use super::phase::{self, Ended, Launch, Lease};
use super::prepare::prepare_drilldown;
use super::prompts::drilldown_prompt;
use super::session::DrilldownSession;
use crate::canary::JobSecurity;
use crate::llm::LlmBackend;
use crate::mcp::PhaseTools;
use crate::runner::{PhaseHeartbeat, Runner};

/// Run one drilldown lease to its end, reporting a failure itself.
pub(crate) async fn run(
	runner: &Runner, backend: &Arc<dyn LlmBackend>, env: LeaseEnvelope<Agent, Server>,
	cancel: CancellationToken, security: Arc<JobSecurity>, heartbeat: PhaseHeartbeat,
) {
	// Dispatch passes only phase leases.
	let lease = Lease::new(&env).unwrap_or_else(|| Lease::expired(&env));
	let attempt = attempt(runner, backend, env, &cancel, &security, &heartbeat);
	phase::run(runner, "drilldown", lease, attempt, &cancel, &security, &heartbeat).await;
}

async fn attempt(
	runner: &Runner, backend: &Arc<dyn LlmBackend>, env: LeaseEnvelope<Agent, Server>,
	cancel: &CancellationToken, security: &Arc<JobSecurity>, heartbeat: &PhaseHeartbeat,
) -> Result<Ended, FailureReason> {
	let prepared = prepare_drilldown(runner, env, security, cancel)
		.await
		.map_err(|e| FailureReason::from_prepare(&e))?;
	let agent_cancel = cancel.child_token();
	let session = Arc::new(
		DrilldownSession::from_prepared(
			&prepared,
			runner.phase_clock().clone(),
			agent_cancel.clone(),
		)
		.with_heartbeat(heartbeat.stop_token()),
	);
	let launch = Launch {
		worktree: &prepared.worktree,
		repo_id: prepared.repo_id,
		job_capability: &prepared.job_capability,
		limits: &prepared.limits,
	};
	let prompt = |now| drilldown_prompt(&prepared, now);
	phase::invoke(backend, launch, PhaseTools::Drilldown(session), prompt, security, agent_cancel)
		.await
}
