//! The survey handler: prepare the attempt, run one agent invocation against
//! the survey catalog, and end with the sealed receipt the agent produced or
//! a `complete{failed}` carrying a fixed host reason.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use loupe_proto::review_lease::ReviewLimits;
use loupe_proto::LeaseEnvelope;
use loupe_provenance::{Agent, Server};
use tokio_util::sync::CancellationToken;

use super::deadline::survey_timeout;
use super::prepare::{at, prepare, Preparation, PrepareError, PreparedSurvey};
use super::prompts::survey_prompt;
use super::session::{Clock, SurveySession};
use crate::canary::JobSecurity;
use crate::client::{PhaseError, PhaseJob};
use crate::llm::{LlmBackend, LlmRequest};
use crate::mcp::McpMode;
use crate::runner::{PhaseHeartbeat, Runner};

/// How long the failure report may keep retrying.
const REPORT_WINDOW: Duration = Duration::from_secs(60);

/// Why an attempt ended without a sealed receipt. The text is the whole
/// `complete{failed}` reason; it never carries agent, repository or server
/// text.
// debug-ok: closed host vocabulary only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
	AgentExited,
	HardDeadline,
	InventoryUnsupported,
	CheckoutConflict,
	AuthorityLost,
	Cancelled,
	Quarantined,
	UnsupportedRecipe,
	CheckoutFailed,
	WorkdirTooLarge,
	InventoryMismatch,
	PhaseRequestFailed,
	PromptFailed,
	HostTaskFailed,
}

impl FailureReason {
	pub const fn text(self) -> &'static str {
		match self {
			Self::AgentExited => "agent exited without finalizing",
			Self::HardDeadline => "hard deadline reached",
			Self::InventoryUnsupported => "inventory unsupported",
			Self::CheckoutConflict => "checkout conflict",
			Self::AuthorityLost => "authority lost",
			Self::Cancelled => "job cancelled",
			Self::Quarantined => "injection_suspected",
			Self::UnsupportedRecipe => "survey recipe unsupported",
			Self::CheckoutFailed => "checkout failed",
			Self::WorkdirTooLarge => "checkout exceeds the workdir size cap",
			Self::InventoryMismatch => "inventory progress mismatch",
			Self::PhaseRequestFailed => "phase request failed",
			Self::PromptFailed => "prompt assembly failed",
			Self::HostTaskFailed => "host task failed",
		}
	}

	fn from_prepare(error: &PrepareError) -> Self {
		match error {
			PrepareError::UnsupportedLease => Self::UnsupportedRecipe,
			PrepareError::HardDeadline => Self::HardDeadline,
			PrepareError::Checkout => Self::CheckoutFailed,
			PrepareError::WorkdirTooLarge => Self::WorkdirTooLarge,
			PrepareError::Inventory(_) => Self::InventoryUnsupported,
			PrepareError::CheckoutConflict => Self::CheckoutConflict,
			PrepareError::ManifestMismatch => Self::InventoryMismatch,
			PrepareError::Quarantined => Self::Quarantined,
			PrepareError::Cancelled => Self::Cancelled,
			PrepareError::Internal => Self::HostTaskFailed,
			PrepareError::Phase(error) if denied(error) => Self::AuthorityLost,
			PrepareError::Phase(_) => Self::PhaseRequestFailed,
		}
	}
}

/// How long the one try of a failure report sent at or past the hard
/// deadline may take. It is no longer than the first retry pause, so that
/// report is never retried.
const LAST_TRY: Duration = crate::review::retry::PAUSES[0];

/// The failure report retries for a while, never past the hard deadline.
/// An attempt that ends at or past it still sends the report once.
fn report_deadline(now: SystemTime, hard_deadline: SystemTime) -> SystemTime {
	(now + REPORT_WINDOW).min(hard_deadline.max(now + LAST_TRY))
}

fn denied(error: &PhaseError) -> bool {
	matches!(error, PhaseError::Rejected { status: 403, .. } | PhaseError::Status { status: 403 })
}

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
	// The heartbeat must not race the terminal call into a refusal.
	heartbeat.stop().await;
	let job = PhaseJob {
		job_id,
		capability: &capability,
		deadline: report_deadline(SystemTime::now(), hard_deadline),
	};
	match runner.client().phase_failure_reason(&job, reason).await {
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
		survey: Some(session.clone()),
		token_budget: prepared.limits.token_budget,
		job_capability: Some(prepared.job_capability.clone()),
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_failure_report_stops_at_the_hard_deadline() {
		let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
		let hard = now + Duration::from_secs(10);
		assert_eq!(report_deadline(now, hard), hard);
		let far = now + Duration::from_secs(3_600);
		assert_eq!(report_deadline(now, far), now + REPORT_WINDOW);
		let passed = now - Duration::from_secs(10);
		let once = report_deadline(now, passed);
		assert_eq!(once, now + LAST_TRY, "a report past the hard deadline is still sent");
		let since = |t: SystemTime| t.duration_since(SystemTime::UNIX_EPOCH).unwrap();
		assert_eq!(
			crate::review::retry::classify(
				crate::review::retry::Failure::Timeout,
				1,
				since(now),
				since(once)
			),
			crate::review::retry::Decision::Final,
			"and never retried"
		);
	}

	#[test]
	fn failure_reasons_are_fixed_host_text() {
		let reasons = [
			FailureReason::AgentExited,
			FailureReason::HardDeadline,
			FailureReason::InventoryUnsupported,
			FailureReason::CheckoutConflict,
			FailureReason::AuthorityLost,
			FailureReason::Cancelled,
			FailureReason::Quarantined,
			FailureReason::UnsupportedRecipe,
			FailureReason::CheckoutFailed,
			FailureReason::WorkdirTooLarge,
			FailureReason::InventoryMismatch,
			FailureReason::PhaseRequestFailed,
			FailureReason::PromptFailed,
			FailureReason::HostTaskFailed,
		];
		let texts: std::collections::BTreeSet<_> = reasons.iter().map(|r| r.text()).collect();
		assert_eq!(texts.len(), reasons.len(), "each reason has its own text");
		assert_eq!(FailureReason::Quarantined.text(), crate::canary::JobQuarantined.to_string());
		let denied = PrepareError::Phase(PhaseError::Status { status: 403 });
		assert_eq!(FailureReason::from_prepare(&denied), FailureReason::AuthorityLost);
		let conflict = PrepareError::CheckoutConflict;
		assert_eq!(FailureReason::from_prepare(&conflict), FailureReason::CheckoutConflict);
	}
}
