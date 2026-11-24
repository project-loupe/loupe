//! How a review-phase attempt that ended without a sealed receipt is
//! reported: a closed failure vocabulary and the `complete{failed}` call.

use std::time::{Duration, SystemTime};

use loupe_proto::review_lifecycle::PhaseControlResponse;
use loupe_proto::JobCapability;

use super::prepare::PrepareError;
use crate::client::{PhaseError, PhaseJob};
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

	pub(crate) fn from_prepare(error: &PrepareError) -> Self {
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

	/// For a phase that works on one subject of a sealed generation. Its pin
	/// never defers and the lease kind is checked by dispatch, so an
	/// unsupported lease here is a server response the host refuses.
	pub(crate) fn from_subject_prepare(error: &PrepareError) -> Self {
		match error {
			PrepareError::UnsupportedLease => Self::PhaseRequestFailed,
			other => Self::from_prepare(other),
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

/// Stop the heartbeat and report the attempt as failed with `reason`,
/// retrying until [`report_deadline`].
pub(crate) async fn report(
	runner: &Runner, job_id: i64, capability: &JobCapability, hard_deadline: SystemTime,
	heartbeat: &PhaseHeartbeat, reason: FailureReason,
) -> Result<PhaseControlResponse, PhaseError> {
	// The heartbeat must not race the terminal call into a refusal.
	heartbeat.stop().await;
	let job = PhaseJob {
		job_id,
		capability,
		deadline: report_deadline(SystemTime::now(), hard_deadline),
	};
	runner.client().phase_failure_reason(&job, reason).await
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

	#[test]
	fn only_a_survey_reports_an_unsupported_recipe() {
		let unsupported = PrepareError::UnsupportedLease;
		let subject = FailureReason::from_subject_prepare;
		assert_eq!(FailureReason::from_prepare(&unsupported), FailureReason::UnsupportedRecipe);
		assert_eq!(subject(&unsupported), FailureReason::PhaseRequestFailed);
		let conflict = PrepareError::CheckoutConflict;
		assert_eq!(subject(&conflict), FailureReason::CheckoutConflict);
	}
}
