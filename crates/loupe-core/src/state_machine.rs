use thiserror::Error;

use crate::{FindingState, JobState};

// debug-ok: private fields are static machine, state and transition names.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid {machine} transition {transition} from {state}")]
pub struct StateTransitionError {
	machine: &'static str,
	state: &'static str,
	transition: &'static str,
}

impl StateTransitionError {
	fn new(machine: &'static str, state: &'static str, transition: &'static str) -> Self {
		Self { machine, state, transition }
	}
}

// debug-ok: closed job transition unit variants contain no input text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobTransition {
	Enqueue,
	Lease,
	Heartbeat,
	CompleteSucceeded,
	CompleteFailed,
	Cancel,
	Retry,
	ReapToQueued,
	ReapToFailed,
}

impl JobTransition {
	pub fn as_str(self) -> &'static str {
		match self {
			JobTransition::Enqueue => "enqueue",
			JobTransition::Lease => "lease",
			JobTransition::Heartbeat => "heartbeat",
			JobTransition::CompleteSucceeded => "complete_succeeded",
			JobTransition::CompleteFailed => "complete_failed",
			JobTransition::Cancel => "cancel",
			JobTransition::Retry => "retry",
			JobTransition::ReapToQueued => "reap_to_queued",
			JobTransition::ReapToFailed => "reap_to_failed",
		}
	}

	pub fn apply(self, current: JobState) -> Result<JobState, StateTransitionError> {
		current.apply(self)
	}
}

impl JobState {
	pub fn apply(self, transition: JobTransition) -> Result<Self, StateTransitionError> {
		match (self, transition) {
			(JobState::Queued, JobTransition::Lease) => Ok(JobState::Leased),
			(JobState::Leased, JobTransition::Heartbeat) => Ok(JobState::Leased),
			(JobState::Leased, JobTransition::CompleteSucceeded) => Ok(JobState::Succeeded),
			(JobState::Leased, JobTransition::CompleteFailed) => Ok(JobState::Failed),
			(JobState::Queued | JobState::Leased, JobTransition::Cancel) => Ok(JobState::Cancelled),
			(JobState::Failed, JobTransition::Retry) => Ok(JobState::Queued),
			(JobState::Leased, JobTransition::ReapToQueued) => Ok(JobState::Queued),
			(JobState::Leased, JobTransition::ReapToFailed) => Ok(JobState::Failed),
			_ => Err(StateTransitionError::new("job", self.as_str(), transition.as_str())),
		}
	}
}

pub fn initial_job_state(transition: JobTransition) -> Result<JobState, StateTransitionError> {
	match transition {
		JobTransition::Enqueue => Ok(JobState::Queued),
		_ => Err(StateTransitionError::new("job", "<none>", transition.as_str())),
	}
}

// debug-ok: closed finding transition unit variants contain no input text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingTransition {
	ScanAccepted,
	ScanAutoConfirm,
	ScanAwaitApproval,
	ScanRequireVerification,
	VerdictConfirm,
	VerdictAwaitApproval,
	VerdictDismiss,
	DeadlineExpire,
	Approve,
	Reject,
	RetryVerification,
	MarkReported,
}

impl FindingTransition {
	pub fn as_str(self) -> &'static str {
		match self {
			FindingTransition::ScanAccepted => "scan_accepted",
			FindingTransition::ScanAutoConfirm => "scan_auto_confirm",
			FindingTransition::ScanAwaitApproval => "scan_await_approval",
			FindingTransition::ScanRequireVerification => "scan_require_verification",
			FindingTransition::VerdictConfirm => "verdict_confirm",
			FindingTransition::VerdictAwaitApproval => "verdict_await_approval",
			FindingTransition::VerdictDismiss => "verdict_dismiss",
			FindingTransition::DeadlineExpire => "deadline_expire",
			FindingTransition::Approve => "approve",
			FindingTransition::Reject => "reject",
			FindingTransition::RetryVerification => "retry_verification",
			FindingTransition::MarkReported => "mark_reported",
		}
	}

	pub fn apply(self, current: FindingState) -> Result<FindingState, StateTransitionError> {
		current.apply(self)
	}
}

impl FindingState {
	pub fn apply(self, transition: FindingTransition) -> Result<Self, StateTransitionError> {
		match (self, transition) {
			(FindingState::Pending, FindingTransition::ScanAutoConfirm) => {
				Ok(FindingState::Confirmed)
			},
			(FindingState::Pending, FindingTransition::ScanAwaitApproval) => {
				Ok(FindingState::AwaitingApproval)
			},
			(FindingState::Pending, FindingTransition::ScanRequireVerification) => {
				Ok(FindingState::Validating)
			},
			(FindingState::Validating, FindingTransition::VerdictConfirm) => {
				Ok(FindingState::Confirmed)
			},
			(FindingState::Validating, FindingTransition::VerdictAwaitApproval) => {
				Ok(FindingState::AwaitingApproval)
			},
			(FindingState::Validating, FindingTransition::VerdictDismiss) => {
				Ok(FindingState::Dismissed)
			},
			(FindingState::Validating, FindingTransition::DeadlineExpire) => {
				Ok(FindingState::Dismissed)
			},
			(FindingState::AwaitingApproval, FindingTransition::Approve) => {
				Ok(FindingState::Confirmed)
			},
			(FindingState::AwaitingApproval, FindingTransition::Reject) => {
				Ok(FindingState::Dismissed)
			},
			(
				FindingState::Pending | FindingState::Validating | FindingState::Dismissed,
				FindingTransition::RetryVerification,
			) => Ok(FindingState::Validating),
			(FindingState::Confirmed, FindingTransition::MarkReported) => {
				Ok(FindingState::Reported)
			},
			_ => Err(StateTransitionError::new("finding", self.as_str(), transition.as_str())),
		}
	}
}

pub fn initial_finding_state(
	transition: FindingTransition,
) -> Result<FindingState, StateTransitionError> {
	match transition {
		FindingTransition::ScanAccepted => Ok(FindingState::Pending),
		_ => Err(StateTransitionError::new("finding", "<none>", transition.as_str())),
	}
}

// debug-ok: aggregate state contains only four booleans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerdictRollup {
	pub has_confirmed: bool,
	pub has_dismissed: bool,
	pub terminal_inconclusive: bool,
	pub require_approval: bool,
}

pub fn roll_up_verdicts(
	current: FindingState, rollup: VerdictRollup,
) -> Result<Option<FindingState>, StateTransitionError> {
	if current != FindingState::Validating {
		return Ok(None);
	}
	let transition = if rollup.terminal_inconclusive || rollup.has_dismissed {
		Some(FindingTransition::VerdictDismiss)
	} else if rollup.has_confirmed {
		Some(if rollup.require_approval {
			FindingTransition::VerdictAwaitApproval
		} else {
			FindingTransition::VerdictConfirm
		})
	} else {
		None
	};
	transition.map(|t| current.apply(t)).transpose()
}

#[cfg(test)]
mod tests {
	use super::*;

	const JOB_STATES: [JobState; 5] = [
		JobState::Queued,
		JobState::Leased,
		JobState::Succeeded,
		JobState::Failed,
		JobState::Cancelled,
	];

	const JOB_TRANSITIONS: [JobTransition; 9] = [
		JobTransition::Enqueue,
		JobTransition::Lease,
		JobTransition::Heartbeat,
		JobTransition::CompleteSucceeded,
		JobTransition::CompleteFailed,
		JobTransition::Cancel,
		JobTransition::Retry,
		JobTransition::ReapToQueued,
		JobTransition::ReapToFailed,
	];

	const FINDING_STATES: [FindingState; 6] = [
		FindingState::Pending,
		FindingState::Validating,
		FindingState::AwaitingApproval,
		FindingState::Confirmed,
		FindingState::Dismissed,
		FindingState::Reported,
	];

	const FINDING_TRANSITIONS: [FindingTransition; 12] = [
		FindingTransition::ScanAccepted,
		FindingTransition::ScanAutoConfirm,
		FindingTransition::ScanAwaitApproval,
		FindingTransition::ScanRequireVerification,
		FindingTransition::VerdictConfirm,
		FindingTransition::VerdictAwaitApproval,
		FindingTransition::VerdictDismiss,
		FindingTransition::DeadlineExpire,
		FindingTransition::Approve,
		FindingTransition::Reject,
		FindingTransition::RetryVerification,
		FindingTransition::MarkReported,
	];

	#[test]
	fn transition_names_and_rejection_messages_are_exact() {
		let jobs = [
			(JobTransition::Enqueue, "enqueue"),
			(JobTransition::Lease, "lease"),
			(JobTransition::Heartbeat, "heartbeat"),
			(JobTransition::CompleteSucceeded, "complete_succeeded"),
			(JobTransition::CompleteFailed, "complete_failed"),
			(JobTransition::Cancel, "cancel"),
			(JobTransition::Retry, "retry"),
			(JobTransition::ReapToQueued, "reap_to_queued"),
			(JobTransition::ReapToFailed, "reap_to_failed"),
		];
		for (transition, label) in jobs {
			assert_eq!(transition.as_str(), label);
			assert_eq!(
				JobState::Succeeded.apply(transition).unwrap_err().to_string(),
				format!("invalid job transition {label} from succeeded")
			);
		}
		let findings = [
			(FindingTransition::ScanAccepted, "scan_accepted"),
			(FindingTransition::ScanAutoConfirm, "scan_auto_confirm"),
			(FindingTransition::ScanAwaitApproval, "scan_await_approval"),
			(FindingTransition::ScanRequireVerification, "scan_require_verification"),
			(FindingTransition::VerdictConfirm, "verdict_confirm"),
			(FindingTransition::VerdictAwaitApproval, "verdict_await_approval"),
			(FindingTransition::VerdictDismiss, "verdict_dismiss"),
			(FindingTransition::DeadlineExpire, "deadline_expire"),
			(FindingTransition::Approve, "approve"),
			(FindingTransition::Reject, "reject"),
			(FindingTransition::RetryVerification, "retry_verification"),
			(FindingTransition::MarkReported, "mark_reported"),
		];
		for (transition, label) in findings {
			assert_eq!(transition.as_str(), label);
			assert_eq!(
				FindingState::Reported.apply(transition).unwrap_err().to_string(),
				format!("invalid finding transition {label} from reported")
			);
		}
	}

	#[test]
	fn initial_job_state_is_only_enqueue() {
		assert_eq!(initial_job_state(JobTransition::Enqueue).unwrap(), JobState::Queued);
		for transition in JOB_TRANSITIONS {
			if transition != JobTransition::Enqueue {
				assert!(initial_job_state(transition).is_err());
			}
		}
	}

	#[test]
	fn job_transition_matrix_is_explicit() {
		let allowed = [
			(JobState::Queued, JobTransition::Lease, JobState::Leased),
			(JobState::Leased, JobTransition::Heartbeat, JobState::Leased),
			(JobState::Leased, JobTransition::CompleteSucceeded, JobState::Succeeded),
			(JobState::Leased, JobTransition::CompleteFailed, JobState::Failed),
			(JobState::Queued, JobTransition::Cancel, JobState::Cancelled),
			(JobState::Leased, JobTransition::Cancel, JobState::Cancelled),
			(JobState::Failed, JobTransition::Retry, JobState::Queued),
			(JobState::Leased, JobTransition::ReapToQueued, JobState::Queued),
			(JobState::Leased, JobTransition::ReapToFailed, JobState::Failed),
		];
		for (state, transition, target) in allowed {
			assert_eq!(state.apply(transition).unwrap(), target);
		}
		for state in JOB_STATES {
			for transition in JOB_TRANSITIONS {
				let is_allowed = allowed.iter().any(|(s, t, _)| *s == state && *t == transition);
				if !is_allowed {
					assert!(
						state.apply(transition).is_err(),
						"{state:?} unexpectedly accepted {transition:?}"
					);
				}
			}
		}
	}

	#[test]
	fn initial_finding_state_is_only_scan_acceptance() {
		assert_eq!(
			initial_finding_state(FindingTransition::ScanAccepted).unwrap(),
			FindingState::Pending
		);
		for transition in FINDING_TRANSITIONS {
			if transition != FindingTransition::ScanAccepted {
				assert!(initial_finding_state(transition).is_err());
			}
		}
	}

	#[test]
	fn finding_transition_matrix_is_explicit() {
		let allowed = [
			(FindingState::Pending, FindingTransition::ScanAutoConfirm, FindingState::Confirmed),
			(
				FindingState::Pending,
				FindingTransition::ScanAwaitApproval,
				FindingState::AwaitingApproval,
			),
			(
				FindingState::Pending,
				FindingTransition::ScanRequireVerification,
				FindingState::Validating,
			),
			(FindingState::Validating, FindingTransition::VerdictConfirm, FindingState::Confirmed),
			(
				FindingState::Validating,
				FindingTransition::VerdictAwaitApproval,
				FindingState::AwaitingApproval,
			),
			(FindingState::Validating, FindingTransition::VerdictDismiss, FindingState::Dismissed),
			(FindingState::Validating, FindingTransition::DeadlineExpire, FindingState::Dismissed),
			(FindingState::AwaitingApproval, FindingTransition::Approve, FindingState::Confirmed),
			(FindingState::AwaitingApproval, FindingTransition::Reject, FindingState::Dismissed),
			(FindingState::Pending, FindingTransition::RetryVerification, FindingState::Validating),
			(
				FindingState::Validating,
				FindingTransition::RetryVerification,
				FindingState::Validating,
			),
			(
				FindingState::Dismissed,
				FindingTransition::RetryVerification,
				FindingState::Validating,
			),
			(FindingState::Confirmed, FindingTransition::MarkReported, FindingState::Reported),
		];
		for (state, transition, target) in allowed {
			assert_eq!(state.apply(transition).unwrap(), target);
		}
		for state in FINDING_STATES {
			for transition in FINDING_TRANSITIONS {
				let is_allowed = allowed.iter().any(|(s, t, _)| *s == state && *t == transition);
				if !is_allowed {
					assert!(
						state.apply(transition).is_err(),
						"{state:?} unexpectedly accepted {transition:?}"
					);
				}
			}
		}
	}

	#[test]
	fn verdict_rollup_precedence_is_terminal_inconclusive_dismissed_confirmed() {
		assert_eq!(
			roll_up_verdicts(
				FindingState::Validating,
				VerdictRollup {
					has_confirmed: true,
					has_dismissed: true,
					terminal_inconclusive: false,
					require_approval: false,
				}
			)
			.unwrap(),
			Some(FindingState::Dismissed)
		);
		assert_eq!(
			roll_up_verdicts(
				FindingState::Validating,
				VerdictRollup {
					has_confirmed: true,
					has_dismissed: false,
					terminal_inconclusive: true,
					require_approval: false,
				}
			)
			.unwrap(),
			Some(FindingState::Dismissed)
		);
		assert_eq!(
			roll_up_verdicts(
				FindingState::Validating,
				VerdictRollup {
					has_confirmed: true,
					has_dismissed: false,
					terminal_inconclusive: false,
					require_approval: true,
				}
			)
			.unwrap(),
			Some(FindingState::AwaitingApproval)
		);
		assert_eq!(
			roll_up_verdicts(
				FindingState::Validating,
				VerdictRollup {
					has_confirmed: true,
					has_dismissed: false,
					terminal_inconclusive: false,
					require_approval: false,
				}
			)
			.unwrap(),
			Some(FindingState::Confirmed)
		);
		assert_eq!(
			roll_up_verdicts(FindingState::Validating, VerdictRollup::default()).unwrap(),
			None
		);
		assert_eq!(
			roll_up_verdicts(
				FindingState::Confirmed,
				VerdictRollup {
					has_confirmed: false,
					has_dismissed: true,
					terminal_inconclusive: true,
					require_approval: false,
				}
			)
			.unwrap(),
			None
		);
	}
}
