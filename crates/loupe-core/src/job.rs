use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Lifecycle state of a job in the server-side queue.
///
/// Wire/db representation is `snake_case`. The state machine is:
///
/// ```text
/// queued ──lease──► leased ──complete(Succeeded)──► succeeded ──► dispatch
///   ▲                │
///   │                ├─ complete(Failed) ──► failed
///   │                │
///   └── reap (attempts < max) ◄── lease_expires_at < now
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
	Queued,
	Leased,
	Succeeded,
	Failed,
	Cancelled,
}

impl JobState {
	pub fn as_str(self) -> &'static str {
		match self {
			JobState::Queued => "queued",
			JobState::Leased => "leased",
			JobState::Succeeded => "succeeded",
			JobState::Failed => "failed",
			JobState::Cancelled => "cancelled",
		}
	}

	pub fn is_terminal(self) -> bool {
		matches!(self, JobState::Succeeded | JobState::Failed | JobState::Cancelled)
	}
}

impl FromStr for JobState {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"queued" => Ok(JobState::Queued),
			"leased" => Ok(JobState::Leased),
			"succeeded" => Ok(JobState::Succeeded),
			"failed" => Ok(JobState::Failed),
			"cancelled" => Ok(JobState::Cancelled),
			other => Err(Error::UnknownJobState(other.to_owned())),
		}
	}
}

/// Whether a job is a fresh repo scan or a verification of an existing
/// finding from a previous scan job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
	Scan,
	Verify,
}

impl JobKind {
	pub fn as_str(self) -> &'static str {
		match self {
			JobKind::Scan => "scan",
			JobKind::Verify => "verify",
		}
	}
}

impl FromStr for JobKind {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"scan" => Ok(JobKind::Scan),
			"verify" => Ok(JobKind::Verify),
			other => Err(Error::UnknownJobKind(other.to_owned())),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn job_state_terminality() {
		assert!(!JobState::Queued.is_terminal());
		assert!(!JobState::Leased.is_terminal());
		assert!(JobState::Succeeded.is_terminal());
		assert!(JobState::Failed.is_terminal());
		assert!(JobState::Cancelled.is_terminal());
	}

	#[test]
	fn job_state_round_trips_via_string() {
		for st in [
			JobState::Queued,
			JobState::Leased,
			JobState::Succeeded,
			JobState::Failed,
			JobState::Cancelled,
		] {
			assert_eq!(st.as_str().parse::<JobState>().unwrap(), st);
		}
	}

	#[test]
	fn job_state_round_trips_via_json() {
		let st = JobState::Leased;
		let s = serde_json::to_string(&st).unwrap();
		assert_eq!(s, "\"leased\"");
		let back: JobState = serde_json::from_str(&s).unwrap();
		assert_eq!(st, back);
	}

	#[test]
	fn job_kind_round_trips_via_string() {
		for k in [JobKind::Scan, JobKind::Verify] {
			assert_eq!(k.as_str().parse::<JobKind>().unwrap(), k);
		}
	}

	#[test]
	fn unknown_strings_are_rejected() {
		assert!("running".parse::<JobState>().is_err());
		assert!("audit".parse::<JobKind>().is_err());
	}
}
