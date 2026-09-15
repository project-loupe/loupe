use std::convert::Infallible;
use std::fmt;
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

/// Job kind. Future kinds remain readable after a binary rollback, but
/// must never grant authority or be written by this binary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum JobKind {
	Scan,
	Verify,
	Survey,
	Drilldown,
	Unknown(String),
}

impl JobKind {
	pub fn as_str(&self) -> &str {
		match self {
			JobKind::Scan => "scan",
			JobKind::Verify => "verify",
			JobKind::Survey => "survey",
			JobKind::Drilldown => "drilldown",
			JobKind::Unknown(raw) => raw,
		}
	}

	/// Matches the persisted `job_kinds.legacy` flag, not lease eligibility.
	pub fn is_legacy(&self) -> bool {
		matches!(self, Self::Scan)
	}

	/// Verification is shared with the legacy runtime, not a phase-only kind.
	pub fn is_phase(&self) -> bool {
		matches!(self, Self::Survey | Self::Drilldown)
	}

	pub fn is_known(&self) -> bool {
		!matches!(self, Self::Unknown(_))
	}
}

impl FromStr for JobKind {
	type Err = Infallible;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"scan" => Ok(JobKind::Scan),
			"verify" => Ok(JobKind::Verify),
			"survey" => Ok(JobKind::Survey),
			"drilldown" => Ok(JobKind::Drilldown),
			other => Ok(JobKind::Unknown(other.to_owned())),
		}
	}
}

impl fmt::Display for JobKind {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.as_str())
	}
}

impl Serialize for JobKind {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		serializer.serialize_str(self.as_str())
	}
}

impl<'de> Deserialize<'de> for JobKind {
	fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		Ok(String::deserialize(deserializer)?.parse().expect("infallible kind parser"))
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
		for k in [
			JobKind::Scan,
			JobKind::Verify,
			JobKind::Survey,
			JobKind::Drilldown,
			JobKind::Unknown("future".into()),
		] {
			assert_eq!(k.as_str().parse::<JobKind>().unwrap(), k);
			let json = serde_json::to_string(&k).unwrap();
			assert_eq!(serde_json::from_str::<JobKind>(&json).unwrap(), k);
			assert_eq!(serde_json::from_str::<String>(&json).unwrap(), k.as_str());
		}
	}

	#[test]
	fn kind_classification_keeps_shared_verification_distinct() {
		assert!(JobKind::Scan.is_legacy());
		assert!(!JobKind::Verify.is_legacy());
		assert!(!JobKind::Verify.is_phase());
		assert!(JobKind::Verify.is_known());
		assert!(JobKind::Survey.is_phase());
		assert!(JobKind::Drilldown.is_phase());
		assert!(!JobKind::Unknown("scan".into()).is_known());
	}

	#[test]
	fn unknown_states_are_rejected_but_future_kinds_stay_readable() {
		assert!("running".parse::<JobState>().is_err());
		let kind = "audit".parse::<JobKind>().unwrap();
		assert_eq!(kind, JobKind::Unknown("audit".into()));
		assert!(!kind.is_known());
	}
}
