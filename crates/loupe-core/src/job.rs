use std::fmt;
use std::str::FromStr;

use loupe_provenance::Source;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::text::policy::JobKindName;
use crate::text::BoundedText;

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
pub enum JobKind<S: Source> {
	Scan,
	Verify,
	Survey,
	Drilldown,
	Unknown(BoundedText<JobKindName, S>),
}

impl<S: Source> JobKind<S> {
	/// Preserve the original marked spelling for forward-readable unknown kinds.
	pub fn from_text(text: BoundedText<JobKindName, S>) -> Self {
		match text.expose() {
			"scan" => Self::Scan,
			"verify" => Self::Verify,
			"survey" => Self::Survey,
			"drilldown" => Self::Drilldown,
			_ => Self::Unknown(text),
		}
	}
	pub fn as_str(&self) -> &str {
		match self {
			JobKind::Scan => "scan",
			JobKind::Verify => "verify",
			JobKind::Survey => "survey",
			JobKind::Drilldown => "drilldown",
			JobKind::Unknown(raw) => raw.expose(),
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

impl<S: Source> fmt::Debug for JobKind<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		if self.is_known() {
			f.write_str(self.as_str())
		} else {
			write!(f, "JobKind<{}>::Unknown([redacted])", S::NAME)
		}
	}
}

impl<S: Source> Serialize for JobKind<S> {
	fn serialize<T: serde::Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
		serializer.serialize_str(self.as_str())
	}
}

impl<S: Source> Clone for JobKind<S> {
	fn clone(&self) -> Self {
		match self {
			Self::Scan => Self::Scan,
			Self::Verify => Self::Verify,
			Self::Survey => Self::Survey,
			Self::Drilldown => Self::Drilldown,
			Self::Unknown(text) => Self::Unknown(text.clone()),
		}
	}
}
impl<S: Source> PartialEq for JobKind<S> {
	fn eq(&self, other: &Self) -> bool {
		std::mem::discriminant(self) == std::mem::discriminant(other)
			&& self.as_str() == other.as_str()
	}
}
impl<S: Source> Eq for JobKind<S> {}
impl<S: Source> std::hash::Hash for JobKind<S> {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		std::hash::Hash::hash(&std::mem::discriminant(self), state);
		std::hash::Hash::hash(self.as_str(), state);
	}
}

#[cfg(test)]
mod tests {
	use loupe_provenance::Agent;

	use super::*;
	type JobKind = super::JobKind<Agent>;
	fn kind(raw: &str) -> JobKind {
		JobKind::from_text(crate::test_support::text(raw).unwrap())
	}

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
		for k in
			[JobKind::Scan, JobKind::Verify, JobKind::Survey, JobKind::Drilldown, kind("future")]
		{
			assert_eq!(kind(k.as_str()), k);
			let json = serde_json::to_string(&k).unwrap();
			assert_eq!(kind(&serde_json::from_str::<String>(&json).unwrap()), k);
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
		assert!(!JobKind::Unknown(crate::test_support::text("scan").unwrap()).is_known());
	}

	#[test]
	fn unknown_states_are_rejected_but_future_kinds_stay_readable() {
		assert!("running".parse::<JobState>().is_err());
		let observed = kind("audit");
		assert_eq!(observed, JobKind::Unknown(crate::test_support::text("audit").unwrap()));
		assert!(!observed.is_known());
	}
}
