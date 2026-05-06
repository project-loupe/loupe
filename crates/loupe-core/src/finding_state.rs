use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Lifecycle state of a finding in the server-side review/reporting pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
	Pending,
	Validating,
	AwaitingApproval,
	Confirmed,
	Dismissed,
	Reported,
}

impl FindingState {
	pub fn as_str(self) -> &'static str {
		match self {
			FindingState::Pending => "pending",
			FindingState::Validating => "validating",
			FindingState::AwaitingApproval => "awaiting_approval",
			FindingState::Confirmed => "confirmed",
			FindingState::Dismissed => "dismissed",
			FindingState::Reported => "reported",
		}
	}
}

impl fmt::Display for FindingState {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.as_str())
	}
}

impl FromStr for FindingState {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"pending" => Ok(FindingState::Pending),
			"validating" => Ok(FindingState::Validating),
			"awaiting_approval" => Ok(FindingState::AwaitingApproval),
			"confirmed" => Ok(FindingState::Confirmed),
			"dismissed" => Ok(FindingState::Dismissed),
			"reported" => Ok(FindingState::Reported),
			other => Err(Error::UnknownFindingState(other.to_owned())),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn finding_state_round_trips_via_string() {
		for state in [
			FindingState::Pending,
			FindingState::Validating,
			FindingState::AwaitingApproval,
			FindingState::Confirmed,
			FindingState::Dismissed,
			FindingState::Reported,
		] {
			assert_eq!(state.as_str().parse::<FindingState>().unwrap(), state);
		}
	}

	#[test]
	fn finding_state_round_trips_via_json() {
		let state = FindingState::AwaitingApproval;
		let s = serde_json::to_string(&state).unwrap();
		assert_eq!(s, "\"awaiting_approval\"");
		let back: FindingState = serde_json::from_str(&s).unwrap();
		assert_eq!(state, back);
	}
}
