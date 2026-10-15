use std::convert::Infallible;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
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
