use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Severity of a security finding.
///
/// Ordered from least to most severe so that `severity >= Severity::High`
/// reads naturally in policy code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
	Info,
	Low,
	Medium,
	High,
	Critical,
}

impl Severity {
	pub fn as_str(self) -> &'static str {
		match self {
			Severity::Info => "info",
			Severity::Low => "low",
			Severity::Medium => "medium",
			Severity::High => "high",
			Severity::Critical => "critical",
		}
	}
}

impl fmt::Display for Severity {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.as_str())
	}
}

impl FromStr for Severity {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"info" => Ok(Severity::Info),
			"low" => Ok(Severity::Low),
			"medium" => Ok(Severity::Medium),
			"high" => Ok(Severity::High),
			"critical" => Ok(Severity::Critical),
			other => Err(Error::UnknownSeverity(other.to_owned())),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn order_is_least_to_most_severe() {
		assert!(Severity::Info < Severity::Low);
		assert!(Severity::Low < Severity::Medium);
		assert!(Severity::Medium < Severity::High);
		assert!(Severity::High < Severity::Critical);
	}

	#[test]
	fn round_trips_through_json() {
		for sev in
			[Severity::Info, Severity::Low, Severity::Medium, Severity::High, Severity::Critical]
		{
			let s = serde_json::to_string(&sev).unwrap();
			let back: Severity = serde_json::from_str(&s).unwrap();
			assert_eq!(sev, back, "round-trip mismatch via {s}");
		}
	}

	#[test]
	fn from_str_rejects_unknown() {
		assert!("Critical".parse::<Severity>().is_err()); // case-sensitive
		assert!("urgent".parse::<Severity>().is_err());
	}
}
