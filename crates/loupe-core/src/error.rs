use std::result::Result as StdResult;

use thiserror::Error;

#[derive(Error)]
pub enum Error {
	#[error("unknown severity")]
	UnknownSeverity(String),

	#[error("unknown job state")]
	UnknownJobState(String),

	#[error("unknown finding state")]
	UnknownFindingState(String),
}

impl std::fmt::Debug for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			Self::UnknownSeverity(_) => "UnknownSeverity([redacted])",
			Self::UnknownJobState(_) => "UnknownJobState([redacted])",
			Self::UnknownFindingState(_) => "UnknownFindingState([redacted])",
		})
	}
}

pub type Result<T, E = Error> = StdResult<T, E>;

#[cfg(test)]
mod tests {
	use crate::{FindingState, JobState, Severity};

	fn invalid_values() -> [super::Error; 3] {
		let raw = "untrusted-field-sentinel";
		[
			raw.parse::<Severity>().unwrap_err(),
			raw.parse::<JobState>().unwrap_err(),
			raw.parse::<FindingState>().unwrap_err(),
		]
	}

	#[test]
	fn parser_error_debug_redacts_unknown_input() {
		assert_eq!(
			invalid_values().map(|error| format!("{error:?}")),
			[
				"UnknownSeverity([redacted])",
				"UnknownJobState([redacted])",
				"UnknownFindingState([redacted])",
			],
			"parser Debug must disclose only its category"
		);
	}

	#[test]
	fn parser_error_display_redacts_unknown_input() {
		assert_eq!(
			invalid_values().map(|error| error.to_string()),
			["unknown severity", "unknown job state", "unknown finding state"],
			"parser Display must disclose only its category"
		);
	}
}
