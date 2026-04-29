use serde::{Deserialize, Serialize};

use crate::severity::Severity;

/// A single security finding produced by a `Scanner` and ferried back to
/// the server. The wire format intentionally mirrors the `findings` table
/// columns one-for-one so the worker can construct one without consulting
/// the storage layer.
///
/// `fingerprint` is the dedup key — `blake3(scanner_id|file|line|title)`
/// in the canonical implementation, but treated as opaque bytes here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
	pub scanner_id: String,
	pub severity: Severity,
	pub title: String,
	pub description: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub file_path: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub line_start: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub line_end: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cwe: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub patch_unified: Option<String>,
	pub fingerprint: String,
}

#[cfg(test)]
mod tests {
	use super::*;

	fn sample() -> Finding {
		Finding {
			scanner_id: "regex-secrets".into(),
			severity: Severity::High,
			title: "AWS access key".into(),
			description: "Found AKIA-prefixed token in source".into(),
			file_path: Some("src/config.rs".into()),
			line_start: Some(42),
			line_end: Some(42),
			cwe: Some("CWE-798".into()),
			patch_unified: None,
			fingerprint: "deadbeef".into(),
		}
	}

	#[test]
	fn round_trips_through_json() {
		let f = sample();
		let s = serde_json::to_string(&f).unwrap();
		let back: Finding = serde_json::from_str(&s).unwrap();
		assert_eq!(f, back);
	}

	#[test]
	fn omits_none_fields_in_serialization() {
		let f = Finding {
			scanner_id: "x".into(),
			severity: Severity::Info,
			title: "t".into(),
			description: "d".into(),
			file_path: None,
			line_start: None,
			line_end: None,
			cwe: None,
			patch_unified: None,
			fingerprint: "fp".into(),
		};
		let s = serde_json::to_string(&f).unwrap();
		assert!(!s.contains("file_path"));
		assert!(!s.contains("cwe"));
		assert!(!s.contains("patch_unified"));
	}
}
