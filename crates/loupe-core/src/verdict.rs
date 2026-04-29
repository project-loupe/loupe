use serde::{Deserialize, Serialize};

/// Outcome of a verification job — a verifier's vote on whether a finding
/// from a prior scan is real, false-positive, or undecidable.
///
/// The server's rollup policy aggregates one or more `Verdict`s into the
/// finding's `state` (`confirmed` / `dismissed` / stays `validating`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Verdict {
	Confirmed {
		#[serde(default, skip_serializing_if = "Option::is_none")]
		notes: Option<String>,
	},
	Dismissed {
		#[serde(default, skip_serializing_if = "Option::is_none")]
		notes: Option<String>,
	},
	Inconclusive {
		reason: String,
	},
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn round_trips_each_variant() {
		let cases = [
			Verdict::Confirmed { notes: Some("matched second scanner".into()) },
			Verdict::Dismissed { notes: None },
			Verdict::Inconclusive { reason: "scanner does not verify".into() },
		];
		for v in cases {
			let s = serde_json::to_string(&v).unwrap();
			let back: Verdict = serde_json::from_str(&s).unwrap();
			assert_eq!(v, back);
		}
	}

	#[test]
	fn tag_field_is_outcome() {
		let v = Verdict::Dismissed { notes: None };
		let s = serde_json::to_string(&v).unwrap();
		assert!(s.contains(r#""outcome":"dismissed""#), "got: {s}");
	}
}
