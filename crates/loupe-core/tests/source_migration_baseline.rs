//! Compatibility evidence for the temporary, still-unlabelled public API.
//! These tests pass before staging and stay intact until atomic adoption.

use loupe_core::text::policy::{AnchorText, Objective, Payload, Title};
use loupe_core::text::{Anchor, BoundedJson, BoundedText, RepoPath, Rule};
use loupe_core::{Finding, Verdict};

#[test]
fn legacy_findings_preserve_exact_text_and_accept_newly_restricted_inputs() {
	let quoted = "  cafe\u{301}\r\n\tcode  \r\n\r\n\r\n";
	for text in [quoted, "", "old\0control", &"x".repeat(2 * 1024 * 1024 + 1)] {
		let raw = serde_json::json!({
			"scanner_id": text, "severity": "high", "title": text,
			"description": text, "file_path": "", "cwe": text,
			"poc_unified": text, "patch_unified": text, "fingerprint": text,
		});
		let finding: Finding = serde_json::from_value(raw.clone()).unwrap();
		assert_eq!(finding.title.as_bytes(), text.as_bytes());
		assert_eq!(finding.description.as_bytes(), text.as_bytes());
		assert_eq!(finding.poc_unified.as_deref(), Some(text));
		assert_eq!(finding.patch_unified.as_deref(), Some(text));
		assert_eq!(finding.file_path.as_deref(), Some(""));
		assert_eq!(serde_json::to_value(finding).unwrap(), raw);
	}
}

#[test]
fn legacy_verdicts_preserve_quotes_empty_notes_and_wire_defaults() {
	for text in ["", "\tquoted cafe\u{301}\r\n\r\n\r\n", "old\u{202e}control"] {
		for raw in [
			serde_json::json!({"outcome":"confirmed", "notes":text,
				"patch":{"patch_unified":text,"notes":text}}),
			serde_json::json!({"outcome":"dismissed", "notes":text}),
			serde_json::json!({"outcome":"inconclusive", "reason":text}),
		] {
			let verdict: Verdict = serde_json::from_value(raw.clone()).unwrap();
			assert_eq!(serde_json::to_value(&verdict).unwrap(), raw);
			let back: Verdict =
				serde_json::from_str(&serde_json::to_string(&verdict).unwrap()).unwrap();
			assert_eq!(back, verdict);
		}
	}
	let null: Verdict =
		serde_json::from_str(r#"{"outcome":"confirmed","notes":null,"patch":null}"#).unwrap();
	assert_eq!(serde_json::to_value(null).unwrap(), serde_json::json!({"outcome":"confirmed"}));
}

#[test]
fn semantic_policy_error_precedence_and_exact_path_spelling_remain_distinct() {
	assert_eq!(
		BoundedText::<Objective>::new("cafe\u{301}\r\nnext").unwrap().expose(),
		"café\nnext"
	);
	assert_eq!(BoundedText::<Title>::new(&"x".repeat(201)).unwrap_err().rule, Rule::Chars);
	assert_eq!(BoundedText::<Title>::new(&"界".repeat(134)).unwrap_err().rule, Rule::Bytes);
	assert_eq!(
		BoundedText::<Title>::new(&format!("\0{}", "x".repeat(1600))).unwrap_err().rule,
		Rule::Bytes
	);
	assert_eq!(BoundedText::<Title>::new("\0 ").unwrap_err().rule, Rule::Character);
	assert_eq!(BoundedText::<Objective>::new("a\n\n\nb").unwrap_err().rule, Rule::Whitespace);
	assert_eq!(
		Anchor::<AnchorText>::new("  CAFE\u{301}   handler  ").unwrap().expose(),
		"café handler"
	);
	for text in ["café.rs", "cafe\u{301}.rs", " space /%2e%2e.rs "] {
		assert_eq!(RepoPath::new(text).unwrap().expose(), text);
	}
	let json = BoundedJson::<Payload>::new(r#"{"b":"cafe\u0301","a":""}"#).unwrap();
	assert_eq!(json.expose(), r#"{"a":"","b":"café"}"#);
	assert_eq!(
		BoundedJson::<Payload>::new(r#"{"a":1,"a":2}"#).unwrap_err().rule,
		Rule::JsonDuplicateKey
	);
}
