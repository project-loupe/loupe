//! Field-policy controls. Constructor authority and the absence of raw
//! deserialization are checked by the compile-fail API contracts.
#[path = "support/marked.rs"]
mod marked;

use loupe_core::text::policy::{
	AnchorText, FindingDescription, FindingTitle, Objective, PatchUnified, Payload, PocUnified,
	Title, VerdictNotes,
};
use loupe_core::text::{Anchor, BoundedJson, BoundedText, Error, RepoPath, Rule, TextPolicy};
use loupe_core::Verdict;
use loupe_provenance::Agent;

fn text<P: TextPolicy>(raw: &str) -> Result<BoundedText<P, Agent>, Error> {
	marked::fixture(raw, |raw, mark| BoundedText::new(mark, raw))
}

#[test]
fn final_fields_retain_admitted_legacy_bytes_and_reject_removed_raw_bypass() {
	let quoted = "  cafe\u{301}\r\n\tcode  \r\n\r\n\r\n";
	for raw in [quoted, ""] {
		assert_eq!(text::<FindingDescription>(raw).unwrap().expose().as_bytes(), raw.as_bytes());
		assert_eq!(text::<PatchUnified>(raw).unwrap().expose(), raw);
		assert_eq!(text::<PocUnified>(raw).unwrap().expose(), raw);
	}
	for raw in ["", "  cafe\u{301}  "] {
		assert_eq!(text::<FindingTitle>(raw).unwrap().expose().as_bytes(), raw.as_bytes());
	}
	assert_eq!(text::<FindingDescription>("old\0control").unwrap_err().rule, Rule::Character);
	assert_eq!(
		text::<FindingDescription>(&"x".repeat(2 * 1024 * 1024 + 1)).unwrap_err().rule,
		Rule::Bytes
	);
	assert_eq!(
		marked::fixture::<Agent, _>("", |raw, mark| RepoPath::new(mark, raw)).unwrap_err().rule,
		Rule::Path
	);
}

#[test]
fn verdicts_preserve_quotes_empty_notes_and_wire_defaults() {
	for raw in ["", "\tquoted cafe\u{301}\r\n\r\n\r\n"] {
		let notes = text::<VerdictNotes>(raw).unwrap();
		let confirmed = Verdict::Confirmed { notes: Some(notes.clone()), patch: None };
		let dismissed = Verdict::Dismissed { notes: Some(notes) };
		assert_eq!(
			serde_json::to_value(confirmed).unwrap(),
			serde_json::json!({"outcome":"confirmed","notes":raw})
		);
		assert_eq!(
			serde_json::to_value(dismissed).unwrap(),
			serde_json::json!({"outcome":"dismissed","notes":raw})
		);
	}
	assert_eq!(text::<VerdictNotes>("old\u{202e}control").unwrap_err().rule, Rule::Character);
	let absent = Verdict::<Agent>::Confirmed { notes: None, patch: None };
	assert_eq!(serde_json::to_value(absent).unwrap(), serde_json::json!({"outcome":"confirmed"}));
}

#[test]
fn semantic_policy_error_precedence_and_exact_path_spelling_remain_distinct() {
	assert_eq!(text::<Objective>("cafe\u{301}\r\nnext").unwrap().expose(), "café\nnext");
	assert_eq!(text::<Title>(&"x".repeat(201)).unwrap_err().rule, Rule::Chars);
	assert_eq!(text::<Title>(&"界".repeat(134)).unwrap_err().rule, Rule::Bytes);
	assert_eq!(text::<Title>(&format!("\0{}", "x".repeat(1600))).unwrap_err().rule, Rule::Bytes);
	assert_eq!(text::<Title>("\0 ").unwrap_err().rule, Rule::Character);
	assert_eq!(text::<Objective>("a\n\n\nb").unwrap_err().rule, Rule::Whitespace);
	marked::fixture::<Agent, _>("", |_, mark| {
		assert_eq!(
			Anchor::<AnchorText, _>::new(mark, "  CAFE\u{301}   handler  ").unwrap().expose(),
			"café handler"
		);
		for raw in ["café.rs", "cafe\u{301}.rs", " space /%2e%2e.rs "] {
			assert_eq!(RepoPath::new(mark, raw).unwrap().expose(), raw);
		}
		let json = BoundedJson::<Payload, _>::new(mark, r#"{"b":"cafe\u0301","a":""}"#).unwrap();
		assert_eq!(json.expose(), r#"{"a":"","b":"café"}"#);
		assert_eq!(
			BoundedJson::<Payload, _>::new(mark, r#"{"a":1,"a":2}"#).unwrap_err().rule,
			Rule::JsonDuplicateKey
		);
	});
}
