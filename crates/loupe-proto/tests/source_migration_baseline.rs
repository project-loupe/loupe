//! Existing DTO behavior, before the staged original-token decoder exists.
#[path = "support/verdict_cases.rs"]
mod cases;

use loupe_core::Verdict;
use loupe_proto::VerdictSubmission;

#[test]
fn legacy_verdict_schema_keeps_each_variant_options_unknowns_and_duplicate_rules() {
	for raw in cases::VALID {
		let original: VerdictSubmission = serde_json::from_str(raw).unwrap();
		let back: VerdictSubmission =
			serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
		assert_eq!(back, original);
	}
	for raw in cases::INVALID {
		assert!(serde_json::from_str::<VerdictSubmission>(raw).is_err(), "{raw}");
	}
}

#[test]
fn legacy_verdict_default_and_null_options_are_distinct_from_present_empty_strings() {
	let parse = |raw| serde_json::from_str::<VerdictSubmission>(raw).unwrap();
	assert_eq!(parse(cases::VALID[0]), parse(cases::VALID[1]));
	assert!(
		matches!(parse(cases::VALID[2]).verdict, Verdict::Confirmed { notes: Some(ref notes), patch: Some(ref patch) } if notes.is_empty() && patch.notes.is_empty() && patch.patch_unified.is_empty())
	);
	assert!(
		matches!(parse(cases::VALID[6]).verdict, Verdict::Inconclusive { reason, terminal: false } if reason.is_empty())
	);
	assert_eq!(
		parse(cases::VALID[7]).protocol_version,
		65535,
		"version compatibility is checked by the route, not DTO serde"
	);
}

#[test]
fn legacy_verdict_preserves_exact_unicode_and_unbounded_control_bearing_strings() {
	let value: VerdictSubmission = serde_json::from_str(cases::VALID[4]).unwrap();
	assert_eq!(
		value.verdict,
		Verdict::Dismissed { notes: Some("cafe\u{301}\r\n\t \"q\" \\ 😀".into()) }
	);
	let notes = format!("{}\0", "x".repeat(2 * 1024 * 1024 + 1));
	let raw =
		serde_json::json!({"protocol_version":2,"verdict":{"outcome":"dismissed","notes":notes}});
	let parsed: VerdictSubmission = serde_json::from_value(raw).unwrap();
	assert_eq!(parsed.verdict, Verdict::Dismissed { notes: Some(notes) });
}
