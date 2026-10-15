//! Source-aware fixture compared with the independent serde wire oracle.
#[path = "support/verdict_cases.rs"]
mod cases;
#[path = "support/verdict.rs"]
mod fixture;
#[path = "support/legacy_verdict.rs"]
mod legacy;

use legacy::VerdictSubmission;
use loupe_core::Verdict;

#[test]
fn marked_original_envelopes_preserve_the_actual_serde_contract() {
	for raw in cases::VALID {
		let old: VerdictSubmission = serde_json::from_str(raw).unwrap();
		let marked = fixture::read(raw.as_bytes()).unwrap();
		assert_eq!(marked.protocol_version, old.protocol_version);
		assert_eq!(
			serde_json::to_value(&marked.verdict).unwrap(),
			serde_json::to_value(old.verdict).unwrap()
		);
		assert_eq!(marked.verdict.clone(), marked.verdict);
	}
	for raw in cases::INVALID {
		assert!(fixture::read(raw.as_bytes()).is_err(), "{raw}");
	}
}

#[test]
fn repeated_equal_tokens_carry_distinct_original_message_offsets() {
	let raw = br#"{"verdict":{"patch":{"notes":"same","patch_unified":"same"},"notes":"same","outcome":"confirmed"},"protocol_version":2}"#;
	let marked = fixture::read(raw).unwrap();
	let expected = [("notes", 68..74), ("patch_unified", 52..58), ("patch_notes", 29..35)];
	assert_eq!(marked.spans.len(), expected.len());
	for (span, (field, range)) in marked.spans.iter().zip(expected) {
		println!("Worker message carry: {span:?}");
		assert_eq!((span.field, span.range.clone()), (field, range));
		assert_eq!(&raw[span.range.clone()], br#""same""#);
		assert_eq!(span.message_address, raw.as_ptr() as usize);
		assert_eq!(span.carried_address, raw.as_ptr() as usize + span.range.start);
	}
	assert!(matches!(marked.verdict, Verdict::Confirmed { notes: Some(ref n), patch: Some(ref p) }
		if n.expose() == "same" && p.notes.expose() == "same" && p.patch_unified.expose() == "same"));
}

#[test]
fn escaped_exact_content_is_decoded_after_carry_and_keeps_original_token_span() {
	let raw = cases::VALID[4].as_bytes();
	let marked = fixture::read(raw).unwrap();
	let Verdict::Dismissed { notes: Some(notes) } = marked.verdict else { panic!("wrong variant") };
	assert_eq!(notes.expose(), "cafe\u{301}\r\n\t \"q\" \\ 😀");
	assert_eq!(marked.spans.len(), 1);
	let span = &marked.spans[0];
	assert_eq!(span.carried_address, raw.as_ptr() as usize + span.range.start);
	assert_eq!(&raw[span.range.clone()], br#""cafe\u0301\r\n\t \"q\" \\ \uD83D\uDE00""#);
	assert_eq!(format!("{notes:?}"), "BoundedText<verdict_notes, agent>([redacted])");
}

#[test]
fn bounded_fixture_rejects_new_admission_without_altering_legacy_protocol() {
	for notes in ["bad\0text", "bad\u{7f}text"] {
		let bytes = serde_json::to_vec(
			&serde_json::json!({"protocol_version":2,"verdict":{"outcome":"dismissed","notes":notes}}),
		)
		.unwrap();
		assert!(serde_json::from_slice::<VerdictSubmission>(&bytes).is_ok());
		assert_eq!(fixture::read(&bytes).err().unwrap().to_string(), "invalid worker verdict");
	}
	let mut bytes = cases::VALID[0].as_bytes().to_vec();
	bytes.resize(fixture::BODY_CAP, b' ');
	assert!(fixture::read(&bytes).is_ok());
	bytes.push(b' ');
	assert!(serde_json::from_slice::<VerdictSubmission>(&bytes).is_ok());
	assert_eq!(fixture::read(&bytes).err().unwrap().to_string(), "invalid worker verdict");
	assert!(fixture::read(&[0xff]).is_err());
}

#[test]
fn tagged_content_nesting_keeps_the_original_envelopes_recursion_boundary() {
	for depth in [0, 1, 120, 124, 125, 126, 127, 128, 129] {
		let raw = format!(
			r#"{{"protocol_version":2,"verdict":{{"outcome":"confirmed","ignored":{}0{}}}}}"#,
			"[".repeat(depth),
			"]".repeat(depth)
		);
		assert_eq!(
			fixture::read(raw.as_bytes()).is_ok(),
			serde_json::from_str::<VerdictSubmission>(&raw).is_ok(),
			"nesting depth {depth}"
		);
	}
}
