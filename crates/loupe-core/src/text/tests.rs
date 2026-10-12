use policy::*;
use unicode_general_category::{get_general_category, GeneralCategory as G};

#[test]
fn review_duplicate_json_keys_are_not_silently_discarded() {
	for raw in [r#"{"a":1,"a":2}"#, r#"{"nested":{"a":1,"a":1}}"#] {
		assert!(
			crate::test_support::json::<Payload>(raw).is_err(),
			"duplicate keys must not discard a submitted value"
		);
		assert!(crate::test_support::json::<Payload>(raw).is_err());
	}
}

#[test]
fn review_labels_reject_whitespace_aliases() {
	for label in ["needs-triage ", "needs  triage"] {
		assert!(
			crate::test_support::identifier::<Label>(label).is_err(),
			"label whitespace must not create aliases"
		);
	}
	assert!(crate::test_support::identifier::<Label>("needs triage").is_ok());
}

#[test]
fn review_required_text_is_nonempty_but_json_strings_may_be_empty() {
	assert!(crate::test_support::text::<Title>("").is_err(), "a present title must not be empty");
	assert!(crate::test_support::text::<Objective>("").is_err());
	assert!(crate::test_support::text::<JsonLeaf>("").is_ok());
	assert!(crate::test_support::json::<Payload>(r#"{"a":""}"#).is_ok());
}

#[test]
fn review_anchor_prose_is_not_mistaken_for_provenance() {
	for text in ["defaced response header", "acceded", "deadbeef", "port 8080 exposed", "x 12"] {
		assert!(
			crate::test_support::anchor::<AnchorText>(text).is_ok(),
			"ordinary anchor prose must remain usable: {text}"
		);
	}
	for text in ["commit 79dec41", "deadbeef1", "line 212", "unit 5", "request.rs:212"] {
		assert!(crate::test_support::anchor::<AnchorText>(text).is_err());
	}
}

#[test]
fn review_json_deserialization_stops_at_the_byte_budget() {
	// The trailing malformed token distinguishes incremental rejection from
	// a final length check after parsing and normalizing the entire tree.
	let leaf = format!("\"{}\"", "x".repeat(4000));
	let raw = format!("[{},invalid]", vec![leaf; 17].join(","));
	let error = json::visitor_fixture::<Payload, _>(&mut serde_json::Deserializer::from_str(&raw))
		.unwrap_err();
	assert!(
		error.to_string().contains("Bytes"),
		"reject the byte budget before visiting the suffix: {error}"
	);
}

use super::*;

#[test]
fn normalizes_semantics_without_exposing_payloads() {
	let text = crate::test_support::text::<Objective>("Cafe\u{301}\r\n秘密").unwrap();
	assert_eq!(text.expose(), "Café\n秘密");
	assert!(!format!("{text:?}").contains("Café"));
	assert_eq!(
		crate::test_support::json_text::<Objective>(&serde_json::to_string(&text).unwrap())
			.unwrap(),
		text
	);
	for s in ["中文", "مرحبا", "שלום", "👍🏽"] {
		assert_eq!(crate::test_support::text::<Title>(s).unwrap().expose(), s);
	}
}

#[test]
fn policy_caps_and_deserialization_cannot_be_bypassed() {
	let emoji = "😀".repeat(150);
	assert_eq!(crate::test_support::text::<Title>(&emoji).unwrap_err().rule, Rule::Bytes);
	assert!(crate::test_support::text::<Objective>(&emoji).is_ok());
	assert!(
		crate::test_support::json_text::<Title>(&serde_json::to_string(&emoji).unwrap()).is_err()
	);
	assert_eq!(crate::test_support::text::<Title>(&"x".repeat(201)).unwrap_err().rule, Rule::Chars);
	assert!(crate::test_support::text::<Reason>("a\nb").is_err());
	assert!(crate::test_support::identifier::<Family>("Upper").is_err());
	assert!(crate::test_support::identifier::<ClientKey>("Upper").is_ok());
	assert!(crate::test_support::identifier::<ClientKey>(&"x".repeat(129)).is_err());
	assert!(crate::test_support::identifier::<Label>("a label").is_ok());
	assert!(crate::test_support::identifier::<JsonKey>("_ENV_NAME").is_ok());
}

#[test]
fn rejected_text_reports_only_the_rule_and_code_point() {
	for ch in [
		'\u{202e}', '\u{2066}', '\u{200d}', '\u{200c}', '\u{feff}', '\u{1b}', '\u{2028}',
		'\u{e000}',
	] {
		let error =
			crate::test_support::text::<Objective>(&format!("SECRET{ch}payload")).unwrap_err();
		assert_eq!(error.rule, Rule::Character);
		assert!(error.to_string().contains(&format!("U+{:04X}", ch as u32)));
		assert!(!error.to_string().contains(ch));
		assert!(!format!("{error:?}").contains("SECRET"));
	}
	for text in [" x", "x ", "a\n\n\nb", "\r\n"] {
		assert!(crate::test_support::text::<Objective>(text).is_err());
	}
}

#[test]
fn every_unicode_scalar_obeys_the_category_policy() {
	for ch in char::MIN..=char::MAX {
		if ch == '\r' {
			continue;
		} // Normalized before category validation.
		let forbidden = matches!(
			get_general_category(ch),
			G::Control
				| G::Format
				| G::Unassigned
				| G::PrivateUse
				| G::LineSeparator
				| G::ParagraphSeparator
		);
		let sample = format!("ok {ch} ok");
		assert_eq!(
			crate::test_support::text::<Title>(&sample).is_ok(),
			!forbidden,
			"single U+{:04X}",
			ch as u32
		);
		assert_eq!(
			crate::test_support::text::<Objective>(&sample).is_ok(),
			!forbidden || matches!(ch, '\n' | '\t'),
			"multi U+{:04X}",
			ch as u32
		);
	}
	assert_eq!(crate::test_support::text::<Objective>("a\rb").unwrap().expose(), "a\nb");
	assert!(crate::test_support::text::<Title>("a\rb").is_err());
}

#[test]
fn anchors_have_a_separate_identity_pipeline() {
	assert_eq!(
		crate::test_support::anchor::<AnchorText>("  TOKEN   Refresh  ").unwrap().expose(),
		"token refresh"
	);
	assert_eq!(crate::test_support::anchor::<AnchorText>("CAFE\u{301}").unwrap().expose(), "café");
	for anchor in [
		"request.rs:212",
		"2:42",
		"commit 79dec41",
		"lead 41",
		"line 212",
		"job_9",
		"generation#4",
		"a\tb",
		"a\nb",
		" ",
	] {
		assert!(
			crate::test_support::anchor::<AnchorText>(anchor).is_err(),
			"must reject {anchor:?}"
		);
	}
	assert!(crate::test_support::anchor::<AnchorText>("parse_header() in http/request.rs").is_ok());
}

#[test]
fn anchor_caps_apply_after_whitespace_collapse() {
	for whitespace in [" ", "\u{a0}", "\u{2003}"] {
		let padding = whitespace.repeat(AnchorText::MAX_BYTES * 4 + 1);
		let raw = format!("{padding}TOKEN{padding}Refresh{padding}");
		assert_eq!(
			crate::test_support::anchor::<AnchorText>(&raw)
				.expect("bound the collapsed anchor")
				.expose(),
			"token refresh"
		);
		assert_eq!(
			crate::test_support::anchor::<InstanceKey>(&raw)
				.expect("bound the collapsed instance key")
				.expose(),
			"token refresh"
		);
		// Collapsing whitespace must not discard forbidden control characters.
		assert_eq!(
			crate::test_support::anchor::<AnchorText>(&format!("{raw}\t")).unwrap_err().rule,
			Rule::Character
		);
	}
	assert_eq!(
		crate::test_support::anchor::<AnchorText>(&"x".repeat(AnchorText::MAX_CHARS + 1))
			.unwrap_err()
			.rule,
		Rule::Chars
	);
	assert_eq!(
		crate::test_support::anchor::<InstanceKey>(&"😀".repeat(InstanceKey::MAX_BYTES / 4 + 1))
			.unwrap_err()
			.rule,
		Rule::Bytes
	);
}

#[test]
fn repository_paths_preserve_both_unicode_spellings() {
	for raw in ["café.rs", "cafe\u{301}.rs", "src/lib.rs"] {
		let path = crate::test_support::path(raw).unwrap();
		assert_eq!(path.expose(), raw);
		assert_eq!(
			serde_json::from_str::<String>(&serde_json::to_string(&path).unwrap()).unwrap(),
			path.expose()
		);
	}
	for raw in ["", ".", "/src", "a/../b", "a/./b", "a//b", "a/", "a\\b", "x\u{200b}"] {
		assert!(crate::test_support::path(raw).is_err());
	}
}

#[test]
fn json_bounds_validation_and_digests_are_one_boundary() {
	let json = crate::test_support::json::<Payload>("{\"z\":\"Cafe\\u0301\",\"a\":1}").unwrap();
	assert_eq!(json.expose(), "{\"a\":1,\"z\":\"Café\"}");
	assert_eq!(*json.digest(), crate::canonical::digest(json.canonical()));
	assert!(!format!("{json:?}").contains("Café"));
	let sixteen = format!("{}0{}", "[".repeat(15), "]".repeat(15));
	assert!(crate::test_support::json::<Payload>(&sixteen).is_ok());
	let seventeen = format!("[{sixteen}]");
	assert_eq!(crate::test_support::json::<Payload>(&seventeen).unwrap_err().rule, Rule::JsonDepth);
	let nodes = format!("[{}]", vec!["0"; 4096].join(","));
	assert_eq!(crate::test_support::json::<Payload>(&nodes).unwrap_err().rule, Rule::JsonNodes);
	assert!(
		crate::test_support::json::<Payload>(&format!("[{}]", vec!["0"; 4095].join(","))).is_ok()
	);
	assert_eq!(
		crate::test_support::json::<Payload>(&" ".repeat(65537)).unwrap_err().rule,
		Rule::Bytes
	);
	for raw in
		["{\"\\u200B\":1}", "{\"a\":\"x\\u202ey\"}", "{\"a\":\" trailing \"}", "null trailing"]
	{
		assert!(crate::test_support::json::<Payload>(raw).is_err());
		assert!(crate::test_support::json::<Payload>(raw).is_err());
	}
	assert_eq!(crate::test_support::json::<Payload>(json.expose()).unwrap(), json);
}

struct TwoByteText;
impl TextPolicy for TwoByteText {
	const FIELD: &'static str = "two_byte_text";
	const MAX_CHARS: usize = 2;
	const MAX_BYTES: usize = 2;
	const MULTILINE: bool = false;
}

#[test]
fn text_caps_include_the_exact_byte_boundary() {
	for raw in ["a", "ab", "é"] {
		assert_eq!(crate::test_support::text::<TwoByteText>(raw).unwrap().expose(), raw);
	}
	for raw in ["aé", "😀"] {
		assert_eq!(crate::test_support::text::<TwoByteText>(raw).unwrap_err().rule, Rule::Bytes);
	}
	assert_eq!(crate::test_support::text::<TwoByteText>("abc").unwrap_err().rule, Rule::Chars);
}

#[test]
fn raw_text_admission_precedes_character_validation() {
	for length in [7, 8] {
		assert_eq!(oversized("fixture", &"x".repeat(length), 2), Ok(()));
	}
	assert_eq!(oversized("fixture", &"x".repeat(9), 2), Err(Error::new("fixture", Rule::Bytes)));
	assert_eq!(oversized("fixture", "x", usize::MAX), Ok(()));
	assert_eq!(
		crate::test_support::text::<TwoByteText>(&"\0".repeat(9)).unwrap_err().rule,
		Rule::Bytes,
		"reject excessive raw input before interpreting forbidden characters"
	);
	assert_eq!(crate::test_support::text::<TwoByteText>("\0").unwrap_err().rule, Rule::Character);
}

#[test]
fn debug_retains_metadata_without_payloads() {
	let error = crate::test_support::text::<Title>("SECRET\u{202e}payload").unwrap_err();
	assert_eq!(format!("{error:?}"), "title: Character (U+202E)");
	assert_eq!(format!("{:?}", Error::new("title", Rule::Bytes)), "title: Bytes");
	let path = crate::test_support::path("SECRET.rs").unwrap();
	assert_eq!(format!("{path:?}"), "RepoPath<agent>(len=9, [redacted])");
	let json = crate::test_support::json::<Payload>(r#""SECRET""#).unwrap();
	assert_eq!(format!("{json:?}"), "BoundedJson<payload, agent>(len=8, [redacted])");
}

struct JsonBudget<const BYTES: usize, const DEPTH: usize>;
impl<const BYTES: usize, const DEPTH: usize> JsonPolicy for JsonBudget<BYTES, DEPTH> {
	const FIELD: &'static str = "json_budget";
	const MAX_BYTES: usize = BYTES;
	const MAX_DEPTH: usize = DEPTH;
	const MAX_NODES: usize = 32;
}

#[test]
fn embedded_json_checks_the_final_canonical_byte_boundary() {
	// Enter the actual visitor directly: numbers are charged at finish, so
	// this isolates the final canonical cap from the marked raw-entry cap.
	for raw in ["1", "12"] {
		let json = json::visitor_fixture::<JsonBudget<2, 1>, _>(
			&mut serde_json::Deserializer::from_str(raw),
		)
		.unwrap();
		assert_eq!(json, raw);
	}
	let error = json::visitor_fixture::<JsonBudget<2, 1>, _>(
		&mut serde_json::Deserializer::from_str("123"),
	)
	.unwrap_err();
	assert!(error.to_string().contains("json_budget: Bytes"), "{error}");
}

#[test]
fn embedded_json_charges_raw_strings_before_normalization() {
	// Six decoded bytes contract to four; with the quotes, the canonical
	// representation fits the same six-byte budget exactly.
	let exact = "\"e\u{301}e\u{301}\"";
	let json = json::visitor_fixture::<JsonBudget<6, 1>, _>(
		&mut serde_json::Deserializer::from_str(exact),
	)
	.unwrap();
	assert_eq!(json, "\"éé\"");
	let over = "\"e\u{301}e\u{301}e\u{301}\"";
	let error =
		json::visitor_fixture::<JsonBudget<6, 1>, _>(&mut serde_json::Deserializer::from_str(over))
			.unwrap_err();
	assert!(error.to_string().contains("json_budget: Bytes"), "{error}");
}

#[test]
fn json_scalar_visitors_preserve_values() {
	for raw in ["null", "true", "false", "-37", "1.25", "-1.25"] {
		let json = crate::test_support::json::<Payload>(raw).unwrap();
		assert_eq!(json.expose(), raw, "preserve scalar {raw}");
		assert_eq!(serde_json::to_string(&json).unwrap(), raw);
	}
	let owned = serde::de::value::StringDeserializer::<serde::de::value::Error>::new(
		"Cafe\u{301}".to_owned(),
	);
	let json = json::visitor_fixture::<Payload, _>(owned).unwrap();
	assert_eq!(json, "\"Café\"");
}

#[test]
fn unsupported_json_types_report_the_expected_kind() {
	let bytes = serde::de::value::BytesDeserializer::<serde::de::value::Error>::new(b"secret");
	let error = json::visitor_fixture::<Payload, _>(bytes).unwrap_err();
	assert_eq!(error.to_string(), "invalid type: byte array, expected bounded JSON");
}

#[test]
fn json_map_values_count_toward_the_depth_boundary() {
	let exact = crate::test_support::json::<JsonBudget<64, 2>>(r#"{"a":0}"#).unwrap();
	assert_eq!(exact.expose(), r#"{"a":0}"#);
	let error = crate::test_support::json::<JsonBudget<64, 2>>(r#"{"a":{"b":0}}"#).unwrap_err();
	assert_eq!(error.rule, Rule::JsonDepth, "nested object values must consume depth");
}
