use policy::*;
use unicode_general_category::{get_general_category, GeneralCategory as G};

#[test]
fn review_duplicate_json_keys_are_not_silently_discarded() {
	for raw in [r#"{"a":1,"a":2}"#, r#"{"nested":{"a":1,"a":1}}"#] {
		assert!(
			BoundedJson::<Payload>::new(raw).is_err(),
			"duplicate keys must not discard a submitted value"
		);
		assert!(serde_json::from_str::<BoundedJson<Payload>>(raw).is_err());
	}
}

#[test]
fn review_labels_reject_whitespace_aliases() {
	for label in ["needs-triage ", "needs  triage"] {
		assert!(
			Identifier::<Label>::new(label).is_err(),
			"label whitespace must not create aliases"
		);
	}
	assert!(Identifier::<Label>::new("needs triage").is_ok());
}

#[test]
fn review_required_text_is_nonempty_but_json_strings_may_be_empty() {
	assert!(BoundedText::<Title>::new("").is_err(), "a present title must not be empty");
	assert!(BoundedText::<Objective>::new("").is_err());
	assert!(BoundedText::<JsonLeaf>::new("").is_ok());
	assert!(BoundedJson::<Payload>::new(r#"{"a":""}"#).is_ok());
}

#[test]
fn review_anchor_prose_is_not_mistaken_for_provenance() {
	for text in ["defaced response header", "acceded", "deadbeef", "port 8080 exposed", "x 12"] {
		assert!(
			Anchor::<AnchorText>::new(text).is_ok(),
			"ordinary anchor prose must remain usable: {text}"
		);
	}
	for text in ["commit 79dec41", "deadbeef1", "line 212", "unit 5", "request.rs:212"] {
		assert!(Anchor::<AnchorText>::new(text).is_err());
	}
}

#[test]
fn review_json_deserialization_stops_at_the_byte_budget() {
	// The trailing malformed token distinguishes incremental rejection from
	// a final length check after parsing and normalizing the entire tree.
	let leaf = format!("\"{}\"", "x".repeat(4000));
	let raw = format!("[{},invalid]", vec![leaf; 17].join(","));
	let error = serde_json::from_str::<BoundedJson<Payload>>(&raw).unwrap_err();
	assert!(
		error.to_string().contains("Bytes"),
		"reject the byte budget before visiting the suffix: {error}"
	);
}

use super::*;

#[test]
fn normalizes_semantics_without_exposing_payloads() {
	let text = BoundedText::<Objective>::new("Cafe\u{301}\r\n秘密").unwrap();
	assert_eq!(text.expose(), "Café\n秘密");
	assert!(!format!("{text:?}").contains("Café"));
	assert_eq!(
		serde_json::from_str::<BoundedText<Objective>>(&serde_json::to_string(&text).unwrap())
			.unwrap(),
		text
	);
	for s in ["中文", "مرحبا", "שלום", "👍🏽"] {
		assert_eq!(BoundedText::<Title>::new(s).unwrap().expose(), s);
	}
}

#[test]
fn policy_caps_and_deserialization_cannot_be_bypassed() {
	let emoji = "😀".repeat(150);
	assert_eq!(BoundedText::<Title>::new(&emoji).unwrap_err().rule, Rule::Bytes);
	assert!(BoundedText::<Objective>::new(&emoji).is_ok());
	assert!(serde_json::from_str::<BoundedText<Title>>(&serde_json::to_string(&emoji).unwrap())
		.is_err());
	assert_eq!(BoundedText::<Title>::new(&"x".repeat(201)).unwrap_err().rule, Rule::Chars);
	assert!(BoundedText::<Reason>::new("a\nb").is_err());
	assert!(Identifier::<Family>::new("Upper").is_err());
	assert!(Identifier::<ClientKey>::new("Upper").is_ok());
	assert!(Identifier::<ClientKey>::new(&"x".repeat(129)).is_err());
	assert!(Identifier::<Label>::new("a label").is_ok());
	assert!(Identifier::<JsonKey>::new("_ENV_NAME").is_ok());
}

#[test]
fn rejected_text_reports_only_the_rule_and_code_point() {
	for ch in [
		'\u{202e}', '\u{2066}', '\u{200d}', '\u{200c}', '\u{feff}', '\u{1b}', '\u{2028}',
		'\u{e000}',
	] {
		let error = BoundedText::<Objective>::new(&format!("SECRET{ch}payload")).unwrap_err();
		assert_eq!(error.rule, Rule::Character);
		assert!(error.to_string().contains(&format!("U+{:04X}", ch as u32)));
		assert!(!error.to_string().contains(ch));
		assert!(!format!("{error:?}").contains("SECRET"));
	}
	for text in [" x", "x ", "a\n\n\nb", "\r\n"] {
		assert!(BoundedText::<Objective>::new(text).is_err());
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
				| G::Format | G::Unassigned
				| G::PrivateUse
				| G::LineSeparator
				| G::ParagraphSeparator
		);
		let sample = format!("ok {ch} ok");
		assert_eq!(
			BoundedText::<Title>::new(&sample).is_ok(),
			!forbidden,
			"single U+{:04X}",
			ch as u32
		);
		assert_eq!(
			BoundedText::<Objective>::new(&sample).is_ok(),
			!forbidden || matches!(ch, '\n' | '\t'),
			"multi U+{:04X}",
			ch as u32
		);
	}
	assert_eq!(BoundedText::<Objective>::new("a\rb").unwrap().expose(), "a\nb");
	assert!(BoundedText::<Title>::new("a\rb").is_err());
}

#[test]
fn anchors_have_a_separate_identity_pipeline() {
	assert_eq!(Anchor::<AnchorText>::new("  TOKEN   Refresh  ").unwrap().expose(), "token refresh");
	assert_eq!(Anchor::<AnchorText>::new("CAFE\u{301}").unwrap().expose(), "café");
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
		assert!(Anchor::<AnchorText>::new(anchor).is_err(), "must reject {anchor:?}");
	}
	assert!(Anchor::<AnchorText>::new("parse_header() in http/request.rs").is_ok());
}

#[test]
fn anchor_caps_apply_after_whitespace_collapse() {
	for whitespace in [" ", "\u{a0}", "\u{2003}"] {
		let padding = whitespace.repeat(AnchorText::MAX_BYTES * 4 + 1);
		let raw = format!("{padding}TOKEN{padding}Refresh{padding}");
		assert_eq!(
			Anchor::<AnchorText>::new(&raw).expect("bound the collapsed anchor").expose(),
			"token refresh"
		);
		assert_eq!(
			Anchor::<InstanceKey>::new(&raw).expect("bound the collapsed instance key").expose(),
			"token refresh"
		);
		// Collapsing whitespace must not discard forbidden control characters.
		assert_eq!(
			Anchor::<AnchorText>::new(&format!("{raw}\t")).unwrap_err().rule,
			Rule::Character
		);
	}
	assert_eq!(
		Anchor::<AnchorText>::new(&"x".repeat(AnchorText::MAX_CHARS + 1)).unwrap_err().rule,
		Rule::Chars
	);
	assert_eq!(
		Anchor::<InstanceKey>::new(&"😀".repeat(InstanceKey::MAX_BYTES / 4 + 1)).unwrap_err().rule,
		Rule::Bytes
	);
}

#[test]
fn repository_paths_preserve_both_unicode_spellings() {
	for raw in ["café.rs", "cafe\u{301}.rs", "src/lib.rs"] {
		let path = RepoPath::new(raw).unwrap();
		assert_eq!(path.expose(), raw);
		assert_eq!(
			serde_json::from_str::<RepoPath>(&serde_json::to_string(&path).unwrap()).unwrap(),
			path
		);
	}
	for raw in ["", ".", "/src", "a/../b", "a/./b", "a//b", "a/", "a\\b", "x\u{200b}"] {
		assert!(RepoPath::new(raw).is_err());
	}
}

#[test]
fn json_bounds_validation_and_digests_are_one_boundary() {
	let json = BoundedJson::<Payload>::new("{\"z\":\"Cafe\\u0301\",\"a\":1}").unwrap();
	assert_eq!(json.expose(), "{\"a\":1,\"z\":\"Café\"}");
	assert_eq!(*json.digest(), crate::canonical::digest(json.canonical()));
	assert!(!format!("{json:?}").contains("Café"));
	let sixteen = format!("{}0{}", "[".repeat(15), "]".repeat(15));
	assert!(BoundedJson::<Payload>::new(&sixteen).is_ok());
	let seventeen = format!("[{sixteen}]");
	assert_eq!(BoundedJson::<Payload>::new(&seventeen).unwrap_err().rule, Rule::JsonDepth);
	let nodes = format!("[{}]", vec!["0"; 4096].join(","));
	assert_eq!(BoundedJson::<Payload>::new(&nodes).unwrap_err().rule, Rule::JsonNodes);
	assert!(BoundedJson::<Payload>::new(&format!("[{}]", vec!["0"; 4095].join(","))).is_ok());
	assert_eq!(BoundedJson::<Payload>::new(&" ".repeat(65537)).unwrap_err().rule, Rule::Bytes);
	for raw in
		["{\"\\u200B\":1}", "{\"a\":\"x\\u202ey\"}", "{\"a\":\" trailing \"}", "null trailing"]
	{
		assert!(BoundedJson::<Payload>::new(raw).is_err());
		assert!(serde_json::from_str::<BoundedJson<Payload>>(raw).is_err());
	}
	assert_eq!(serde_json::from_str::<BoundedJson<Payload>>(json.expose()).unwrap(), json);
}
