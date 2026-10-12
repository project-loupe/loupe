use std::borrow::Cow;

use super::json_string::preflight;
use super::{decode_json_string_bounded as decode, Rule};

#[test]
fn preflight_counts_decoded_bytes_and_scalars_before_output_allocation() {
	let raw = r#""café""#;
	let decoded = decode(raw, "fixture", 6, 5).unwrap();
	assert!(matches!(decoded, Cow::Borrowed(_)));
	assert_eq!(decoded.as_ptr(), raw[1..].as_ptr());
	let escaped = r#""\u00E9\uD83D\uDE00""#;
	let plan = preflight(escaped, "fixture", 6, 2).unwrap();
	assert_eq!((plan.bytes, plan.chars), (6, 2));
	let decoded = decode(escaped, "fixture", 6, 2).unwrap();
	assert!(matches!(decoded, Cow::Owned(_)));
	assert_eq!(decoded, "é😀");
	assert_eq!(preflight(escaped, "fixture", 5, 2).err().unwrap().rule, Rule::Bytes);
	assert_eq!(preflight(escaped, "fixture", 6, 1).err().unwrap().rule, Rule::Chars);
	assert_eq!(decode(r#""""#, "fixture", 0, 0).unwrap(), "");
}

#[test]
fn complete_token_syntax_and_error_metadata_are_fixed_and_payload_free() {
	for raw in [
		r#""\uD800""#,
		r#""\uDC00""#,
		r#""\uD800\u0041""#,
		r#""\x00""#,
		r#""\u12x4""#,
		"true",
		"\"raw\nline\"",
		"\"unterminated",
		"\"extra\"tail",
		" \"padded\"",
		"\"padded\" ",
		"\"trailing\\\"",
		r#""unescaped"quote""#,
	] {
		let error = preflight(raw, "fixture", usize::MAX, usize::MAX).err().unwrap();
		assert_eq!(error.rule, Rule::JsonSyntax, "{raw:?}");
		assert_eq!(error.field, "fixture");
		assert_eq!(error.code_point, None);
		assert_eq!(error.to_string(), "fixture: JsonSyntax");
		assert!(serde_json::from_str::<String>(raw).is_err() || raw.trim() != raw);
		assert!(decode(raw, "fixture", usize::MAX, usize::MAX).is_err());
	}
}

#[test]
fn serde_equivalence_covers_escaped_unescaped_controls_and_surrogate_extremes() {
	for raw in [
		r#""\"\\\/\b\f\n\r\t\u0000é\uD834\uDD1E""#,
		r#""\uD800\uDC00\uDBFF\uDFFF""#,
		r#""\u0000\uFFFF""#,
		r#""\u0061\u0301""#,
		r#""literalé😀""#,
	] {
		let expected: String = serde_json::from_str(raw).unwrap();
		let bytes = expected.len();
		let chars = expected.chars().count();
		assert_eq!(decode(raw, "fixture", bytes, chars).unwrap(), expected);
		assert_eq!(preflight(raw, "fixture", usize::MAX, usize::MAX).unwrap().bytes, bytes);
		assert_eq!(preflight(raw, "fixture", usize::MAX, usize::MAX).unwrap().chars, chars);
		assert!(decode(raw, "fixture", bytes - 1, chars).is_err());
		assert!(decode(raw, "fixture", bytes, chars - 1).is_err());
	}
	let samples = [
		'\0',
		'\u{8}',
		'\u{c}',
		'\n',
		'\r',
		'\t',
		'"',
		'\\',
		'/',
		'é',
		'\u{301}',
		'😀',
		'\u{10ffff}',
	];
	for first in samples {
		for second in samples {
			let expected = format!("{first}{second}");
			let raw = serde_json::to_string(&expected).unwrap();
			assert_eq!(decode(&raw, "fixture", expected.len(), 2).unwrap(), expected);
		}
	}
}

#[test]
fn encoded_length_is_independent_of_decoded_caps_and_policy_is_caller_owned() {
	let raw = format!("\"{}\"", "\\u0061".repeat(512));
	assert!(raw.len() > 512 * 4);
	assert_eq!(decode(&raw, "path", 512, 512).unwrap(), "a".repeat(512));
	assert_eq!(decode(r#""\u0000""#, "fixture", 1, 1).unwrap(), "\0");
	// The helper counts and parses; a domain's control/normalization policy is
	// deliberately absent. Both zero and full usize caps use checked counts.
	assert_eq!(decode(r#""a""#, "fixture", 0, 0).err().unwrap().rule, Rule::Bytes);
	assert_eq!(decode(r#""a""#, "fixture", usize::MAX, 0).err().unwrap().rule, Rule::Chars);
	assert_eq!(decode(r#""a""#, "fixture", usize::MAX, usize::MAX).unwrap(), "a");
}
