//! Original JSON string tokens, independent serde admission and decoded caps.
//! This checks bounded results; source inspection and Kani own preflight order.

use std::borrow::Cow;

use loupe_core::text::{decode_json_string_bounded, Error, Rule};

use crate::utils::test_logger;

const FIELD: &str = "fuzz_json_string";

pub fn do_test(data: &[u8]) {
	if data.len() > 64 * 1024 {
		return;
	}
	let Ok(raw) = std::str::from_utf8(data) else { return };
	let expected = serde_json::from_str::<String>(raw)
		.ok()
		.filter(|_| raw.starts_with('"') && raw.ends_with('"'));
	for (bytes, chars) in [(0, 0), (1, 1), (4, 1), (512, 512), (usize::MAX, usize::MAX)] {
		check(raw, expected.as_deref(), bytes, chars);
	}
	if let Some(expected) = &expected {
		let bytes = expected.len();
		let chars = expected.chars().count();
		for (bytes, chars) in
			[(bytes, chars), (bytes.saturating_sub(1), chars), (bytes, chars.saturating_sub(1))]
		{
			check(raw, Some(expected), bytes, chars);
		}
		let encoded = serde_json::to_string(expected)
			.unwrap_or_else(|error| panic!("reference string encoding failed: {error}"));
		check(&encoded, Some(expected), bytes, chars);
	}
}

fn first_limit(expected: &str, max_bytes: usize, max_chars: usize) -> Option<Rule> {
	let mut bytes = 0;
	for (index, character) in expected.chars().enumerate() {
		bytes += character.len_utf8();
		if bytes > max_bytes {
			return Some(Rule::Bytes);
		}
		if index >= max_chars {
			return Some(Rule::Chars);
		}
	}
	None
}

fn fixed_error(error: &Error) {
	assert_eq!(error.field, FIELD);
	assert_eq!(error.code_point, None);
	let expected = match error.rule {
		Rule::Bytes => "fuzz_json_string: Bytes",
		Rule::Chars => "fuzz_json_string: Chars",
		Rule::JsonSyntax => "fuzz_json_string: JsonSyntax",
		_ => panic!("string decoding returned a domain-policy error"),
	};
	assert_eq!(error.to_string(), expected);
	assert_eq!(format!("{error:#}"), expected);
	assert_eq!(format!("{error:?}"), expected);
	assert_eq!(format!("{error:#?}"), expected);
}

fn check(raw: &str, expected: Option<&str>, max_bytes: usize, max_chars: usize) {
	let actual = decode_json_string_bounded(raw, FIELD, max_bytes, max_chars);
	let limit = expected.and_then(|value| first_limit(value, max_bytes, max_chars));
	assert_eq!(
		actual.is_ok(),
		expected.is_some() && limit.is_none(),
		"JSON string admission disagrees with serde and decoded limits"
	);
	match actual {
		Ok(value) => {
			let Some(expected) = expected else { panic!("accepted token has no reference string") };
			assert_eq!(value.as_bytes(), expected.as_bytes(), "JSON string changed decoded bytes");
			assert!(value.len() <= max_bytes && value.chars().count() <= max_chars);
			if raw.contains('\\') {
				assert!(matches!(value, Cow::Owned(_)), "escaped token must use checked storage");
			} else {
				assert!(matches!(value, Cow::Borrowed(_)), "unescaped token must stay borrowed");
				let Some(interior) = raw.get(1..) else {
					panic!("accepted token has no opening quote")
				};
				assert_eq!(
					value.as_ptr(),
					interior.as_ptr(),
					"borrow must retain the original token"
				);
			}
		},
		Err(error) => {
			fixed_error(&error);
			if let Some(limit) = limit {
				assert_eq!(error.rule, limit, "decoded cap error order changed");
			} else if max_bytes == usize::MAX && max_chars == usize::MAX {
				assert_eq!(error.rule, Rule::JsonSyntax);
			}
			// A bounded malformed token may exceed its cap before encountering
			// a later syntax error. No unsupported global precedence is assumed.
		},
	}
}

pub fn core_json_string_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn core_json_string_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller supplies readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn syntax_and_decoded_boundary_classes_reach_the_oracle() {
		for raw in [
			r#""""#,
			r#""caféé😀""#,
			r#""\"\\\/\b\f\n\r\t\u0000""#,
			r#""\ud800\udc00\udbff\udfff""#,
			r#""\ud800""#,
			r#""\udc00""#,
			r#""\ud800\u0041""#,
			r#""\ud800\ud""#,
			r#""\x00""#,
			r#""\u12x4""#,
			r#""a" "b""#,
			r#""\""#,
			"\"unterminated",
			" \"outer whitespace\" ",
			"\"raw\ncontrol\"",
			"null",
			"",
		] {
			do_test(raw.as_bytes());
		}
		do_test(b"\"invalid\xff\"");
	}

	#[test]
	fn field_sized_literals_and_escapes_keep_decoded_limits() {
		for bytes in [512, 2 * 1024 * 1024] {
			let text = "é".repeat(bytes / 2);
			let raw = serde_json::to_string(&text)
				.unwrap_or_else(|error| panic!("reference string encoding failed: {error}"));
			check(&raw, Some(&text), bytes, bytes / 2);
			check(&raw, Some(&text), bytes - 1, bytes / 2);
			check(&raw, Some(&text), bytes, bytes / 2 - 1);
			let escaped = format!("\"{}\"", "\\u00e9".repeat(bytes / 2));
			check(&escaped, Some(&text), bytes, bytes / 2);
			check(&escaped, Some(&text), bytes - 1, bytes / 2);
			check(&escaped, Some(&text), bytes, bytes / 2 - 1);
		}
	}
}
