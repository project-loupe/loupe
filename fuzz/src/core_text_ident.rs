//! Byte zero selects ClientKey, Family, Label, or JsonKey. Remaining bytes are
//! UTF-8 input; the recognizer never calls the production policy predicate.

use loupe_core::text::policy::{ClientKey, Family, JsonKey, Label};
use loupe_core::text::{IdentPolicy, Rule};

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	let Some((&policy, bytes)) = data.split_first() else { return };
	let Ok(raw) = std::str::from_utf8(bytes) else { return };
	let policy = policy % 4;
	match policy {
		0 => check::<ClientKey>(raw, policy),
		1 => check::<Family>(raw, policy),
		2 => check::<Label>(raw, policy),
		_ => check::<JsonKey>(raw, policy),
	}
}

fn alphanumeric(byte: u8) -> bool {
	matches!(byte, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
}

fn recognizes(raw: &[u8], policy: u8) -> bool {
	let Some(&first) = raw.first() else { return false };
	let initial = match policy {
		1 => raw.len() >= 3,
		3 => matches!(first, b'A'..=b'Z' | b'a'..=b'z' | b'_'),
		_ => alphanumeric(first),
	};
	initial
		&& raw.iter().copied().all(|byte| match policy {
			0 => alphanumeric(byte) || matches!(byte, b'.' | b'_' | b'-'),
			1 => matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'),
			2 => alphanumeric(byte) || matches!(byte, b'.' | b'_' | b'-' | b' '),
			_ => alphanumeric(byte) || byte == b'_',
		})
}

fn check<P: IdentPolicy>(raw: &str, policy: u8) {
	// The policy predicate describes syntax; Identifier adds length and spacing.
	let syntax = recognizes(raw.as_bytes(), policy);
	assert_eq!(P::accepts(raw), syntax, "identifier policy disagrees with byte recognizer");
	let accepted = syntax
		&& raw.len() <= P::MAX_LEN
		&& !raw.ends_with(' ')
		&& !raw.as_bytes().windows(2).any(|pair| pair == b"  ");
	let result = crate::fixtures::identifier::<P>(raw);
	assert_eq!(result.is_ok(), accepted, "identifier acceptance disagrees with oracle");
	match result {
		Ok(value) => {
			assert_eq!(value.expose(), raw, "identifier spelling must be preserved");
			assert_eq!(
				format!("{value:?}"),
				format!("Identifier<{}, agent>([redacted])", P::FIELD),
				"identifier Debug must contain only metadata"
			);
		},
		Err(error) => {
			assert_eq!(error.field, P::FIELD);
			let rule = match error.rule {
				Rule::Character => "Character",
				Rule::Bytes => "Bytes",
				Rule::Identifier => "Identifier",
				Rule::Whitespace => "Whitespace",
				_ => panic!("unexpected identifier error rule"),
			};
			let mut expected = format!("{}: {rule}", P::FIELD);
			if let Some(point) = error.code_point {
				assert_eq!(error.rule, Rule::Character);
				assert!(raw.chars().any(|character| u32::from(character) == point));
				expected.push_str(&format!(" (U+{point:04X})"));
			} else {
				assert_ne!(error.rule, Rule::Character);
			}
			assert_eq!(error.to_string(), expected, "identifier error must contain only metadata");
			assert_eq!(format!("{error:?}"), expected);
		},
	}
}

pub fn core_text_ident_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn core_text_ident_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
