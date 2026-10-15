//! Byte zero selects Title, Objective, Reason, Argument, Symbol, MediaType,
//! OriginalName, AnchorText, InstanceKey, or JsonLeaf; the rest is UTF-8 text.
//! This checks prose policies; Anchor's additional identity rules are separate.

use loupe_core::text::policy::*;
use loupe_core::text::{Rule, TextPolicy};
use unicode_general_category::{get_general_category, GeneralCategory};
use unicode_normalization::{is_nfc, UnicodeNormalization};

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	let Some((&policy, bytes)) = data.split_first() else { return };
	let Ok(raw) = std::str::from_utf8(bytes) else { return };
	match policy % 10 {
		0 => check::<Title>(raw),
		1 => check::<Objective>(raw),
		2 => check::<Reason>(raw),
		3 => check::<Argument>(raw),
		4 => check::<Symbol>(raw),
		5 => check::<MediaType>(raw),
		6 => check::<OriginalName>(raw),
		7 => check::<AnchorText>(raw),
		8 => check::<InstanceKey>(raw),
		_ => check::<JsonLeaf>(raw),
	}
}

fn permitted(character: char, multiline: bool) -> bool {
	if multiline && matches!(character, '\n' | '\t') {
		return true;
	}
	let point = u32::from(character);
	!matches!(
		get_general_category(character),
		GeneralCategory::Control
			| GeneralCategory::Format
			| GeneralCategory::Unassigned
			| GeneralCategory::PrivateUse
			| GeneralCategory::LineSeparator
			| GeneralCategory::ParagraphSeparator
	) && !(0xfdd0..=0xfdef).contains(&point)
		&& !matches!(point % 0x1_0000, 0xfffe | 0xffff)
}

// Fold CR and CRLF in one pass, independently of production's replacements.
fn normalize(raw: &str) -> String {
	let mut input = raw.chars().peekable();
	let mut folded = String::with_capacity(raw.len());
	while let Some(character) = input.next() {
		if character == '\r' {
			if input.peek() == Some(&'\n') {
				let _ = input.next();
			}
			folded.push('\n');
		} else {
			folded.push(character);
		}
	}
	folded.nfc().collect()
}

fn check<P: TextPolicy>(raw: &str) {
	let result = crate::fixtures::text::<P>(raw);
	// The documented raw admission budget is separate from normalized limits.
	// Check it before allocating the oracle's normalized representation too.
	let normalized = (raw.len() <= P::MAX_BYTES.saturating_mul(4)).then(|| normalize(raw));
	let accepted = normalized.as_ref().is_some_and(|text| {
		(P::ALLOW_EMPTY || !text.is_empty())
			&& text.chars().count() <= P::MAX_CHARS
			&& text.len() <= P::MAX_BYTES
			&& text.chars().all(|c| permitted(c, P::MULTILINE))
			&& !text.starts_with(char::is_whitespace)
			&& !text.ends_with(char::is_whitespace)
			&& !text.as_bytes().windows(3).any(|window| window == b"\n\n\n")
	});
	assert_eq!(result.is_ok(), accepted, "bounded-text acceptance disagrees with oracle");
	match result {
		Ok(value) => {
			assert_eq!(Some(value.expose()), normalized.as_deref(), "normalization changed");
			assert!(is_nfc(value.expose()), "accepted prose must be NFC");
			// Exact metadata grammar proves redaction without short-input collisions.
			assert_eq!(
				format!("{value:?}"),
				format!("BoundedText<{}, agent>([redacted])", P::FIELD),
				"bounded-text Debug must contain only metadata"
			);
		},
		Err(error) => {
			assert_eq!(error.field, P::FIELD);
			let rule = match error.rule {
				Rule::Character => "Character",
				Rule::Chars => "Chars",
				Rule::Bytes => "Bytes",
				Rule::Whitespace => "Whitespace",
				Rule::Empty => "Empty",
				_ => panic!("unexpected prose error rule"),
			};
			let mut expected = format!("{}: {rule}", P::FIELD);
			if let Some(point) = error.code_point {
				assert_eq!(error.rule, Rule::Character);
				assert!(normalized.as_ref().is_some_and(|text| text
					.chars()
					.any(|c| u32::from(c) == point && !permitted(c, P::MULTILINE))));
				expected.push_str(&format!(" (U+{point:04X})"));
			} else {
				assert_ne!(error.rule, Rule::Character);
			}
			assert_eq!(error.to_string(), expected, "prose error must contain only metadata");
			assert_eq!(format!("{error:?}"), expected);
		},
	}
}

pub fn core_text_bounded_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn core_text_bounded_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
