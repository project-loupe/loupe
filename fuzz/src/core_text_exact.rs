//! Byte zero selects one of the 17 exact-text policies; the rest is UTF-8.
//! The oracle independently pins byte preservation, admission and diagnostics.
//! The temporary core namespace is removed at atomic source adoption.

use std::marker::PhantomData;

use loupe_core::source_migration::text::BoundedText;
use loupe_core::text::policy::*;
use loupe_core::text::{Error, Normalization, Rule, TextPolicy, Whitespace};
use loupe_provenance::{Agent, Ingress, Mark, Untrusted, Unvalidated, Validate};
use unicode_general_category::{get_general_category, GeneralCategory};

use crate::utils::test_logger;

const LIMIT: usize = 2 * 1024 * 1024;

struct ExactField<P>(PhantomData<P>);
impl<P: TextPolicy> Validate<&str, Agent> for ExactField<P> {
	type Output = BoundedText<P, Agent>;
	type Error = Error;
	fn validate<'view>(
		self, value: Unvalidated<'view, &str>, mark: Mark<'view, Agent>,
	) -> Result<Self::Output, Error> {
		BoundedText::new(&mark, value.get())
	}
}

pub fn do_test(data: &[u8]) {
	let Some((&policy, bytes)) = data.split_first() else { return };
	let Ok(raw) = std::str::from_utf8(bytes) else { return };
	match policy % 17 {
		0 => check::<FindingTitle>(raw, false),
		1 => check::<FindingDescription>(raw, true),
		2 => check::<PocUnified>(raw, true),
		3 => check::<PatchUnified>(raw, true),
		4 => check::<VerdictNotes>(raw, true),
		5 => check::<VerdictReason>(raw, true),
		6 => check::<PatchNotes>(raw, true),
		7 => check::<ScannerIdText>(raw, false),
		8 => check::<CweText>(raw, false),
		9 => check::<FindingFingerprintText>(raw, false),
		10 => check::<RepoHost>(raw, false),
		11 => check::<RepoOwner>(raw, false),
		12 => check::<RepoName>(raw, false),
		13 => check::<CloneUrl>(raw, false),
		14 => check::<GitBranch>(raw, false),
		15 => check::<MailAddress>(raw, false),
		_ => check::<MailSubjectPrefix>(raw, false),
	}
}

fn permitted(character: char, multiline: bool) -> bool {
	if multiline && matches!(character, '\n' | '\t' | '\r') {
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

#[allow(unsafe_code)]
fn check<P: TextPolicy>(raw: &str, multiline: bool) {
	// Pin the named combinations independently of the production policy macro.
	assert_eq!(P::NORMALIZATION, Normalization::Exact);
	assert_eq!(P::WHITESPACE, Whitespace::Significant);
	assert_eq!(P::MULTILINE, multiline);
	assert_eq!(P::ALLOW_CR, multiline);
	assert!(P::ALLOW_EMPTY);
	assert_eq!(P::MAX_BYTES, LIMIT);
	assert_eq!(P::MAX_CHARS, LIMIT);
	// SAFETY: the fuzzer made up these bytes; this is an Agent-labelled fixture.
	let ingress = unsafe { Ingress::<Agent>::new() };
	let result = Untrusted::new(raw, ingress).validate(ExactField::<P>(PhantomData));
	let accepted = raw.len() <= LIMIT
		&& raw.chars().count() <= LIMIT
		&& raw.chars().all(|character| permitted(character, multiline));
	assert_eq!(result.is_ok(), accepted, "exact-text admission disagrees with oracle");
	match result {
		Ok(value) => {
			assert_eq!(value.expose().as_bytes(), raw.as_bytes(), "exact field changed bytes");
			assert_eq!(value, value.clone());
			assert_eq!(
				serde_json::to_vec(&value).ok(),
				serde_json::to_vec(raw).ok(),
				"source tracking changed the wire string"
			);
			let expected = format!("BoundedText<{}, agent>([redacted])", P::FIELD);
			assert_eq!(format!("{value:?}"), expected);
			assert_eq!(format!("{value:#?}"), expected);
		},
		Err(error) => {
			assert_eq!(error.field, P::FIELD);
			let expected = if raw.len() > LIMIT {
				assert_eq!(error.rule, Rule::Bytes);
				assert_eq!(error.code_point, None);
				format!("{}: Bytes", P::FIELD)
			} else {
				assert_eq!(error.rule, Rule::Character);
				let first = raw.chars().find(|&character| !permitted(character, multiline));
				assert_eq!(error.code_point, first.map(u32::from));
				let Some(point) = error.code_point else { panic!("missing rejected code point") };
				format!("{}: Character (U+{point:04X})", P::FIELD)
			};
			assert_eq!(error.to_string(), expected);
			assert_eq!(format!("{error:?}"), expected);
		},
	}
}

pub fn core_text_exact_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn core_text_exact_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn every_named_policy_reaches_its_admission_oracle() {
		for policy in 0..17 {
			for raw in ["", "  cafe\u{301}  ", "\r\n\tquoted\r\n\r\n\r\n", "\0", "\u{202e}"] {
				let mut input = vec![policy];
				input.extend_from_slice(raw.as_bytes());
				do_test(&input);
			}
		}
	}

	#[test]
	fn decoded_byte_limits_include_multibyte_inputs() {
		for policy in [0, 3] {
			for raw in ["x".repeat(LIMIT), "é".repeat(LIMIT / 2)] {
				let mut input = vec![policy];
				input.extend_from_slice(raw.as_bytes());
				do_test(&input);
				input.push(b'x');
				do_test(&input);
			}
		}
	}
}
