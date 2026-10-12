//! UTF-8 JSON {family, anchor, instance?}, at most 64 KiB. Anchor acceptance is
//! recognized without the production regex; fingerprint checks pin byte framing
//! and compare BLAKE3 results, without assuming hashes never collide.

use loupe_core::text::policy::{AnchorText, Family, InstanceKey};
use loupe_core::text::{Anchor, AnchorPolicy, Rule};
use loupe_storage::identity::{fingerprint, Identity};
use serde::Deserialize;
use unicode_general_category::{get_general_category, GeneralCategory};
use unicode_normalization::{is_nfc, UnicodeNormalization};

use crate::utils::test_logger;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
	family: String,
	anchor: String,
	instance: Option<String>,
}

fn word_byte(byte: u8) -> bool {
	byte.is_ascii_alphanumeric() || byte == b'_'
}

fn transient_id(text: &str) -> bool {
	let bytes = text.as_bytes();
	for keyword in ["job", "campaign", "generation", "unit", "lead", "finding", "line"] {
		for (start, _) in text.match_indices(keyword) {
			if start != 0 && bytes.get(start - 1).is_some_and(|byte| word_byte(*byte)) {
				continue;
			}
			let mut end = start + keyword.len();
			if bytes.get(end).is_some_and(|byte| matches!(*byte, b' ' | b'#' | b'_' | b'-')) {
				end += 1;
			}
			let digits = end;
			while bytes.get(end).is_some_and(u8::is_ascii_digit) {
				end += 1;
			}
			if end > digits && bytes.get(end).is_none_or(|byte| !word_byte(*byte)) {
				return true;
			}
		}
	}
	false
}

fn expected_anchor<P: AnchorPolicy>(raw: &str) -> Option<String> {
	let nfc: String = raw.nfc().collect();
	if nfc.chars().any(|character| {
		let point = u32::from(character);
		matches!(
			get_general_category(character),
			GeneralCategory::Control
				| GeneralCategory::Format
				| GeneralCategory::Unassigned
				| GeneralCategory::PrivateUse
				| GeneralCategory::LineSeparator
				| GeneralCategory::ParagraphSeparator
		) || (0xfdd0..=0xfdef).contains(&point)
			|| matches!(point % 65536, 65534 | 65535)
	}) {
		return None;
	}
	let lower = nfc.to_lowercase();
	let words: Vec<_> = lower.split_whitespace().collect();
	let text: String = words.join(" ").nfc().collect();
	if text.is_empty() || text.len() > P::MAX_BYTES || text.chars().count() > P::MAX_CHARS {
		return None;
	}
	for word in text.split(' ') {
		if word.rsplit_once(':').is_some_and(|(prefix, suffix)| {
			!prefix.is_empty()
				&& !suffix.is_empty()
				&& suffix.bytes().all(|byte| byte.is_ascii_digit())
		}) {
			return None;
		}
		let hash = (7..=64).contains(&word.len())
			&& word.bytes().all(|byte| byte.is_ascii_hexdigit())
			&& word.bytes().any(|byte| byte.is_ascii_digit());
		if hash {
			return None;
		}
	}
	(!transient_id(&text)).then_some(text)
}

fn check_anchor<P: AnchorPolicy>(raw: &str) -> Option<Anchor<P, loupe_provenance::Agent>> {
	let expected = expected_anchor::<P>(raw);
	let result = crate::fixtures::anchor::<P>(raw);
	assert_eq!(result.is_ok(), expected.is_some(), "anchor acceptance disagrees with recognizer");
	match result {
		Ok(anchor) => {
			assert_eq!(
				Some(anchor.expose()),
				expected.as_deref(),
				"anchor normalization disagrees"
			);
			assert!(is_nfc(anchor.expose()));
			assert_eq!(format!("{anchor:?}"), format!("Anchor<{}, agent>([redacted])", P::FIELD));
			let variant = format!(
				"  {}  ",
				anchor
					.expose()
					.to_ascii_uppercase()
					.split(' ')
					.collect::<Vec<_>>()
					.join("\u{a0}   ")
			);
			let equivalent = crate::fixtures::anchor::<P>(&variant).unwrap_or_else(|_| {
				panic!("equivalent anchor spacing and ASCII case must be accepted")
			});
			assert_eq!(
				equivalent.expose(),
				anchor.expose(),
				"equivalent anchor normalization changed identity"
			);
			Some(anchor)
		},
		Err(error) => {
			assert_eq!(error.field, P::FIELD);
			let rule = match error.rule {
				Rule::Character => "Character",
				Rule::Chars => "Chars",
				Rule::Bytes => "Bytes",
				Rule::Empty => "Empty",
				Rule::IdentityLocation => "IdentityLocation",
				Rule::IdentityHash => "IdentityHash",
				Rule::IdentityTransientId => "IdentityTransientId",
				_ => panic!("unexpected anchor error rule"),
			};
			let mut expected = format!("{}: {rule}", P::FIELD);
			if let Some(point) = error.code_point {
				assert_eq!(error.rule, Rule::Character);
				expected.push_str(&format!(" (U+{point:04X})"));
			} else {
				assert_ne!(error.rule, Rule::Character);
			}
			assert_eq!(error.to_string(), expected);
			assert_eq!(format!("{error:?}"), expected);
			None
		},
	}
}

fn frame(family: &str, anchor: &str, instance: Option<&str>) -> Vec<u8> {
	let mut bytes = b"lead-identity-v1".to_vec();
	for piece in [family, anchor, instance.unwrap_or("")] {
		bytes.push(0);
		bytes.extend_from_slice(piece.as_bytes());
	}
	bytes
}

pub fn do_test(data: &[u8]) {
	if data.len() > 64 * 1024 {
		return;
	}
	let Ok(input) = serde_json::from_slice::<Input>(data) else { return };
	let anchor = check_anchor::<AnchorText>(&input.anchor);
	let instance = input.instance.as_deref().map(check_anchor::<InstanceKey>);
	let Ok(family) = crate::fixtures::identifier::<Family>(&input.family) else { return };
	let Some(anchor) = anchor else { return };
	let instance = match instance {
		None => None,
		Some(Some(value)) => Some(value),
		Some(None) => return,
	};
	let bytes = frame(family.expose(), anchor.expose(), instance.as_ref().map(Anchor::expose));
	let actual = fingerprint(&family, &anchor, instance.as_ref());
	assert_eq!(actual, *blake3::hash(&bytes).as_bytes(), "identity fingerprint framing changed");
	let identity =
		Identity { family: family.clone(), anchor: anchor.clone(), instance: instance.clone() };
	assert_eq!(identity.fingerprint(), actual);
	let variant = crate::fixtures::anchor::<AnchorText>(&format!(
		"  {}  ",
		anchor.expose().to_ascii_uppercase()
	))
	.unwrap_or_else(|_| panic!("case-equivalent anchor must be accepted"));
	assert_eq!(fingerprint(&family, &variant, instance.as_ref()), actual);
	let other = if family.expose() == "other-family" { "another-family" } else { "other-family" };
	let other = crate::fixtures::identifier::<Family>(other)
		.unwrap_or_else(|_| panic!("fixed family must be valid"));
	let other_bytes = frame(other.expose(), anchor.expose(), instance.as_ref().map(Anchor::expose));
	assert_ne!(other_bytes, bytes, "different families must have different identity encodings");
	assert_eq!(
		fingerprint(&other, &anchor, instance.as_ref()),
		*blake3::hash(&other_bytes).as_bytes()
	);
}

pub fn storage_identity_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn storage_identity_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
