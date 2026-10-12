//! Source-preserving field mechanics for concrete worker boundary validators.
//! This module has no ingress token and no source-selecting decoder.

use std::ops::Range;

use loupe_core::source_migration::text::BoundedText;
use loupe_core::text::{decode_json_string_bounded, Normalization, TextPolicy, Whitespace};
use loupe_provenance::{Mark, Source};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;

#[derive(Debug, thiserror::Error)]
pub(crate) enum DecodeError {
	#[error("invalid JSON syntax")]
	Syntax,
	#[error("{0}")]
	Data(&'static str),
	#[error("{reason} at line {line} column {column}")]
	Json { reason: &'static str, line: usize, column: usize },
	#[error(transparent)]
	Policy(#[from] loupe_core::text::Error),
}

impl From<serde_json::Error> for DecodeError {
	fn from(error: serde_json::Error) -> Self {
		let reason = if error.is_data() {
			if error.to_string().starts_with("missing field") {
				"missing field"
			} else {
				"invalid response data"
			}
		} else {
			"invalid JSON syntax"
		};
		Self::Json { reason, line: error.line(), column: error.column() }
	}
}

pub(crate) fn require_string(token: &str) -> Result<(), DecodeError> {
	if token.starts_with('"') {
		return Ok(());
	}
	if token.as_bytes().first().is_some_and(|b| matches!(b, b'-' | b'0'..=b'9')) {
		let _: serde_json::Number = serde_json::from_str(token)?;
	}
	Err(DecodeError::Data("expected string"))
}

pub(crate) fn json_text<P: TextPolicy, S: Source>(
	mark: &Mark<'_, S>, token: &RawValue,
) -> Result<BoundedText<P, S>, DecodeError> {
	require_string(token.get())?;
	let decoded = decode_json_string_bounded(token.get(), P::FIELD, P::MAX_BYTES, P::MAX_CHARS)?;
	Ok(BoundedText::new(mark, &decoded)?)
}

pub(crate) fn token_range(body: &[u8], token: &RawValue) -> Result<Range<usize>, DecodeError> {
	let start = (token.get().as_ptr() as usize)
		.checked_sub(body.as_ptr() as usize)
		.ok_or(DecodeError::Syntax)?;
	let end = start
		.checked_add(token.get().len())
		.filter(|end| *end <= body.len())
		.ok_or(DecodeError::Syntax)?;
	Ok(start..end)
}

macro_rules! exact_policy {
	($($name:ident, $field:literal;)*) => { $(
		pub(crate) struct $name;
		impl TextPolicy for $name {
			const FIELD: &'static str = $field;
			const MAX_CHARS: usize = loupe_core::text::policy::LEGACY_TEXT_MAX_BYTES;
			const MAX_BYTES: usize = loupe_core::text::policy::LEGACY_TEXT_MAX_BYTES;
			const MULTILINE: bool = false;
			const ALLOW_EMPTY: bool = true;
			const NORMALIZATION: Normalization = Normalization::Exact;
			const WHITESPACE: Whitespace = Whitespace::Significant;
		}
	)* };
}
exact_policy! {
	RevisionText, "revision";
	AuditName, "audit_name";
	ScannerExtension, "scanner_extension";
	ScannerExcludePattern, "scanner_exclude_pattern";
}

/// No-output compatibility visitor for legacy Value/tagged-enum interiors.
/// Call it at the original envelope depth after designated field validation.
pub(crate) struct DiscardContent;
impl<'de> Deserialize<'de> for DiscardContent {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Discard;
		impl<'de> Visitor<'de> for Discard {
			type Value = DiscardContent;
			fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				f.write_str("JSON content")
			}
			fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
				Ok(DiscardContent)
			}
			fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
				Ok(DiscardContent)
			}
			fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
				Ok(DiscardContent)
			}
			fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
				Ok(DiscardContent)
			}
			fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
				Ok(DiscardContent)
			}
			fn visit_unit<E>(self) -> Result<Self::Value, E> {
				Ok(DiscardContent)
			}
			fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
				while seq.next_element::<DiscardContent>()?.is_some() {}
				Ok(DiscardContent)
			}
			fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
				while map.next_entry::<DiscardContent, DiscardContent>()?.is_some() {}
				Ok(DiscardContent)
			}
		}
		d.deserialize_any(Discard)
	}
}

pub(crate) struct SequenceTag<'a>(pub(crate) &'a RawValue);
impl<'de> Deserialize<'de> for SequenceTag<'de> {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Tag;
		impl<'de> Visitor<'de> for Tag {
			type Value = SequenceTag<'de>;
			fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				f.write_str("tagged sequence")
			}
			fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
				let token = seq.next_element()?.ok_or_else(|| de::Error::custom("missing tag"))?;
				while seq.next_element::<de::IgnoredAny>()?.is_some() {}
				Ok(SequenceTag(token))
			}
		}
		d.deserialize_seq(Tag)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn original_token_ranges_distinguish_equal_and_escaped_contents() {
		let bytes = br#"["same","\u0073ame","same"]"#;
		let tokens: Vec<&RawValue> = serde_json::from_slice(bytes).unwrap();
		assert_eq!(token_range(bytes, tokens[0]).unwrap(), 1..7);
		assert_eq!(token_range(bytes, tokens[1]).unwrap(), 8..19);
		assert_eq!(token_range(bytes, tokens[2]).unwrap(), 20..26);
		let foreign = RawValue::from_string("\"same\"".to_owned()).unwrap();
		assert!(
			token_range(bytes, &foreign).is_err(),
			"equal foreign content is not an original token span"
		);
	}
}
