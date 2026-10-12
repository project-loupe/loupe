use loupe_core::source_migration::text::BoundedText;
use loupe_core::text::{decode_json_string_bounded, TextPolicy};
use loupe_provenance::{Mark, Source};
use serde_json::value::RawValue;

use super::DecodeError;

pub(super) fn json_secret(
	token: &RawValue,
) -> Result<loupe_provenance::Secret<String>, DecodeError> {
	require_json_string(token.get())?;
	let decoded =
		decode_json_string_bounded(token.get(), "credential", super::BODY_CAP, super::BODY_CAP)?;
	// Own the bounded decoded allocation immediately; no source-generic secret
	// adapter or String extraction from an existing Secret is introduced.
	Ok(loupe_provenance::Secret::new(decoded.into_owned()))
}

/// Source-preserving field mechanics; callers supply their current source mark
/// and a token from their own concrete schema. No ingress or carry occurs here.
/// This helper is for the current exact policies only. A future semantic policy
/// must first admit its specified decoded-raw margin, then apply final caps;
/// using P::MAX_* as that raw admission would incorrectly reject normalization.
pub(crate) fn json_text<P: TextPolicy, S: Source>(
	mark: &Mark<'_, S>, token: &RawValue,
) -> Result<BoundedText<P, S>, DecodeError> {
	require_json_string(token.get())?;
	let decoded = decode_json_string_bounded(token.get(), P::FIELD, P::MAX_BYTES, P::MAX_CHARS)?;
	Ok(BoundedText::new(mark, &decoded)?)
}

pub(super) fn require_json_string(token: &str) -> Result<(), DecodeError> {
	if token.starts_with('"') {
		return Ok(());
	}
	// RawValue preserves number lexemes without converting them. The legacy
	// String visitor first parses a numeric scalar, so overflow is Syntax/400
	// while a finite wrong-type scalar is Data/422. Do not recursively inspect
	// objects/arrays: the legacy string visitor rejects their type immediately.
	if token.as_bytes().first().is_some_and(|byte| matches!(byte, b'-' | b'0'..=b'9')) {
		let _: serde_json::Number = serde_json::from_str(token).map_err(DecodeError::json)?;
	}
	Err(DecodeError::Data("invalid type"))
}

/// serde's internally tagged enums validate every ignored inner string and
/// number, unlike IgnoredAny. This compatibility pass retains no dynamic Value.
pub(super) struct DiscardContent;
impl<'de> serde::Deserialize<'de> for DiscardContent {
	fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Discard;
		impl<'de> serde::de::Visitor<'de> for Discard {
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
			fn visit_seq<A: serde::de::SeqAccess<'de>>(
				self, mut seq: A,
			) -> Result<Self::Value, A::Error> {
				while seq.next_element::<DiscardContent>()?.is_some() {}
				Ok(DiscardContent)
			}
			fn visit_map<A: serde::de::MapAccess<'de>>(
				self, mut map: A,
			) -> Result<Self::Value, A::Error> {
				while map.next_entry::<DiscardContent, DiscardContent>()?.is_some() {}
				Ok(DiscardContent)
			}
		}
		d.deserialize_any(Discard)
	}
}

// Internally tagged legacy enums also accept sequences, with the tag first.
// Probe it while retaining all actual field tokens for the concrete decoder.
pub(super) struct SequenceTag<'a>(pub(super) &'a RawValue);
impl<'de> serde::Deserialize<'de> for SequenceTag<'de> {
	fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Tag;
		impl<'de> serde::de::Visitor<'de> for Tag {
			type Value = SequenceTag<'de>;
			fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				f.write_str("tagged sequence")
			}
			fn visit_seq<A: serde::de::SeqAccess<'de>>(
				self, mut seq: A,
			) -> Result<Self::Value, A::Error> {
				let tag =
					seq.next_element()?.ok_or_else(|| serde::de::Error::custom("missing tag"))?;
				while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
				Ok(SequenceTag(tag))
			}
		}
		d.deserialize_seq(Tag)
	}
}
