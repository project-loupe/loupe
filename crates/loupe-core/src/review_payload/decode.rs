//! Private field admission for the fixed review payload schemas.
use loupe_provenance::{Mark, Source};
use serde::Deserialize;
use serde_json::value::RawValue;

use super::{
	Confidence, ContinuationClass, DuplicateTarget, Error, LocationRole, PreProofApplicability,
	PreProofRung, SurveyTerminalReason, Version1,
};
use crate::text::{
	decode_json_string_bounded, Anchor, AnchorPolicy, BoundedText, IdentPolicy, Identifier,
	Normalization, RepoPath, SourceRef, TextPolicy,
};

pub(super) fn required(raw: Option<&RawValue>) -> Result<&RawValue, Error> {
	raw.ok_or_else(|| super::invalid("payload", "missing required field"))
}
pub(super) trait Field<S: Source>: Sized {
	fn decode(mark: &Mark<'_, S>, raw: Option<&RawValue>) -> Result<Self, Error>;
}
pub(super) fn field<S: Source, T: Field<S>>(
	mark: &Mark<'_, S>, raw: Option<&RawValue>,
) -> Result<T, Error> {
	T::decode(mark, raw)
}
macro_rules! scalar {
	($($ty:ty),* $(,)?) => { $(
		impl<S: Source> Field<S> for $ty {
			fn decode(_: &Mark<'_, S>, raw: Option<&RawValue>) -> Result<Self, Error> {
				Ok(serde_json::from_str(required(raw)?.get())?)
			}
		}
	)* };
}
scalar!(
	Version1,
	DuplicateTarget,
	i64,
	u32,
	LocationRole,
	Confidence,
	SurveyTerminalReason,
	ContinuationClass,
	PreProofRung,
	PreProofApplicability,
	super::LeadEvidenceFormat,
	super::UnitResultFormat,
	super::UnitResultDisposition,
	crate::review_priority::Impact,
	crate::review_priority::Access,
	crate::review_priority::Reachability,
);

// Severity is shared with legacy findings and keeps its derived serde shape;
// typed evidence still admits it only as a string.
impl<S: Source> Field<S> for crate::Severity {
	fn decode(_: &Mark<'_, S>, raw: Option<&RawValue>) -> Result<Self, Error> {
		let mut json = serde_json::Deserializer::from_str(required(raw)?.get());
		let text = crate::closed_string::string(&mut json)?;
		json.end()?;
		Ok(Self::deserialize(serde::de::value::StrDeserializer::<serde_json::Error>::new(&text))?)
	}
}

impl<S: Source, P: TextPolicy> Field<S> for BoundedText<P, S> {
	fn decode(mark: &Mark<'_, S>, raw: Option<&RawValue>) -> Result<Self, Error> {
		let factor = if P::NORMALIZATION == Normalization::Semantic { 4 } else { 1 };
		let text = decode_json_string_bounded(
			required(raw)?.get(),
			P::FIELD,
			P::MAX_BYTES.saturating_mul(factor),
			P::MAX_BYTES.saturating_mul(factor),
		)?;
		Ok(Self::new(mark, &text)?)
	}
}
impl<S: Source, P: IdentPolicy> Field<S> for Identifier<P, S> {
	fn decode(mark: &Mark<'_, S>, raw: Option<&RawValue>) -> Result<Self, Error> {
		let text =
			decode_json_string_bounded(required(raw)?.get(), P::FIELD, P::MAX_LEN, P::MAX_LEN)?;
		Ok(Self::new(mark, &text)?)
	}
}
impl<S: Source, P: AnchorPolicy> Field<S> for Anchor<P, S> {
	fn decode(mark: &Mark<'_, S>, raw: Option<&RawValue>) -> Result<Self, Error> {
		let raw = required(raw)?.get();
		// Anchor whitespace folding has no bounded raw-to-normalized ratio.
		// Its enclosing ingress bounds the original document; preflight still
		// determines the complete decoded size before allocating the string.
		let text = decode_json_string_bounded(raw, P::FIELD, raw.len(), raw.len())?;
		Ok(Self::new(mark, &text)?)
	}
}
impl<S: Source> Field<S> for RepoPath<S> {
	fn decode(mark: &Mark<'_, S>, raw: Option<&RawValue>) -> Result<Self, Error> {
		let path = decode_json_string_bounded(required(raw)?.get(), "path", 512, 512)?;
		Ok(Self::new(mark, &path)?)
	}
}
impl<S: Source> Field<S> for SourceRef<S> {
	fn decode(mark: &Mark<'_, S>, raw: Option<&RawValue>) -> Result<Self, Error> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire<'a> {
			#[serde(borrow)]
			path: &'a RawValue,
			#[serde(borrow, default)]
			symbol: Option<&'a RawValue>,
		}
		let raw: Wire<'_> = serde_json::from_str(required(raw)?.get())?;
		Ok(Self { path: field(mark, Some(raw.path))?, symbol: field(mark, raw.symbol)? })
	}
}
impl<S: Source, T: Field<S>> Field<S> for Option<T> {
	fn decode(mark: &Mark<'_, S>, raw: Option<&RawValue>) -> Result<Self, Error> {
		raw.filter(|raw| raw.get() != "null").map(|raw| T::decode(mark, Some(raw))).transpose()
	}
}
impl<S: Source, T: Field<S>> Field<S> for Box<T> {
	fn decode(mark: &Mark<'_, S>, raw: Option<&RawValue>) -> Result<Self, Error> {
		T::decode(mark, raw).map(Box::new)
	}
}
impl<S: Source, T: Field<S>> Field<S> for Vec<T> {
	fn decode(mark: &Mark<'_, S>, raw: Option<&RawValue>) -> Result<Self, Error> {
		list::<S, T, 16>(mark, raw)
	}
}

/// Each schema selects its own closed list budget before owned admission.
pub(super) fn list<S: Source, T: Field<S>, const MAX: usize>(
	mark: &Mark<'_, S>, raw: Option<&RawValue>,
) -> Result<Vec<T>, Error> {
	struct Tokens<'a, const MAX: usize>(Vec<&'a RawValue>);
	impl<'de, const MAX: usize> Deserialize<'de> for Tokens<'de, MAX> {
		fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
			struct Visitor<const MAX: usize>;
			impl<'de, const MAX: usize> serde::de::Visitor<'de> for Visitor<MAX> {
				type Value = Tokens<'de, MAX>;
				fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
					f.write_str("a bounded evidence list")
				}
				fn visit_seq<A: serde::de::SeqAccess<'de>>(
					self, mut seq: A,
				) -> Result<Self::Value, A::Error> {
					let mut tokens = Vec::new();
					while let Some(raw) = seq.next_element()? {
						if tokens.len() == MAX {
							return Err(serde::de::Error::custom("too many evidence entries"));
						}
						tokens.push(raw);
					}
					Ok(Tokens(tokens))
				}
			}
			d.deserialize_seq(Visitor::<MAX>)
		}
	}
	let tokens: Tokens<'_, MAX> = serde_json::from_str(required(raw)?.get())?;
	tokens.0.into_iter().map(|raw| T::decode(mark, Some(raw))).collect()
}
