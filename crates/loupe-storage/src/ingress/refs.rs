//! Nested reference tokens retain the original SQLite column spans.
use std::fmt;
use std::ops::Range;

use loupe_core::text::{
	decode_json_string_bounded, policy, BoundedText, Error, RepoPath, Rule, SourceRef, TextPolicy,
};
use loupe_provenance::{Agent, Db as DbSource, Mark, Unvalidated, Validate, ValidateCarrying};
use rusqlite::Row;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;

use super::{column, invalid, sql_error, ReadError};

// Live pointer observations are private; only the checked range is used for
// classification. They are not serialized or retained by public DAO outputs.
struct Span {
	index: usize,
	field: &'static str,
	range: Range<usize>,
	column_address: usize,
	column_len: usize,
	carried_address: usize,
}
struct StoredRefs<const MAX: usize> {
	refs: crate::source_refs::SourceRefs<MAX, Agent>,
	spans: Vec<Span>,
}

fn refs<const MAX: usize>(
	row: &Row<'_>, index: usize,
) -> rusqlite::Result<crate::source_refs::SourceRefs<MAX, Agent>> {
	let marked = column(row, index)?
		.validate_carrying(StoredRefColumn::<MAX>)
		.map_err(|e| sql_error(index, ReadError::existing(e)))?;
	// These range invariants are checked by token_span and carry, before
	// decoding; the original SQL TEXT remains live throughout validation.
	for span in &marked.spans {
		debug_assert_eq!(
			span.column_address.checked_add(span.range.start),
			Some(span.carried_address)
		);
		debug_assert!(span.range.end <= span.column_len);
		debug_assert!(span.index < MAX && matches!(span.field, "path" | "symbol"));
	}
	Ok(marked.refs)
}
pub(crate) fn unit_refs(
	row: &Row<'_>, index: usize,
) -> rusqlite::Result<crate::source_refs::UnitRefs<Agent>> {
	refs::<32>(row, index)
}
pub(crate) fn inspected_refs(
	row: &Row<'_>, index: usize,
) -> rusqlite::Result<crate::source_refs::InspectedRefs<Agent>> {
	refs::<64>(row, index)
}

#[cfg(fuzzing)]
pub(crate) fn fuzz_decode<const MAX: usize>(
	raw: &[u8],
) -> Result<crate::source_refs::SourceRefs<MAX, Agent>, Error> {
	// SAFETY: synthetic original Db column fixture; the actual production
	// validator carries its original path/symbol token spans before decoding.
	#[allow(unsafe_code)]
	let ingress = unsafe { loupe_provenance::Ingress::<DbSource>::new() };
	loupe_provenance::Untrusted::new(raw, ingress)
		.validate_carrying(StoredRefColumn::<MAX>)
		.map(|value| value.refs)
}
struct StoredRefColumn<const MAX: usize>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRef<'a> {
	#[serde(borrow)]
	path: &'a RawValue,
	#[serde(borrow)]
	symbol: Option<&'a RawValue>,
}
struct RawRefs<'a, const MAX: usize>(Vec<RawRef<'a>>);
impl<'de, const MAX: usize> Deserialize<'de> for RawRefs<'de, MAX> {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct RefsVisitor<const MAX: usize>;
		impl<'de, const MAX: usize> Visitor<'de> for RefsVisitor<MAX> {
			type Value = RawRefs<'de, MAX>;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.write_str("bounded source refs")
			}
			fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
				let mut refs = Vec::new();
				while let Some(entry) = seq.next_element::<RawRef<'de>>()? {
					if refs.len() == MAX {
						return Err(de::Error::custom("too many source refs"));
					}
					refs.push(entry);
				}
				Ok(RawRefs(refs))
			}
		}
		d.deserialize_seq(RefsVisitor::<MAX>)
	}
}
impl<'a, const MAX: usize> ValidateCarrying<&'a [u8], DbSource> for StoredRefColumn<MAX> {
	type Output = StoredRefs<MAX>;
	type Error = Error;
	fn validate(self, u: Unvalidated<'_, &'a [u8], DbSource>) -> Result<StoredRefs<MAX>, Error> {
		let bytes = *u.get();
		if bytes.len() > 65536 {
			return Err(Error::new("source_refs", Rule::Bytes));
		}
		let raw: RawRefs<'_, MAX> = serde_json::from_slice(bytes).map_err(|_| invalid())?;
		let mut refs = Vec::with_capacity(raw.0.len());
		let mut spans = Vec::new();
		for (index, entry) in raw.0.into_iter().enumerate() {
			let mut span = token_span(bytes, entry.path, index, "path")?;
			let (path, address) =
				u.carry::<Agent>(span.range.clone()).ok_or_else(invalid)?.validate(AgentRefPath)?;
			span.carried_address = address;
			spans.push(span);
			let symbol = if let Some(token) = entry.symbol {
				let mut span = token_span(bytes, token, index, "symbol")?;
				let (symbol, address) = u
					.carry::<Agent>(span.range.clone())
					.ok_or_else(invalid)?
					.validate(AgentRefSymbol)?;
				span.carried_address = address;
				spans.push(span);
				Some(symbol)
			} else {
				None
			};
			refs.push(SourceRef { path, symbol });
		}
		// The collection itself, including an empty one, retains the source of
		// this designated original SQL column. Element carries above remain
		// bound to their individual original tokens.
		let refs = u
			.carry::<Agent>(0..bytes.len())
			.ok_or_else(invalid)?
			.validate(AgentRefCollection::<MAX>(refs))?;
		Ok(StoredRefs { refs, spans })
	}
}
struct AgentRefCollection<const MAX: usize>(Vec<SourceRef<Agent>>);
impl<const MAX: usize> Validate<&[u8], Agent> for AgentRefCollection<MAX> {
	type Output = crate::source_refs::SourceRefs<MAX, Agent>;
	type Error = Error;
	fn validate<'view>(
		self, _: Unvalidated<'view, &[u8]>, mark: Mark<'view, Agent>,
	) -> Result<Self::Output, Error> {
		crate::source_refs::SourceRefs::new(&mark, self.0)
	}
}
fn token_span(
	bytes: &[u8], token: &RawValue, index: usize, field: &'static str,
) -> Result<Span, Error> {
	let start =
		(token.get().as_ptr() as usize).checked_sub(bytes.as_ptr() as usize).ok_or_else(invalid)?;
	let end = start
		.checked_add(token.get().len())
		.filter(|end| *end <= bytes.len())
		.ok_or_else(invalid)?;
	Ok(Span {
		index,
		field,
		range: start..end,
		column_address: bytes.as_ptr() as usize,
		column_len: bytes.len(),
		carried_address: 0,
	})
}
struct AgentRefPath;
impl Validate<&[u8], Agent> for AgentRefPath {
	type Output = (RepoPath<Agent>, usize);
	type Error = Error;
	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, mark: Mark<'view, Agent>,
	) -> Result<Self::Output, Error> {
		let raw = std::str::from_utf8(u.get()).map_err(|_| invalid())?;
		let decoded = decode_json_string_bounded(raw, "path", 512, 512)?;
		Ok((RepoPath::new(&mark, &decoded)?, raw.as_ptr() as usize))
	}
}
struct AgentRefSymbol;
impl Validate<&[u8], Agent> for AgentRefSymbol {
	type Output = (BoundedText<policy::Symbol, Agent>, usize);
	type Error = Error;
	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, mark: Mark<'view, Agent>,
	) -> Result<Self::Output, Error> {
		let raw = std::str::from_utf8(u.get()).map_err(|_| invalid())?;
		// Existing prose bound applies to decoded raw text, before normalization.
		let raw_bound = policy::Symbol::MAX_BYTES * 4;
		let decoded = decode_json_string_bounded(raw, "symbol", raw_bound, raw_bound)?;
		Ok((BoundedText::new(&mark, &decoded)?, raw.as_ptr() as usize))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn actual_ref_column_uses_distinct_original_tokens_before_decoding() {
		let db = crate::review_tests::fixture();
		let raw = r#"[ {"symbol":"same","path":"same"}, {"path":"same","symbol":"same"} ]"#;
		db.with_conn(|conn| {
            conn.execute("INSERT INTO review_units (review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES (31,11,'key','title','objective',?1,0)",[raw])?;
            conn.query_row("SELECT source_refs FROM review_units WHERE review_unit_id=31",[],|row| {
                let refs=column(row,0)?.validate_carrying(StoredRefColumn::<32>)
                    .map_err(|error| sql_error(0,ReadError::existing(error)))?;
                let expected=[(0,"path",26..32),(0,"symbol",12..18),(1,"path",43..49),(1,"symbol",59..65)];
                assert_eq!(refs.spans.len(),4);
                for (span,(index,field,range)) in refs.spans.iter().zip(expected) {
                    assert_eq!((span.index,span.field,span.range.clone()),(index,field,range));
                    assert_eq!(span.carried_address.checked_sub(span.column_address),Some(span.range.start));
                    assert_eq!(span.column_len,raw.len());
                    println!("actual nested SQL carry {field} {index}: {:?}, offset={}",span.range,span.carried_address-span.column_address);
                }
                let canonical = r#"[{"path":"same","symbol":"same"},{"path":"same","symbol":"same"}]"#;
                assert_eq!(refs.refs.expose(),canonical);
                assert_eq!(unit_refs(row,0)?.expose(),canonical);
                Ok(())
            })?;
            assert_eq!(crate::review_units::get(conn,31)?.unwrap().source_refs.as_slice().len(),2);
            Ok(())
        }).unwrap();
	}
}
