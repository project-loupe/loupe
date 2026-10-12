//! Private D-owner fixture readers. Every carry uses a live SQLite column.
//! These do not replace the production DAOs or classify arbitrary Db text.
#![allow(unsafe_code)] // Test-only Db ingress at the two named row readers below.

use std::fmt;
use std::ops::Range;

use loupe_core::text::{
	decode_json_string_bounded, policy, BoundedText, Error, Normalization, RepoPath, Rule,
	SourceRef, TextPolicy, Whitespace,
};
use loupe_core::Finding;
use loupe_provenance::{
	Agent, Db as DbSource, Ingress, Mark, Untrusted, Unvalidated, Validate, ValidateCarrying,
};
use loupe_storage::Db;
use rusqlite::types::ValueRef;
use rusqlite::Row;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;

// debug-ok: closed read categories, never column content.
#[derive(Debug)]
pub enum ReadError {
	Finding,
	Refs,
}
impl fmt::Display for ReadError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Self::Finding => "invalid stored finding",
			Self::Refs => "invalid stored source refs",
		})
	}
}
impl std::error::Error for ReadError {}

// debug-ok: only static field names, indices, ranges and observed live addresses.
#[derive(Debug)]
pub struct Span {
	pub index: usize,
	pub field: &'static str,
	pub range: Range<usize>,
	pub column_address: usize,
	pub column_len: usize,
	pub carried_address: usize,
}

// This private policy exercises the accepted exact single-line metadata rule.
// It does not claim that an audit CN is Agent or invent certificate authority.
pub struct AuditName;
impl TextPolicy for AuditName {
	const FIELD: &'static str = "audit_common_name";
	const MAX_BYTES: usize = policy::LEGACY_TEXT_MAX_BYTES;
	const MAX_CHARS: usize = policy::LEGACY_TEXT_MAX_BYTES;
	const MULTILINE: bool = false;
	const ALLOW_EMPTY: bool = true;
	const NORMALIZATION: Normalization = Normalization::Exact;
	const WHITESPACE: Whitespace = Whitespace::Significant;
}

pub struct StoredFinding {
	pub finding: Finding<Agent>,
	pub approved_by_cn: Option<BoundedText<AuditName, DbSource>>,
	pub rejected_by_cn: Option<BoundedText<AuditName, DbSource>>,
	pub patch_proposed_by_cn: Option<BoundedText<AuditName, DbSource>>,
	pub patch_notes: Option<BoundedText<policy::PatchNotes, Agent>>,
	pub spans: Vec<Span>,
}

// Generate only these concrete column validators, not a caller-selected source
// or arbitrary output parser. Each invocation is a designated finding column.
macro_rules! finding_column {
	($stored:ident, $agent:ident, $policy:ty, $field:literal) => {
		struct $stored;
		struct $agent;
		impl<'a> ValidateCarrying<&'a [u8], DbSource> for $stored {
			type Output = (BoundedText<$policy, Agent>, Span);
			type Error = Error;
			fn validate(
				self, u: Unvalidated<'_, &'a [u8], DbSource>,
			) -> Result<Self::Output, Error> {
				let raw = *u.get();
				let (value, address) =
					u.carry::<Agent>(0..raw.len()).ok_or_else(invalid)?.validate($agent)?;
				Ok((
					value,
					Span {
						index: 0,
						field: $field,
						range: 0..raw.len(),
						column_address: raw.as_ptr() as usize,
						column_len: raw.len(),
						carried_address: address,
					},
				))
			}
		}
		impl Validate<&[u8], Agent> for $agent {
			type Output = (BoundedText<$policy, Agent>, usize);
			type Error = Error;
			fn validate<'view>(
				self, u: Unvalidated<'view, &[u8]>, mark: Mark<'view, Agent>,
			) -> Result<Self::Output, Error> {
				let raw = std::str::from_utf8(u.get()).map_err(|_| invalid())?;
				Ok((BoundedText::new(&mark, raw)?, raw.as_ptr() as usize))
			}
		}
	};
}
finding_column!(StoredScanner, AgentScanner, policy::ScannerIdText, "scanner_id");
finding_column!(StoredTitle, AgentTitle, policy::FindingTitle, "title");
finding_column!(StoredDescription, AgentDescription, policy::FindingDescription, "description");
finding_column!(StoredCwe, AgentCwe, policy::CweText, "cwe");
finding_column!(StoredPatch, AgentPatch, policy::PatchUnified, "patch_unified");
finding_column!(StoredPoc, AgentPoc, policy::PocUnified, "poc_unified");
finding_column!(StoredFingerprint, AgentFingerprint, policy::FindingFingerprintText, "fingerprint");
finding_column!(StoredPatchNotes, AgentPatchNotes, policy::PatchNotes, "patch_notes");

struct StoredPath;
struct AgentPath;
impl<'a> ValidateCarrying<&'a [u8], DbSource> for StoredPath {
	type Output = (RepoPath<Agent>, Span);
	type Error = Error;
	fn validate(self, u: Unvalidated<'_, &'a [u8], DbSource>) -> Result<Self::Output, Error> {
		let raw = *u.get();
		let (value, address) =
			u.carry::<Agent>(0..raw.len()).ok_or_else(invalid)?.validate(AgentPath)?;
		Ok((
			value,
			Span {
				index: 0,
				field: "file_path",
				range: 0..raw.len(),
				column_address: raw.as_ptr() as usize,
				column_len: raw.len(),
				carried_address: address,
			},
		))
	}
}
impl Validate<&[u8], Agent> for AgentPath {
	type Output = (RepoPath<Agent>, usize);
	type Error = Error;
	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, mark: Mark<'view, Agent>,
	) -> Result<Self::Output, Error> {
		let raw = std::str::from_utf8(u.get()).map_err(|_| invalid())?;
		Ok((RepoPath::new(&mark, raw)?, raw.as_ptr() as usize))
	}
}
struct StoredAuditName;
impl Validate<&[u8], DbSource> for StoredAuditName {
	type Output = BoundedText<AuditName, DbSource>;
	type Error = Error;
	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, mark: Mark<'view, DbSource>,
	) -> Result<Self::Output, Error> {
		BoundedText::new(&mark, std::str::from_utf8(u.get()).map_err(|_| invalid())?)
	}
}

pub fn read_finding(db: &Db, id: i64) -> Result<StoredFinding, ReadError> {
	db.with_conn(|conn| {
		Ok(conn.query_row(
			"SELECT scanner_id,severity,title,description,file_path,line_start,line_end,cwe,
		patch_unified,poc_unified,fingerprint,approved_by_cn,rejected_by_cn,
		patch_proposed_by_cn,patch_notes FROM findings WHERE id=?1",
			[id],
			|row| Ok(finding_row(row)),
		)?)
	})
	.map_err(|_| ReadError::Finding)?
}

fn finding_row(row: &Row<'_>) -> Result<StoredFinding, ReadError> {
	// SAFETY: the only values wrapped with this token below are borrowed TEXT
	// from this actual SQLite result row, before any decoding or serialization.
	let ingress = unsafe { Ingress::<DbSource>::new() };
	let mut spans = Vec::new();
	macro_rules! content {
		($index:literal, $validator:expr) => {{
			let ValueRef::Text(bytes) = row.get_ref($index).map_err(|_| ReadError::Finding)? else {
				return Err(ReadError::Finding);
			};
			let (value, span) = Untrusted::new(bytes, ingress)
				.validate_carrying($validator)
				.map_err(|_| ReadError::Finding)?;
			spans.push(span);
			value
		}};
	}
	macro_rules! optional_content {
		($index:literal, $validator:expr) => {{
			match row.get_ref($index).map_err(|_| ReadError::Finding)? {
				ValueRef::Null => None,
				_ => Some(content!($index, $validator)),
			}
		}};
	}
	macro_rules! audit {
		($index:literal) => {{
			match row.get_ref($index).map_err(|_| ReadError::Finding)? {
				ValueRef::Null => None,
				ValueRef::Text(bytes) => Some(
					Untrusted::new(bytes, ingress)
						.validate(StoredAuditName)
						.map_err(|_| ReadError::Finding)?,
				),
				_ => return Err(ReadError::Finding),
			}
		}};
	}
	let finding = Finding {
		scanner_id: content!(0, StoredScanner),
		severity: row
			.get::<_, String>(1)
			.map_err(|_| ReadError::Finding)?
			.parse()
			.map_err(|_| ReadError::Finding)?,
		title: content!(2, StoredTitle),
		description: content!(3, StoredDescription),
		file_path: optional_content!(4, StoredPath),
		line_start: row.get(5).map_err(|_| ReadError::Finding)?,
		line_end: row.get(6).map_err(|_| ReadError::Finding)?,
		cwe: optional_content!(7, StoredCwe),
		patch_unified: optional_content!(8, StoredPatch),
		poc_unified: optional_content!(9, StoredPoc),
		fingerprint: content!(10, StoredFingerprint),
	};
	let patch_notes = optional_content!(14, StoredPatchNotes);
	Ok(StoredFinding {
		finding,
		approved_by_cn: audit!(11),
		rejected_by_cn: audit!(12),
		patch_proposed_by_cn: audit!(13),
		patch_notes,
		spans,
	})
}

pub struct StoredRefs {
	pub refs: Vec<SourceRef<Agent>>,
	pub canonical: String,
	pub spans: Vec<Span>,
}
pub fn read_unit_refs(db: &Db) -> Result<StoredRefs, ReadError> {
	db.with_conn(|conn| {
		Ok(conn.query_row(
			"SELECT source_refs FROM review_units WHERE review_unit_id=1",
			[],
			|row| Ok(refs_row::<32>(row)),
		)?)
	})
	.map_err(|_| ReadError::Refs)?
}
pub fn read_inspected_refs(db: &Db) -> Result<StoredRefs, ReadError> {
	db.with_conn(|conn| {
		Ok(conn.query_row(
			"SELECT inspected_refs FROM review_unit_results WHERE review_unit_result_id=1",
			[],
			|row| Ok(refs_row::<64>(row)),
		)?)
	})
	.map_err(|_| ReadError::Refs)?
}
fn refs_row<const MAX: usize>(row: &Row<'_>) -> Result<StoredRefs, ReadError> {
	let ValueRef::Text(bytes) = row.get_ref(0).map_err(|_| ReadError::Refs)? else {
		return Err(ReadError::Refs);
	};
	// SAFETY: bytes is the original borrowed SQLite TEXT column from the
	// concrete unit/inspection query above; no Value or String was reserialized.
	let ingress = unsafe { Ingress::<DbSource>::new() };
	Untrusted::new(bytes, ingress)
		.validate_carrying(StoredRefColumn::<MAX>)
		.map_err(|_| ReadError::Refs)
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
	type Output = StoredRefs;
	type Error = Error;
	fn validate(self, u: Unvalidated<'_, &'a [u8], DbSource>) -> Result<StoredRefs, Error> {
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
		// Named canonical storage projection of already validated values. This
		// serialization is never fed back into a carry operation.
		let value = serde_json::to_value(&refs).map_err(|_| invalid())?;
		let canonical = loupe_core::canonical::canonical_bytes(&value);
		if canonical.len() > 65536 {
			return Err(Error::new("source_refs", Rule::Bytes));
		}
		let canonical = String::from_utf8(canonical).map_err(|_| invalid())?;
		Ok(StoredRefs { refs, canonical, spans })
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
fn invalid() -> Error {
	Error::new("source_refs", Rule::JsonSyntax)
}
