//! Original reporting JSON tokens and the distinct scanner fallback contract.
use std::fmt;
use std::marker::PhantomData;

use loupe_core::source_migration::text::BoundedText;
use loupe_core::source_migration::ReportingDestination;
use loupe_core::text::{decode_json_string_bounded, policy, TextPolicy};
use loupe_provenance::{Db, Mark, Unvalidated, Validate};
use rusqlite::Row;
use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;

use super::{column, sql_error, utf8, ReadError};

enum Kind {
	GithubIssue,
	Email,
	Manual,
}
impl<'de> Deserialize<'de> for Kind {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Tag;
		impl Visitor<'_> for Tag {
			type Value = Kind;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.write_str("reporting kind string")
			}
			fn visit_str<E: de::Error>(self, s: &str) -> Result<Kind, E> {
				match s {
					"github_issue" => Ok(Kind::GithubIssue),
					"email" => Ok(Kind::Email),
					"manual" => Ok(Kind::Manual),
					_ => Err(E::custom("invalid reporting kind")),
				}
			}
		}
		d.deserialize_identifier(Tag)
	}
}
#[derive(Deserialize)]
struct Tag {
	kind: Kind,
}
struct SequenceTag(Kind);
impl<'de> Deserialize<'de> for SequenceTag {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct TagVisitor;
		impl<'de> Visitor<'de> for TagVisitor {
			type Value = SequenceTag;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.write_str("tagged reporting sequence")
			}
			fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
				let tag = a.next_element()?.ok_or_else(|| de::Error::missing_field("kind"))?;
				while a.next_element::<IgnoredAny>()?.is_some() {}
				Ok(SequenceTag(tag))
			}
		}
		d.deserialize_seq(TagVisitor)
	}
}
#[derive(Deserialize)]
struct Github<'a> {
	#[serde(rename = "kind")]
	_kind: Kind,
	#[serde(borrow)]
	target_owner: &'a RawValue,
	#[serde(borrow)]
	target_repo: &'a RawValue,
	#[serde(default)]
	pat_secret_id: Option<i64>,
}
#[derive(Deserialize)]
struct Email<'a> {
	#[serde(rename = "kind")]
	_kind: Kind,
	#[serde(borrow)]
	to: Vec<&'a RawValue>,
	#[serde(default, borrow)]
	from: Option<&'a RawValue>,
	#[serde(default, borrow)]
	subject_prefix: Option<&'a RawValue>,
}
macro_rules! field {
	($name:ident, $policy:ty) => {
		fn $name(
			mark: &Mark<'_, Db>, token: &RawValue,
		) -> Result<BoundedText<$policy, Db>, ReadError> {
			let decoded = decode_json_string_bounded(
				token.get(),
				<$policy>::FIELD,
				<$policy>::MAX_BYTES,
				<$policy>::MAX_CHARS,
			)
			.map_err(ReadError::decoded)?;
			BoundedText::new(mark, &decoded).map_err(ReadError::admission)
		}
	};
}
field!(owner, policy::RepoOwner);
field!(repo, policy::RepoName);
field!(address, policy::MailAddress);
field!(subject, policy::MailSubjectPrefix);
struct StoredReporting;
impl Validate<&[u8], Db> for StoredReporting {
	type Output = ReportingDestination<Db>;
	type Error = ReadError;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Db>,
	) -> Result<Self::Output, ReadError> {
		let raw = utf8(u.get()).map_err(ReadError::existing)?;
		let kind = if raw.trim_start().starts_with('[') {
			serde_json::from_str::<SequenceTag>(raw).map_err(|_| ReadError::Syntax)?.0
		} else {
			serde_json::from_str::<Tag>(raw).map_err(|_| ReadError::Syntax)?.kind
		};
		let reporting = match kind {
			Kind::GithubIssue => {
				let raw: Github<'_> = serde_json::from_str(raw).map_err(|_| ReadError::Syntax)?;
				ReportingDestination::GithubIssue {
					target_owner: owner(&mark, raw.target_owner)?,
					target_repo: repo(&mark, raw.target_repo)?,
					pat_secret_id: raw.pat_secret_id,
				}
			},
			Kind::Email => {
				let raw: Email<'_> = serde_json::from_str(raw).map_err(|_| ReadError::Syntax)?;
				ReportingDestination::Email {
					to: raw
						.to
						.into_iter()
						.map(|token| address(&mark, token))
						.collect::<Result<_, _>>()?,
					from: raw.from.map(|token| address(&mark, token)).transpose()?,
					subject_prefix: raw
						.subject_prefix
						.map(|token| subject(&mark, token))
						.transpose()?,
				}
			},
			Kind::Manual => {
				// Unit variants reject additional sequence members; maps keep
				// the existing permissive unknown-member semantics.
				serde_json::from_str::<Tag>(raw).map_err(|_| ReadError::Syntax)?;
				ReportingDestination::Manual
			},
		};
		// Match serde's internally tagged content validation, including invalid
		// ignored Unicode/numbers, without retaining a second dynamic tree.
		// The SQL document itself has no newly invented aggregate limit.
		serde_json::from_str::<DiscardContent>(raw).map_err(|_| ReadError::Syntax)?;
		Ok(reporting)
	}
}
pub(crate) fn reporting_legacy(
	row: &Row<'_>, index: usize,
) -> rusqlite::Result<loupe_core::ReportingDestination> {
	let value = column(row, index)?.validate(StoredReporting).map_err(|e| sql_error(index, e))?;
	Ok(match value {
		ReportingDestination::GithubIssue { target_owner, target_repo, pat_secret_id } => {
			loupe_core::ReportingDestination::GithubIssue {
				target_owner: target_owner.expose().to_owned(),
				target_repo: target_repo.expose().to_owned(),
				pat_secret_id,
			}
		},
		ReportingDestination::Email { to, from, subject_prefix } => {
			loupe_core::ReportingDestination::Email {
				to: to.into_iter().map(|s| s.expose().to_owned()).collect(),
				from: from.map(|s| s.expose().to_owned()),
				subject_prefix: subject_prefix.map(|s| s.expose().to_owned()),
			}
		},
		ReportingDestination::Manual => loupe_core::ReportingDestination::Manual,
	})
}
struct ScannerDocument(serde_json::Value, PhantomData<Db>);
struct StoredScanner;
impl Validate<&[u8], Db> for StoredScanner {
	type Output = ScannerDocument;
	type Error = ReadError;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, _mark: Mark<'v, Db>,
	) -> Result<Self::Output, ReadError> {
		// Invalid UTF-8 was a SQL conversion failure, whereas syntactically
		// invalid UTF-8 JSON text was historically the null scanner fallback.
		let raw = utf8(u.get()).map_err(ReadError::existing)?;
		Ok(ScannerDocument(
			serde_json::from_str(raw).unwrap_or(serde_json::Value::Null),
			PhantomData,
		))
	}
}
pub(crate) fn scanner_document_legacy(
	row: &Row<'_>, index: usize,
) -> rusqlite::Result<serde_json::Value> {
	Ok(column(row, index)?.validate(StoredScanner).map_err(|e| sql_error(index, e))?.0)
}
struct DiscardContent;
impl<'de> Deserialize<'de> for DiscardContent {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Discard;
		impl<'de> Visitor<'de> for Discard {
			type Value = DiscardContent;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
