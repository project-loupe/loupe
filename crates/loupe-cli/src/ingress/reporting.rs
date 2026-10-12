//! Reporting's internally tagged Content rules differ from ignored members of
//! ordinary DTOs. Envelope depth counts toward the parser's recursion budget.
use std::fmt;

use loupe_proto::{GithubReportingAuth, ReportingSummary};
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserializer;

use super::*;

enum Kind {
	GithubIssue,
	Email,
	Manual,
}
impl<'de> Deserialize<'de> for Kind {
	fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
		struct Tag;
		impl Visitor<'_> for Tag {
			type Value = Kind;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.write_str("reporting kind string")
			}
			fn visit_str<E: de::Error>(self, s: &str) -> std::result::Result<Kind, E> {
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
	fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
		struct First;
		impl<'de> Visitor<'de> for First {
			type Value = SequenceTag;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.write_str("reporting sequence")
			}
			fn visit_seq<A: SeqAccess<'de>>(
				self, mut a: A,
			) -> std::result::Result<Self::Value, A::Error> {
				let first = a.next_element()?.ok_or_else(|| de::Error::missing_field("kind"))?;
				while a.next_element::<IgnoredAny>()?.is_some() {}
				Ok(SequenceTag(first))
			}
		}
		d.deserialize_seq(First)
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
	auth: GithubReportingAuth,
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
pub(super) fn reporting_summary(
	mark: &Mark<'_, Server>, token: &RawValue, depth: usize,
) -> Result<ReportingSummary<Server>> {
	let raw = token.get();
	let mut decoder = serde_json::Deserializer::from_str(raw);
	ContentDepth(depth).deserialize(&mut decoder).map_err(|_| invalid())?;
	decoder.end().map_err(|_| invalid())?;
	let tag = if raw.trim_start().starts_with('[') {
		serde_json::from_str::<SequenceTag>(raw).map_err(|_| invalid())?.0
	} else {
		serde_json::from_str::<Tag>(raw).map_err(|_| invalid())?.kind
	};
	Ok(match tag {
		Kind::GithubIssue => {
			let r: Github<'_> = serde_json::from_str(raw).map_err(|_| invalid())?;
			ReportingSummary::GithubIssue {
				target_owner: owner(mark, r.target_owner)?,
				target_repo: repo(mark, r.target_repo)?,
				auth: r.auth,
			}
		},
		Kind::Email => {
			let r: Email<'_> = serde_json::from_str(raw).map_err(|_| invalid())?;
			ReportingSummary::Email {
				to: r.to.into_iter().map(|t| address(mark, t)).collect::<Result<_>>()?,
				from: r.from.map(|t| address(mark, t)).transpose()?,
				subject_prefix: r.subject_prefix.map(|t| subject(mark, t)).transpose()?,
			}
		},
		Kind::Manual => {
			serde_json::from_str::<Tag>(raw).map_err(|_| invalid())?;
			ReportingSummary::Manual
		},
	})
}
struct ContentDepth(usize);
impl<'de> DeserializeSeed<'de> for ContentDepth {
	type Value = ();
	fn deserialize<D: Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
		d.deserialize_any(self)
	}
}
impl<'de> Visitor<'de> for ContentDepth {
	type Value = ();
	fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("JSON content")
	}
	fn visit_bool<E>(self, _: bool) -> std::result::Result<(), E> {
		Ok(())
	}
	fn visit_i64<E>(self, _: i64) -> std::result::Result<(), E> {
		Ok(())
	}
	fn visit_u64<E>(self, _: u64) -> std::result::Result<(), E> {
		Ok(())
	}
	fn visit_f64<E>(self, _: f64) -> std::result::Result<(), E> {
		Ok(())
	}
	fn visit_str<E>(self, _: &str) -> std::result::Result<(), E> {
		Ok(())
	}
	fn visit_unit<E>(self) -> std::result::Result<(), E> {
		Ok(())
	}
	fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<(), A::Error> {
		let depth = self.0 + 1;
		if depth >= 128 {
			return Err(de::Error::custom("recursion limit"));
		}
		while a.next_element_seed(ContentDepth(depth))?.is_some() {}
		Ok(())
	}
	fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<(), A::Error> {
		let depth = self.0 + 1;
		if depth >= 128 {
			return Err(de::Error::custom("recursion limit"));
		}
		while a.next_key_seed(ContentDepth(depth))?.is_some() {
			a.next_value_seed(ContentDepth(depth))?;
		}
		Ok(())
	}
}
