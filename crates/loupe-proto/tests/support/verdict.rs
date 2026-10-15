//! Private original-message fixture, not a production Worker ingress.
#![allow(unsafe_code)] // Only the fixture entry point mints Worker below.

use std::fmt;
use std::ops::Range;

use loupe_core::text::{decode_json_string_bounded, policy, BoundedText, Error, Rule, TextPolicy};
use loupe_core::{Verdict, VerdictPatch};
use loupe_provenance::{
	Agent, Ingress, Mark, Untrusted, Unvalidated, Validate, ValidateCarrying, Worker,
};
use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;

// This fixture bounds its own message; production HTTP routes apply their
// own body budgets.
pub const BODY_CAP: usize = 2 * 1024 * 1024;

// debug-ok: fixed diagnostic with no message content.
#[derive(Debug)]
pub struct ReadError;
impl fmt::Display for ReadError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("invalid worker verdict")
	}
}
impl std::error::Error for ReadError {}

// debug-ok: static field names, offsets and live addresses only.
#[derive(Debug)]
pub struct Span {
	pub field: &'static str,
	pub range: Range<usize>,
	pub message_address: usize,
	pub carried_address: usize,
}
pub struct Submission {
	pub protocol_version: u16,
	pub verdict: Verdict<Agent>,
	pub spans: Vec<Span>,
}
pub fn read(bytes: &[u8]) -> Result<Submission, ReadError> {
	// SAFETY: this private test entry point labels only the immutable original
	// message supplied by the fixture. Production routes authenticate separately.
	let ingress = unsafe { Ingress::<Worker>::new() };
	Untrusted::new(bytes, ingress).validate_carrying(WorkerVerdict).map_err(|_| ReadError)
}

#[derive(Deserialize)]
struct RawEnvelope<'a> {
	protocol_version: u16,
	#[serde(borrow)]
	verdict: &'a RawValue,
}
enum Outcome {
	Confirmed,
	Dismissed,
	Inconclusive,
}
impl<'de> Deserialize<'de> for Outcome {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Identifier;
		impl Visitor<'_> for Identifier {
			type Value = Outcome;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.write_str("a verdict outcome string")
			}
			fn visit_str<E: de::Error>(self, value: &str) -> Result<Outcome, E> {
				match value {
					"confirmed" => Ok(Outcome::Confirmed),
					"dismissed" => Ok(Outcome::Dismissed),
					"inconclusive" => Ok(Outcome::Inconclusive),
					_ => Err(de::Error::custom("invalid verdict outcome")),
				}
			}
		}
		// Match the internally tagged reference enum's identifier admission.
		// A derived external enum would additionally accept {"confirmed":null}.
		d.deserialize_identifier(Identifier)
	}
}
#[derive(Deserialize)]
struct RawTag {
	outcome: Outcome,
}
#[derive(Deserialize)]
struct RawConfirmed<'a> {
	#[serde(rename = "outcome")]
	_outcome: Outcome,
	#[serde(borrow, default)]
	notes: Option<&'a RawValue>,
	#[serde(borrow, default)]
	patch: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct RawDismissed<'a> {
	#[serde(rename = "outcome")]
	_outcome: Outcome,
	#[serde(borrow, default)]
	notes: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct RawInconclusive<'a> {
	#[serde(rename = "outcome")]
	_outcome: Outcome,
	#[serde(borrow)]
	reason: &'a RawValue,
	#[serde(default)]
	terminal: bool,
}

// serde's internally tagged enum accepts a sequence with the tag first as
// well as a map. Probe only that closed tag; leave content in original tokens.
struct SequenceTag(Outcome);
impl<'de> Deserialize<'de> for SequenceTag {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Tag;
		impl<'de> Visitor<'de> for Tag {
			type Value = SequenceTag;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.write_str("tagged sequence")
			}
			fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
				let tag = seq.next_element()?.ok_or_else(|| de::Error::missing_field("outcome"))?;
				while seq.next_element::<IgnoredAny>()?.is_some() {}
				Ok(SequenceTag(tag))
			}
		}
		d.deserialize_seq(Tag)
	}
}
#[derive(Deserialize)]
struct RawPatch<'a> {
	#[serde(borrow)]
	patch_unified: &'a RawValue,
	#[serde(borrow)]
	notes: &'a RawValue,
}

struct WorkerVerdict;
impl<'a> ValidateCarrying<&'a [u8], Worker> for WorkerVerdict {
	type Output = Submission;
	type Error = Error;
	fn validate(self, u: Unvalidated<'_, &'a [u8], Worker>) -> Result<Submission, Error> {
		let bytes = *u.get();
		if bytes.len() > BODY_CAP {
			return Err(Error::new("verdict", Rule::Bytes));
		}
		let envelope: RawEnvelope<'_> = serde_json::from_slice(bytes).map_err(|_| invalid())?;
		let raw = envelope.verdict.get();
		let outcome = if raw.starts_with('[') {
			serde_json::from_str::<SequenceTag>(raw).map_err(|_| invalid())?.0
		} else {
			serde_json::from_str::<RawTag>(raw).map_err(|_| invalid())?.outcome
		};
		let mut spans = Vec::new();
		// These concrete call sites designate Agent fields; neither callers nor
		// the string decoder can choose an arbitrary source or output type.
		macro_rules! field {
			($token:expr, $validator:expr, $name:literal) => {{
				let token = $token;
				let start = (token.get().as_ptr() as usize)
					.checked_sub(bytes.as_ptr() as usize)
					.ok_or_else(invalid)?;
				let end = start
					.checked_add(token.get().len())
					.filter(|end| *end <= bytes.len())
					.ok_or_else(invalid)?;
				let range = start..end;
				let (value, address) =
					u.carry::<Agent>(range.clone()).ok_or_else(invalid)?.validate($validator)?;
				spans.push(Span {
					field: $name,
					range,
					message_address: bytes.as_ptr() as usize,
					carried_address: address,
				});
				value
			}};
		}
		let verdict = match outcome {
			Outcome::Confirmed => {
				let raw: RawConfirmed<'_> = serde_json::from_str(raw).map_err(|_| invalid())?;
				let notes =
					raw.notes.map(|token| Ok(field!(token, AgentNotes, "notes"))).transpose()?;
				let patch = if let Some(token) = raw.patch {
					let patch: RawPatch<'_> =
						serde_json::from_str(token.get()).map_err(|_| invalid())?;
					Some(VerdictPatch {
						patch_unified: field!(patch.patch_unified, AgentPatch, "patch_unified"),
						notes: field!(patch.notes, AgentPatchNotes, "patch_notes"),
					})
				} else {
					None
				};
				Verdict::Confirmed { notes, patch }
			},
			Outcome::Dismissed => {
				let raw: RawDismissed<'_> = serde_json::from_str(raw).map_err(|_| invalid())?;
				let notes =
					raw.notes.map(|token| Ok(field!(token, AgentNotes, "notes"))).transpose()?;
				Verdict::Dismissed { notes }
			},
			Outcome::Inconclusive => {
				let raw: RawInconclusive<'_> = serde_json::from_str(raw).map_err(|_| invalid())?;
				Verdict::Inconclusive {
					reason: field!(raw.reason, AgentReason, "reason"),
					terminal: raw.terminal,
				}
			},
		};
		// The internally tagged reference Verdict buffers every inner value as serde
		// content, rejecting invalid Unicode/overflow even in ignored fields.
		// Reuse serde's validation without retaining values. This runs AFTER
		// every designated field's carry and bounded decode, never before it.
		// Parser scratch for this compatibility pass is bounded by BODY_CAP.
		serde_json::from_slice::<ContentEnvelope>(bytes).map_err(|_| invalid())?;
		Ok(Submission { protocol_version: envelope.protocol_version, verdict, spans })
	}
}

macro_rules! agent_field {
	($name:ident, $policy:ty) => {
		struct $name;
		impl Validate<&[u8], Agent> for $name {
			type Output = (BoundedText<$policy, Agent>, usize);
			type Error = Error;
			fn validate<'view>(
				self, u: Unvalidated<'view, &[u8]>, mark: Mark<'view, Agent>,
			) -> Result<Self::Output, Error> {
				let raw = std::str::from_utf8(u.get()).map_err(|_| invalid())?;
				let decoded = decode_json_string_bounded(
					raw,
					<$policy>::FIELD,
					<$policy>::MAX_BYTES,
					<$policy>::MAX_CHARS,
				)?;
				Ok((BoundedText::new(&mark, &decoded)?, raw.as_ptr() as usize))
			}
		}
	};
}
agent_field!(AgentNotes, policy::VerdictNotes);
agent_field!(AgentReason, policy::VerdictReason);
agent_field!(AgentPatch, policy::PatchUnified);
agent_field!(AgentPatchNotes, policy::PatchNotes);

// Unlike IgnoredAny, deserialize_any validates string scalars and finite JSON
// numbers. No map, array, string, or dynamic value is retained by this visitor.
struct DiscardContent;
// Retain the envelope level (and its permissive unknown-field behavior) so
// serde's recursion boundary matches the reference DTO's boundary.
#[derive(Deserialize)]
struct ContentEnvelope {
	#[serde(rename = "protocol_version")]
	_protocol_version: u16,
	#[serde(rename = "verdict")]
	_verdict: DiscardContent,
}
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
fn invalid() -> Error {
	Error::new("verdict", Rule::JsonSyntax)
}
