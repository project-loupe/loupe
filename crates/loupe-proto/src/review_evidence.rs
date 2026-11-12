//! Strict typed checkpoint envelopes; paths retain their exact Git identity.
//! Worker idempotency keys remain separate from carried Agent semantics.
//! ```compile_fail,E0277
//! let _:loupe_proto::review_evidence::LeadCheckpointRequest=serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! let _:loupe_proto::review_evidence::UnitResultCheckpointRequest=serde_json::from_str("{}").unwrap();
//! ```
use loupe_core::canonical;
use loupe_core::review_payload::{
	Error, LeadEvidenceV1, LeadEvidenceV1Decoder, UnitResultDisposition, UnitResultPayloadV1,
	UnitResultPayloadV1Decoder,
};
use loupe_core::text::policy::ClientKey;
use loupe_core::text::{decode_json_string_bounded, IdentPolicy, Identifier};
use loupe_provenance::{Agent, Unvalidated, Validate, ValidateCarrying, Worker};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::review_api::ReviewProtocol;
use crate::review_lease::ReviewId;

// debug-ok: fields use redacted typed owners and closed protocol metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeadCheckpointRequest {
	pub protocol_version: ReviewProtocol,
	pub client_lead_key: Identifier<ClientKey, Worker>,
	pub evidence: LeadEvidenceV1<Agent>,
}

// debug-ok: fields use redacted typed owners and closed protocol metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnitResultCheckpointRequest {
	pub protocol_version: ReviewProtocol,
	pub client_result_key: Identifier<ClientKey, Worker>,
	pub result: UnitResultPayloadV1<Agent>,
}

impl LeadCheckpointRequest {
	pub fn digest(&self) -> Result<[u8; 32], serde_json::Error> {
		Ok(canonical::digest(&canonical::canonical_bytes(&serde_json::to_value(self)?)))
	}
}
impl UnitResultCheckpointRequest {
	pub fn digest(&self) -> Result<[u8; 32], serde_json::Error> {
		Ok(canonical::digest(&canonical::canonical_bytes(&serde_json::to_value(self)?)))
	}
}

// debug-ok: closed response vocabulary contains no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeadOutcome {
	Created,
	Attached,
	ClosedExists,
}

// debug-ok: closed response vocabulary contains no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityBand {
	Urgent,
	High,
	Normal,
	Background,
}

// debug-ok: numeric receipt fields and closed response vocabulary only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedPriority {
	pub band: PriorityBand,
	pub score: u32,
}

// debug-ok: numeric receipt fields and closed response vocabulary only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeadCheckpointResponse {
	pub protocol_version: ReviewProtocol,
	pub lead_id: ReviewId,
	pub outcome: LeadOutcome,
	pub observation_id: Option<ReviewId>,
	pub accepted_priority: AcceptedPriority,
}

// debug-ok: numeric receipt fields and closed response vocabulary only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitResultCheckpointResponse {
	pub protocol_version: ReviewProtocol,
	pub result_id: ReviewId,
	pub review_unit_id: ReviewId,
	pub assignment_epoch: u64,
	pub disposition: UnitResultDisposition,
}

type View<'v, 'a> = Unvalidated<'v, &'a [u8], Worker>;
fn content<'a, T>(
	u: &View<'_, 'a>, raw: &RawValue,
	decoder: impl Validate<&'a [u8], Agent, Output = T, Error = Error>,
) -> Result<T, Error> {
	let outside =
		|| Error::Invalid { field: "review_evidence", rule: "content span outside request" };
	let start =
		(raw.get().as_ptr() as usize).checked_sub(u.get().as_ptr() as usize).ok_or_else(outside)?;
	let end = start.checked_add(raw.get().len()).ok_or_else(outside)?;
	u.carry::<Agent>(start..end).ok_or_else(outside)?.validate(decoder)
}
macro_rules! request_decoder {
	($decoder:ident, $request:ident, $key:ident, $payload:ident, $content:ident) => {
		pub struct $decoder;
		impl ValidateCarrying<&[u8], Worker> for $decoder {
			type Output = $request;
			type Error = Error;
			fn validate(self, u: View<'_, '_>) -> Result<Self::Output, Error> {
				if u.get().len() > 256 * 1024 {
					return Err(Error::Bytes {
						field: "review_evidence_request",
						max_bytes: 256 * 1024,
					});
				}
				#[derive(Deserialize)]
				#[serde(deny_unknown_fields)]
				struct Wire<'a> {
					protocol_version: ReviewProtocol,
					#[serde(borrow)]
					$key: &'a RawValue,
					#[serde(borrow)]
					$payload: &'a RawValue,
				}
				let wire: Wire<'_> = serde_json::from_slice(u.get())?;
				let key = decode_json_string_bounded(
					wire.$key.get(),
					ClientKey::FIELD,
					ClientKey::MAX_LEN,
					ClientKey::MAX_LEN,
				)?;
				let value = $request {
					protocol_version: wire.protocol_version,
					$key: Identifier::new(&u.mark(), &key)?,
					$payload: content(&u, wire.$payload, $content)?,
				};
				crate::objects_only(
					u.get(),
					value,
					Error::Invalid {
						field: "review_evidence_request",
						rule: "request object in sequence form",
					},
				)
			}
		}
	};
}
request_decoder!(
	LeadCheckpointRequestDecoder,
	LeadCheckpointRequest,
	client_lead_key,
	evidence,
	LeadEvidenceV1Decoder
);
request_decoder!(
	UnitResultCheckpointRequestDecoder,
	UnitResultCheckpointRequest,
	client_result_key,
	result,
	UnitResultPayloadV1Decoder
);

#[cfg(test)]
mod tests {
	use serde_json::{json, Value};

	use super::*;
	use crate::test_support::worker_request;
	fn decode_lead(raw: &str) -> Result<LeadCheckpointRequest, Error> {
		worker_request(raw.as_bytes()).validate_carrying(LeadCheckpointRequestDecoder)
	}
	fn decode_result(raw: &str) -> Result<UnitResultCheckpointRequest, Error> {
		worker_request(raw.as_bytes()).validate_carrying(UnitResultCheckpointRequestDecoder)
	}
	fn lead() -> Value {
		json!({"protocol_version":3,"client_lead_key":"lead","evidence":{"format":"loupe.lead_evidence","version":1,"identity_family":"auth-bypass","identity_anchor":"handler","review_unit_id":1,"assignment_epoch":0,"hypothesis":"Attacker crosses boundary","source_refs":[{"path":"e\u{301}.rs"}],"next_proof_step":"Trace entry","counterevidence":"No guard found","proof_gaps":"Need proof"}})
	}
	#[test]
	fn mixed_sources_transport_boundary_and_copied_spans_are_explicit() {
		let raw = lead().to_string();
		let request = decode_lead(&raw).unwrap();
		let _: &Identifier<ClientKey, Worker> = &request.client_lead_key;
		let _: &LeadEvidenceV1<Agent> = &request.evidence;
		assert!(!format!("{request:?}").contains("Attacker crosses boundary"));
		let mut boundary = raw.clone();
		boundary.push_str(&" ".repeat(256 * 1024 - boundary.len()));
		assert!(decode_lead(&boundary).is_ok());
		boundary.push(' ');
		assert!(matches!(decode_lead(&boundary), Err(Error::Bytes { .. })));
		struct Copied;
		impl ValidateCarrying<&[u8], Worker> for Copied {
			type Output = ();
			type Error = Error;
			fn validate(self, u: View<'_, '_>) -> Result<(), Error> {
				#[derive(Deserialize)]
				struct Wire<'a> {
					#[serde(borrow)]
					evidence: &'a RawValue,
				}
				let wire: Wire<'_> = serde_json::from_slice(u.get())?;
				let copy = RawValue::from_string(wire.evidence.get().to_owned())?;
				content(&u, &copy, LeadEvidenceV1Decoder).map(|_| ())
			}
		}
		assert!(worker_request(raw.as_bytes()).validate_carrying(Copied).is_err());
	}
	#[test]
	fn complete_request_digest_binds_key_epoch_hint_and_exact_paths() {
		let value = lead();
		let original: LeadCheckpointRequest = decode_lead(&value.to_string()).unwrap();
		let digest = original.digest().unwrap();
		for (field, replacement) in [
			("assignment_epoch", json!(1)),
			("source_refs", json!([{"path":"é.rs"}])),
			("duplicate_hint", json!({"lead_id":2,"rationale":"same boundary"})),
		] {
			let mut changed = value.clone();
			changed["evidence"][field] = replacement;
			assert_ne!(
				decode_lead(&changed.to_string()).unwrap().digest().unwrap(),
				digest,
				"{field}"
			);
		}
		let mut changed = value;
		changed["client_lead_key"] = json!("another");
		assert_ne!(decode_lead(&changed.to_string()).unwrap().digest().unwrap(), digest);
		assert_eq!(original.evidence.source_refs[0].path.expose(), "e\u{301}.rs");
	}
	#[test]
	fn request_envelopes_reject_unknown_duplicate_versions_and_invalid_typed_evidence() {
		let original = lead();
		for (field, value) in [("protocol_version", json!(2)), ("unexpected", json!(0))] {
			let mut invalid = original.clone();
			invalid[field] = value;
			assert!(decode_lead(&invalid.to_string()).is_err());
		}
		for (field, value) in [
			("version", json!(2)),
			("source_refs", json!([])),
			("assignment_epoch", json!(-1)),
			("unexpected", json!(0)),
		] {
			let mut invalid = original.clone();
			invalid["evidence"][field] = value;
			assert!(decode_lead(&invalid.to_string()).is_err());
		}
		for raw in [
			original
				.to_string()
				.replace("\"protocol_version\":3", "\"protocol_version\":3,\"protocol_version\":3"),
			original.to_string().replace("\"version\":1", "\"version\":1,\"version\":1"),
		] {
			assert!(decode_lead(&raw).is_err());
		}
		let result = json!({"protocol_version":3,"client_result_key":"result","result":{"format":"loupe.unit_result","version":1,"review_unit_id":1,"assignment_epoch":0,"disposition":"no_lead_found","inspected_refs":[{"path":"a.rs"}],"created_lead_ids":[],"counterevidence":"Guard holds","proof_gaps":"None"}});
		let valid: UnitResultCheckpointRequest = decode_result(&result.to_string()).unwrap();
		assert!(valid.digest().is_ok());
		for (field, value) in [
			("created_lead_ids", json!([1])),
			("disposition", json!("needs_follow_up")),
			("review_unit_id", json!(0)),
			("unknown", json!(1)),
		] {
			let mut invalid = result.clone();
			invalid["result"][field] = value;
			assert!(decode_result(&invalid.to_string()).is_err());
		}
	}
}
