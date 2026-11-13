//! Full evidence enters once; replies retain SQL-owned identifiers and closed decisions.
//! ```compile_fail,E0277
//! let _:loupe_proto::review_verification::FinalizeVerificationRequest<loupe_provenance::Agent>=serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! let _:loupe_proto::review_verification::VerificationReceipt<loupe_provenance::Db>=serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! let _: loupe_proto::review_verification::FinalizeVerificationRequest<loupe_provenance::Operator> = serde_json::from_str("{}").unwrap();
//! ```
use loupe_core::review_payload::{VerificationTerminalV1, VerificationTerminalV1Decoder, Version1};
use loupe_provenance::{Agent, Source, Unvalidated, ValidateCarrying, Worker};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::review_api::ReviewProtocol;
use crate::review_lease::{ReviewCommit, ReviewDigest, ReviewId};

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct FinalizeVerificationRequest<S: Source> {
	pub protocol_version: ReviewProtocol,
	pub payload: VerificationTerminalV1<S>,
}

record_impls!(FinalizeVerificationRequest<S> {protocol_version,payload});

// debug-ok: closed protocol verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationVerdict {
	Verified,
	Rejected,
	Inconclusive,
}
impl VerificationVerdict {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Verified => "verified",
			Self::Rejected => "rejected",
			Self::Inconclusive => "inconclusive",
		}
	}
}
// debug-ok: closed protocol states and numeric identifiers only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSummary {
	pub version: Version1,
	pub finding_id: ReviewId,
	pub verification_id: ReviewId,
	pub verdict: VerificationVerdict,
	pub finding_state: loupe_core::FindingState,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub continuation: Option<crate::review_terminal::ContinuationSummary>,
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct VerificationReceipt<S: Source> {
	pub receipt_id: ReviewId,
	pub job_id: ReviewId,
	pub commit_sha: ReviewCommit<S>,
	pub result_digest: ReviewDigest<S>,
	pub summary: VerificationSummary,
}

record_impls!(VerificationReceipt<S> {receipt_id,job_id,commit_sha,result_digest,summary});

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct VerificationTerminalResponse<S: Source> {
	pub protocol_version: ReviewProtocol,
	pub receipt: VerificationReceipt<S>,
}

record_impls!(VerificationTerminalResponse<S> {protocol_version,receipt});

// debug-ok: one closed decoder rejection without content.
#[derive(Debug, thiserror::Error)]
#[error("invalid verification terminal request")]
pub struct InvalidTerminal;
pub struct FinalizeVerificationRequestDecoder;
impl ValidateCarrying<&[u8], Worker> for FinalizeVerificationRequestDecoder {
	type Output = FinalizeVerificationRequest<Agent>;
	type Error = InvalidTerminal;
	fn validate(self, input: Unvalidated<'_, &[u8], Worker>) -> Result<Self::Output, Self::Error> {
		if input.get().len() > 512 * 1024 {
			return Err(InvalidTerminal);
		}
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire<'a> {
			protocol_version: ReviewProtocol,
			#[serde(borrow)]
			payload: &'a RawValue,
		}
		let wire: Wire<'_> = serde_json::from_slice(input.get()).map_err(|_| InvalidTerminal)?;
		let start = (wire.payload.get().as_ptr() as usize)
			.checked_sub(input.get().as_ptr() as usize)
			.ok_or(InvalidTerminal)?;
		let end = start.checked_add(wire.payload.get().len()).ok_or(InvalidTerminal)?;
		let payload = input
			.carry::<Agent>(start..end)
			.ok_or(InvalidTerminal)?
			.validate(VerificationTerminalV1Decoder)
			.map_err(|_| InvalidTerminal)?;
		let value =
			FinalizeVerificationRequest { protocol_version: wire.protocol_version, payload };
		crate::objects_only(input.get(), value, InvalidTerminal)
	}
}
#[cfg(test)]
mod tests {
	use super::*;
	fn decode(raw: &str) -> Result<FinalizeVerificationRequest<Agent>, InvalidTerminal> {
		crate::test_support::worker_request(raw.as_bytes())
			.validate_carrying(FinalizeVerificationRequestDecoder)
	}
	const VALID: &str = r#"{"protocol_version":3,"payload":{"version":1,"verdict":"rejected","counterargument":{"argument":"retained\\nargument","source_refs":[{"path":"é.rs"}]}}}"#;
	#[test]
	fn actual_worker_span_carries_agent_semantics_and_exact_paths() {
		let value = decode(VALID).unwrap();
		let _: &VerificationTerminalV1<Agent> = &value.payload;
		let VerificationTerminalV1::Rejected { counterargument, .. } = &value.payload else {
			panic!("reject")
		};
		assert_eq!(counterargument.source_refs[0].path.expose(), "é.rs");
		assert!(!format!("{value:?}").contains("retained"));
		assert_eq!(value, value.clone());
		fn source_only<S: Source>() {
			fn traits<T: Clone + Eq>() {}
			traits::<FinalizeVerificationRequest<S>>();
			traits::<VerificationReceipt<S>>();
			traits::<VerificationTerminalResponse<S>>();
		}
		source_only::<Agent>();
	}
	#[test]
	fn outer_and_nested_schema_and_original_byte_cap_are_strict() {
		for raw in [
			VALID
				.replace("\"protocol_version\":3", "\"protocol_version\":3,\"protocol_version\":3"),
			VALID.replace("\"version\":1", "\"version\":1,\"version\":1"),
			VALID.replace("\"version\":1", "\"version\":99"),
			VALID.replace("\"payload\":{", "\"owner\":1,\"payload\":{"),
			VALID.replace("\"payload\":{", "\"payload\":{\"owner\":1,"),
		] {
			assert!(decode(&raw).is_err());
		}
		let boundary = format!("{VALID}{}", " ".repeat(512 * 1024 - VALID.len()));
		assert!(decode(&boundary).is_ok());
		assert!(decode(&(boundary + " ")).is_err());
	}
}
