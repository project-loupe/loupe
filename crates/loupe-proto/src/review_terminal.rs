//! Terminal payload admission retains the actual Agent span within Worker bytes.
//! Receipts serialize database-labelled metadata without minting a new source.
//! ```compile_fail,E0277
//! use loupe_proto::review_terminal::FinalizeSurveyRequest;
//! use loupe_provenance::Agent;
//! let _: FinalizeSurveyRequest<Agent> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_proto::review_terminal::SurveyReceipt;
//! use loupe_provenance::Db;
//! let _: SurveyReceipt<Db> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! let _: loupe_proto::review_terminal::FinalizeSurveyRequest<loupe_provenance::Operator> = serde_json::from_str("{}").unwrap();
//! ```
use loupe_core::review_metadata::{ReviewCommit, ReviewDigest};
use loupe_core::review_payload::{
	ContinuationClass, SurveyTerminalReason, SurveyTerminalV1, SurveyTerminalV1Decoder, Version1,
};
use loupe_provenance::{Agent, Source, Unvalidated, ValidateCarrying, Worker};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::review_api::ReviewProtocol;
use crate::review_lease::ReviewId;

// debug-ok: closed protocol summary with numeric identifiers only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuationBlockReason {
	AwaitingProofInfrastructure,
	ExternalDependency,
	RequiresSuccessor,
}

// debug-ok: closed protocol summary with numeric identifiers only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContinuationSummary {
	Pending {
		class: ContinuationClass,
		revision: u64,
		logical_sequence: u64,
		not_before: i64,
	},
	Blocked {
		class: ContinuationClass,
		revision: u64,
		logical_sequence: u64,
		reason: ContinuationBlockReason,
	},
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct FinalizeSurveyRequest<S: Source> {
	pub protocol_version: ReviewProtocol,
	pub payload: SurveyTerminalV1<S>,
}
record_impls!(FinalizeSurveyRequest<S> { protocol_version, payload });

// debug-ok: closed coverage state only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurveyCoverage {
	Complete,
	Partial,
}

// debug-ok: closed version/state and numeric summary only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurveySummary {
	pub version: Version1,
	pub coverage: SurveyCoverage,
	pub corroboration_satisfied: bool,
	pub missing_results: u64,
	pub needs_follow_up: u64,
	pub unresolved_inventory: u64,
	pub follow_up_batches: u64,
	pub follow_up_units: u64,
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct SurveyReceipt<S: Source> {
	pub receipt_id: ReviewId,
	pub job_id: ReviewId,
	pub commit_sha: ReviewCommit<S>,
	pub result_digest: ReviewDigest<S>,
	pub terminal_reason: SurveyTerminalReason,
	pub summary: SurveySummary,
}
record_impls!(SurveyReceipt<S> { receipt_id, job_id, commit_sha, result_digest, terminal_reason, summary });

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct SurveyTerminalResponse<S: Source> {
	pub protocol_version: ReviewProtocol,
	pub receipt: SurveyReceipt<S>,
}
record_impls!(SurveyTerminalResponse<S> { protocol_version, receipt });

// debug-ok: one closed rejection category, without decoder diagnostics.
#[derive(Debug, thiserror::Error)]
#[error("invalid survey terminal request")]
pub struct InvalidTerminal;

pub struct FinalizeSurveyRequestDecoder;
impl ValidateCarrying<&[u8], Worker> for FinalizeSurveyRequestDecoder {
	type Output = FinalizeSurveyRequest<Agent>;
	type Error = InvalidTerminal;
	fn validate(self, input: Unvalidated<'_, &[u8], Worker>) -> Result<Self::Output, Self::Error> {
		if input.get().len() > 128 * 1024 {
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
			.validate(SurveyTerminalV1Decoder)
			.map_err(|_| InvalidTerminal)?;
		Ok(FinalizeSurveyRequest { protocol_version: wire.protocol_version, payload })
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_support::worker_request;
	fn decode(raw: &str) -> Result<FinalizeSurveyRequest<Agent>, InvalidTerminal> {
		worker_request(raw.as_bytes()).validate_carrying(FinalizeSurveyRequestDecoder)
	}
	#[test]
	fn payload_carries_agent_from_the_original_worker_span() {
		let value=decode(r#" { "protocol_version":3, "payload":{"version":1,"terminal_reason":"partial","continuation":"remaining","security_model_notes":"literal\nnotes"} } "#).unwrap();
		let _: &SurveyTerminalV1<Agent> = &value.payload;
		assert_eq!(value.payload.security_model_notes.as_ref().unwrap().expose(), "literal\nnotes");
		assert!(!format!("{value:?}").contains("remaining"));
		assert_eq!(value, value.clone());
		fn source_only<S: Source>() {
			fn traits<T: Clone + Eq>() {}
			traits::<FinalizeSurveyRequest<S>>();
			traits::<SurveyReceipt<S>>();
			traits::<SurveyTerminalResponse<S>>();
		}
		source_only::<Agent>();
	}
	#[test]
	fn original_keys_versions_and_payload_bounds_are_not_normalized_away() {
		let valid = r#"{"protocol_version":3,"payload":{"version":1,"terminal_reason":"partial"}}"#;
		assert!(decode(valid).is_ok());
		for raw in [
            valid.replace("\"protocol_version\":3","\"protocol_version\":3,\"protocol_version\":3"),
            valid.replace("\"version\":1","\"version\":1,\"version\":1"),
            valid.replace("\"version\":1","\"version\":2"),
            valid.replace("\"protocol_version\":3","\"protocol_version\":2"),
            valid.replace("\"payload\":{","\"owner\":1,\"payload\":{"),
            valid.replace("\"payload\":{","\"payload\":{\"inventory_dispositions\":[],"),
            format!("{{\"protocol_version\":3,\"payload\":{{\"version\":1,\"terminal_reason\":\"partial\",\"security_model_notes\":\"{}\"}}}}","\\u0061".repeat(8001)),
            " ".repeat(128*1024)+valid,
        ] { assert!(decode(&raw).is_err()); }
		let max=serde_json::json!({"protocol_version":3,"payload":{"version":1,"terminal_reason":"partial","security_model_notes":"a".repeat(8000)}}).to_string();
		assert!(decode(&max).is_ok());
	}
}
