//! Full evidence enters once; replies retain SQL-owned identifiers and closed decisions.
//! ```compile_fail,E0277
//! let _:loupe_proto::review_drilldown::FinalizeDrilldownRequest<loupe_provenance::Agent>=serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! let _:loupe_proto::review_drilldown::DrilldownReceipt<loupe_provenance::Db>=serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! let _: loupe_proto::review_drilldown::FinalizeDrilldownRequest<loupe_provenance::Operator> = serde_json::from_str("{}").unwrap();
//! ```
use loupe_core::review_payload::{DrilldownTerminalV1, DrilldownTerminalV1Decoder, Version1};
use loupe_provenance::{Agent, Source, Unvalidated, ValidateCarrying, Worker};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::review_api::ReviewProtocol;
use crate::review_lease::{ReviewCommit, ReviewDigest, ReviewId};

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct FinalizeDrilldownRequest<S: Source> {
	pub protocol_version: ReviewProtocol,
	pub payload: DrilldownTerminalV1<S>,
}

record_impls!(FinalizeDrilldownRequest<S> {protocol_version,payload});

// debug-ok: closed protocol summary with numeric identifiers only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrilldownDisposition {
	Promoted,
	Rejected,
	Duplicate,
	Hardening,
	Deferred,
}
impl DrilldownDisposition {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Promoted => "promoted",
			Self::Rejected => "rejected",
			Self::Duplicate => "duplicate",
			Self::Hardening => "hardening",
			Self::Deferred => "deferred",
		}
	}
}

pub use crate::review_terminal::{ContinuationBlockReason, ContinuationSummary};

// debug-ok: closed protocol summary with numeric identifiers only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrilldownSummary {
	pub version: Version1,
	pub lead_id: ReviewId,
	pub disposition: DrilldownDisposition,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub promoted_finding_id: Option<ReviewId>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub continuation: Option<ContinuationSummary>,
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct DrilldownReceipt<S: Source> {
	pub receipt_id: ReviewId,
	pub job_id: ReviewId,
	pub commit_sha: ReviewCommit<S>,
	pub result_digest: ReviewDigest<S>,
	pub summary: DrilldownSummary,
}

record_impls!(DrilldownReceipt<S> {receipt_id,job_id,commit_sha,result_digest,summary});

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct DrilldownTerminalResponse<S: Source> {
	pub protocol_version: ReviewProtocol,
	pub receipt: DrilldownReceipt<S>,
}

record_impls!(DrilldownTerminalResponse<S> {protocol_version,receipt});

// debug-ok: one closed decoder rejection without content.
#[derive(Debug, thiserror::Error)]
#[error("invalid drilldown terminal request")]
pub struct InvalidTerminal;
pub struct FinalizeDrilldownRequestDecoder;
impl ValidateCarrying<&[u8], Worker> for FinalizeDrilldownRequestDecoder {
	type Output = FinalizeDrilldownRequest<Agent>;
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
			.validate(DrilldownTerminalV1Decoder)
			.map_err(|_| InvalidTerminal)?;
		let value = FinalizeDrilldownRequest { protocol_version: wire.protocol_version, payload };
		crate::objects_only(input.get(), value, InvalidTerminal)
	}
}
#[cfg(test)]
mod tests {
	use super::*;
	fn decode(raw: &str) -> Result<FinalizeDrilldownRequest<Agent>, InvalidTerminal> {
		crate::test_support::worker_request(raw.as_bytes())
			.validate_carrying(FinalizeDrilldownRequestDecoder)
	}
	const VALID: &str = r#"{"protocol_version":3,"payload":{"version":1,"disposition":"reject","counterargument":{"argument":"retained\\nargument","source_refs":[{"path":"é.rs"}]}}}"#;
	#[test]
	fn actual_worker_span_carries_agent_semantics_and_exact_paths() {
		let value = decode(VALID).unwrap();
		let _: &DrilldownTerminalV1<Agent> = &value.payload;
		let DrilldownTerminalV1::Reject { counterargument, .. } = &value.payload else {
			panic!("reject")
		};
		assert_eq!(counterargument.source_refs[0].path.expose(), "é.rs");
		assert!(!format!("{value:?}").contains("retained"));
		assert_eq!(value, value.clone());
		fn source_only<S: Source>() {
			fn traits<T: Clone + Eq>() {}
			traits::<FinalizeDrilldownRequest<S>>();
			traits::<DrilldownReceipt<S>>();
			traits::<DrilldownTerminalResponse<S>>();
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
