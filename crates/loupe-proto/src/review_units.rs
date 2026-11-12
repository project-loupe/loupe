//! Survey proposals describe scopes; their priority labels grant no authority.
//! Semantic content carries Agent from original Worker bytes. The idempotency
//! key remains Worker metadata, and serde cannot manufacture either source.
//! ```compile_fail,E0277
//! use loupe_proto::review_units::ReviewUnitRequest;
//! use loupe_provenance::{Agent, Worker};
//! let _: ReviewUnitRequest<Agent, Worker> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! let _: loupe_proto::review_units::ReviewUnitRequest<loupe_provenance::Operator, loupe_provenance::Operator> = serde_json::from_str("{}").unwrap();
//! ```
use loupe_core::canonical;
use loupe_core::text::policy::{Argument, ClientKey, Objective, Reason, Title};
use loupe_core::text::{BoundedText, Identifier, SourceRef};
use loupe_provenance::Source;
use serde::{Deserialize, Serialize};

use crate::review_api::ReviewProtocol;
use crate::review_lease::{LeaseList, ReviewId};

mod decode;
pub use decode::ReviewUnitRequestDecoder;

// debug-ok: closed advisory priority labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityBand {
	Urgent,
	High,
	Normal,
	Background,
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct ReviewUnitRequest<C: Source, K: Source> {
	pub protocol_version: ReviewProtocol,
	pub client_review_unit_key: Identifier<ClientKey, K>,
	pub title: BoundedText<Title, C>,
	pub objective: BoundedText<Objective, C>,
	pub priority_band: PriorityBand,
	pub priority_rationale: Option<BoundedText<Reason, C>>,
	pub source_refs: LeaseList<SourceRef<C>, 32, 1>,
	pub depends_on_review_unit_ids: LeaseList<ReviewId, 8>,
	// New work must fit the bounded lease without truncating its obligations.
	pub closure_criteria: Option<BoundedText<Reason, C>>,
	pub semantic_context: Option<BoundedText<Argument, C>>,
}
record_impls!(ReviewUnitRequest<C, K> {
	protocol_version, client_review_unit_key, title, objective, priority_band,
	priority_rationale, source_refs, depends_on_review_unit_ids, closure_criteria,
	semantic_context
});
impl<C: Source, K: Source> ReviewUnitRequest<C, K> {
	pub fn validate(&self) -> Result<(), &'static str> {
		let mut seen = std::collections::HashSet::new();
		if self.depends_on_review_unit_ids.as_slice().iter().any(|id| !seen.insert(i64::from(*id)))
		{
			return Err("dependencies must be distinct");
		}
		Ok(())
	}
	pub fn digest(&self) -> Result<[u8; 32], serde_json::Error> {
		Ok(canonical::digest(&canonical::canonical_bytes(&serde_json::to_value(self)?)))
	}
}

// debug-ok: only numeric receipt metadata and a closed priority label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewUnitResponse {
	pub protocol_version: ReviewProtocol,
	pub review_unit_id: ReviewId,
	pub assignment_epoch: u64,
	pub accepted_priority_band: PriorityBand,
}

#[cfg(test)]
mod tests;
