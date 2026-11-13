//! Complete semantic checkpoint submissions; transport keys and producer
//! provenance remain with their owning checkpoint/row, not these payloads.
use super::*;
use crate::review_priority::{Access, Impact, Reachability};

// debug-ok: closed checkpoint schema vocabulary contains no caller text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LeadEvidenceFormat {
	#[serde(rename = "loupe.lead_evidence")]
	V1,
}
crate::closed_string_enum!(LeadEvidenceFormat { V1 });
// debug-ok: closed checkpoint schema vocabulary contains no caller text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum UnitResultFormat {
	#[serde(rename = "loupe.unit_result")]
	V1,
}
crate::closed_string_enum!(UnitResultFormat { V1 });

checked_struct!(PriorityProposal, "PriorityProposal" {
	impact: Impact,
	access: Access,
	reachability: Reachability,
	boundary_refs: Vec<SourceRef<S>>,
	rationale: BoundedText<policy::Reason, S>,
});
impl<S: Source> PriorityProposal<S> {
	fn validate(&self) -> Result<(), Error> {
		if self.boundary_refs.len() > 16 {
			return Err(invalid("boundary_refs", "expected at most 16 entries"));
		}
		Ok(())
	}
}
checked_struct!(DuplicateLeadHint, "DuplicateLeadHint" {
	lead_id: i64,
	rationale: BoundedText<policy::DuplicateRationale, S>,
});
impl<S: Source> DuplicateLeadHint<S> {
	fn validate(&self) -> Result<(), Error> {
		if self.lead_id <= 0 {
			return Err(invalid("duplicate_hint.lead_id", "must be positive"));
		}
		Ok(())
	}
}

checked_struct!(LeadEvidenceV1, "LeadEvidenceV1", canonical_bytes {
	format: LeadEvidenceFormat,
	version: Version1,
	identity_family: Identifier<policy::Family, S>,
	identity_anchor: Anchor<policy::AnchorText, S>,
	#[serde(skip_serializing_if = "Option::is_none")]
	identity_instance_key: Option<Anchor<policy::InstanceKey, S>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	review_unit_id: Option<i64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	assignment_epoch: Option<i64>,
	hypothesis: BoundedText<policy::Argument, S>,
	#[serde(skip_serializing_if = "Option::is_none")]
	invariant_or_boundary: Option<BoundedText<policy::Reason, S>>,
	source_refs: Vec<SourceRef<S>>,
	next_proof_step: BoundedText<policy::Reason, S>,
	counterevidence: BoundedText<policy::Objective, S>,
	proof_gaps: BoundedText<policy::Objective, S>,
	#[serde(skip_serializing_if = "Option::is_none")]
	priority_proposal: Option<PriorityProposal<S>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	duplicate_hint: Option<DuplicateLeadHint<S>>,
});
impl<S: Source> LeadEvidenceV1<S> {
	pub const FORMAT: &'static str = "loupe.lead_evidence";
	fn validate(&self) -> Result<(), Error> {
		match (self.review_unit_id, self.assignment_epoch) {
			(None, None) => {},
			(Some(unit), Some(epoch)) if unit > 0 && epoch >= 0 => {},
			_ => {
				return Err(invalid(
					"review_unit_id",
					"requires a positive unit and nonnegative paired assignment_epoch",
				))
			},
		}
		reference_count("source_refs", self.source_refs.len())?;
		if let Some(proposal) = &self.priority_proposal {
			proposal.validate()?;
		}
		if let Some(hint) = &self.duplicate_hint {
			hint.validate()?;
		}
		Ok(())
	}
}

// debug-ok: closed checkpoint schema vocabulary contains no caller text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitResultDisposition {
	LeadCreated,
	NoLeadFound,
	NotApplicable,
	NeedsFollowUp,
}
crate::closed_string_enum!(UnitResultDisposition {
	LeadCreated,
	NoLeadFound,
	NotApplicable,
	NeedsFollowUp
});
impl UnitResultDisposition {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::LeadCreated => "lead_created",
			Self::NoLeadFound => "no_lead_found",
			Self::NotApplicable => "not_applicable",
			Self::NeedsFollowUp => "needs_follow_up",
		}
	}
}
impl std::str::FromStr for UnitResultDisposition {
	type Err = Error;
	fn from_str(raw: &str) -> Result<Self, Error> {
		match raw {
			"lead_created" => Ok(Self::LeadCreated),
			"no_lead_found" => Ok(Self::NoLeadFound),
			"not_applicable" => Ok(Self::NotApplicable),
			"needs_follow_up" => Ok(Self::NeedsFollowUp),
			_ => Err(invalid("disposition", "unknown unit result disposition")),
		}
	}
}
pub struct UnitResultPayloadV1<S: Source> {
	pub format: UnitResultFormat,
	pub version: Version1,
	pub review_unit_id: i64,
	pub assignment_epoch: i64,
	pub disposition: UnitResultDisposition,
	pub inspected_refs: Vec<SourceRef<S>>,
	pub created_lead_ids: Vec<i64>,
	pub counterevidence: BoundedText<policy::Objective, S>,
	pub proof_gaps: BoundedText<policy::Objective, S>,
	pub follow_up: Option<BoundedText<policy::Objective, S>>,
	pub notes: Option<BoundedText<policy::ReviewNotes, S>>,
	pub continuation: Option<ContinuationClass>,
}
record_impls!(UnitResultPayloadV1 {
	format,
	version,
	review_unit_id,
	assignment_epoch,
	disposition,
	inspected_refs,
	created_lead_ids,
	counterevidence,
	proof_gaps,
	follow_up,
	notes,
	continuation
});
impl<S: Source> UnitResultPayloadV1<S> {
	fn serialize_fields<T: serde::Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
		#[derive(Serialize)]
		#[serde(bound(serialize = ""))]
		struct Wire<'a, S: Source> {
			format: &'a UnitResultFormat,
			version: &'a Version1,
			review_unit_id: &'a i64,
			assignment_epoch: &'a i64,
			disposition: &'a UnitResultDisposition,
			inspected_refs: &'a Vec<SourceRef<S>>,
			created_lead_ids: &'a Vec<i64>,
			counterevidence: &'a BoundedText<policy::Objective, S>,
			proof_gaps: &'a BoundedText<policy::Objective, S>,
			#[serde(skip_serializing_if = "Option::is_none")]
			follow_up: &'a Option<BoundedText<policy::Objective, S>>,
			#[serde(skip_serializing_if = "Option::is_none")]
			notes: &'a Option<BoundedText<policy::ReviewNotes, S>>,
			#[serde(skip_serializing_if = "Option::is_none")]
			continuation: &'a Option<ContinuationClass>,
		}
		Wire {
			format: &self.format,
			version: &self.version,
			review_unit_id: &self.review_unit_id,
			assignment_epoch: &self.assignment_epoch,
			disposition: &self.disposition,
			inspected_refs: &self.inspected_refs,
			created_lead_ids: &self.created_lead_ids,
			counterevidence: &self.counterevidence,
			proof_gaps: &self.proof_gaps,
			follow_up: &self.follow_up,
			notes: &self.notes,
			continuation: &self.continuation,
		}
		.serialize(serializer)
	}
}
impl<S: Source> decode::Field<S> for UnitResultPayloadV1<S> {
	fn decode(
		mark: &Mark<'_, S>, raw: Option<&serde_json::value::RawValue>,
	) -> Result<Self, Error> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire<'a> {
			#[serde(borrow, default)]
			format: Option<&'a serde_json::value::RawValue>,
			#[serde(borrow, default)]
			version: Option<&'a serde_json::value::RawValue>,
			#[serde(borrow, default)]
			review_unit_id: Option<&'a serde_json::value::RawValue>,
			#[serde(borrow, default)]
			assignment_epoch: Option<&'a serde_json::value::RawValue>,
			#[serde(borrow, default)]
			disposition: Option<&'a serde_json::value::RawValue>,
			#[serde(borrow, default)]
			inspected_refs: Option<&'a serde_json::value::RawValue>,
			#[serde(borrow, default)]
			created_lead_ids: Option<&'a serde_json::value::RawValue>,
			#[serde(borrow, default)]
			counterevidence: Option<&'a serde_json::value::RawValue>,
			#[serde(borrow, default)]
			proof_gaps: Option<&'a serde_json::value::RawValue>,
			#[serde(borrow, default)]
			follow_up: Option<&'a serde_json::value::RawValue>,
			#[serde(borrow, default)]
			notes: Option<&'a serde_json::value::RawValue>,
			#[serde(borrow, default)]
			continuation: Option<&'a serde_json::value::RawValue>,
		}
		let raw: Wire<'_> = serde_json::from_str(decode::required(raw)?.get())?;
		let value = Self {
			format: decode::field(mark, raw.format)?,
			version: decode::field(mark, raw.version)?,
			review_unit_id: decode::field(mark, raw.review_unit_id)?,
			assignment_epoch: decode::field(mark, raw.assignment_epoch)?,
			disposition: decode::field(mark, raw.disposition)?,
			inspected_refs: decode::list::<S, SourceRef<S>, 64>(mark, raw.inspected_refs)?,
			created_lead_ids: decode::field(mark, raw.created_lead_ids)?,
			counterevidence: decode::field(mark, raw.counterevidence)?,
			proof_gaps: decode::field(mark, raw.proof_gaps)?,
			follow_up: decode::field(mark, raw.follow_up)?,
			notes: decode::field(mark, raw.notes)?,
			continuation: decode::field(mark, raw.continuation)?,
		};
		value.validate()?;
		value.canonical_bytes()?;
		Ok(value)
	}
}
checked_serde!(UnitResultPayloadV1, canonical_bytes);
impl<S: Source> UnitResultPayloadV1<S> {
	pub const FORMAT: &'static str = "loupe.unit_result";
	fn validate(&self) -> Result<(), Error> {
		if self.review_unit_id <= 0 || self.assignment_epoch < 0 {
			return Err(invalid(
				"review_unit_id",
				"requires a positive unit and nonnegative assignment_epoch",
			));
		}
		if !(1..=64).contains(&self.inspected_refs.len()) {
			return Err(invalid("inspected_refs", "expected 1 to 64 entries"));
		}
		let ids = &self.created_lead_ids;
		if ids.len() > 16
			|| ids.iter().any(|id| *id <= 0)
			|| ids.iter().enumerate().any(|(index, id)| ids[..index].contains(id))
		{
			return Err(invalid("created_lead_ids", "expected at most 16 unique positive ids"));
		}
		if (self.disposition == UnitResultDisposition::LeadCreated) == ids.is_empty() {
			return Err(invalid("created_lead_ids", "nonempty exactly for lead_created"));
		}
		if self.disposition == UnitResultDisposition::NeedsFollowUp {
			if self.follow_up.is_none() || self.continuation.is_none() {
				return Err(invalid(
					"follow_up",
					"needs_follow_up requires follow_up and continuation",
				));
			}
		} else if self.follow_up.is_some() || self.continuation.is_some() {
			return Err(invalid(
				"follow_up",
				"only needs_follow_up accepts follow_up or continuation",
			));
		}
		Ok(())
	}
}
canonical_payload!(LeadEvidenceV1, "lead_evidence", 64 * 1024);
canonical_payload!(UnitResultPayloadV1, "unit_result", 64 * 1024);

payload_decoder!(LeadEvidenceV1Decoder, LeadEvidenceV1);
payload_decoder!(UnitResultPayloadV1Decoder, UnitResultPayloadV1);

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;
