//! Survey tool arguments.

use loupe_core::review_candidates::{CandidateQuery, QueryPolicy};
use loupe_core::review_payload::{
	ContinuationClass, GeneratedProfile, SurveyTerminalReason, SurveyTerminalV1,
	UnitResultDisposition, UnitResultFormat, UnitResultPayloadV1, Version1,
};
use loupe_core::text::policy::{
	Argument, ClientKey, InventoryReason, Objective, Reason, ReviewNotes, SecurityModelNotes,
	SurveyContinuation, Title,
};
use loupe_core::text::Identifier;
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_inventory::Disposition;
use loupe_proto::review_lease::{LeaseList, ReviewId};
use loupe_proto::review_units::{PriorityBand, ReviewUnitRequest};

use super::phase::{lead, payload, Args};
use super::*;

pub(in crate::mcp) struct UnitResultArgs {
	pub(in crate::mcp) key: Identifier<ClientKey, Agent>,
	/// `assignment_epoch` is 0 until the host supplies the unit's epoch.
	pub(in crate::mcp) result: UnitResultPayloadV1<Agent>,
}
pub(in crate::mcp) struct DispositionArgs {
	pub(in crate::mcp) key: Identifier<ClientKey, Agent>,
	pub(in crate::mcp) path: RepoPath<Agent>,
	pub(in crate::mcp) disposition: Disposition,
	pub(in crate::mcp) reason: Option<BoundedText<InventoryReason, Agent>>,
	pub(in crate::mcp) mapped_review_unit_ids: Vec<ReviewId>,
}
pub(super) fn arguments(
	u: &Unvalidated<'_, &[u8], Sandbox>, name: &ToolName, fields: &Fields<'_>,
) -> Result<Arguments> {
	let args = Args { u, fields, top_level: true };
	Ok(match name {
		ToolName::JobLimits => {
			args.only(&[])?;
			Arguments::JobLimits
		},
		ToolName::PublishProfile => {
			args.only(&["profile"])?;
			Arguments::PublishProfile(args.required::<GeneratedProfile<Agent>>("profile")?)
		},
		ToolName::ProposeUnit => {
			args.only(&[
				"client_review_unit_key",
				"title",
				"objective",
				"priority_band",
				"priority_rationale",
				"source_refs",
				"depends_on_review_unit_ids",
				"closure_criteria",
				"semantic_context",
			])?;
			let request = ReviewUnitRequest {
				protocol_version: ReviewProtocol,
				client_review_unit_key: args.required("client_review_unit_key")?,
				title: args.required::<BoundedText<Title, Agent>>("title")?,
				objective: args.required::<BoundedText<Objective, Agent>>("objective")?,
				priority_band: args.required_closed::<PriorityBand>("priority_band")?,
				priority_rationale: args
					.optional::<BoundedText<Reason, Agent>>("priority_rationale")?,
				source_refs: LeaseList::new(args.list("source_refs", 1, 32)?)
					.map_err(anyhow::Error::msg)?,
				depends_on_review_unit_ids: LeaseList::new(
					args.ids("depends_on_review_unit_ids", 8)?,
				)
				.map_err(anyhow::Error::msg)?,
				closure_criteria: args
					.optional::<BoundedText<Reason, Agent>>("closure_criteria")?,
				semantic_context: args
					.optional::<BoundedText<Argument, Agent>>("semantic_context")?,
			};
			request.validate().map_err(anyhow::Error::msg)?;
			Arguments::ProposeUnit(Box::new(request))
		},
		ToolName::Lead => Arguments::Lead(Box::new(lead(&args, true)?)),
		ToolName::UnitResult => {
			args.only(&[
				"client_result_key",
				"review_unit_id",
				"disposition",
				"inspected_refs",
				"created_lead_ids",
				"counterevidence",
				"proof_gaps",
				"follow_up",
				"notes",
				"continuation",
			])?;
			let review_unit_id =
				args.id("review_unit_id")?.context("`review_unit_id` argument is required")?;
			let result = UnitResultPayloadV1 {
				format: UnitResultFormat::V1,
				version: Version1,
				review_unit_id: review_unit_id.into(),
				assignment_epoch: 0,
				disposition: args.required_closed::<UnitResultDisposition>("disposition")?,
				inspected_refs: args.list("inspected_refs", 1, 64)?,
				created_lead_ids: args
					.ids("created_lead_ids", 16)?
					.into_iter()
					.map(i64::from)
					.collect(),
				counterevidence: args
					.required::<BoundedText<Objective, Agent>>("counterevidence")?,
				proof_gaps: args.required::<BoundedText<Objective, Agent>>("proof_gaps")?,
				follow_up: args.optional::<BoundedText<Objective, Agent>>("follow_up")?,
				notes: args.optional::<BoundedText<ReviewNotes, Agent>>("notes")?,
				continuation: args.closed::<ContinuationClass>("continuation")?,
			};
			Arguments::UnitResult(Box::new(UnitResultArgs {
				key: args.required("client_result_key")?,
				result: payload(result, UnitResultPayloadV1::canonical_bytes)?,
			}))
		},
		ToolName::Disposition => {
			args.only(&[
				"client_inventory_disposition_key",
				"path",
				"disposition",
				"reason",
				"mapped_review_unit_ids",
			])?;
			let args = DispositionArgs {
				key: args.required("client_inventory_disposition_key")?,
				path: args.required("path")?,
				disposition: args.required_closed::<Disposition>("disposition")?,
				reason: args.optional::<BoundedText<InventoryReason, Agent>>("reason")?,
				mapped_review_unit_ids: args.ids("mapped_review_unit_ids", 8)?,
			};
			let ids = &args.mapped_review_unit_ids;
			if (args.disposition == Disposition::Mapped) == ids.is_empty() {
				anyhow::bail!("`mapped_review_unit_ids` is required exactly for `mapped`");
			}
			if ids.iter().enumerate().any(|(index, id)| ids[..index].contains(id)) {
				anyhow::bail!("`mapped_review_unit_ids` must be distinct");
			}
			if matches!(args.disposition, Disposition::Context | Disposition::Excluded)
				&& args.reason.is_none()
			{
				anyhow::bail!("`reason` argument is required for `context` and `excluded`");
			}
			Arguments::Disposition(Box::new(args))
		},
		ToolName::Candidates => {
			args.only(&["query", "limit"])?;
			let limit = match args.present("limit") {
				None => 10,
				Some(raw) => serde_json::from_str::<u8>(raw.get())
					.ok()
					.filter(|limit| (1..=20).contains(limit))
					.context("`limit` must be an integer from 1 to 20")?,
			};
			Arguments::Candidates(CandidateQuery {
				query: args.required::<BoundedText<QueryPolicy, Agent>>("query")?,
				limit,
			})
		},
		ToolName::Finalize => {
			args.only(&["terminal_reason", "continuation", "security_model_notes"])?;
			let terminal = SurveyTerminalV1 {
				version: Version1,
				terminal_reason: args.required_closed::<SurveyTerminalReason>("terminal_reason")?,
				continuation: args
					.optional::<BoundedText<SurveyContinuation, Agent>>("continuation")?,
				security_model_notes: args
					.optional::<BoundedText<SecurityModelNotes, Agent>>("security_model_notes")?,
			};
			Arguments::Finalize(Box::new(payload(terminal, SurveyTerminalV1::canonical_bytes)?))
		},
		_ => return Err(UnknownTool.into()),
	})
}
