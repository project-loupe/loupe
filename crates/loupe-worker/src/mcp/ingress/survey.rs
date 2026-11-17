//! Survey tool arguments. Each content token is carried from the original
//! Sandbox record as Agent and admitted under the server's own field caps, so
//! an over-long or malformed field is rejected here with its field and rule.

use std::marker::PhantomData;

use loupe_core::review_candidates::{CandidateQuery, QueryPolicy};
use loupe_core::review_payload::{
	ContinuationClass, DuplicateLeadHint, GeneratedProfile, LeadEvidenceFormat, LeadEvidenceV1,
	PriorityProposal, SurveyTerminalReason, SurveyTerminalV1, UnitResultDisposition,
	UnitResultFormat, UnitResultPayloadV1, Version1,
};
use loupe_core::text::policy::{
	AnchorText, Argument, ClientKey, DuplicateRationale, Family, InstanceKey, InventoryReason,
	Objective, Reason, ReviewNotes, SecurityModelNotes, SurveyContinuation, Symbol, Title,
};
use loupe_core::text::{Anchor, AnchorPolicy, BoundedJson, IdentPolicy, Identifier, SourceRef};
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_inventory::Disposition;
use loupe_proto::review_lease::{LeaseList, ReviewId};
use loupe_proto::review_units::{PriorityBand, ReviewUnitRequest};

use super::*;

pub(in crate::mcp) struct LeadArgs {
	pub(in crate::mcp) key: Identifier<ClientKey, Agent>,
	/// Paired with its assignment epoch by the host before submission.
	pub(in crate::mcp) review_unit_id: Option<ReviewId>,
	pub(in crate::mcp) evidence: LeadEvidenceV1<Agent>,
}
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

pub(super) trait Content: Sized {
	fn admit(mark: &Mark<'_, Agent>, raw: &RawValue) -> Result<Self>;
}
fn string_token(raw: &RawValue) -> Result<&str> {
	crate::ingress_text::require_string(raw.get())?;
	Ok(raw.get())
}
impl<P: TextPolicy> Content for BoundedText<P, Agent> {
	fn admit(mark: &Mark<'_, Agent>, raw: &RawValue) -> Result<Self> {
		let factor = if P::NORMALIZATION == Normalization::Semantic { 4 } else { 1 };
		let ceiling = P::MAX_BYTES.saturating_mul(factor);
		let text = decode_json_string_bounded(string_token(raw)?, P::FIELD, ceiling, ceiling)?;
		Ok(Self::new(mark, &text)?)
	}
}
impl<P: IdentPolicy> Content for Identifier<P, Agent> {
	fn admit(mark: &Mark<'_, Agent>, raw: &RawValue) -> Result<Self> {
		let text =
			decode_json_string_bounded(string_token(raw)?, P::FIELD, P::MAX_LEN, P::MAX_LEN)?;
		Ok(Self::new(mark, &text)?)
	}
}
impl<P: AnchorPolicy> Content for Anchor<P, Agent> {
	fn admit(mark: &Mark<'_, Agent>, raw: &RawValue) -> Result<Self> {
		let raw = string_token(raw)?;
		// The bounded record bounds the original token; the policy bounds the
		// normalized anchor.
		let text = decode_json_string_bounded(raw, P::FIELD, raw.len(), raw.len())?;
		Ok(Self::new(mark, &text)?)
	}
}
impl Content for RepoPath<Agent> {
	fn admit(mark: &Mark<'_, Agent>, raw: &RawValue) -> Result<Self> {
		let path = decode_json_string_bounded(string_token(raw)?, "path", 512, 512)?;
		Ok(Self::new(mark, &path)?)
	}
}
impl Content for SourceRef<Agent> {
	fn admit(mark: &Mark<'_, Agent>, raw: &RawValue) -> Result<Self> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire<'a> {
			#[serde(borrow)]
			path: &'a RawValue,
			#[serde(borrow, default)]
			symbol: Option<&'a RawValue>,
		}
		let wire: Wire<'_> = serde_json::from_str(raw.get()).map_err(|_| {
			anyhow::anyhow!("source reference must be an object with `path` and optional `symbol`")
		})?;
		Ok(Self {
			path: RepoPath::admit(mark, wire.path)?,
			symbol: wire
				.symbol
				.filter(|raw| raw.get() != "null")
				.map(|raw| BoundedText::<Symbol, Agent>::admit(mark, raw))
				.transpose()?,
		})
	}
}
impl Content for GeneratedProfile<Agent> {
	fn admit(mark: &Mark<'_, Agent>, raw: &RawValue) -> Result<Self> {
		if !raw.get().starts_with('{') {
			anyhow::bail!("`profile` argument is required and must be an object");
		}
		Ok(BoundedJson::new(mark, raw.get())?)
	}
}
impl Content for PriorityProposal<Agent> {
	fn admit(mark: &Mark<'_, Agent>, raw: &RawValue) -> Result<Self> {
		Ok(Self::from_json(mark, raw.get())?)
	}
}

struct AgentContent<T>(PhantomData<T>);
impl<T: Content> Validate<&[u8], Agent> for AgentContent<T> {
	type Output = T;
	type Error = anyhow::Error;
	fn validate<'view>(self, u: Unvalidated<'view, &[u8]>, mark: Mark<'view, Agent>) -> Result<T> {
		let raw: &RawValue = serde_json::from_slice(u.get()).map_err(DecodeError::from)?;
		T::admit(&mark, raw)
	}
}
fn content<T: Content>(u: &Unvalidated<'_, &[u8], Sandbox>, raw: &RawValue) -> Result<T> {
	Ok(carry!(u, raw, AgentContent::<T>(PhantomData)))
}

pub(super) struct Args<'u, 'v, 'b, 'f, 'a> {
	pub(super) u: &'u Unvalidated<'v, &'b [u8], Sandbox>,
	pub(super) fields: &'f Fields<'a>,
	/// The tool's own arguments, where `protocol_version` is admitted.
	pub(super) top_level: bool,
}
impl<'u, 'v, 'b, 'a> Args<'u, 'v, 'b, '_, 'a> {
	/// The members of the object argument `name`, read as their own
	/// arguments.
	pub(super) fn object(&self, name: &'static str) -> Result<Fields<'a>> {
		let raw = self.present(name).with_context(|| format!("`{name}` argument is required"))?;
		raw.get()
			.starts_with('{')
			.then(|| serde_json::from_str(raw.get()).ok())
			.flatten()
			.with_context(|| format!("`{name}` argument must be an object"))
	}
	pub(super) fn optional_object(&self, name: &'static str) -> Result<Option<Fields<'a>>> {
		self.present(name).map(|_| self.object(name)).transpose()
	}
	pub(super) fn nested<'g>(&self, fields: &'g Fields<'a>) -> Args<'u, 'v, 'b, 'g, 'a> {
		Args { u: self.u, fields, top_level: false }
	}
	pub(super) fn present(&self, name: &'static str) -> Option<&'a RawValue> {
		self.fields.get(name).copied().filter(|raw| raw.get() != "null")
	}
	pub(super) fn required<T: Content>(&self, name: &'static str) -> Result<T> {
		let raw = self.present(name).with_context(|| format!("`{name}` argument is required"))?;
		content(self.u, raw)
	}
	pub(super) fn optional<T: Content>(&self, name: &'static str) -> Result<Option<T>> {
		self.present(name).map(|raw| content(self.u, raw)).transpose()
	}
	pub(super) fn list<T: Content>(
		&self, name: &'static str, min: usize, max: usize,
	) -> Result<Vec<T>> {
		self.tokens(name, min, max)?.into_iter().map(|raw| content(self.u, raw)).collect()
	}
	pub(super) fn tokens(
		&self, name: &'static str, min: usize, max: usize,
	) -> Result<Vec<&'a RawValue>> {
		let tokens: Vec<&'a RawValue> = match self.present(name) {
			Some(raw) => serde_json::from_str(raw.get())
				.map_err(|_| anyhow::anyhow!("`{name}` argument must be an array"))?,
			None => Vec::new(),
		};
		if !(min..=max).contains(&tokens.len()) {
			anyhow::bail!("`{name}` argument must have {min} to {max} entries");
		}
		Ok(tokens)
	}
	pub(super) fn closed<T: serde::de::DeserializeOwned>(
		&self, name: &'static str,
	) -> Result<Option<T>> {
		self.present(name)
			.map(|raw| {
				serde_json::from_str(raw.get())
					.map_err(|_| anyhow::anyhow!("`{name}` argument is not an accepted value"))
			})
			.transpose()
	}
	pub(super) fn required_closed<T: serde::de::DeserializeOwned>(
		&self, name: &'static str,
	) -> Result<T> {
		self.closed(name)?.with_context(|| format!("`{name}` argument is required"))
	}
	pub(super) fn id(&self, name: &'static str) -> Result<Option<ReviewId>> {
		self.present(name).map(|raw| positive_id(name, raw)).transpose()
	}
	fn ids(&self, name: &'static str, max: usize) -> Result<Vec<ReviewId>> {
		self.tokens(name, 0, max)?.into_iter().map(|raw| positive_id(name, raw)).collect()
	}
	pub(super) fn only(&self, allowed: &[&'static str]) -> Result<()> {
		if self.fields.keys().all(|key| {
			(self.top_level && key == "protocol_version") || allowed.contains(&key.as_str())
		}) {
			Ok(())
		} else {
			Err(UnknownArgument.into())
		}
	}
}
fn positive_id(name: &'static str, raw: &RawValue) -> Result<ReviewId> {
	serde_json::from_str::<i64>(raw.get())
		.ok()
		.and_then(|id| ReviewId::try_from(id).ok())
		.with_context(|| format!("`{name}` must contain positive integer ids"))
}

// debug-ok: Fieldless fixed error with no rejected input retained.
#[derive(Debug, thiserror::Error)]
#[error("unknown argument for this tool")]
pub(in crate::mcp) struct UnknownArgument;

pub(super) fn payload<T>(
	value: T, check: impl FnOnce(&T) -> Result<Vec<u8>, loupe_core::review_payload::Error>,
) -> Result<T> {
	check(&value)?;
	Ok(value)
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

/// `submit_lead` arguments; a sibling lead (`with_unit` false) never names
/// a review unit.
pub(super) fn lead(args: &Args<'_, '_, '_, '_, '_>, with_unit: bool) -> Result<LeadArgs> {
	const FIELDS: [&str; 13] = [
		"client_lead_key",
		"identity_family",
		"identity_anchor",
		"identity_instance_key",
		"hypothesis",
		"invariant_or_boundary",
		"source_refs",
		"next_proof_step",
		"counterevidence",
		"proof_gaps",
		"priority_proposal",
		"duplicate_of_lead_id",
		"duplicate_rationale",
	];
	if with_unit {
		let mut fields = FIELDS.to_vec();
		fields.insert(4, "review_unit_id");
		args.only(&fields)?;
	} else {
		args.only(&FIELDS)?;
	}
	let duplicate_hint =
		match (args.id("duplicate_of_lead_id")?, args.present("duplicate_rationale")) {
			(None, None) => None,
			(Some(lead_id), Some(_)) => Some(DuplicateLeadHint {
				lead_id: lead_id.into(),
				rationale: args
					.required::<BoundedText<DuplicateRationale, Agent>>("duplicate_rationale")?,
			}),
			_ => anyhow::bail!(
				"`duplicate_of_lead_id` and `duplicate_rationale` must be given together"
			),
		};
	let evidence = LeadEvidenceV1 {
		format: LeadEvidenceFormat::V1,
		version: Version1,
		identity_family: args.required::<Identifier<Family, Agent>>("identity_family")?,
		identity_anchor: args.required::<Anchor<AnchorText, Agent>>("identity_anchor")?,
		identity_instance_key: args
			.optional::<Anchor<InstanceKey, Agent>>("identity_instance_key")?,
		review_unit_id: None,
		assignment_epoch: None,
		hypothesis: args.required::<BoundedText<Argument, Agent>>("hypothesis")?,
		invariant_or_boundary: args
			.optional::<BoundedText<Reason, Agent>>("invariant_or_boundary")?,
		source_refs: args.list("source_refs", 1, 16)?,
		next_proof_step: args.required::<BoundedText<Reason, Agent>>("next_proof_step")?,
		counterevidence: args.required::<BoundedText<Objective, Agent>>("counterevidence")?,
		proof_gaps: args.required::<BoundedText<Objective, Agent>>("proof_gaps")?,
		priority_proposal: args.optional::<PriorityProposal<Agent>>("priority_proposal")?,
		duplicate_hint,
	};
	Ok(LeadArgs {
		key: args.required("client_lead_key")?,
		review_unit_id: if with_unit { args.id("review_unit_id")? } else { None },
		evidence: payload(evidence, LeadEvidenceV1::canonical_bytes)?,
	})
}
