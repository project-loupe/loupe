//! Closed drilldown projections: host scalars under the server label, the
//! assigned lead's agent-authored text under the agent label.

use std::num::NonZeroU32;

use loupe_core::review_metadata::ReviewCommit;
use loupe_core::text::policy::{AnchorText, Argument, Family, InstanceKey, Objective, Reason};
use loupe_core::text::{Anchor, BoundedText, Identifier, SourceRef};
use loupe_proto::review_api::{Capacity, PhaseLimitsResponse};
use loupe_proto::review_lease::{
	AssignedReviewLead, LeaseList, ReviewGeneration, ReviewId, ReviewLimits,
};
use loupe_provenance::{Agent, Repo, Server, Source};
use serde::Serialize;

use super::survey::{Campaign, Deadlines};
use super::{PromptBuilder, PromptError};

/// Host-known facts of one drilldown attempt at launch.
pub(crate) struct DrilldownJobContext<'a> {
	pub attempt: NonZeroU32,
	pub repo_id: i64,
	pub generation: &'a ReviewGeneration<Server>,
	pub checkout_commit: &'a ReviewCommit<Repo>,
	pub lead: &'a AssignedReviewLead<Agent, Server>,
	pub limits: &'a ReviewLimits,
	pub capacity: &'a PhaseLimitsResponse,
	/// Unix seconds at launch.
	pub now: i64,
}

impl<'a> PromptBuilder<'a> {
	pub(crate) fn drilldown_context(
		&mut self, context: &DrilldownJobContext<'_>,
	) -> Result<(), PromptError> {
		self.projection_from("job_context", Server::NAME, &Context::from(context))
	}

	pub(crate) fn drilldown_lead(
		&mut self, lead: &AssignedReviewLead<Agent, Server>,
	) -> Result<(), PromptError> {
		self.projection_from("lead", Agent::NAME, &Lead::from(lead))
	}
}

#[derive(Serialize)]
struct Context<'a> {
	phase: &'static str,
	workflow_contract_version: i64,
	attempt: NonZeroU32,
	repo_id: i64,
	source_root: &'static str,
	generation_id: &'a ReviewId,
	generation_commit: &'a ReviewCommit<Server>,
	checkout_commit: &'a ReviewCommit<Repo>,
	producer_commit: &'a ReviewCommit<Server>,
	lead_id: &'a ReviewId,
	deadlines: Deadlines,
	#[serde(skip_serializing_if = "Option::is_none")]
	token_budget: Option<std::num::NonZeroU64>,
	capacity: Capacities<'a>,
	terminal_action: &'static str,
}

#[derive(Serialize)]
struct Capacities<'a> {
	siblings: &'a Capacity,
	candidate_queries: &'a Capacity,
	campaign: Campaign,
}

impl<'a> From<&DrilldownJobContext<'a>> for Context<'a> {
	fn from(c: &DrilldownJobContext<'a>) -> Self {
		Self {
			phase: "drilldown",
			workflow_contract_version: loupe_core::WORKFLOW_CONTRACT_VERSION,
			attempt: c.attempt,
			repo_id: c.repo_id,
			source_root: "/workdir",
			generation_id: &c.generation.generation_id,
			generation_commit: &c.generation.commit_sha,
			checkout_commit: c.checkout_commit,
			producer_commit: &c.lead.producer_commit_sha,
			lead_id: &c.lead.lead_id,
			deadlines: Deadlines::at(c.now, c.limits),
			token_budget: c.limits.token_budget,
			capacity: Capacities {
				siblings: &c.capacity.siblings,
				candidate_queries: &c.capacity.candidate_queries,
				campaign: Campaign::from(c.capacity),
			},
			terminal_action: "finalize_drilldown",
		}
	}
}

/// The lead's agent-authored fields; its id and producer commit are host
/// scalars and go to the job context.
#[derive(Serialize)]
struct Lead<'a> {
	identity_family: &'a Identifier<Family, Agent>,
	identity_anchor: &'a Anchor<AnchorText, Agent>,
	#[serde(skip_serializing_if = "Option::is_none")]
	identity_instance_key: Option<&'a Anchor<InstanceKey, Agent>>,
	hypothesis: &'a BoundedText<Argument, Agent>,
	#[serde(skip_serializing_if = "Option::is_none")]
	invariant_or_boundary: Option<&'a BoundedText<Reason, Agent>>,
	source_refs: &'a LeaseList<SourceRef<Agent>, 16, 1>,
	next_proof_step: &'a BoundedText<Reason, Agent>,
	counterevidence: &'a BoundedText<Objective, Agent>,
	proof_gaps: &'a BoundedText<Objective, Agent>,
}

impl<'a> From<&'a AssignedReviewLead<Agent, Server>> for Lead<'a> {
	fn from(l: &'a AssignedReviewLead<Agent, Server>) -> Self {
		Self {
			identity_family: &l.identity_family,
			identity_anchor: &l.identity_anchor,
			identity_instance_key: l.identity_instance_key.as_ref(),
			hypothesis: &l.hypothesis,
			invariant_or_boundary: l.invariant_or_boundary.as_ref(),
			source_refs: &l.source_refs,
			next_proof_step: &l.next_proof_step,
			counterevidence: &l.counterevidence,
			proof_gaps: &l.proof_gaps,
		}
	}
}
