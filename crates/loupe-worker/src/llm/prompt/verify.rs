//! Closed verify projections: host scalars under the server label, the
//! finding and its evidence, as another agent wrote them, under the agent
//! label.

use std::num::NonZeroU32;

use loupe_core::review_metadata::ReviewCommit;
use loupe_core::review_payload::{Confidence, FindingEvidenceV1, L2Argument, MaterialLocation};
use loupe_core::text::policy::{
	AnchorText, AssumptionsGaps, EvidenceCounterevidence, Family, InstanceKey,
	ReviewFindingDescription, ReviewFindingTitle,
};
use loupe_core::text::{Anchor, BoundedText, Identifier};
use loupe_core::Severity;
use loupe_proto::review_api::PhaseLimitsResponse;
use loupe_proto::review_lease::{AssignedReviewFinding, ReviewGeneration, ReviewId, ReviewLimits};
use loupe_provenance::{Agent, Repo, Server, Source};
use serde::Serialize;

use super::survey::{Campaign, Deadlines};
use super::{PromptBuilder, PromptError};

/// Host-known facts of one verify attempt at launch.
pub(crate) struct VerifyJobContext<'a> {
	pub attempt: NonZeroU32,
	pub repo_id: i64,
	pub generation: &'a ReviewGeneration<Server>,
	pub checkout_commit: &'a ReviewCommit<Repo>,
	pub finding: &'a AssignedReviewFinding<Agent, Server>,
	pub limits: &'a ReviewLimits,
	pub capacity: &'a PhaseLimitsResponse,
	/// Unix seconds at launch.
	pub now: i64,
}

impl<'a> PromptBuilder<'a> {
	pub(crate) fn verify_context(
		&mut self, context: &VerifyJobContext<'_>,
	) -> Result<(), PromptError> {
		self.projection_from("job_context", Server::NAME, &Context::from(context))
	}

	pub(crate) fn verify_finding(
		&mut self, finding: &AssignedReviewFinding<Agent, Server>,
	) -> Result<(), PromptError> {
		self.projection_from("finding", Agent::NAME, &Finding::from(finding))
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
	finding_id: &'a ReviewId,
	deadlines: Deadlines,
	#[serde(skip_serializing_if = "Option::is_none")]
	token_budget: Option<std::num::NonZeroU64>,
	capacity: Capacities,
	terminal_action: &'static str,
}

/// A verify job has no per-job capacity.
#[derive(Serialize)]
struct Capacities {
	campaign: Campaign,
}

impl<'a> From<&VerifyJobContext<'a>> for Context<'a> {
	fn from(c: &VerifyJobContext<'a>) -> Self {
		Self {
			phase: "verify",
			workflow_contract_version: loupe_core::WORKFLOW_CONTRACT_VERSION,
			attempt: c.attempt,
			repo_id: c.repo_id,
			source_root: "/workdir",
			generation_id: &c.generation.generation_id,
			generation_commit: &c.generation.commit_sha,
			checkout_commit: c.checkout_commit,
			producer_commit: &c.finding.reviewed_commit_sha,
			finding_id: &c.finding.finding_id,
			deadlines: Deadlines::at(c.now, c.limits),
			token_budget: c.limits.token_budget,
			capacity: Capacities { campaign: Campaign::from(c.capacity) },
			terminal_action: "finalize_verification",
		}
	}
}

/// The finding's agent-authored fields; its id and reviewed commit are host
/// scalars and go to the job context.
#[derive(Serialize)]
struct Finding<'a> {
	severity: Severity,
	title: &'a BoundedText<ReviewFindingTitle, Agent>,
	description: &'a BoundedText<ReviewFindingDescription, Agent>,
	identity_family: &'a Identifier<Family, Agent>,
	identity_anchor: &'a Anchor<AnchorText, Agent>,
	#[serde(skip_serializing_if = "Option::is_none")]
	identity_instance_key: Option<&'a Anchor<InstanceKey, Agent>>,
	evidence: Evidence<'a>,
}

/// The evidence in the shape `finalize_verification` takes it, which has no
/// version.
#[derive(Serialize)]
struct Evidence<'a> {
	l2_argument: &'a L2Argument<Agent>,
	material_locations: &'a [MaterialLocation<Agent>],
	counterevidence: &'a BoundedText<EvidenceCounterevidence, Agent>,
	assumptions_gaps: &'a BoundedText<AssumptionsGaps, Agent>,
	confidence: Confidence,
}

impl<'a> From<&'a AssignedReviewFinding<Agent, Server>> for Finding<'a> {
	fn from(finding: &'a AssignedReviewFinding<Agent, Server>) -> Self {
		// Exhaustive, so a field added to the claim cannot be left out unseen.
		let AssignedReviewFinding {
			finding_id: _,
			reviewed_commit_sha: _,
			severity,
			title,
			description,
			identity_family,
			identity_anchor,
			identity_instance_key,
			evidence,
		} = finding;
		let FindingEvidenceV1 {
			version: _,
			l2_argument,
			material_locations,
			counterevidence,
			assumptions_gaps,
			confidence,
		} = evidence;
		Self {
			severity: *severity,
			title,
			description,
			identity_family,
			identity_anchor,
			identity_instance_key: identity_instance_key.as_ref(),
			evidence: Evidence {
				l2_argument,
				material_locations,
				counterevidence,
				assumptions_gaps,
				confidence: *confidence,
			},
		}
	}
}
