//! Closed survey projections: host scalars under the server label, assigned
//! unit text under the agent label.

use std::num::NonZeroU32;

use loupe_core::review_metadata::ReviewCommit;
use loupe_proto::review_api::{Capacity, PhaseLimitsResponse};
use loupe_proto::review_lease::{
	OrdinarySurveyRecipe, ReviewAssignments, ReviewGeneration, ReviewLimits,
};
use loupe_provenance::{Agent, Repo, Server, Source};
use serde::Serialize;

use super::{PromptBuilder, PromptError};
use crate::review::prepare::SurveyRecipe;

/// Host-known facts of one survey attempt at launch.
pub(crate) struct SurveyJobContext<'a> {
	pub recipe: SurveyRecipe,
	pub attempt: NonZeroU32,
	pub repo_id: i64,
	pub generation: &'a ReviewGeneration<Server>,
	pub checkout_commit: &'a ReviewCommit<Repo>,
	pub limits: &'a ReviewLimits,
	pub capacity: &'a PhaseLimitsResponse,
	/// Unix seconds at launch.
	pub now: i64,
}

impl<'a> PromptBuilder<'a> {
	pub(crate) fn survey_context(
		&mut self, context: &SurveyJobContext<'_>,
	) -> Result<(), PromptError> {
		self.projection_from("job_context", Server::NAME, &Context::from(context))
	}

	pub(crate) fn survey_assignments(
		&mut self, assignments: &ReviewAssignments<Agent>,
	) -> Result<(), PromptError> {
		self.projection_from("assignments", Agent::NAME, assignments)
	}
}

#[derive(Serialize)]
struct Context<'a> {
	phase: &'static str,
	workflow_contract_version: i64,
	recipe: &'static str,
	attempt: NonZeroU32,
	repo_id: i64,
	source_root: &'static str,
	generation_id: &'a loupe_proto::review_lease::ReviewId,
	generation_commit: &'a ReviewCommit<Server>,
	checkout_commit: &'a ReviewCommit<Repo>,
	deadlines: Deadlines,
	#[serde(skip_serializing_if = "Option::is_none")]
	token_budget: Option<std::num::NonZeroU64>,
	capacity: Capacities<'a>,
	terminal_action: &'static str,
}

#[derive(Serialize)]
struct Deadlines {
	launched_at: i64,
	submit_by_at: i64,
	submit_by_remaining_seconds: u64,
	hard_deadline_at: i64,
	hard_deadline_remaining_seconds: u64,
}

#[derive(Serialize)]
struct Capacities<'a> {
	review_units: &'a Capacity,
	leads: &'a Capacity,
	siblings: &'a Capacity,
	candidate_queries: &'a Capacity,
	campaign: Campaign,
}

#[derive(Serialize)]
struct Campaign {
	jobs_limit: u64,
	jobs_admitted: u64,
	general_remaining: u64,
	urgent_remaining: u64,
	verification_remaining: u64,
}

impl<'a> From<&SurveyJobContext<'a>> for Context<'a> {
	fn from(c: &SurveyJobContext<'a>) -> Self {
		let left = |at: i64| u64::try_from(at.saturating_sub(c.now)).unwrap_or(0);
		let p = c.capacity;
		Self {
			phase: "survey",
			workflow_contract_version: loupe_core::WORKFLOW_CONTRACT_VERSION,
			recipe: match c.recipe {
				SurveyRecipe::Bootstrap => "bootstrap",
				SurveyRecipe::ResolveTarget => "resolve_target",
				SurveyRecipe::Ordinary(OrdinarySurveyRecipe::Coverage) => "coverage",
				SurveyRecipe::Ordinary(OrdinarySurveyRecipe::SameCommitIncremental) => {
					"same_commit_incremental"
				},
			},
			attempt: c.attempt,
			repo_id: c.repo_id,
			source_root: "/workdir",
			generation_id: &c.generation.generation_id,
			generation_commit: &c.generation.commit_sha,
			checkout_commit: c.checkout_commit,
			deadlines: Deadlines {
				launched_at: c.now,
				submit_by_at: c.limits.submit_by,
				submit_by_remaining_seconds: left(c.limits.submit_by),
				hard_deadline_at: c.limits.hard_deadline_at,
				hard_deadline_remaining_seconds: left(c.limits.hard_deadline_at),
			},
			token_budget: c.limits.token_budget,
			capacity: Capacities {
				review_units: &p.new_units,
				leads: &p.leads,
				siblings: &p.siblings,
				candidate_queries: &p.candidate_queries,
				campaign: Campaign {
					jobs_limit: p.campaign_jobs_limit,
					jobs_admitted: p.campaign_jobs_admitted,
					general_remaining: p.campaign_general_remaining,
					urgent_remaining: p.campaign_urgent_remaining,
					verification_remaining: p.campaign_verification_remaining,
				},
			},
			terminal_action: "finalize_survey",
		}
	}
}
