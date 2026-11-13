//! Shared phase authority. Call inside the same immediate transaction as each
//! mutation or authority-issuing read, never only as an HTTP precheck.
//!
//! This module does not enable routes or runtime claims. Access purpose and
//! expected phase are selected by the server, never deserialized from requests.
use axum::http::HeaderMap;
use loupe_core::review_payload::Version1;
use loupe_storage::{jobs, review_authority as stored, Db, Error, Result};
use serde::Deserialize;
pub use stored::{Access, Phase};

use crate::auth::AuthedWorker;
use crate::job_capability;

// debug-ok: recipe variants are closed server policy choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SurveyRecipe {
	Bootstrap,
	Coverage,
	Incremental,
	Reconciliation,
	Corroboration,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum AssignmentKey {
	Ordinary,
}

#[derive(Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Recipe {
	Survey {
		#[serde(rename = "version")]
		_version: Version1,
		recipe: SurveyRecipe,
		#[serde(rename = "assignment_key")]
		_assignment_key: AssignmentKey,
	},
	Drilldown {
		#[serde(rename = "version")]
		_version: Version1,
	},
	Verify {
		#[serde(rename = "version")]
		_version: Version1,
	},
}

impl Recipe {
	fn phase(&self) -> Phase {
		match self {
			Self::Survey { .. } => Phase::Survey,
			Self::Drilldown { .. } => Phase::Drilldown,
			Self::Verify { .. } => Phase::Verify,
		}
	}
	fn bootstrap(&self) -> bool {
		matches!(self, Self::Survey { recipe: SurveyRecipe::Bootstrap, .. })
	}
	fn kind(&self) -> support::RecipeKind {
		use support::RecipeKind as K;
		match self {
			Self::Survey { recipe: SurveyRecipe::Bootstrap, .. } => K::Bootstrap,
			Self::Survey { recipe: SurveyRecipe::Coverage, .. } => K::Coverage,
			Self::Survey { recipe: SurveyRecipe::Incremental, .. } => K::Incremental,
			Self::Survey { recipe: SurveyRecipe::Reconciliation, .. } => K::Reconciliation,
			Self::Survey { recipe: SurveyRecipe::Corroboration, .. } => K::Corroboration,
			Self::Drilldown { .. } => K::Drilldown,
			Self::Verify { .. } => K::Verify,
		}
	}
	fn supported(&self, context: &stored::Context, access: Access) -> bool {
		let facts = support::SupportFacts {
			campaign: context.campaign_recipe,
			generation: context.generation.as_ref().map(|generation| support::GenerationFacts {
				state: generation.state,
				predecessor_present: generation.predecessor.is_some(),
				commits_equal: generation.commit == context.target_commit,
			}),
			head_present: context.head_sha.is_some(),
			access,
		};
		support::supported(self.kind(), facts)
	}
}

/// Recipe support decided over closed facts, parsed once from stored context.
pub(crate) mod support {
	pub use loupe_storage::campaigns::Recipe as CampaignRecipe;
	pub use loupe_storage::generations::State as GenerationState;
	pub use loupe_storage::review_authority::Access;

	// debug-ok: recipe kinds are closed server policy choices.
	#[derive(Debug, Clone, Copy, PartialEq, Eq)]
	pub enum RecipeKind {
		Bootstrap,
		Coverage,
		Incremental,
		Reconciliation,
		Corroboration,
		Drilldown,
		Verify,
	}

	// debug-ok: closed states and booleans only, no stored text.
	#[derive(Debug, Clone, Copy, PartialEq, Eq)]
	pub struct GenerationFacts {
		pub state: GenerationState,
		pub predecessor_present: bool,
		pub commits_equal: bool,
	}

	// debug-ok: closed variants and booleans only, no stored text.
	#[derive(Debug, Clone, Copy, PartialEq, Eq)]
	pub struct SupportFacts {
		pub campaign: CampaignRecipe,
		pub generation: Option<GenerationFacts>,
		pub head_present: bool,
		pub access: Access,
	}

	pub fn supported(recipe: RecipeKind, facts: SupportFacts) -> bool {
		if !matches!(facts.campaign, CampaignRecipe::Bootstrap | CampaignRecipe::Incremental) {
			return false;
		}
		let Some(generation) = facts.generation else {
			return facts.access == Access::Checkout
				&& !facts.head_present
				&& match recipe {
					RecipeKind::Bootstrap => facts.campaign == CampaignRecipe::Bootstrap,
					RecipeKind::Incremental => facts.campaign == CampaignRecipe::Incremental,
					_ => false,
				};
		};
		if !generation.commits_equal {
			return false;
		}
		let active = generation.state == GenerationState::Active;
		let bootstrap = generation.state == GenerationState::Building
			&& !generation.predecessor_present
			&& facts.campaign == CampaignRecipe::Bootstrap;
		match recipe {
			RecipeKind::Bootstrap => bootstrap,
			RecipeKind::Coverage => active,
			RecipeKind::Incremental => active && facts.campaign == CampaignRecipe::Incremental,
			RecipeKind::Reconciliation | RecipeKind::Corroboration => false,
			RecipeKind::Drilldown | RecipeKind::Verify => active || bootstrap,
		}
	}
}

/// Bind the authenticated worker, job and header to storage's transaction owner.
/// The clock is sampled after the write lock; callback errors prevent commit.
/// A malformed header never enters the callback or returns authority.
pub fn with_transaction<T, E: From<Error>>(
	db: &Db, worker: &AuthedWorker, headers: &HeaderMap, job_id: i64, clock: impl FnOnce() -> i64,
	body: impl for<'tx> FnOnce(&mut stored::PhaseTransaction<'tx>) -> std::result::Result<T, E>,
) -> std::result::Result<Option<T>, E> {
	let Ok(hash) = job_capability::parse_hash(headers) else { return Ok(None) };
	stored::with_phase_transaction(
		db,
		jobs::LeaseIdentity { job_id, worker_id: worker.id(), capability_hash: &hash },
		clock,
		body,
	)
	.map(Some)
}

/// Strict server recipe policy runs on the original stored text, only after
/// storage checks live identity and context. Control never decodes that context.
#[doc = include_str!("authority_scope.md")]
pub fn authorize<'scope, 'tx>(
	tx: &'scope mut stored::PhaseTransaction<'tx>, phase: Phase, access: Access,
) -> Result<Option<stored::PhaseScope<'scope, 'scope>>> {
	tx.authorize(phase, access, |context| policy(phase, access, context))
}

/// Checkout preparation re-runs this same policy after resolving its generation.
pub fn policy(
	phase: Phase, access: Access, context: &stored::Context,
) -> Result<Option<stored::PolicyDecision>> {
	let Some(recipe) =
		context.recipe.as_ref().and_then(|raw| serde_json::from_str::<Recipe>(raw.expose()).ok())
	else {
		return Ok(None);
	};
	Ok((recipe.phase() == phase && recipe.supported(context, access)).then_some(
		if recipe.bootstrap() {
			stored::PolicyDecision::Bootstrap
		} else {
			stored::PolicyDecision::Ordinary
		},
	))
}

/// The same strict recipe policy, without transaction or persistence access.
/// Planned variants are host choices; stored text is never reconstructed.
pub fn admission_policy(
	phase: Phase, context: &stored::Context, input: loupe_storage::admission_claim::RecipeInput<'_>,
) -> std::result::Result<
	loupe_storage::admission_claim::RecipeDecision,
	loupe_storage::admission_claim::CallbackError<Error>,
> {
	use loupe_storage::admission_claim::{
		CallbackError, Incompatibility, RecipeDecision as D, RecipeInput,
	};
	let recipe = match input {
		RecipeInput::Stored(raw) => raw
			.and_then(|raw| serde_json::from_str::<Recipe>(raw.expose()).ok())
			.ok_or(CallbackError::Incompatible(Incompatibility::InvalidData))?,
		RecipeInput::Planned(decision) => match decision {
			D::Bootstrap | D::Coverage | D::Incremental => Recipe::Survey {
				_version: Version1,
				_assignment_key: AssignmentKey::Ordinary,
				recipe: match decision {
					D::Bootstrap => SurveyRecipe::Bootstrap,
					D::Coverage => SurveyRecipe::Coverage,
					_ => SurveyRecipe::Incremental,
				},
			},
			D::Drilldown => Recipe::Drilldown { _version: Version1 },
			D::Verify => Recipe::Verify { _version: Version1 },
		},
	};
	if recipe.phase() != phase {
		return Err(CallbackError::Incompatible(Incompatibility::InvalidData));
	}
	if !recipe.supported(context, Access::Checkout) {
		return Err(CallbackError::Incompatible(Incompatibility::UnsupportedRecipe));
	}
	Ok(match recipe {
		Recipe::Survey { recipe: SurveyRecipe::Bootstrap, .. } => D::Bootstrap,
		Recipe::Survey { recipe: SurveyRecipe::Coverage, .. } => D::Coverage,
		Recipe::Survey { recipe: SurveyRecipe::Incremental, .. } => D::Incremental,
		Recipe::Drilldown { .. } => D::Drilldown,
		Recipe::Verify { .. } => D::Verify,
		Recipe::Survey { .. } => {
			return Err(CallbackError::Incompatible(Incompatibility::UnsupportedRecipe))
		},
	})
}

#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;
