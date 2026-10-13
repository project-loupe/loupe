//! Transactional campaign orchestration. Worker checkout pins the commit.
use loupe_core::text::policy::{Reason, RevisionText};
use loupe_core::text::BoundedText;
pub use loupe_core::ReviewIntent as KindHint;
use loupe_core::{FollowUpTrigger, JobKind, JobState, PendingFollowUp, WORKFLOW_CONTRACT_VERSION};
use loupe_provenance::{Db as DbSource, Source};
use rusqlite::{params, OptionalExtension};

use crate::scheduler::{self, Band, CampaignPolicy, NewPhaseJob, PhaseRecipeInput, SurveyRecipe};
use crate::scope::RepoScope;
use crate::{
	campaigns, generations, jobs, review_units, transaction, Conflict, Db, Entity, Error,
	Ownership, Result,
};

// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug)]
pub enum RequestedRef<'a, S: Source> {
	Pinned(&'a BoundedText<RevisionText, S>),
	Branch(&'a BoundedText<RevisionText, S>),
}
impl<S: Source> Clone for RequestedRef<'_, S> {
	fn clone(&self) -> Self {
		*self
	}
}
impl<S: Source> Copy for RequestedRef<'_, S> {}

impl<'a, S: Source> RequestedRef<'a, S> {
	fn value(&self) -> &'a BoundedText<RevisionText, S> {
		match self {
			Self::Pinned(value) | Self::Branch(value) => value,
		}
	}
}

pub struct OpenCampaign<'a, S: Source> {
	pub trigger: campaigns::Trigger,
	pub requested_ref: RequestedRef<'a, S>,
	pub base_sha: Option<&'a BoundedText<RevisionText, S>>,
	pub kind_hint: KindHint,
}

// debug-ok: opening outcomes contain only closed states and integer campaign/job IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
	Created { campaign_id: i64, job_id: i64 },
	Coalesced { campaign_id: i64 },
	Pending { campaign_id: i64 },
}

fn get(scope: &RepoScope<'_>, id: i64) -> Result<campaigns::Campaign> {
	campaigns::get(scope, id)?.ok_or(Error::NotFound(Entity::Campaign, id))
}

pub fn open<S: Source>(
	scope: &RepoScope<'_>, new: &OpenCampaign<'_, S>, policy: &CampaignPolicy, now: i64,
) -> Result<Opened> {
	scope.require_operator()?;
	policy.validate()?;
	let tx = scope.conn;
	let active: Option<i64> = tx
		.query_row(
			"SELECT campaign_id FROM review_campaigns WHERE repo_id=?1 AND state='active'",
			[scope.repo_id],
			|r| r.get(0),
		)
		.optional()?;
	if let Some(campaign_id) = active {
		let campaign = get(scope, campaign_id)?;
		let Some(generation_id) = campaign.generation_id else {
			return Ok(Opened::Pending { campaign_id });
		};
		let generation = generations::get(scope, generation_id)?
			.ok_or(Error::NotFound(Entity::Generation, generation_id))?;
		let trigger = match new.trigger {
			campaigns::Trigger::Manual => FollowUpTrigger::Manual,
			campaigns::Trigger::Scheduled => FollowUpTrigger::Scheduled,
			campaigns::Trigger::CompatScanApi => FollowUpTrigger::CompatScanApi,
			campaigns::Trigger::Reconciliation => FollowUpTrigger::Reconciliation,
			campaigns::Trigger::Operator => FollowUpTrigger::Operator,
		};
		let pending = PendingFollowUp::new(
			generation.pending_follow_up.as_ref(),
			new.requested_ref.value(),
			trigger,
			new.kind_hint,
			now,
		)?;
		generations::coalesce_follow_up(scope, generation_id, &pending)?;
		return Ok(Opened::Coalesced { campaign_id });
	}
	let has_baseline: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM review_generations WHERE repo_id=?1 AND state='active')",
		[scope.repo_id],
		|r| r.get(0),
	)?;
	let initial = if !has_baseline {
		campaigns::Recipe::Bootstrap
	} else if new.kind_hint == KindHint::FullReview {
		campaigns::Recipe::Reconciliation
	} else {
		campaigns::Recipe::Incremental
	};
	let snapshot = policy;
	let deadline = now
		.checked_add(policy.campaign_deadline_seconds)
		.ok_or(Error::Conflict(Conflict::CampaignPolicy))?;
	let campaign_id = campaigns::create(
		scope,
		&campaigns::NewCampaign {
			recipe: initial,
			trigger: new.trigger,
			requested_base_sha: new.base_sha,
			target_commit_sha: new.requested_ref.value(),
			generation_id: None,
			effective_policy: campaigns::CampaignPolicyInput::<S>::Resolved(snapshot),
			deadline_at: Some(deadline),
			root_campaign_id: None,
			continuation_of_campaign_id: None,
		},
		now,
	)?;
	let recipe = match initial {
		campaigns::Recipe::Bootstrap => SurveyRecipe::Bootstrap,
		campaigns::Recipe::Incremental => SurveyRecipe::Incremental,
		campaigns::Recipe::Reconciliation => SurveyRecipe::Reconciliation,
		campaigns::Recipe::Corroboration => unreachable!("initial recipe is a survey"),
	};
	let job_id = scheduler::enqueue_phase(
		scope,
		&NewPhaseJob {
			kind: JobKind::<S>::Survey,
			campaign_id,
			generation_id: None,
			assigned_lead_id: None,
			target_finding_id: None,
			continuation_of_job_id: None,
			band: Band::Normal,
			effective_priority: 0,
			eligible_at: now,
			token_budget: policy.survey_token_budget,
			recipe: PhaseRecipeInput::Survey(recipe),
			handoff: false,
		},
		now,
	)?;
	if let RequestedRef::Pinned(sha) = new.requested_ref {
		pin(scope, campaign_id, job_id, sha, now)?;
	}
	Ok(Opened::Created { campaign_id, job_id })
}

/// A complete, lowercase Git object id (SHA-1 or SHA-256). The pinned commit
/// comes from the worker's checkout checkpoint, so it is boundary input and
/// nothing else may reach `target_commit_sha` or generation selection.
fn is_commit_sha(sha: &str) -> bool {
	matches!(sha.len(), 40 | 64) && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn pin<S: Source>(
	scope: &RepoScope<'_>, campaign_id: i64, job_id: i64, sha: &BoundedText<RevisionText, S>,
	now: i64,
) -> Result<i64> {
	scope.require_operator()?;
	let tx = scope.conn;
	if !is_commit_sha(sha.expose()) {
		return Err(
			loupe_core::text::Error::new("commit_sha", loupe_core::text::Rule::Identifier).into()
		);
	}
	let campaign = get(scope, campaign_id)?;
	if campaign.state != campaigns::State::Active {
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	let job = jobs::get(scope, job_id)?.ok_or(Error::NotFound(Entity::Job, job_id))?;
	if job.campaign_id != Some(campaign_id)
		|| job.repo_id != campaign.repo_id
		|| job.kind != JobKind::Survey
		|| !matches!(job.state, JobState::Queued | JobState::Leased)
	{
		return Err(Error::Ownership(Ownership::CampaignJob));
	}
	if let Some(generation) = campaign.generation_id {
		return if campaign.target_commit_sha.expose() == sha.expose() {
			Ok(generation)
		} else {
			Err(Error::Conflict(Conflict::CampaignPinned))
		};
	}
	let generations = generations::list_for_repo(scope)?;
	let active = generations.iter().find(|g| g.state == generations::State::Active);
	let existing = active.and_then(|g| {
		if g.commit_sha.expose() == sha.expose()
			&& g.workflow_contract_version == WORKFLOW_CONTRACT_VERSION
		{
			Some(g.generation_id)
		} else if g.commit_sha.expose() != sha.expose() {
			generations
				.iter()
				.find(|s| {
					s.state == generations::State::Building
						&& s.commit_sha.expose() == sha.expose()
						&& s.workflow_contract_version == WORKFLOW_CONTRACT_VERSION
						&& s.predecessor_generation_id == Some(g.generation_id)
				})
				.map(|s| s.generation_id)
		} else {
			None
		}
	});
	let generation_id = if let Some(existing) = existing {
		existing
	} else {
		if active.is_none() {
			for g in generations.iter().filter(|g| g.state == generations::State::Building) {
				generations::abandon_superseded_bootstrap(scope, g.generation_id, now)?;
			}
		}
		generations::create(
			scope,
			&generations::NewGeneration {
				predecessor_generation_id: active.map(|g| g.generation_id),
				commit_sha: sha,
				workflow_contract_version: WORKFLOW_CONTRACT_VERSION,
			},
			now,
		)?
	};
	tx.execute(
		"UPDATE review_campaigns SET target_commit_sha=?2,generation_id=?3 WHERE campaign_id=?1 AND repo_id=?4",
		params![campaign_id, sha.expose(), generation_id, scope.repo_id],
	)?;
	tx.execute(
		"UPDATE jobs SET generation_id=?2 WHERE id=?1 AND repo_id=?3",
		params![job_id, generation_id, scope.repo_id],
	)?;
	Ok(generation_id)
}

/// Bootstrap finalization must call this inside its checkpoint transaction.
pub fn activate_generation(scope: &RepoScope<'_>, campaign_id: i64, now: i64) -> Result<()> {
	scope.require_operator()?;
	let campaign = get(scope, campaign_id)?;
	if campaign.state != campaigns::State::Active {
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	let id = campaign.generation_id.ok_or(Error::Conflict(Conflict::GenerationState))?;
	let generation = generations::get(scope, id)?.ok_or(Error::NotFound(Entity::Generation, id))?;
	if generation.predecessor_generation_id.is_some() {
		return Err(Error::Conflict(Conflict::GenerationPredecessor));
	}
	if generation.state != generations::State::Building
		|| generation.generated_profile.is_none()
		|| generation.inventory_digest.is_none()
	{
		return Err(Error::Conflict(Conflict::GenerationState));
	}
	generations::activate(scope, id, now)
}

enum Replenished {
	Queued(i64),
	NotNeeded,
	BudgetExhausted,
}

pub fn replenish(scope: &RepoScope<'_>, campaign_id: i64, now: i64) -> Result<Option<i64>> {
	scope.require_operator()?;
	Ok(match replenish_inner(scope, campaign_id, now)? {
		Replenished::Queued(id) => Some(id),
		Replenished::NotNeeded | Replenished::BudgetExhausted => None,
	})
}

fn replenish_inner(scope: &RepoScope<'_>, campaign_id: i64, now: i64) -> Result<Replenished> {
	let tx = scope.conn;
	let campaign = get(scope, campaign_id)?;
	if campaign.state != campaigns::State::Active
		|| campaign.deadline_at.is_some_and(|at| at <= now)
	{
		return Ok(Replenished::NotNeeded);
	}
	let Some(generation_id) = campaign.generation_id else {
		return Ok(Replenished::NotNeeded);
	};
	let generation = generations::get(scope, generation_id)?
		.ok_or(Error::NotFound(Entity::Generation, generation_id))?;
	if generation.state != generations::State::Active {
		return Ok(Replenished::NotNeeded);
	}
	let queued:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM jobs WHERE campaign_id=?1 AND repo_id=?2 AND kind='survey' AND state='queued')",params![campaign_id,scope.repo_id],|r|r.get(0))?;
	if queued {
		return Ok(Replenished::NotNeeded);
	}
	let band:Option<String>=tx.query_row(&format!("SELECT u.priority_band FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.generation_id=?1 AND g.repo_id=?2 AND {} ORDER BY CASE u.priority_band WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END LIMIT 1",*review_units::UNIT_NEEDS_WORK),params![generation_id,scope.repo_id],|r|r.get(0)).optional()?;
	let Some(band) = band else {
		return Ok(Replenished::NotNeeded);
	};
	let band: Band = band.parse()?;
	let parent:Option<i64>=tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1 AND repo_id=?2 AND kind='survey' AND state IN ('succeeded','failed','cancelled') ORDER BY finished_at DESC,id DESC LIMIT 1",params![campaign_id,scope.repo_id],|r|r.get(0)).optional()?;
	let policy = CampaignPolicy::from_snapshot(&campaign.effective_policy)?;
	match scheduler::enqueue_phase(
		scope,
		&NewPhaseJob {
			kind: JobKind::<DbSource>::Survey,
			campaign_id,
			generation_id: Some(generation_id),
			assigned_lead_id: None,
			target_finding_id: None,
			continuation_of_job_id: parent,
			band,
			effective_priority: 0,
			eligible_at: now,
			token_budget: policy.survey_token_budget,
			recipe: PhaseRecipeInput::Survey(SurveyRecipe::Coverage),
			handoff: false,
		},
		now,
	) {
		Ok(id) => Ok(Replenished::Queued(id)),
		Err(Error::Conflict(Conflict::CampaignBudget)) => Ok(Replenished::BudgetExhausted),
		Err(error) => Err(error),
	}
}

pub fn cancel<S: Source>(
	scope: &RepoScope<'_>, campaign_id: i64, reason: &BoundedText<Reason, S>, now: i64,
) -> Result<()> {
	scope.require_operator()?;
	get(scope, campaign_id)?;
	scheduler::cancel_queued_children(scope, campaign_id, now, reason)?;
	campaigns::cancel(scope, campaign_id, reason, now)
}

// debug-ok: finish reasons are closed host scheduling outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
	Completed,
	DeadlineReached,
}

// debug-ok: the tick report contains only outcome counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TickReport {
	pub enqueued: usize,
	pub completed: usize,
	pub deadline_reached: usize,
	pub budget_exhausted: usize,
	/// A failed campaign transaction is rolled back; other campaigns proceed.
	pub failed: usize,
}

#[derive(Default)]
struct Progress {
	enqueued: bool,
	finish: Option<Finish>,
	budget_exhausted: bool,
}

pub fn try_finish(scope: &RepoScope<'_>, campaign_id: i64, now: i64) -> Result<Option<Finish>> {
	scope.require_operator()?;
	Ok(advance(scope, campaign_id, now)?.finish)
}

fn advance(scope: &RepoScope<'_>, campaign_id: i64, now: i64) -> Result<Progress> {
	let tx = scope.conn;
	let campaign = get(scope, campaign_id)?;
	let mut progress = Progress::default();
	if campaign.state != campaigns::State::Active {
		return Ok(progress);
	}
	let expired = campaign.deadline_at.is_some_and(|at| at <= now);
	if expired {
		scheduler::cancel_queued_at_deadline(scope, campaign_id, now)?;
	}
	let busy: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM jobs WHERE campaign_id=?1 AND repo_id=?2 AND state IN ('queued','leased'))",
		params![campaign_id,scope.repo_id],
		|r| r.get(0),
	)?;
	if busy {
		return Ok(progress);
	}
	if !expired {
		match replenish_inner(scope, campaign_id, now)? {
			Replenished::Queued(_) => {
				progress.enqueued = true;
				return Ok(progress);
			},
			Replenished::BudgetExhausted => progress.budget_exhausted = true,
			Replenished::NotNeeded => {},
		}
	}
	let (finish, reason) = if expired {
		(Finish::DeadlineReached, campaigns::FinishedReason::Deadline)
	} else {
		(Finish::Completed, campaigns::FinishedReason::Completed)
	};
	let summary = campaigns::summarize(scope, campaign_id)?;
	campaigns::finish_scheduled(scope, campaign_id, &summary, reason, now)?;
	progress.finish = Some(finish);
	Ok(progress)
}

/// No active campaigns means no write transaction. Each campaign otherwise
/// advances independently, so a malformed row cannot stall another repository.
pub fn tick(db: &Db, now: i64) -> Result<TickReport> {
	let active: Vec<(i64, i64)> = db.with_conn(|c| {
		Ok(c.prepare(
			"SELECT campaign_id,repo_id FROM review_campaigns WHERE state='active' ORDER BY campaign_id",
		)?
		.query_map([], |r| Ok((r.get(0)?,r.get(1)?)))?
		.collect::<rusqlite::Result<_>>()?)
	})?;
	let mut report = TickReport::default();
	for (campaign_id, repo_id) in active {
		let progress = db.with_conn(|c| {
			transaction::immediate(c, |tx| {
				let committed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
				let scope = RepoScope {
					conn: tx,
					repo_id,
					identity: &db.identity,
					operator: true,
					committed: &committed,
				};
				advance(&scope, campaign_id, now)
			})
		});
		let progress = match progress {
			Ok(progress) => progress,
			Err(_) => {
				report.failed += 1;
				continue;
			},
		};
		report.enqueued += usize::from(progress.enqueued);
		match progress.finish {
			Some(Finish::Completed) => report.completed += 1,
			Some(Finish::DeadlineReached) => report.deadline_reached += 1,
			None => {},
		}
		if progress.budget_exhausted {
			report.budget_exhausted += 1;
			// The finish committed above; subsequent ticks cannot log this again.
		}
	}
	Ok(report)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn scope_safety_invalid_policy_cannot_hide_behind_an_active_campaign() {
		let db = crate::review_tests::fixture();
		let reference = crate::test_support::text("main").unwrap();
		let invalid = CampaignPolicy { survey_units_per_job: 33, ..CampaignPolicy::default() };
		let result = crate::scope::with_operator_repository(
			&db,
			&crate::test_support::operator_ingress(),
			crate::scope::OperatorTarget::Repository(1),
			|scope| {
				open(
					scope,
					&OpenCampaign {
						trigger: campaigns::Trigger::Manual,
						requested_ref: RequestedRef::Branch(&reference),
						base_sha: None,
						kind_hint: KindHint::Incremental,
					},
					&invalid,
					1,
				)
			},
		);
		assert!(
			matches!(result, Err(Error::Conflict(Conflict::CampaignPolicy))),
			"public campaign open must validate policy even on the coalescing path"
		);
		db.with_conn(|conn| {
			let pending: Option<String> = conn.query_row(
				"SELECT pending_follow_up FROM review_generations WHERE generation_id=11",
				[],
				|row| row.get(0),
			)?;
			assert!(pending.is_none(), "invalid policy must not mutate the active generation");
			Ok(())
		})
		.unwrap();
	}

	#[test]
	fn stored_policy_sql_bytes_and_digest_match_the_actual_typed_readback() {
		for policy in [
			CampaignPolicy::default(),
			CampaignPolicy {
				campaign_max_jobs: 19,
				campaign_handoff_reserve: 3,
				survey_units_per_job: 7,
				max_attempts: 5,
				survey_token_budget: Some(1000),
				..CampaignPolicy::default()
			},
		] {
			let db = crate::review_tests::fixture();
			db.with_conn(|conn| {
				conn.execute_batch("DELETE FROM jobs; DELETE FROM review_campaigns;")?;
				Ok(())
			})
			.unwrap();
			let reference = crate::test_support::text("main").unwrap();
			crate::scope::with_operator_repository(
				&db,
				&crate::test_support::operator_ingress(),
				crate::scope::OperatorTarget::Repository(1),
				|scope| {
					let opened = open(
						scope,
						&OpenCampaign {
							trigger: campaigns::Trigger::Manual,
							requested_ref: RequestedRef::Branch(&reference),
							base_sha: None,
							kind_hint: KindHint::Incremental,
						},
						&policy,
						0,
					)?;
					let Opened::Created { campaign_id, .. } = opened else {
						panic!("new campaign")
					};
					let stored = campaigns::get(scope, campaign_id)?.unwrap().effective_policy;
					let (raw, digest): (String, Vec<u8>) = scope.conn.query_row(
						"SELECT effective_policy,effective_policy_digest FROM review_campaigns WHERE campaign_id=?1",
						[campaign_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
					assert_eq!(raw.as_bytes(), stored.canonical());
					assert_eq!(digest.as_slice(), stored.digest());
					Ok(())
				},
			)
			.unwrap();
		}
	}

	#[test]
	fn requested_ref_traits_need_only_source_and_preserve_variant_and_borrow() {
		#[allow(clippy::clone_on_copy)] // Exercise Clone independently to check its generic bounds.
		fn cloned<'a, S: Source>(value: &RequestedRef<'a, S>) -> RequestedRef<'a, S> {
			Clone::clone(value)
		}
		fn copied<'a, S: Source>(value: &RequestedRef<'a, S>) -> RequestedRef<'a, S> {
			*value
		}

		let pinned = crate::test_support::text("pinned-revision").unwrap();
		let branch = crate::test_support::text("main").unwrap();
		for original in [RequestedRef::Pinned(&pinned), RequestedRef::Branch(&branch)] {
			for copy in [cloned(&original), copied(&original)] {
				match (&original, &copy) {
					(RequestedRef::Pinned(left), RequestedRef::Pinned(right))
					| (RequestedRef::Branch(left), RequestedRef::Branch(right)) => {
						assert!(std::ptr::eq(*left, *right));
					},
					_ => panic!("requested reference clone or copy changed variant"),
				}
			}
		}
	}
}
