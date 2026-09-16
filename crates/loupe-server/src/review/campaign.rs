//! Transactional campaign orchestration. Worker checkout pins the commit.
use loupe_core::text::policy::{Payload, Reason};
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_core::{JobKind, JobState, WORKFLOW_CONTRACT_VERSION};
use loupe_storage::scheduler::{self, Band, CampaignPolicy, NewPhaseJob};
use loupe_storage::{
	campaigns, generations, jobs, review_units, Conflict, Entity, Error, Ownership, Result,
};
use rusqlite::{params, OptionalExtension, Transaction};

use super::policy::ReviewPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindHint {
	FullReview,
	Incremental,
}

#[derive(Debug, Clone, Copy)]
pub enum RequestedRef<'a> {
	Pinned(&'a str),
	Branch(&'a str),
}
impl<'a> RequestedRef<'a> {
	fn as_str(self) -> &'a str {
		match self {
			Self::Pinned(value) | Self::Branch(value) => value,
		}
	}
}

pub struct OpenCampaign<'a> {
	pub repo_id: i64,
	pub trigger: campaigns::Trigger,
	pub requested_ref: RequestedRef<'a>,
	pub base_sha: Option<&'a str>,
	pub kind_hint: KindHint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
	Created { campaign_id: i64, job_id: i64 },
	Coalesced { campaign_id: i64 },
	Pending { campaign_id: i64 },
}

fn get(tx: &Transaction<'_>, id: i64) -> Result<campaigns::Campaign> {
	campaigns::get(tx, id)?.ok_or(Error::NotFound(Entity::Campaign, id))
}

fn recipe(name: &str) -> Result<BoundedJson<Payload>> {
	Ok(BoundedJson::new(&serde_json::json!({"version":1,"phase":"survey","recipe":name,"assignment_key":"ordinary"}).to_string())?)
}

pub fn open(
	tx: &Transaction<'_>, new: &OpenCampaign<'_>, policy: &ReviewPolicy, now: i64,
) -> Result<Opened> {
	let active: Option<i64> = tx
		.query_row(
			"SELECT campaign_id FROM review_campaigns WHERE repo_id=?1 AND state='active'",
			[new.repo_id],
			|r| r.get(0),
		)
		.optional()?;
	if let Some(campaign_id) = active {
		let campaign = get(tx, campaign_id)?;
		let Some(generation_id) = campaign.generation_id else {
			return Ok(Opened::Pending { campaign_id });
		};
		let generation = generations::get(tx, generation_id)?
			.ok_or(Error::NotFound(Entity::Generation, generation_id))?;
		let mut triggers = generation
			.pending_follow_up
			.as_ref()
			.and_then(|p| serde_json::from_str::<serde_json::Value>(p.expose()).ok())
			.and_then(|p| p["triggers"].as_array().cloned())
			.unwrap_or_default();
		triggers.push(
			serde_json::json!({"trigger":new.trigger.as_str(),"ref":new.requested_ref.as_str(),"at":now}),
		);
		if triggers.len() > 16 {
			triggers.drain(..triggers.len() - 16);
		}
		let pending=BoundedJson::new(&serde_json::json!({"version":1,"triggers":triggers,"newest_ref":new.requested_ref.as_str()}).to_string())?;
		generations::set_pending_follow_up(tx, generation_id, &pending)?;
		return Ok(Opened::Coalesced { campaign_id });
	}
	let has_baseline: bool = tx.query_row(
		"SELECT EXISTS(SELECT 1 FROM review_generations WHERE repo_id=?1 AND state='active')",
		[new.repo_id],
		|r| r.get(0),
	)?;
	let initial = if !has_baseline {
		campaigns::Recipe::Bootstrap
	} else if new.kind_hint == KindHint::FullReview {
		campaigns::Recipe::Reconciliation
	} else {
		campaigns::Recipe::Incremental
	};
	let snapshot = policy.snapshot().map_err(|_| Error::Conflict(Conflict::CampaignPolicy))?;
	let deadline = now
		.checked_add(policy.campaign_deadline_seconds)
		.ok_or(Error::Conflict(Conflict::CampaignPolicy))?;
	let campaign_id = campaigns::create(
		tx,
		&campaigns::NewCampaign {
			repo_id: new.repo_id,
			recipe: initial,
			trigger: new.trigger,
			requested_base_sha: new.base_sha,
			target_commit_sha: new.requested_ref.as_str(),
			generation_id: None,
			effective_policy: &snapshot,
			deadline_at: Some(deadline),
			root_campaign_id: None,
			continuation_of_campaign_id: None,
		},
		now,
	)?;
	let recipe = recipe(initial.as_str())?;
	let job_id = scheduler::enqueue_phase(
		tx,
		&NewPhaseJob {
			repo_id: new.repo_id,
			kind: JobKind::Survey,
			campaign_id,
			generation_id: None,
			assigned_lead_id: None,
			target_finding_id: None,
			continuation_of_job_id: None,
			band: Band::Normal,
			effective_priority: 0,
			eligible_at: now,
			token_budget: policy.survey_token_budget,
			recipe: &recipe,
			handoff: false,
		},
		now,
	)?;
	if let RequestedRef::Pinned(sha) = new.requested_ref {
		pin(tx, campaign_id, job_id, sha, now)?;
	}
	Ok(Opened::Created { campaign_id, job_id })
}

/// A complete, lowercase Git object id (SHA-1 or SHA-256). The pinned commit
/// comes from the worker's checkout checkpoint, so it is boundary input and
/// nothing else may reach `target_commit_sha` or generation selection.
fn is_commit_sha(sha: &str) -> bool {
	matches!(sha.len(), 40 | 64) && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn pin(
	tx: &Transaction<'_>, campaign_id: i64, job_id: i64, sha: &str, now: i64,
) -> Result<i64> {
	if !is_commit_sha(sha) {
		return Err(
			loupe_core::text::Error::new("commit_sha", loupe_core::text::Rule::Identifier).into()
		);
	}
	let campaign = get(tx, campaign_id)?;
	if campaign.state != campaigns::State::Active {
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	let job = jobs::get(tx, job_id)?.ok_or(Error::NotFound(Entity::Job, job_id))?;
	if job.campaign_id != Some(campaign_id)
		|| job.repo_id != campaign.repo_id
		|| job.kind != JobKind::Survey
		|| !matches!(job.state, JobState::Queued | JobState::Leased)
	{
		return Err(Error::Ownership(Ownership::CampaignJob));
	}
	if let Some(generation) = campaign.generation_id {
		return if campaign.target_commit_sha == sha {
			Ok(generation)
		} else {
			Err(Error::Conflict(Conflict::CampaignPinned))
		};
	}
	let generations = generations::list_for_repo(tx, campaign.repo_id)?;
	let active = generations.iter().find(|g| g.state == generations::State::Active);
	let existing = active.and_then(|g| {
		if g.commit_sha == sha && g.workflow_contract_version == WORKFLOW_CONTRACT_VERSION {
			Some(g.generation_id)
		} else if g.commit_sha != sha {
			generations
				.iter()
				.find(|s| {
					s.state == generations::State::Building
						&& s.commit_sha == sha
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
			let reason = BoundedText::new("superseded bootstrap")?;
			for g in generations.iter().filter(|g| g.state == generations::State::Building) {
				generations::abandon(tx, g.generation_id, &reason, now)?;
			}
		}
		generations::create(
			tx,
			&generations::NewGeneration {
				repo_id: campaign.repo_id,
				predecessor_generation_id: active.map(|g| g.generation_id),
				commit_sha: sha,
				workflow_contract_version: WORKFLOW_CONTRACT_VERSION,
			},
			now,
		)?
	};
	tx.execute(
		"UPDATE review_campaigns SET target_commit_sha=?2,generation_id=?3 WHERE campaign_id=?1",
		params![campaign_id, sha, generation_id],
	)?;
	tx.execute("UPDATE jobs SET generation_id=?2 WHERE id=?1", params![job_id, generation_id])?;
	Ok(generation_id)
}

/// B5 calls this once inside the bootstrap finalize checkpoint transaction.
pub fn activate_generation(tx: &Transaction<'_>, campaign_id: i64, now: i64) -> Result<()> {
	let campaign = get(tx, campaign_id)?;
	if campaign.state != campaigns::State::Active {
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	let id = campaign.generation_id.ok_or(Error::Conflict(Conflict::GenerationState))?;
	let generation = generations::get(tx, id)?.ok_or(Error::NotFound(Entity::Generation, id))?;
	if generation.predecessor_generation_id.is_some() {
		return Err(Error::Conflict(Conflict::GenerationPredecessor));
	}
	if generation.state != generations::State::Building
		|| generation.generated_profile.is_none()
		|| generation.inventory_digest.is_none()
	{
		return Err(Error::Conflict(Conflict::GenerationState));
	}
	generations::activate(tx, id, now)
}

pub fn replenish(tx: &Transaction<'_>, campaign_id: i64, now: i64) -> Result<Option<i64>> {
	let campaign = get(tx, campaign_id)?;
	if campaign.state != campaigns::State::Active
		|| campaign.deadline_at.is_some_and(|at| at <= now)
	{
		return Ok(None);
	}
	let Some(generation_id) = campaign.generation_id else {
		return Ok(None);
	};
	let generation = generations::get(tx, generation_id)?
		.ok_or(Error::NotFound(Entity::Generation, generation_id))?;
	if generation.state != generations::State::Active {
		return Ok(None);
	}
	let queued:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM jobs WHERE campaign_id=?1 AND kind='survey' AND state='queued')",[campaign_id],|r|r.get(0))?;
	if queued {
		return Ok(None);
	}
	let band:Option<String>=tx.query_row(&format!("SELECT u.priority_band FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.generation_id=?1 AND {} ORDER BY CASE u.priority_band WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END LIMIT 1",*review_units::UNIT_NEEDS_WORK),[generation_id],|r|r.get(0)).optional()?;
	let Some(band) = band else {
		return Ok(None);
	};
	let band: Band = band.parse()?;
	let parent:Option<i64>=tx.query_row("SELECT id FROM jobs WHERE campaign_id=?1 AND kind='survey' AND state IN ('succeeded','failed','cancelled') ORDER BY finished_at DESC,id DESC LIMIT 1",[campaign_id],|r|r.get(0)).optional()?;
	let policy = CampaignPolicy::from_snapshot(&campaign.effective_policy)?;
	let recipe = recipe("coverage")?;
	match scheduler::enqueue_phase(
		tx,
		&NewPhaseJob {
			repo_id: campaign.repo_id,
			kind: JobKind::Survey,
			campaign_id,
			generation_id: Some(generation_id),
			assigned_lead_id: None,
			target_finding_id: None,
			continuation_of_job_id: parent,
			band,
			effective_priority: 0,
			eligible_at: now,
			token_budget: policy.survey_token_budget,
			recipe: &recipe,
			handoff: false,
		},
		now,
	) {
		Ok(id) => Ok(Some(id)),
		Err(Error::Conflict(Conflict::CampaignBudget)) => Ok(None),
		Err(error) => Err(error),
	}
}

pub fn cancel(
	tx: &Transaction<'_>, campaign_id: i64, reason: &BoundedText<Reason>, now: i64,
) -> Result<()> {
	scheduler::cancel_queued_children(tx, campaign_id, now, reason)?;
	campaigns::cancel(tx, campaign_id, reason, now)
}
