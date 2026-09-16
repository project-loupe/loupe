//! Phase-aware queue policy. Campaign-owned limits are separate from live caps.
mod claim;
mod policy;
#[cfg(test)]
use claim::claim_kinds;
pub use claim::{claim, ClaimRequest, Claimed};
use loupe_core::text::policy::{Payload, Reason};
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_core::{JobKind, JobState, WORKFLOW_CONTRACT_VERSION};
pub use policy::{CampaignPolicy, PhasePolicy};
use rusqlite::{params, Connection, Transaction};

use crate::review::{changed, is_unique};
use crate::{campaigns, jobs, ownership, Conflict, Entity, Error, Ownership, Result};

fn invalid(field: &'static str) -> Error {
	loupe_core::text::Error::new(field, loupe_core::text::Rule::Identifier).into()
}

/// Connection-local, transactional scheduling history. It resets on restart.
pub fn ensure_state(conn: &Connection) -> Result<()> {
	conn.execute_batch(
		"CREATE TEMP TABLE IF NOT EXISTS scheduler_repo_state (
		repo_id INTEGER PRIMARY KEY, last_claim_seq INTEGER NOT NULL DEFAULT 0,
		burst INTEGER NOT NULL DEFAULT 0);
	CREATE TEMP TABLE IF NOT EXISTS scheduler_clock (
		singleton INTEGER PRIMARY KEY CHECK(singleton=1), seq INTEGER NOT NULL);
	INSERT OR IGNORE INTO scheduler_clock(singleton,seq) VALUES(1,0);",
	)?;
	Ok(())
}

pub struct NewPhaseJob<'a> {
	pub repo_id: i64,
	pub kind: JobKind,
	pub campaign_id: i64,
	pub generation_id: Option<i64>,
	pub assigned_lead_id: Option<i64>,
	pub target_finding_id: Option<i64>,
	pub continuation_of_job_id: Option<i64>,
	pub band: Band,
	pub effective_priority: u32,
	pub eligible_at: i64,
	pub token_budget: Option<u64>,
	pub recipe: &'a BoundedJson<Payload>,
	pub handoff: bool,
}

/// Caller owns the transaction; shape and scope checks precede insertion.
pub fn enqueue_phase(tx: &Transaction<'_>, new: &NewPhaseJob<'_>, now: i64) -> Result<i64> {
	if !matches!(new.kind, JobKind::Survey | JobKind::Drilldown | JobKind::Verify) {
		return Err(invalid("job_kind"));
	}
	let campaign = campaigns::get(tx, new.campaign_id)?
		.ok_or(Error::NotFound(Entity::Campaign, new.campaign_id))?;
	if campaign.state != campaigns::State::Active
		|| campaign.repo_id != new.repo_id
		|| campaign.deadline_at.is_some_and(|at| at <= now)
	{
		return Err(Error::Conflict(Conflict::CampaignState));
	}
	let shape = new.generation_id == campaign.generation_id
		&& match new.kind {
			JobKind::Survey => new.assigned_lead_id.is_none() && new.target_finding_id.is_none(),
			JobKind::Drilldown => {
				new.generation_id.is_some()
					&& new.assigned_lead_id.is_some()
					&& new.target_finding_id.is_none()
			},
			JobKind::Verify => {
				new.generation_id.is_some()
					&& new.assigned_lead_id.is_none()
					&& new.target_finding_id.is_some()
			},
			_ => false,
		};
	if !shape {
		return Err(invalid("job_shape"));
	}
	if new.token_budget.is_some_and(|n| n == 0 || n > i64::MAX as u64) {
		return Err(invalid("token_budget"));
	}
	ownership::job_links(tx, new.repo_id, new.generation_id, new.assigned_lead_id)?;
	if let (Some(lead), Some(generation)) = (new.assigned_lead_id, new.generation_id) {
		ownership::lead_in_generation(tx, lead, generation, Ownership::JobLead)?;
	}
	if let Some(finding) = new.target_finding_id {
		ownership::finding(tx, finding, new.repo_id, Ownership::JobFinding)?;
	}
	if let Some(parent) = new.continuation_of_job_id {
		ownership::require(tx, "SELECT EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?2 AND campaign_id=?3 AND kind=?4 AND state IN ('succeeded','failed','cancelled'))", params![parent,new.repo_id,new.campaign_id,new.kind.as_str()], Ownership::JobContinuation)?;
	}
	let policy = CampaignPolicy::from_snapshot(&campaign.effective_policy)?;
	let limit = if new.handoff && new.kind != JobKind::Survey {
		policy.campaign_max_jobs
	} else {
		policy.campaign_max_jobs - policy.campaign_handoff_reserve
	};
	let count: i64 =
		tx.query_row("SELECT COUNT(*) FROM jobs WHERE campaign_id=?1", [new.campaign_id], |r| {
			r.get(0)
		})?;
	if count >= limit {
		return Err(Error::Conflict(Conflict::CampaignBudget));
	}
	tx.execute("INSERT INTO jobs (repo_id,kind,state,enqueued_at,campaign_id,generation_id,assigned_lead_id,target_finding_id,continuation_of_job_id,scheduling_band,effective_priority,eligible_at,token_budget,recipe,workflow_contract_version)
	VALUES (?1,?2,'queued',?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)", params![new.repo_id,new.kind.as_str(),now,new.campaign_id,new.generation_id,new.assigned_lead_id,new.target_finding_id,new.continuation_of_job_id,new.band.as_str(),new.effective_priority.min(PRIORITY_MAX),new.eligible_at,new.token_budget.map(|n|n as i64),new.recipe.expose(),WORKFLOW_CONTRACT_VERSION])
	.map_err(|error| {
		if is_unique(&error, "jobs.assigned_lead_id") { Error::Conflict(Conflict::ActiveDrilldown) }
		else if is_unique(&error, "jobs.target_finding_id") { Error::Conflict(Conflict::ActiveVerify) }
		else { error.into() }
	})?;
	Ok(tx.last_insert_rowid())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryOutcome {
	Requeued { eligible_at: i64 },
	Failed,
}

/// Retry infrastructure failure without resurrecting inactive campaign work.
pub fn retry_or_fail(
	tx: &Transaction<'_>, job_id: i64, now: i64, error: &BoundedText<Reason>,
) -> Result<RetryOutcome> {
	let job = jobs::get(tx, job_id)?.ok_or(Error::NotFound(Entity::Job, job_id))?;
	if job.state != JobState::Leased
		|| !matches!(job.kind, JobKind::Survey | JobKind::Drilldown | JobKind::Verify)
	{
		return Err(Error::Conflict(Conflict::JobState));
	}
	let campaign_id = job.campaign_id.ok_or(Error::Conflict(Conflict::CampaignState))?;
	let campaign =
		campaigns::get(tx, campaign_id)?.ok_or(Error::NotFound(Entity::Campaign, campaign_id))?;
	let inactive_reason;
	let failure = if campaign.state != campaigns::State::Active {
		inactive_reason = format!("campaign {}", campaign.state.as_str());
		Some(inactive_reason.as_str())
	} else {
		let policy = CampaignPolicy::from_snapshot(&campaign.effective_policy)?;
		if job.attempts >= policy.max_attempts {
			Some(error.expose())
		} else {
			let eligible_at = now
				.checked_add(policy.retry_delay(job.attempts))
				.ok_or_else(|| invalid("eligible_at"))?;
			changed(tx.execute("UPDATE jobs SET state='queued',worker_id=NULL,lease_expires_at=NULL,job_capability_hash=NULL,eligible_at=?2,hard_deadline_at=NULL,soft_deadline_at=NULL,submit_by=NULL WHERE id=?1 AND state='leased'", params![job_id,eligible_at])?, Conflict::JobState)?;
			return Ok(RetryOutcome::Requeued { eligible_at });
		}
	};
	changed(tx.execute("UPDATE jobs SET state='failed',error=?2,finished_at=?3,worker_id=NULL,lease_expires_at=NULL,job_capability_hash=NULL WHERE id=?1 AND state='leased'", params![job_id,failure,now])?, Conflict::JobState)?;
	Ok(RetryOutcome::Failed)
}

pub fn cancel_queued_children(
	tx: &Transaction<'_>, campaign_id: i64, now: i64, reason: &BoundedText<Reason>,
) -> Result<usize> {
	Ok(tx.execute("UPDATE jobs SET state='cancelled',error=?2,finished_at=?3,job_capability_hash=NULL WHERE campaign_id=?1 AND state='queued'", params![campaign_id,reason.expose(),now])?)
}
#[cfg(test)]
mod tests;
pub use crate::review_units::Priority as Band;

/// Campaign job kinds this binary can lease *and finish through the phase
/// endpoints*. Empty until B4 lands those endpoints; widen it together with
/// `jobs::RUNTIME_KINDS` and the handlers, never ahead of them.
pub const PHASE_RUNTIME_KINDS: &[JobKind] = &[];

pub const PRIORITY_MAX: u32 = 1000;

/// Live deployment knobs; never substituted for campaign-owned budgets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimPolicy {
	pub active_jobs_per_repo: i64,
	pub active_jobs_total: Option<i64>,
	pub active_surveys_per_repo: i64,
	pub active_drilldowns_per_repo: i64,
	pub active_verifications_per_repo: i64,
	pub verify_reserved_slots: i64,
	pub lease_seconds: i64,
	pub lease_report_grace_seconds: i64,
	pub urgency_burst_length: i64,
	pub priority_aging_interval_seconds: i64,
	pub priority_aging_cap: i64,
}
impl Default for ClaimPolicy {
	fn default() -> Self {
		Self {
			active_jobs_per_repo: 3,
			active_jobs_total: None,
			active_surveys_per_repo: 1,
			active_drilldowns_per_repo: 2,
			active_verifications_per_repo: 2,
			verify_reserved_slots: 1,
			lease_seconds: 600,
			lease_report_grace_seconds: 60,
			urgency_burst_length: 4,
			priority_aging_interval_seconds: 3600,
			priority_aging_cap: 8,
		}
	}
}
