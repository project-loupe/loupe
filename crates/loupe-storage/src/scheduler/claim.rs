//! One transactional claim for legacy and campaign queues.
use loupe_core::JobKind;
use rusqlite::{named_params, params, OptionalExtension, Transaction};

use super::{invalid, CampaignPolicy, ClaimPolicy, PHASE_RUNTIME_KINDS};
use crate::jobs::{self, JobRow, JOB_COLUMNS, RUNTIME_KINDS};
use crate::{campaigns, review_units, Entity, Error, Result};

pub struct ClaimRequest<'a> {
	pub worker_id: i64,
	pub kinds: &'a [JobKind],
	pub now: i64,
	pub capability_hash: &'a [u8],
	pub legacy_lease_seconds: i64,
	pub policy: &'a ClaimPolicy,
}

#[derive(Debug)]
pub struct Claimed {
	pub job: JobRow,
	pub assigned_units: Vec<i64>,
	pub resumed: bool,
}

pub(super) const BAND_RANK: &str = "CASE WHEN j.campaign_id IS NULL THEN 2 ELSE CASE j.scheduling_band WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END END";
pub(super) const SCORE: &str = "CASE WHEN j.campaign_id IS NULL THEN CASE j.kind WHEN 'verify' THEN 1 ELSE 0 END ELSE COALESCE(j.effective_priority,0) + MIN(MAX(:now-j.enqueued_at,0)/:aging_interval,:aging_cap) END";

/// Runtime gating is mandatory, even when callers request unsupported kinds.
/// Legacy rows follow `RUNTIME_KINDS`; campaign rows additionally need a
/// phase handler for their kind (`PHASE_RUNTIME_KINDS`), because `verify`
/// is a runtime kind for the legacy pipeline long before the phase
/// endpoints exist.
pub fn claim(tx: &Transaction<'_>, req: &ClaimRequest<'_>) -> Result<Option<Claimed>> {
	let kinds: Vec<_> =
		req.kinds.iter().filter(|kind| RUNTIME_KINDS.contains(kind)).cloned().collect();
	let campaign_kinds: Vec<_> =
		kinds.iter().filter(|kind| PHASE_RUNTIME_KINDS.contains(kind)).cloned().collect();
	claim_filtered(tx, req, &kinds, &campaign_kinds)
}

/// Kept inside this module's parent so phase logic can be tested before B4.
/// Campaign rows are offered for every requested kind.
#[cfg(test)]
pub(super) fn claim_kinds(
	tx: &Transaction<'_>, req: &ClaimRequest<'_>, kinds: &[JobKind],
) -> Result<Option<Claimed>> {
	claim_filtered(tx, req, kinds, kinds)
}

fn sql_kind_list(kinds: &[JobKind]) -> Vec<String> {
	kinds
		.iter()
		.filter(|kind| {
			matches!(kind, JobKind::Scan | JobKind::Survey | JobKind::Drilldown | JobKind::Verify)
		})
		.map(|kind| format!("'{}'", kind.as_str()))
		.collect()
}

fn claim_filtered(
	tx: &Transaction<'_>, req: &ClaimRequest<'_>, kinds: &[JobKind], campaign_kinds: &[JobKind],
) -> Result<Option<Claimed>> {
	let kinds = sql_kind_list(kinds);
	if kinds.is_empty() {
		return Ok(None);
	}
	let campaign_kinds = sql_kind_list(campaign_kinds);
	let campaign_kind_clause = if campaign_kinds.is_empty() {
		"0".to_owned()
	} else {
		format!("j.kind IN ({})", campaign_kinds.join(","))
	};
	if req.policy.priority_aging_interval_seconds < 1
		|| req.policy.priority_aging_cap < 0
		|| req.policy.lease_seconds < 1
		|| req.policy.lease_report_grace_seconds < 1
	{
		return Err(invalid("claim_policy"));
	}
	let lease =
		req.now.checked_add(req.legacy_lease_seconds).ok_or_else(|| invalid("lease_expires_at"))?;
	let sql = format!("UPDATE jobs SET state='leased',worker_id=:worker,lease_expires_at=:lease,attempts=attempts+1,started_at=COALESCE(started_at,:now),job_capability_hash=:hash
		WHERE id=(SELECT j.id FROM jobs j
		WHERE j.state='queued' AND j.kind IN ({kinds}) AND (
		 j.campaign_id IS NULL OR ({campaign_kind_clause} AND (j.eligible_at IS NULL OR j.eligible_at<=:now)
		 AND EXISTS(SELECT 1 FROM review_campaigns c WHERE c.campaign_id=j.campaign_id AND c.state='active' AND (c.deadline_at IS NULL OR c.deadline_at>:now))))
		ORDER BY {BAND_RANK}, {SCORE} DESC, j.enqueued_at, j.id LIMIT 1)
		RETURNING {JOB_COLUMNS}", kinds=kinds.join(","));
	let selected = tx.query_row(&sql, named_params!{
		":worker":req.worker_id, ":lease":lease, ":now":req.now, ":hash":req.capability_hash,
		":aging_interval":req.policy.priority_aging_interval_seconds, ":aging_cap":req.policy.priority_aging_cap,
	}, jobs::row_to_job).optional()?;
	let Some(mut job) = selected else {
		return Ok(None);
	};
	let mut assigned_units = Vec::new();
	let mut resumed = false;
	if let Some(campaign_id) = job.campaign_id {
		let campaign = campaigns::get(tx, campaign_id)?
			.ok_or(Error::NotFound(Entity::Campaign, campaign_id))?;
		let policy = CampaignPolicy::from_snapshot(&campaign.effective_policy)?;
		let phase = policy.phase(&job.kind)?;
		let hard = req
			.now
			.checked_add(phase.deadline_seconds)
			.ok_or_else(|| invalid("hard_deadline_at"))?;
		let submit =
			hard.checked_sub(phase.submit_margin_seconds).ok_or_else(|| invalid("submit_by"))?;
		let bound = hard
			.checked_add(req.policy.lease_report_grace_seconds)
			.ok_or_else(|| invalid("lease_report_grace_seconds"))?;
		let lease = req
			.now
			.checked_add(req.policy.lease_seconds)
			.ok_or_else(|| invalid("lease_expires_at"))?
			.min(bound);
		tx.execute("UPDATE jobs SET hard_deadline_at=?2,submit_by=?3,soft_deadline_at=?3,lease_expires_at=?4 WHERE id=?1",params![job.id,hard,submit,lease])?;
		if job.kind == JobKind::Survey
			&& let Some(generation) = job.generation_id
		{
			let batch_exists: bool = tx.query_row(
				"SELECT EXISTS(SELECT 1 FROM job_assigned_review_units WHERE job_id=?1)",
				[job.id],
				|r| r.get(0),
			)?;
			if batch_exists {
				resumed = true;
			} else if !is_bootstrap(&job) {
				let units = tx.prepare(&format!("SELECT u.review_unit_id,u.assignment_epoch FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.generation_id=?1 AND {} ORDER BY CASE u.priority_band WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END,u.created_at,u.review_unit_id LIMIT ?2",*review_units::UNIT_NEEDS_WORK))?
						.query_map(params![generation,policy.survey_units_per_job],|r|Ok(review_units::Assignment{unit_id:r.get(0)?,expected_epoch:r.get(1)?}))?.collect::<rusqlite::Result<Vec<_>>>()?;
				review_units::assign(tx, job.id, &units)?;
			}
			assigned_units = tx.prepare("SELECT review_unit_id FROM job_assigned_review_units WHERE job_id=?1 AND completed=0 ORDER BY position")?.query_map([job.id],|r|r.get(0))?.collect::<rusqlite::Result<_>>()?;
		}
		job = jobs::get(tx, job.id)?.ok_or(Error::NotFound(Entity::Job, job.id))?;
	}
	Ok(Some(Claimed { job, assigned_units, resumed }))
}

fn is_bootstrap(job: &JobRow) -> bool {
	job.recipe
		.as_ref()
		.and_then(|recipe| serde_json::from_str::<serde_json::Value>(recipe.expose()).ok())
		.is_some_and(|value| value["recipe"] == "bootstrap")
}
