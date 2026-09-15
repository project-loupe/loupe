//! Canonical campaign lifecycle and generation-independent terminal snapshots.
use loupe_core::text::policy::{Payload, Reason};
use loupe_core::text::{BoundedJson, BoundedText};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::review::{changed, classify, optional, parsed, standalone, string_enum};
use crate::{ownership, Conflict, Entity, Error, Ownership, Result};

string_enum!(Recipe { Bootstrap => "bootstrap", Incremental => "incremental", Reconciliation => "reconciliation", Corroboration => "corroboration" });
string_enum!(Trigger { Manual => "manual", Scheduled => "scheduled", CompatScanApi => "compat_scan_api", Reconciliation => "reconciliation", Operator => "operator" });
string_enum!(State { Active => "active", Finished => "finished", Cancelled => "cancelled" });

pub struct NewCampaign<'a> {
	pub repo_id: i64,
	pub recipe: Recipe,
	pub trigger: Trigger,
	pub requested_base_sha: Option<&'a str>,
	pub target_commit_sha: &'a str,
	pub generation_id: Option<i64>,
	pub effective_policy: &'a BoundedJson<Payload>,
	pub deadline_at: Option<i64>,
	pub root_campaign_id: Option<i64>,
	pub continuation_of_campaign_id: Option<i64>,
}
#[derive(Debug, Clone)]
pub struct Campaign {
	pub campaign_id: i64,
	pub repo_id: i64,
	pub recipe: Recipe,
	pub trigger: Trigger,
	pub requested_base_sha: Option<String>,
	pub target_commit_sha: String,
	pub generation_id: Option<i64>,
	pub state: State,
	pub terminal_reason: Option<BoundedText<Reason>>,
	pub effective_policy: BoundedJson<Payload>,
	pub deadline_at: Option<i64>,
	pub root_campaign_id: Option<i64>,
	pub continuation_of_campaign_id: Option<i64>,
	pub coverage_at_finish: Option<crate::generations::Coverage>,
	pub terminal_counts: Option<BoundedJson<Payload>>,
	pub created_at: i64,
	pub finished_at: Option<i64>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalSummary {
	campaign_id: i64,
	pub coverage: crate::generations::Coverage,
	pub counts: BoundedJson<Payload>,
}

const COLUMNS: &str = "campaign_id,repo_id,recipe,trigger,requested_base_sha,target_commit_sha,generation_id,state,terminal_reason,effective_policy,deadline_at,root_campaign_id,continuation_of_campaign_id,coverage_at_finish,terminal_counts,created_at,finished_at";
fn row(r: &Row<'_>) -> rusqlite::Result<Campaign> {
	Ok(Campaign {
		campaign_id: r.get(0)?,
		repo_id: r.get(1)?,
		recipe: parsed(r, 2)?,
		trigger: parsed(r, 3)?,
		requested_base_sha: r.get(4)?,
		target_commit_sha: r.get(5)?,
		generation_id: r.get(6)?,
		state: parsed(r, 7)?,
		terminal_reason: optional(r, 8)?,
		effective_policy: parsed(r, 9)?,
		deadline_at: r.get(10)?,
		root_campaign_id: r.get(11)?,
		continuation_of_campaign_id: r.get(12)?,
		coverage_at_finish: optional(r, 13)?,
		terminal_counts: optional(r, 14)?,
		created_at: r.get(15)?,
		finished_at: r.get(16)?,
	})
}
pub fn create(tx: &Transaction<'_>, new: &NewCampaign<'_>, now: i64) -> Result<i64> {
	if let Some(id) = new.generation_id {
		ownership::generation(tx, new.repo_id, id, Ownership::CampaignGeneration)?;
	}
	if let Some(id) = new.root_campaign_id {
		ownership::campaign(tx, new.repo_id, id, Ownership::CampaignRoot)?;
	}
	if let Some(id) = new.continuation_of_campaign_id {
		ownership::campaign(tx, new.repo_id, id, Ownership::CampaignContinuation)?;
	}
	tx.execute("INSERT INTO review_campaigns (repo_id,recipe,trigger,requested_base_sha,target_commit_sha,generation_id,state,effective_policy,effective_policy_digest,deadline_at,root_campaign_id,continuation_of_campaign_id,created_at)
	VALUES (?1,?2,?3,?4,?5,?6,'active',?7,?8,?9,?10,?11,?12)", params![new.repo_id,new.recipe.as_str(),new.trigger.as_str(),new.requested_base_sha,new.target_commit_sha,new.generation_id,new.effective_policy.expose(),new.effective_policy.digest().as_slice(),new.deadline_at,new.root_campaign_id,new.continuation_of_campaign_id,now])
		.map_err(|e| classify(e,"review_campaigns.repo_id",Conflict::ActiveCampaign))?;
	Ok(tx.last_insert_rowid())
}
pub fn get(conn: &Connection, id: i64) -> Result<Option<Campaign>> {
	Ok(conn
		.query_row(
			&format!("SELECT {COLUMNS} FROM review_campaigns WHERE campaign_id=?1"),
			[id],
			row,
		)
		.optional()?)
}
pub fn list_for_repo(conn: &Connection, repo: i64) -> Result<Vec<Campaign>> {
	Ok(conn.prepare(&format!("SELECT {COLUMNS} FROM review_campaigns WHERE repo_id=?1 ORDER BY created_at DESC,campaign_id DESC"))?.query_map([repo],row)?.collect::<rusqlite::Result<_>>()?)
}
fn counts(tx: &Transaction<'_>, sql: &str, id: Option<i64>) -> Result<serde_json::Value> {
	let mut object = serde_json::Map::new();
	let mut statement = tx.prepare(sql)?;
	for pair in statement.query_map([id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
		let (key, count) = pair?;
		object.insert(key, count.into());
	}
	Ok(object.into())
}
pub fn summarize(tx: &Transaction<'_>, id: i64) -> Result<TerminalSummary> {
	let campaign = get(tx, id)?.ok_or(Error::NotFound(Entity::Campaign, id))?;
	let coverage = if let Some(generation) = campaign.generation_id {
		ownership::generation(tx, campaign.repo_id, generation, Ownership::CampaignGeneration)?;
		crate::generations::get(tx, generation)?
			.ok_or(Error::NotFound(Entity::Generation, generation))?
			.coverage
	} else {
		crate::generations::Coverage::Unknown
	};
	// Job kinds are unconstrained text (future kinds stay readable after a
	// rollback) and would not pass the JSON object-key policy, so they are
	// values in an array, never keys. The other grouping columns are
	// CHECK-constrained snake_case and remain object keys.
	let mut jobs = Vec::new();
	let mut statement = tx.prepare(
		"SELECT kind,state,COUNT(*) FROM jobs WHERE campaign_id=?1
		 GROUP BY kind,state ORDER BY kind,state",
	)?;
	for record in statement.query_map([id], |r| {
		Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
	})? {
		let (kind, state, count) = record?;
		jobs.push(serde_json::json!({ "kind": kind, "state": state, "count": count }));
	}
	let generation = campaign.generation_id;
	let value = serde_json::json!({ "jobs": jobs, "leads": {
		"status": counts(tx,"SELECT status,COUNT(*) FROM leads WHERE generation_id=?1 GROUP BY status",generation)?,
		"disposition": counts(tx,"SELECT disposition,COUNT(*) FROM leads WHERE generation_id=?1 AND disposition IS NOT NULL GROUP BY disposition",generation)?
	}, "findings": counts(tx,"SELECT f.state,COUNT(*) FROM findings f JOIN finding_review_details d ON d.finding_id=f.id JOIN leads l ON l.lead_id=d.origin_lead_id WHERE l.generation_id=?1 GROUP BY f.state",generation)?,
	"verdicts": counts(tx,"SELECT v.verdict,COUNT(*) FROM finding_verifications v JOIN finding_review_details d ON d.finding_id=v.finding_id JOIN leads l ON l.lead_id=d.origin_lead_id WHERE l.generation_id=?1 GROUP BY v.verdict",generation)? });
	Ok(TerminalSummary { campaign_id: id, coverage, counts: BoundedJson::new(&value.to_string())? })
}
pub fn finish(
	tx: &Transaction<'_>, id: i64, summary: &TerminalSummary, reason: &BoundedText<Reason>,
	now: i64,
) -> Result<()> {
	if summary.campaign_id != id {
		return Err(Error::Ownership(Ownership::CampaignSummary));
	}
	if summarize(tx, id)? != *summary {
		return Err(Error::Conflict(Conflict::CampaignSummary));
	}
	changed(tx.execute("UPDATE review_campaigns SET state='finished',terminal_reason=?2,coverage_at_finish=?3,terminal_counts=?4,finished_at=?5 WHERE campaign_id=?1 AND state='active'",params![id,reason.expose(),summary.coverage.as_str(),summary.counts.expose(),now])?,Conflict::CampaignState)
}
pub fn cancel(tx: &Transaction<'_>, id: i64, reason: &BoundedText<Reason>, now: i64) -> Result<()> {
	let summary = summarize(tx, id)?;
	changed(tx.execute("UPDATE review_campaigns SET state='cancelled',terminal_reason=?2,coverage_at_finish=?3,terminal_counts=?4,finished_at=?5 WHERE campaign_id=?1 AND state='active'",params![id,reason.expose(),summary.coverage.as_str(),summary.counts.expose(),now])?,Conflict::CampaignState)
}
standalone! {
	create(new: &NewCampaign<'_>, now: i64) -> i64;
	finish(id: i64, summary: &TerminalSummary, reason: &BoundedText<Reason>, now: i64) -> ();
	cancel(id: i64, reason: &BoundedText<Reason>, now: i64) -> ();
}
