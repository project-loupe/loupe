//! Scope checks run inside the same transaction as the domain mutation.
use rusqlite::{params, OptionalExtension, Transaction};

use crate::{Entity, Error, Ownership, Result};

pub fn generation_repo(tx: &Transaction<'_>, generation: i64) -> Result<i64> {
	tx.query_row(
		"SELECT repo_id FROM review_generations WHERE generation_id = ?1",
		[generation],
		|r| r.get(0),
	)
	.optional()?
	.ok_or(Error::NotFound(Entity::Generation, generation))
}
pub(crate) fn require(
	tx: &Transaction<'_>, sql: &str, parameters: impl rusqlite::Params, relation: Ownership,
) -> Result<()> {
	if tx.query_row(sql, parameters, |r| r.get::<_, bool>(0))? {
		Ok(())
	} else {
		Err(Error::Ownership(relation))
	}
}
pub fn generation(
	tx: &Transaction<'_>, repo: i64, generation: i64, relation: Ownership,
) -> Result<()> {
	require(
		tx,
		"SELECT EXISTS(SELECT 1 FROM review_generations WHERE generation_id = ?1 AND repo_id = ?2)",
		params![generation, repo],
		relation,
	)
}
pub fn campaign(tx: &Transaction<'_>, repo: i64, campaign: i64, relation: Ownership) -> Result<()> {
	require(
		tx,
		"SELECT EXISTS(SELECT 1 FROM review_campaigns WHERE campaign_id = ?1 AND repo_id = ?2)",
		params![campaign, repo],
		relation,
	)
}

/// An explicit job generation cannot be overridden by a campaign fallback.
/// Campaign-only, host-authored work may create rows in that repo's generation.
pub fn job_for_generation(
	tx: &Transaction<'_>, job: i64, generation: i64, relation: Ownership,
) -> Result<()> {
	require(tx,"SELECT EXISTS(SELECT 1 FROM jobs j JOIN review_generations g ON g.generation_id=?2 WHERE j.id=?1 AND j.repo_id=g.repo_id AND (j.generation_id=g.generation_id OR (j.generation_id IS NULL AND EXISTS(SELECT 1 FROM review_campaigns c WHERE c.campaign_id=j.campaign_id AND c.repo_id=g.repo_id))))",params![job,generation],relation)
}
pub fn unit_in_generation(
	tx: &Transaction<'_>, unit: i64, generation: i64, relation: Ownership,
) -> Result<()> {
	require(
		tx,
		"SELECT EXISTS(SELECT 1 FROM review_units WHERE review_unit_id=?1 AND generation_id=?2)",
		params![unit, generation],
		relation,
	)
}
pub fn unit_in_repo(tx: &Transaction<'_>, unit: i64, repo: i64, relation: Ownership) -> Result<()> {
	require(tx,"SELECT EXISTS(SELECT 1 FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.review_unit_id=?1 AND g.repo_id=?2)",params![unit,repo],relation)
}
pub fn lead_in_generation(
	tx: &Transaction<'_>, lead: i64, generation: i64, relation: Ownership,
) -> Result<()> {
	require(
		tx,
		"SELECT EXISTS(SELECT 1 FROM leads WHERE lead_id=?1 AND generation_id=?2)",
		params![lead, generation],
		relation,
	)
}
pub fn lead_in_repo(tx: &Transaction<'_>, lead: i64, repo: i64, relation: Ownership) -> Result<()> {
	require(tx,"SELECT EXISTS(SELECT 1 FROM leads l JOIN review_generations g ON g.generation_id=l.generation_id WHERE l.lead_id=?1 AND g.repo_id=?2)",params![lead,repo],relation)
}
pub fn finding(tx: &Transaction<'_>, finding: i64, repo: i64, relation: Ownership) -> Result<()> {
	require(
		tx,
		"SELECT EXISTS(SELECT 1 FROM findings WHERE id=?1 AND repo_id=?2)",
		params![finding, repo],
		relation,
	)
}
/// Scheduler-side checks for the nullable, single-column job foreign keys.
pub fn job_links(
	tx: &Transaction<'_>, repo: i64, generation_id: Option<i64>, lead_id: Option<i64>,
) -> Result<()> {
	if let Some(id) = generation_id {
		generation(tx, repo, id, Ownership::JobGeneration)?;
	}
	if let Some(id) = lead_id {
		lead_in_repo(tx, id, repo, Ownership::JobLead)?;
	}
	Ok(())
}
