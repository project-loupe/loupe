//! Scope checks run inside the same transaction as the domain mutation.
use rusqlite::{Connection, OptionalExtension, Row};

use crate::scope::{Scope, Subject, SubjectKind};
use crate::{Error, Ownership, Result};

pub(crate) fn generation_scope(
	tx: &Connection, generation: i64, relation: Ownership,
) -> Result<Scope> {
	let repo = tx
		.query_row(
			"SELECT repo_id FROM review_generations WHERE generation_id=?1",
			[generation],
			|r| r.get(0),
		)
		.optional()?
		.ok_or(Error::Ownership(relation))?;
	Ok(Scope { generation: Some(generation), ..Scope::repository(repo) })
}

pub(crate) fn require(
	tx: &Connection, sql: &str, parameters: impl rusqlite::Params, scope: Scope,
	relation: Ownership, load: impl FnOnce(&Row<'_>) -> rusqlite::Result<Subject>,
) -> Result<()> {
	let subject = tx.query_row(sql, parameters, load).optional()?;
	scope.check(subject.as_ref(), relation).map_err(Error::Ownership)
}

pub(crate) fn repository_row(row: &Row<'_>) -> rusqlite::Result<Subject> {
	Ok(Subject::repository(row.get(0)?))
}

pub(crate) fn generation_row(row: &Row<'_>) -> rusqlite::Result<Subject> {
	Ok(Subject { generation: Some(row.get(1)?), ..Subject::repository(row.get(0)?) })
}

pub(crate) fn generation(
	tx: &Connection, repo: i64, generation: i64, relation: Ownership,
) -> Result<()> {
	require(
		tx,
		"SELECT repo_id FROM review_generations WHERE generation_id=?1",
		[generation],
		Scope::repository(repo),
		relation,
		repository_row,
	)
}
pub(crate) fn campaign(
	tx: &Connection, repo: i64, campaign: i64, relation: Ownership,
) -> Result<()> {
	require(
		tx,
		"SELECT repo_id FROM review_campaigns WHERE campaign_id=?1",
		[campaign],
		Scope::repository(repo),
		relation,
		repository_row,
	)
}

/// An explicit job generation cannot be overridden by a campaign fallback.
/// Campaign-only, host-authored work may create rows in that repo's generation.
pub(crate) fn job_for_generation(
	tx: &Connection, job: i64, generation: i64, relation: Ownership,
) -> Result<()> {
	let scope = generation_scope(tx, generation, relation)?;
	require(tx, "SELECT j.repo_id,j.generation_id,j.campaign_id,c.repo_id FROM jobs j LEFT JOIN review_campaigns c ON c.campaign_id=j.campaign_id WHERE j.id=?1", [job], scope, relation, |r| Ok(Subject {
		repo: r.get(0)?, generation: r.get(1)?, campaign: r.get(2)?, kind: SubjectKind::Job { campaign_repo: r.get(3)? },
	}))
}
pub(crate) fn unit_in_generation(
	tx: &Connection, unit: i64, generation: i64, relation: Ownership,
) -> Result<()> {
	let scope = generation_scope(tx, generation, relation)?;
	require(tx, "SELECT g.repo_id,u.generation_id FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.review_unit_id=?1", [unit], scope, relation, generation_row)
}
pub(crate) fn unit_in_repo(
	tx: &Connection, unit: i64, repo: i64, relation: Ownership,
) -> Result<()> {
	require(tx, "SELECT g.repo_id FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.review_unit_id=?1", [unit], Scope::repository(repo), relation, repository_row)
}
pub(crate) fn lead_in_generation(
	tx: &Connection, lead: i64, generation: i64, relation: Ownership,
) -> Result<()> {
	let scope = generation_scope(tx, generation, relation)?;
	require(tx, "SELECT g.repo_id,l.generation_id FROM leads l JOIN review_generations g ON g.generation_id=l.generation_id WHERE l.lead_id=?1", [lead], scope, relation, generation_row)
}
pub(crate) fn lead_in_repo(
	tx: &Connection, lead: i64, repo: i64, relation: Ownership,
) -> Result<()> {
	require(tx, "SELECT g.repo_id FROM leads l JOIN review_generations g ON g.generation_id=l.generation_id WHERE l.lead_id=?1", [lead], Scope::repository(repo), relation, repository_row)
}
pub(crate) fn finding(tx: &Connection, finding: i64, repo: i64, relation: Ownership) -> Result<()> {
	require(
		tx,
		"SELECT repo_id FROM findings WHERE id=?1",
		[finding],
		Scope::repository(repo),
		relation,
		repository_row,
	)
}
/// Scheduler-side checks for the nullable, single-column job foreign keys.
pub(crate) fn job_links(
	tx: &Connection, repo: i64, generation_id: Option<i64>, lead_id: Option<i64>,
) -> Result<()> {
	if let Some(id) = generation_id {
		generation(tx, repo, id, Ownership::JobGeneration)?;
	}
	if let Some(id) = lead_id {
		lead_in_repo(tx, id, repo, Ownership::JobLead)?;
	}
	Ok(())
}
