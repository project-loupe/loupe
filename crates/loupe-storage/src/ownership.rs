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
