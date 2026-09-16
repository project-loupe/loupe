//! Review scopes and optimistic assignment claims.
use loupe_core::text::policy::{Argument, ClientKey, Objective, Payload, Reason, Title};
use loupe_core::text::{BoundedJson, BoundedText, Identifier};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::review::{changed, classify, optional, parsed, standalone, string_enum};
use crate::source_refs::UnitRefs;
use crate::{inventory, ownership, Conflict, Entity, Error, Ownership, Result};
string_enum!(Status { Open=>"open", Deferred=>"deferred", Retired=>"retired" });
string_enum!(Priority { Urgent=>"urgent", High=>"high", Normal=>"normal", Background=>"background" });
pub struct NewUnit<'a> {
	pub generation_id: i64,
	pub client_key: &'a Identifier<ClientKey>,
	pub title: &'a BoundedText<Title>,
	pub objective: &'a BoundedText<Objective>,
	pub priority: Priority,
	pub priority_proposal: Option<&'a BoundedJson<Payload>>,
	pub source_refs: &'a UnitRefs,
	pub depends_on: Option<&'a BoundedJson<Payload>>,
	pub closure_criteria: Option<&'a BoundedText<Argument>>,
	pub semantic_context: Option<&'a BoundedJson<Payload>>,
	pub carried_from: Option<i64>,
	pub created_by_job: Option<i64>,
}
#[derive(Debug, Clone)]
pub struct Unit {
	pub unit_id: i64,
	pub generation_id: i64,
	pub client_key: Identifier<ClientKey>,
	pub title: BoundedText<Title>,
	pub objective: BoundedText<Objective>,
	pub status: Status,
	pub defer_reason: Option<BoundedText<Reason>>,
	pub priority: Priority,
	pub priority_proposal: Option<BoundedJson<Payload>>,
	pub source_refs: UnitRefs,
	pub depends_on: Option<BoundedJson<Payload>>,
	pub closure_criteria: Option<BoundedText<Argument>>,
	pub semantic_context: Option<BoundedJson<Payload>>,
	pub carry_depth: i64,
	pub carried_from: Option<i64>,
	pub stale: bool,
	pub stale_reason: Option<BoundedText<Reason>>,
	pub assignment_epoch: i64,
	pub created_by_job: Option<i64>,
	pub created_at: i64,
}
#[derive(Debug, Clone, Copy)]
pub struct Assignment {
	pub unit_id: i64,
	pub expected_epoch: i64,
}
pub fn create(tx: &Transaction<'_>, new: &NewUnit<'_>, now: i64) -> Result<i64> {
	let repo = ownership::generation_repo(tx, new.generation_id)?;
	if let Some(job) = new.created_by_job {
		ownership::job_for_generation(tx, job, new.generation_id, Ownership::UnitJob)?;
	}
	let depth = if let Some(parent) = new.carried_from {
		ownership::unit_in_repo(tx, parent, repo, Ownership::CarriedUnit)?;
		let parent = get(tx, parent)?.ok_or(Error::NotFound(Entity::Unit, parent))?;
		if parent.generation_id == new.generation_id {
			return Err(Error::Ownership(Ownership::CarriedUnit));
		}
		parent.carry_depth.checked_add(1).ok_or(Error::Conflict(Conflict::UnitState))?
	} else {
		0
	};
	inventory::verify_refs(tx, new.generation_id, new.source_refs.as_slice())?;
	tx.execute("INSERT INTO review_units (generation_id,client_review_unit_key,title,objective,priority_band,priority_proposal,source_refs,depends_on,closure_criteria,semantic_context,carry_depth,carried_from_review_unit_id,created_by_job_id,created_at)
 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",params![new.generation_id,new.client_key.expose(),new.title.expose(),new.objective.expose(),new.priority.as_str(),new.priority_proposal.map(BoundedJson::expose),new.source_refs.expose(),new.depends_on.map(BoundedJson::expose),new.closure_criteria.map(BoundedText::expose),new.semantic_context.map(BoundedJson::expose),depth,new.carried_from,new.created_by_job,now])
 .map_err(|e|classify(e,"review_units.generation_id, review_units.client_review_unit_key",Conflict::UnitKey))?;
	Ok(tx.last_insert_rowid())
}
const COLUMNS:&str="review_unit_id,generation_id,client_review_unit_key,title,objective,status,defer_reason,priority_band,priority_proposal,source_refs,depends_on,closure_criteria,semantic_context,carry_depth,carried_from_review_unit_id,stale,stale_reason,assignment_epoch,created_by_job_id,created_at";
fn row(r: &Row<'_>) -> rusqlite::Result<Unit> {
	Ok(Unit {
		unit_id: r.get(0)?,
		generation_id: r.get(1)?,
		client_key: parsed(r, 2)?,
		title: parsed(r, 3)?,
		objective: parsed(r, 4)?,
		status: parsed(r, 5)?,
		defer_reason: optional(r, 6)?,
		priority: parsed(r, 7)?,
		priority_proposal: optional(r, 8)?,
		source_refs: parsed(r, 9)?,
		depends_on: optional(r, 10)?,
		closure_criteria: optional(r, 11)?,
		semantic_context: optional(r, 12)?,
		carry_depth: r.get(13)?,
		carried_from: r.get(14)?,
		stale: r.get(15)?,
		stale_reason: optional(r, 16)?,
		assignment_epoch: r.get(17)?,
		created_by_job: r.get(18)?,
		created_at: r.get(19)?,
	})
}
pub fn get(conn: &Connection, id: i64) -> Result<Option<Unit>> {
	Ok(conn
		.query_row(
			&format!("SELECT {COLUMNS} FROM review_units WHERE review_unit_id=?1"),
			[id],
			row,
		)
		.optional()?)
}
pub fn list(conn: &Connection, generation: i64) -> Result<Vec<Unit>> {
	Ok(conn
		.prepare(&format!(
			"SELECT {COLUMNS} FROM review_units WHERE generation_id=?1 ORDER BY review_unit_id"
		))?
		.query_map([generation], row)?
		.collect::<rusqlite::Result<_>>()?)
}
pub fn defer(tx: &Transaction<'_>, id: i64, reason: &BoundedText<Reason>) -> Result<()> {
	changed(tx.execute("UPDATE review_units SET status='deferred',defer_reason=?2 WHERE review_unit_id=?1 AND status='open'",params![id,reason.expose()])?,Conflict::UnitState)
}
pub fn reopen(tx: &Transaction<'_>, id: i64) -> Result<()> {
	changed(tx.execute("UPDATE review_units SET status='open',defer_reason=NULL WHERE review_unit_id=?1 AND status='deferred'",[id])?,Conflict::UnitState)
}
pub fn retire(tx: &Transaction<'_>, id: i64) -> Result<()> {
	changed(tx.execute("UPDATE review_units SET status='retired' WHERE review_unit_id=?1 AND status IN ('open','deferred')",[id])?,Conflict::UnitState)
}
pub fn mark_stale(tx: &Transaction<'_>, id: i64, reason: &BoundedText<Reason>) -> Result<()> {
	changed(tx.execute("UPDATE review_units SET stale=1,stale_reason=?2 WHERE review_unit_id=?1 AND status<>'retired'",params![id,reason.expose()])?,Conflict::UnitState)
}
/// Propagate any error to roll back the entire batch, including earlier claims.
pub fn assign(tx: &Transaction<'_>, job: i64, units: &[Assignment]) -> Result<()> {
	if units.len() > 32 {
		return Err(Error::Conflict(Conflict::Assignment));
	}
	let generation: Option<i64> = tx
		.query_row(
			"SELECT generation_id FROM jobs WHERE id=?1 AND state IN ('queued','leased')",
			[job],
			|r| r.get(0),
		)
		.optional()?
		.flatten();
	let generation = generation.ok_or(Error::Conflict(Conflict::Assignment))?;
	let mut seen = std::collections::HashSet::new();
	for claim in units {
		if !seen.insert(claim.unit_id) {
			return Err(Error::Conflict(Conflict::Assignment));
		}
		ownership::unit_in_generation(tx, claim.unit_id, generation, Ownership::Assignment)?;
		changed(tx.execute("UPDATE review_units SET assignment_epoch=assignment_epoch+1 WHERE review_unit_id=?1 AND status='open' AND assignment_epoch=?2 AND assignment_epoch<9223372036854775807 AND NOT EXISTS(SELECT 1 FROM job_assigned_review_units a JOIN jobs j ON j.id=a.job_id WHERE a.review_unit_id=?1 AND j.state IN ('queued','leased'))",params![claim.unit_id,claim.expected_epoch])?,Conflict::Assignment)?;
	}
	// A later batch extends the job's ordered set rather than restarting at 0.
	let start: i64 = tx.query_row(
		"SELECT COALESCE(MAX(position)+1,0) FROM job_assigned_review_units WHERE job_id=?1",
		[job],
		|r| r.get(0),
	)?;
	for (offset, claim) in units.iter().enumerate() {
		tx.execute("INSERT INTO job_assigned_review_units (job_id,review_unit_id,position) VALUES (?1,?2,?3)",params![job,claim.unit_id,start + offset as i64])?;
	}
	Ok(())
}
/// Callers explicitly supply remapped dependencies; old generation IDs are
/// never copied implicitly. The reconciliation layer rebuilds that graph.
pub fn carry_forward(
	tx: &Transaction<'_>, id: i64, generation: i64, job: Option<i64>,
	dependencies: Option<&BoundedJson<Payload>>, now: i64,
) -> Result<i64> {
	let source = get(tx, id)?.ok_or(Error::NotFound(Entity::Unit, id))?;
	create(
		tx,
		&NewUnit {
			generation_id: generation,
			client_key: &source.client_key,
			title: &source.title,
			objective: &source.objective,
			priority: source.priority,
			priority_proposal: source.priority_proposal.as_ref(),
			source_refs: &source.source_refs,
			depends_on: dependencies,
			closure_criteria: source.closure_criteria.as_ref(),
			semantic_context: source.semantic_context.as_ref(),
			carried_from: Some(id),
			created_by_job: job,
		},
		now,
	)
}
standalone! {
 create(new:&NewUnit<'_>,now:i64)->i64;
 defer(id:i64,reason:&BoundedText<Reason>)->();
 reopen(id:i64)->(); retire(id:i64)->();
 mark_stale(id:i64,reason:&BoundedText<Reason>)->();
 assign(job:i64,units:&[Assignment])->();
 carry_forward(id:i64,generation:i64,job:Option<i64>,dependencies:Option<&BoundedJson<Payload>>,now:i64)->i64;
}
