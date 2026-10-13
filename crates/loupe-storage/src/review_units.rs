//! Review scopes and optimistic assignment claims.
use std::sync::LazyLock;

use loupe_core::text::policy::{Argument, ClientKey, Objective, Payload, Reason, Title};
use loupe_core::text::{BoundedJson, BoundedText, Identifier};
use loupe_provenance::{Agent, Db, Source};
use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::review::{changed, classify, parsed, string_enum};
use crate::source_refs::UnitRefs;
use crate::{inventory, ownership, Conflict, Entity, Error, Ownership, Result};

/// Current ordinary conclusive evidence. Assignment state is not coverage.
pub const UNIT_COVERED: &str = "EXISTS(SELECT 1 FROM review_unit_results r WHERE r.review_unit_id=u.review_unit_id AND r.invalidated=0 AND r.commit_sha=g.generation_commit_sha AND r.profile_version=g.profile_version AND r.disposition IN ('lead_created','no_lead_found','not_applicable') AND r.corroborates_review_unit_result_id IS NULL AND r.corroborates_inventory_exclusion_id IS NULL)";
/// Ordinary scheduling eligibility, composed from the same evidence predicate.
pub static UNIT_NEEDS_WORK: LazyLock<String> = LazyLock::new(|| {
	format!("u.status='open' AND u.stale=0 AND NOT EXISTS(SELECT 1 FROM job_assigned_review_units a JOIN jobs j ON j.id=a.job_id WHERE a.review_unit_id=u.review_unit_id AND j.state IN ('queued','leased')) AND NOT ({UNIT_COVERED})")
});
string_enum!(Status { Open=>"open", Deferred=>"deferred", Retired=>"retired" });
string_enum!(Priority { Urgent=>"urgent", High=>"high", Normal=>"normal", Background=>"background" });
pub struct NewUnit<'a, KeyS: Source> {
	pub generation_id: i64,
	pub client_key: &'a Identifier<ClientKey, KeyS>,
	pub title: &'a BoundedText<Title, Agent>,
	pub objective: &'a BoundedText<Objective, Agent>,
	pub priority: Priority,
	pub priority_proposal: Option<&'a BoundedJson<Payload, Agent>>,
	pub source_refs: &'a UnitRefs<Agent>,
	pub depends_on: Option<&'a BoundedJson<Payload, Agent>>,
	pub closure_criteria: Option<&'a BoundedText<Argument, Agent>>,
	pub semantic_context: Option<&'a BoundedJson<Payload, Agent>>,
	pub carried_from: Option<i64>,
	pub created_by_job: Option<i64>,
}
// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug, Clone)]
pub struct Unit {
	pub unit_id: i64,
	pub generation_id: i64,
	pub client_key: Identifier<ClientKey, Db>,
	pub title: BoundedText<Title, Agent>,
	pub objective: BoundedText<Objective, Agent>,
	pub status: Status,
	pub defer_reason: Option<BoundedText<Reason, Db>>,
	pub priority: Priority,
	pub priority_proposal: Option<BoundedJson<Payload, Agent>>,
	pub source_refs: UnitRefs<Agent>,
	pub depends_on: Option<BoundedJson<Payload, Agent>>,
	pub closure_criteria: Option<BoundedText<Argument, Agent>>,
	pub semantic_context: Option<BoundedJson<Payload, Agent>>,
	pub carry_depth: i64,
	pub carried_from: Option<i64>,
	pub stale: bool,
	pub stale_reason: Option<BoundedText<Reason, Db>>,
	pub assignment_epoch: i64,
	pub created_by_job: Option<i64>,
	pub created_at: i64,
}
// debug-ok: assignment metadata contains only the integer unit ID and epoch.
#[derive(Debug, Clone, Copy)]
pub struct Assignment {
	pub unit_id: i64,
	pub expected_epoch: i64,
}
pub fn create<KeyS: Source>(
	scope: &crate::scope::RepoScope<'_>, new: &NewUnit<'_, KeyS>, now: i64,
) -> Result<i64> {
	scope.require_operator()?;
	let tx = scope.conn;
	ownership::generation(tx, scope.repo_id, new.generation_id, Ownership::InventoryGeneration)?;
	let repo = scope.repo_id;
	if let Some(job) = new.created_by_job {
		ownership::job_for_generation(tx, job, new.generation_id, Ownership::UnitJob)?;
	}
	let depth = if let Some(parent) = new.carried_from {
		ownership::unit_in_repo(tx, parent, repo, Ownership::CarriedUnit)?;
		let parent = get(scope, parent)?.ok_or(Error::NotFound(Entity::Unit, parent))?;
		if parent.generation_id == new.generation_id {
			return Err(Error::Ownership(Ownership::CarriedUnit));
		}
		parent.carry_depth.checked_add(1).ok_or(Error::Conflict(Conflict::UnitState))?
	} else {
		0
	};
	inventory::verify_refs(scope, new.generation_id, new.source_refs.as_slice())?;
	tx.execute("INSERT INTO review_units (generation_id,client_review_unit_key,title,objective,priority_band,priority_proposal,source_refs,depends_on,closure_criteria,semantic_context,carry_depth,carried_from_review_unit_id,created_by_job_id,created_at)
 SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14 WHERE EXISTS(SELECT 1 FROM review_generations WHERE generation_id=?1 AND repo_id=?15)",params![new.generation_id,new.client_key.expose(),new.title.expose(),new.objective.expose(),new.priority.as_str(),new.priority_proposal.map(BoundedJson::expose),new.source_refs.expose(),new.depends_on.map(BoundedJson::expose),new.closure_criteria.map(BoundedText::expose),new.semantic_context.map(BoundedJson::expose),depth,new.carried_from,new.created_by_job,now,scope.repo_id])
 .map_err(|e|classify(e,"review_units.generation_id, review_units.client_review_unit_key",Conflict::UnitKey))?;
	Ok(tx.last_insert_rowid())
}
const COLUMNS:&str="review_unit_id,generation_id,client_review_unit_key,title,objective,status,defer_reason,priority_band,priority_proposal,source_refs,depends_on,closure_criteria,semantic_context,carry_depth,carried_from_review_unit_id,stale,stale_reason,assignment_epoch,created_by_job_id,created_at,source";
fn row(r: &Row<'_>) -> rusqlite::Result<Unit> {
	crate::ingress::require_agent_source(r, 20)?;
	Ok(Unit {
		unit_id: r.get(0)?,
		generation_id: r.get(1)?,
		client_key: crate::ingress::client_key(r, 2)?,
		title: crate::ingress::title(r, 3)?,
		objective: crate::ingress::objective(r, 4)?,
		status: parsed(r, 5)?,
		defer_reason: crate::ingress::optional_reason(r, 6)?,
		priority: parsed(r, 7)?,
		priority_proposal: crate::ingress::optional_agent_payload(r, 8)?,
		source_refs: crate::ingress::unit_refs(r, 9)?,
		depends_on: crate::ingress::optional_agent_payload(r, 10)?,
		closure_criteria: crate::ingress::optional_argument(r, 11)?,
		semantic_context: crate::ingress::optional_agent_payload(r, 12)?,
		carry_depth: r.get(13)?,
		carried_from: r.get(14)?,
		stale: r.get(15)?,
		stale_reason: crate::ingress::optional_reason(r, 16)?,
		assignment_epoch: r.get(17)?,
		created_by_job: r.get(18)?,
		created_at: r.get(19)?,
	})
}

pub(crate) fn validate_stored_rows(conn: &Connection) -> Result<()> {
	crate::migrations::admission::scan(conn, "review_units", COLUMNS, row)
}
pub fn get(scope: &crate::scope::RepoScope<'_>, id: i64) -> Result<Option<Unit>> {
	let tx = scope.conn;
	Ok(tx
		.query_row(
			&format!("SELECT {COLUMNS} FROM review_units WHERE review_unit_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=review_units.generation_id AND g.repo_id=?2)"),
			params![id,scope.repo_id],
			row,
		)
		.optional()?)
}
pub fn list(scope: &crate::scope::RepoScope<'_>, generation: i64) -> Result<Vec<Unit>> {
	let tx = scope.conn;
	Ok(tx
		.prepare(&format!(
			"SELECT {COLUMNS} FROM review_units WHERE generation_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=review_units.generation_id AND g.repo_id=?2) ORDER BY review_unit_id"
		))?
		.query_map(params![generation,scope.repo_id], row)?
		.collect::<rusqlite::Result<_>>()?)
}
pub fn defer<S: Source>(
	scope: &crate::scope::RepoScope<'_>, id: i64, reason: &BoundedText<Reason, S>,
) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	changed(tx.execute("UPDATE review_units SET status='deferred',defer_reason=?2 WHERE review_unit_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=review_units.generation_id AND g.repo_id=?3) AND status='open'",params![id,reason.expose(),scope.repo_id])?,Conflict::UnitState)
}
pub fn reopen(scope: &crate::scope::RepoScope<'_>, id: i64) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	changed(tx.execute("UPDATE review_units SET status='open',defer_reason=NULL WHERE review_unit_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=review_units.generation_id AND g.repo_id=?2) AND status='deferred'",params![id,scope.repo_id])?,Conflict::UnitState)
}
pub fn retire(scope: &crate::scope::RepoScope<'_>, id: i64) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	changed(tx.execute("UPDATE review_units SET status='retired' WHERE review_unit_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=review_units.generation_id AND g.repo_id=?2) AND status IN ('open','deferred')",params![id,scope.repo_id])?,Conflict::UnitState)
}
pub fn mark_stale<S: Source>(
	scope: &crate::scope::RepoScope<'_>, id: i64, reason: &BoundedText<Reason, S>,
) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	changed(tx.execute("UPDATE review_units SET stale=1,stale_reason=?2 WHERE review_unit_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=review_units.generation_id AND g.repo_id=?3) AND status<>'retired'",params![id,reason.expose(),scope.repo_id])?,Conflict::UnitState)
}
/// Propagate any error to roll back the entire batch, including earlier claims.
pub fn assign(scope: &crate::scope::RepoScope<'_>, job: i64, units: &[Assignment]) -> Result<()> {
	scope.require_operator()?;
	assign_selected(scope.conn, scope.repo_id, job, units)
}

/// The storage-owned claim transaction already selected the job and repository.
pub(crate) fn assign_selected(
	tx: &rusqlite::Connection, repo: i64, job: i64, units: &[Assignment],
) -> Result<()> {
	if units.len() > 32 {
		return Err(Error::Conflict(Conflict::Assignment));
	}
	let generation: Option<i64> = tx
		.query_row(
			"SELECT generation_id FROM jobs WHERE id=?1 AND repo_id=?2 AND state IN ('queued','leased')",
			params![job,repo],
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
		changed(tx.execute("UPDATE review_units SET assignment_epoch=assignment_epoch+1 WHERE review_unit_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=review_units.generation_id AND g.repo_id=?3) AND status='open' AND assignment_epoch=?2 AND assignment_epoch<9223372036854775807 AND NOT EXISTS(SELECT 1 FROM job_assigned_review_units a JOIN jobs j ON j.id=a.job_id WHERE a.review_unit_id=?1 AND j.state IN ('queued','leased'))",params![claim.unit_id,claim.expected_epoch,repo])?,Conflict::Assignment)?;
	}
	// A later batch extends the job's ordered set rather than restarting at 0.
	let start: i64 = tx.query_row(
		"SELECT COALESCE(MAX(position)+1,0) FROM job_assigned_review_units WHERE job_id=?1 AND EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?2)",
		params![job,repo],
		|r| r.get(0),
	)?;
	for (offset, claim) in units.iter().enumerate() {
		tx.execute("INSERT INTO job_assigned_review_units (job_id,review_unit_id,position) SELECT ?1,?2,?3 WHERE EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?4)",params![job,claim.unit_id,start + offset as i64,repo])?;
	}
	Ok(())
}
/// Callers explicitly supply remapped dependencies; old generation IDs are
/// never copied implicitly. The reconciliation layer rebuilds that graph.
pub fn carry_forward(
	scope: &crate::scope::RepoScope<'_>, id: i64, generation: i64, job: Option<i64>,
	dependencies: Option<&BoundedJson<Payload, Agent>>, now: i64,
) -> Result<i64> {
	scope.require_operator()?;
	let source = get(scope, id)?.ok_or(Error::NotFound(Entity::Unit, id))?;
	create(
		scope,
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
