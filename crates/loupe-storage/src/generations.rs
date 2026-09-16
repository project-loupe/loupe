//! Rebuildable generations; all lifecycle writes are caller-transactional.
use loupe_core::text::policy::{Payload, Reason};
use loupe_core::text::{BoundedJson, BoundedText};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::review::{changed, classify, optional, parsed, standalone, string_enum};
use crate::{ownership, Conflict, Entity, Error, Ownership, Result};

string_enum!(State { Building => "building", Active => "active", Retired => "retired" });
string_enum!(Coverage { Complete => "complete", Partial => "partial", Unknown => "unknown" });
string_enum!(Corroboration { Pending => "pending", Sampled => "sampled", Satisfied => "satisfied", Contradicted => "contradicted" });
pub struct NewGeneration<'a> {
	pub repo_id: i64,
	pub predecessor_generation_id: Option<i64>,
	pub commit_sha: &'a str,
	pub workflow_contract_version: i64,
}
#[derive(Debug, Clone)]
pub struct Generation {
	pub generation_id: i64,
	pub repo_id: i64,
	pub predecessor_generation_id: Option<i64>,
	pub commit_sha: String,
	pub state: State,
	pub workflow_contract_version: i64,
	pub profile_version: i64,
	pub generated_profile: Option<BoundedJson<Payload>>,
	pub inventory_digest: Option<Vec<u8>>,
	pub coverage: Coverage,
	pub corroboration: Corroboration,
	pub pending_follow_up: Option<BoundedJson<Payload>>,
	pub created_at: i64,
	pub activated_at: Option<i64>,
	pub retired_at: Option<i64>,
	pub retired_reason: Option<BoundedText<Reason>>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageRollup {
	pub missing_results: i64,
	pub needs_follow_up: i64,
	pub unresolved_inventory: i64,
}
impl CoverageRollup {
	pub fn complete(self) -> bool {
		self.missing_results == 0 && self.needs_follow_up == 0 && self.unresolved_inventory == 0
	}
}

const COLUMNS: &str = "generation_id,repo_id,predecessor_generation_id,generation_commit_sha,state,workflow_contract_version,profile_version,generated_profile,inventory_digest,coverage,corroboration_state,pending_follow_up,created_at,activated_at,retired_at,retired_reason";
fn row(r: &Row<'_>) -> rusqlite::Result<Generation> {
	Ok(Generation {
		generation_id: r.get(0)?,
		repo_id: r.get(1)?,
		predecessor_generation_id: r.get(2)?,
		commit_sha: r.get(3)?,
		state: parsed(r, 4)?,
		workflow_contract_version: r.get(5)?,
		profile_version: r.get(6)?,
		generated_profile: optional(r, 7)?,
		inventory_digest: r.get(8)?,
		coverage: parsed(r, 9)?,
		corroboration: parsed(r, 10)?,
		pending_follow_up: optional(r, 11)?,
		created_at: r.get(12)?,
		activated_at: r.get(13)?,
		retired_at: r.get(14)?,
		retired_reason: optional(r, 15)?,
	})
}
pub fn create(tx: &Transaction<'_>, new: &NewGeneration<'_>, now: i64) -> Result<i64> {
	if let Some(parent) = new.predecessor_generation_id {
		ownership::generation(tx, new.repo_id, parent, Ownership::GenerationPredecessor)?;
	}
	tx.execute("INSERT INTO review_generations (repo_id,predecessor_generation_id,generation_commit_sha,state,workflow_contract_version,created_at) VALUES (?1,?2,?3,'building',?4,?5)",params![new.repo_id,new.predecessor_generation_id,new.commit_sha,new.workflow_contract_version,now])?;
	Ok(tx.last_insert_rowid())
}
pub fn get(conn: &Connection, id: i64) -> Result<Option<Generation>> {
	Ok(conn
		.query_row(
			&format!("SELECT {COLUMNS} FROM review_generations WHERE generation_id=?1"),
			[id],
			row,
		)
		.optional()?)
}
pub fn list_for_repo(conn: &Connection, repo: i64) -> Result<Vec<Generation>> {
	Ok(conn.prepare(&format!("SELECT {COLUMNS} FROM review_generations WHERE repo_id=?1 ORDER BY created_at DESC,generation_id DESC"))?.query_map([repo],row)?.collect::<rusqlite::Result<_>>()?)
}
pub fn activate(tx: &Transaction<'_>, id: i64, now: i64) -> Result<()> {
	let successor = get(tx, id)?.ok_or(Error::NotFound(Entity::Generation, id))?;
	if successor.state != State::Building {
		return Err(Error::Conflict(Conflict::GenerationState));
	}
	let active: Option<i64> = tx
		.query_row(
			"SELECT generation_id FROM review_generations WHERE repo_id=?1 AND state='active'",
			[successor.repo_id],
			|r| r.get(0),
		)
		.optional()?;
	if let Some(active) = active {
		if successor.predecessor_generation_id != Some(active) {
			return Err(Error::Conflict(Conflict::GenerationPredecessor));
		}
		retire(tx, active, &BoundedText::new("superseded")?, now)?;
	}
	changed(tx.execute("UPDATE review_generations SET state='active',activated_at=?2 WHERE generation_id=?1 AND state='building'",params![id,now])
		.map_err(|e|classify(e,"review_generations.repo_id",Conflict::ActiveGeneration))?,Conflict::GenerationState)
}
pub fn retire(tx: &Transaction<'_>, id: i64, reason: &BoundedText<Reason>, now: i64) -> Result<()> {
	changed(tx.execute("UPDATE review_generations SET state='retired',retired_reason=?2,retired_at=?3 WHERE generation_id=?1 AND state='active'",params![id,reason.expose(),now])?,Conflict::GenerationState)
}
/// Discard rebuildable state from a bootstrap that never became a baseline.
pub fn abandon(
	tx: &Transaction<'_>, id: i64, reason: &BoundedText<Reason>, now: i64,
) -> Result<()> {
	changed(tx.execute("UPDATE review_generations SET state='retired',retired_reason=?2,retired_at=?3 WHERE generation_id=?1 AND state='building'",params![id,reason.expose(),now])?,Conflict::GenerationState)
}
pub fn set_profile(
	tx: &Transaction<'_>, id: i64, version: i64, profile: &BoundedJson<Payload>,
) -> Result<()> {
	changed(tx.execute("UPDATE review_generations SET profile_version=?2,generated_profile=?3,generated_profile_digest=?4 WHERE generation_id=?1 AND state IN ('building','active') AND ?2>0 AND (?2>profile_version OR generated_profile IS NULL)",params![id,version,profile.expose(),profile.digest().as_slice()])?,Conflict::GenerationState)
}
pub fn set_corroboration(tx: &Transaction<'_>, id: i64, state: Corroboration) -> Result<()> {
	changed(tx.execute("UPDATE review_generations SET corroboration_state=?2,coverage=CASE WHEN ?2<>'satisfied' AND coverage='complete' THEN 'partial' ELSE coverage END WHERE generation_id=?1 AND state IN ('building','active')",params![id,state.as_str()])?,Conflict::GenerationState)
}
pub fn set_coverage(tx: &Transaction<'_>, id: i64, coverage: Coverage) -> Result<()> {
	if coverage == Coverage::Complete && !coverage_rollup(tx, id)?.complete() {
		return Err(Error::Conflict(Conflict::Coverage));
	}
	changed(tx.execute("UPDATE review_generations SET coverage=?2 WHERE generation_id=?1 AND state IN ('building','active') AND (?2<>'complete' OR corroboration_state='satisfied')",params![id,coverage.as_str()])?,Conflict::Coverage)
}
pub fn coverage_rollup(tx: &Transaction<'_>, id: i64) -> Result<CoverageRollup> {
	get(tx, id)?.ok_or(Error::NotFound(Entity::Generation, id))?;
	let uncovered = format!("FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.generation_id=?1 AND u.status='open' AND NOT ({})", crate::review_units::UNIT_COVERED);
	let missing_results =
		tx.query_row(&format!("SELECT COUNT(*) {uncovered}"), [id], |r| r.get(0))?;
	let needs_follow_up = tx.query_row(&format!("SELECT COUNT(*) {uncovered} AND (SELECT r.disposition FROM review_unit_results r WHERE r.review_unit_id=u.review_unit_id AND r.invalidated=0 AND r.commit_sha=g.generation_commit_sha AND r.profile_version=g.profile_version ORDER BY r.review_unit_result_id DESC LIMIT 1)='needs_follow_up'"),[id],|r|r.get(0))?;
	let unresolved_inventory = tx.query_row("SELECT COUNT(*) FROM generation_inventory WHERE generation_id=?1 AND disposition='unresolved'",[id],|r|r.get(0))?;
	Ok(CoverageRollup { missing_results, needs_follow_up, unresolved_inventory })
}
pub fn set_pending_follow_up(
	tx: &Transaction<'_>, id: i64, follow_up: &BoundedJson<Payload>,
) -> Result<()> {
	changed(tx.execute("UPDATE review_generations SET pending_follow_up=?2 WHERE generation_id=?1 AND state IN ('building','active')",params![id,follow_up.expose()])?,Conflict::GenerationState)
}
standalone! {
	create(new: &NewGeneration<'_>, now: i64) -> i64;
	activate(id: i64, now: i64) -> ();
	retire(id: i64, reason: &BoundedText<Reason>, now: i64) -> ();
	abandon(id: i64, reason: &BoundedText<Reason>, now: i64) -> ();
	set_profile(id: i64, version: i64, profile: &BoundedJson<Payload>) -> ();
	set_corroboration(id: i64, state: Corroboration) -> ();
	set_coverage(id: i64, coverage: Coverage) -> ();
	set_pending_follow_up(id: i64, follow_up: &BoundedJson<Payload>) -> ();
}
