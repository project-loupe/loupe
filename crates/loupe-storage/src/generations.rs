//! Rebuildable generations; all lifecycle writes are caller-transactional.
use loupe_core::text::policy::{Payload, Reason, RevisionText};
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_provenance::{Db, Source};
use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::review::{changed, classify, parsed, string_enum};
use crate::{ownership, Conflict, Entity, Error, Ownership, Result};

string_enum!(State { Building => "building", Active => "active", Retired => "retired" });
string_enum!(Coverage { Complete => "complete", Partial => "partial", Unknown => "unknown" });
string_enum!(Corroboration { Pending => "pending", Sampled => "sampled", Satisfied => "satisfied", Contradicted => "contradicted" });
pub struct NewGeneration<'a, S: Source> {
	pub predecessor_generation_id: Option<i64>,
	pub commit_sha: &'a BoundedText<RevisionText, S>,
	pub workflow_contract_version: i64,
}
// debug-ok: Generation text and JSON owners redact; inventory digest, states and identifiers are metadata.
#[derive(Debug, Clone)]
pub struct Generation {
	pub generation_id: i64,
	pub repo_id: i64,
	pub predecessor_generation_id: Option<i64>,
	pub commit_sha: BoundedText<RevisionText, Db>,
	pub state: State,
	pub workflow_contract_version: i64,
	pub profile_version: i64,
	pub generated_profile: Option<BoundedJson<Payload, Db>>,
	pub inventory_digest: Option<Vec<u8>>,
	pub coverage: Coverage,
	pub corroboration: Corroboration,
	pub pending_follow_up: Option<BoundedJson<Payload, Db>>,
	pub created_at: i64,
	pub activated_at: Option<i64>,
	pub retired_at: Option<i64>,
	pub retired_reason: Option<BoundedText<Reason, Db>>,
}
// debug-ok: coverage rollup contains only counts of outstanding work.
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
		commit_sha: crate::ingress::revision(r, 3)?,
		state: parsed(r, 4)?,
		workflow_contract_version: r.get(5)?,
		profile_version: r.get(6)?,
		generated_profile: crate::ingress::optional_db_payload(r, 7)?,
		inventory_digest: r.get(8)?,
		coverage: parsed(r, 9)?,
		corroboration: parsed(r, 10)?,
		pending_follow_up: crate::ingress::optional_db_payload(r, 11)?,
		created_at: r.get(12)?,
		activated_at: r.get(13)?,
		retired_at: r.get(14)?,
		retired_reason: crate::ingress::optional_reason(r, 15)?,
	})
}

pub(crate) fn validate_stored_rows(conn: &Connection) -> Result<()> {
	crate::migrations::admission::scan(conn, "review_generations", COLUMNS, row)?;
	crate::migrations::admission::scan(
		conn,
		"review_generations",
		"generated_profile_digest",
		|_| Ok::<_, rusqlite::Error>(()),
	)
}
pub fn create<S: Source>(
	scope: &crate::scope::RepoScope<'_>, new: &NewGeneration<'_, S>, now: i64,
) -> Result<i64> {
	scope.require_operator()?;
	let tx = scope.conn;
	if let Some(parent) = new.predecessor_generation_id {
		ownership::generation(tx, scope.repo_id, parent, Ownership::GenerationPredecessor)?;
	}
	tx.execute("INSERT INTO review_generations (repo_id,predecessor_generation_id,generation_commit_sha,state,workflow_contract_version,created_at) VALUES (?1,?2,?3,'building',?4,?5)",params![scope.repo_id,new.predecessor_generation_id,new.commit_sha.expose(),new.workflow_contract_version,now])?;
	Ok(tx.last_insert_rowid())
}
#[cfg(test)]
pub(crate) fn get_raw(conn: &rusqlite::Connection, id: i64) -> Result<Option<Generation>> {
	Ok(conn
		.query_row(
			&format!("SELECT {COLUMNS} FROM review_generations WHERE generation_id=?1"),
			[id],
			row,
		)
		.optional()?)
}

pub fn get(scope: &crate::scope::RepoScope<'_>, id: i64) -> Result<Option<Generation>> {
	Ok(scope
		.conn
		.query_row(
			&format!(
				"SELECT {COLUMNS} FROM review_generations WHERE generation_id=?1 AND repo_id=?2"
			),
			params![id, scope.repo_id],
			row,
		)
		.optional()?)
}
pub fn list_for_repo(scope: &crate::scope::RepoScope<'_>) -> Result<Vec<Generation>> {
	Ok(scope.conn.prepare(&format!("SELECT {COLUMNS} FROM review_generations WHERE repo_id=?1 ORDER BY created_at DESC,generation_id DESC"))?.query_map([scope.repo_id],row)?.collect::<rusqlite::Result<_>>()?)
}
pub fn activate(scope: &crate::scope::RepoScope<'_>, id: i64, now: i64) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	let successor = get(scope, id)?.ok_or(Error::NotFound(Entity::Generation, id))?;
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
		retire_superseded(scope, active, now)?;
	}
	changed(tx.execute("UPDATE review_generations SET state='active',activated_at=?2 WHERE generation_id=?1 AND repo_id=?3 AND state='building'",params![id,now,scope.repo_id])
		.map_err(|e|classify(e,"review_generations.repo_id",Conflict::ActiveGeneration))?,Conflict::GenerationState)
}
fn retire_superseded(scope: &crate::scope::RepoScope<'_>, id: i64, now: i64) -> Result<()> {
	let tx = scope.conn;
	changed(tx.execute("UPDATE review_generations SET state='retired',retired_reason='superseded',retired_at=?2 WHERE generation_id=?1 AND repo_id=?3 AND state='active'", params![id,now,scope.repo_id])?, Conflict::GenerationState)
}
pub fn retire<S: Source>(
	scope: &crate::scope::RepoScope<'_>, id: i64, reason: &BoundedText<Reason, S>, now: i64,
) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	changed(tx.execute("UPDATE review_generations SET state='retired',retired_reason=?2,retired_at=?3 WHERE generation_id=?1 AND repo_id=?4 AND state='active'",params![id,reason.expose(),now,scope.repo_id])?,Conflict::GenerationState)
}
/// Discard rebuildable state from a bootstrap that never became a baseline.
pub fn abandon<S: Source>(
	scope: &crate::scope::RepoScope<'_>, id: i64, reason: &BoundedText<Reason, S>, now: i64,
) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	changed(tx.execute("UPDATE review_generations SET state='retired',retired_reason=?2,retired_at=?3 WHERE generation_id=?1 AND repo_id=?4 AND state='building'",params![id,reason.expose(),now,scope.repo_id])?,Conflict::GenerationState)
}
/// The scheduler supersedes an unactivated bootstrap using a closed host fact.
pub(crate) fn abandon_superseded_bootstrap(
	scope: &crate::scope::RepoScope<'_>, id: i64, now: i64,
) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	changed(tx.execute("UPDATE review_generations SET state='retired',retired_reason='superseded bootstrap',retired_at=?2 WHERE generation_id=?1 AND repo_id=?3 AND state='building'", params![id,now,scope.repo_id])?, Conflict::GenerationState)
}
pub fn set_profile<S: Source>(
	scope: &crate::scope::RepoScope<'_>, id: i64, version: i64, profile: &BoundedJson<Payload, S>,
) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	changed(tx.execute("UPDATE review_generations SET profile_version=?2,generated_profile=?3,generated_profile_digest=?4 WHERE generation_id=?1 AND repo_id=?5 AND state IN ('building','active') AND ?2>0 AND (?2>profile_version OR generated_profile IS NULL)",params![id,version,profile.expose(),profile.digest().as_slice(),scope.repo_id])?,Conflict::GenerationState)
}
pub fn set_corroboration(
	scope: &crate::scope::RepoScope<'_>, id: i64, state: Corroboration,
) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	changed(tx.execute("UPDATE review_generations SET corroboration_state=?2,coverage=CASE WHEN ?2<>'satisfied' AND coverage='complete' THEN 'partial' ELSE coverage END WHERE generation_id=?1 AND repo_id=?3 AND state IN ('building','active')",params![id,state.as_str(),scope.repo_id])?,Conflict::GenerationState)
}
pub fn set_coverage(
	scope: &crate::scope::RepoScope<'_>, id: i64, coverage: Coverage,
) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	if coverage == Coverage::Complete && !coverage_rollup(scope, id)?.complete() {
		return Err(Error::Conflict(Conflict::Coverage));
	}
	changed(tx.execute("UPDATE review_generations SET coverage=?2 WHERE generation_id=?1 AND repo_id=?3 AND state IN ('building','active') AND (?2<>'complete' OR corroboration_state='satisfied')",params![id,coverage.as_str(),scope.repo_id])?,Conflict::Coverage)
}
pub fn coverage_rollup(scope: &crate::scope::RepoScope<'_>, id: i64) -> Result<CoverageRollup> {
	let tx = scope.conn;
	get(scope, id)?.ok_or(Error::NotFound(Entity::Generation, id))?;
	let uncovered = format!("FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.generation_id=?1 AND g.repo_id=?2 AND u.status='open' AND NOT ({})", crate::review_units::UNIT_COVERED);
	let missing_results =
		tx.query_row(&format!("SELECT COUNT(*) {uncovered}"), params![id, scope.repo_id], |r| {
			r.get(0)
		})?;
	let needs_follow_up = tx.query_row(&format!("SELECT COUNT(*) {uncovered} AND (SELECT r.disposition FROM review_unit_results r WHERE r.review_unit_id=u.review_unit_id AND r.invalidated=0 AND r.commit_sha=g.generation_commit_sha AND r.profile_version=g.profile_version ORDER BY r.review_unit_result_id DESC LIMIT 1)='needs_follow_up'"),params![id,scope.repo_id],|r|r.get(0))?;
	let unresolved_inventory = tx.query_row("SELECT COUNT(*) FROM generation_inventory WHERE generation_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=generation_inventory.generation_id AND g.repo_id=?2) AND disposition='unresolved'",params![id,scope.repo_id],|r|r.get(0))?;
	Ok(CoverageRollup { missing_results, needs_follow_up, unresolved_inventory })
}
pub fn set_pending_follow_up<S: Source>(
	scope: &crate::scope::RepoScope<'_>, id: i64, follow_up: &BoundedJson<Payload, S>,
) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	changed(tx.execute("UPDATE review_generations SET pending_follow_up=?2 WHERE generation_id=?1 AND repo_id=?3 AND state IN ('building','active')",params![id,follow_up.expose(),scope.repo_id])?,Conflict::GenerationState)
}
pub(crate) fn coalesce_follow_up<S: Source>(
	scope: &crate::scope::RepoScope<'_>, id: i64, follow_up: &loupe_core::PendingFollowUp<'_, S>,
) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	changed(tx.execute("UPDATE review_generations SET pending_follow_up=?2 WHERE generation_id=?1 AND repo_id=?3 AND state IN ('building','active')", params![id,follow_up.canonical(),scope.repo_id])?, Conflict::GenerationState)
}
