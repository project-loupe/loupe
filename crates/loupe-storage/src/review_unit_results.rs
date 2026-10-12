//! Append-only unit evidence and explicit invalidation.
use loupe_core::text::policy::{Argument, Payload, Reason, RevisionText};
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_provenance::{Agent, Db, Source};
use rusqlite::{params, Connection, Transaction};

use crate::review::{changed, parsed, standalone, string_enum};
use crate::source_refs::InspectedRefs;
use crate::{inventory, ownership, Conflict, Error, Ownership, Result};
string_enum!(Disposition { LeadCreated=>"lead_created", NoLeadFound=>"no_lead_found", NotApplicable=>"not_applicable", NeedsFollowUp=>"needs_follow_up" });
pub struct NewResult<'a, RevisionS: Source> {
	pub generation_id: i64,
	pub unit_id: i64,
	pub produced_by_job: Option<i64>,
	pub commit_sha: &'a BoundedText<RevisionText, RevisionS>,
	pub profile_version: i64,
	pub disposition: Disposition,
	pub inspected_refs: &'a InspectedRefs<Agent>,
	pub counterevidence: Option<&'a BoundedText<Argument, Agent>>,
	pub proof_gaps: Option<&'a BoundedText<Argument, Agent>>,
	pub payload: &'a BoundedJson<Payload, Agent>,
	pub corroborates_result: Option<i64>,
	pub corroborates_exclusion: Option<i64>,
}
#[derive(Debug, Clone)]
pub struct UnitResult {
	pub result_id: i64,
	pub unit_id: i64,
	pub produced_by_job: Option<i64>,
	pub commit_sha: BoundedText<RevisionText, Db>,
	pub profile_version: i64,
	pub disposition: Disposition,
	pub inspected_refs: InspectedRefs<Agent>,
	pub counterevidence: Option<BoundedText<Argument, Agent>>,
	pub proof_gaps: Option<BoundedText<Argument, Agent>>,
	pub payload: BoundedJson<Payload, Agent>,
	pub invalidated: bool,
	pub invalidated_reason: Option<BoundedText<Reason, Db>>,
	pub corroborates_result: Option<i64>,
	pub corroborates_exclusion: Option<i64>,
	pub created_at: i64,
}
pub fn insert<RevisionS: Source>(
	tx: &Transaction<'_>, new: &NewResult<'_, RevisionS>, now: i64,
) -> Result<i64> {
	ownership::unit_in_generation(tx, new.unit_id, new.generation_id, Ownership::ResultUnit)?;
	if let Some(job) = new.produced_by_job {
		ownership::job_for_generation(tx, job, new.generation_id, Ownership::ResultJob)?;
	}
	if new.corroborates_result.is_some() && new.corroborates_exclusion.is_some() {
		return Err(Error::Conflict(Conflict::Corroboration));
	}
	if let Some(id) = new.corroborates_result {
		let scope =
			ownership::generation_scope(tx, new.generation_id, Ownership::CorroboratedResult)?;
		ownership::require(tx,"SELECT g.repo_id,u.generation_id FROM review_unit_results r JOIN review_units u ON u.review_unit_id=r.review_unit_id JOIN review_generations g ON g.generation_id=u.generation_id WHERE r.review_unit_result_id=?1 AND r.corroborates_review_unit_result_id IS NULL AND r.corroborates_inventory_exclusion_id IS NULL",[id],scope,Ownership::CorroboratedResult,ownership::generation_row)?;
	}
	if let Some(id) = new.corroborates_exclusion {
		let scope =
			ownership::generation_scope(tx, new.generation_id, Ownership::CorroboratedExclusion)?;
		ownership::require(tx,"SELECT g.repo_id,i.generation_id FROM generation_inventory i JOIN review_generations g ON g.generation_id=i.generation_id WHERE i.inventory_entry_id=?1 AND i.disposition='excluded'",[id],scope,Ownership::CorroboratedExclusion,ownership::generation_row)?;
	}
	inventory::verify_refs(tx, new.generation_id, new.inspected_refs.as_slice())?;
	tx.execute("INSERT INTO review_unit_results (review_unit_id,produced_by_job_id,commit_sha,profile_version,disposition,inspected_refs,counterevidence,proof_gaps,result_payload,result_digest,corroborates_review_unit_result_id,corroborates_inventory_exclusion_id,created_at)
 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",params![new.unit_id,new.produced_by_job,new.commit_sha.expose(),new.profile_version,new.disposition.as_str(),new.inspected_refs.expose(),new.counterevidence.map(BoundedText::expose),new.proof_gaps.map(BoundedText::expose),new.payload.expose(),new.payload.digest().as_slice(),new.corroborates_result,new.corroborates_exclusion,now])?;
	Ok(tx.last_insert_rowid())
}
pub fn list(conn: &Connection, unit: i64) -> Result<Vec<UnitResult>> {
	Ok(conn.prepare(&format!("SELECT {COLUMNS} FROM review_unit_results WHERE review_unit_id=?1 ORDER BY review_unit_result_id"))?.query_map([unit],row)?.collect::<rusqlite::Result<_>>()?)
}
const COLUMNS: &str = "review_unit_result_id,review_unit_id,produced_by_job_id,commit_sha,profile_version,disposition,inspected_refs,counterevidence,proof_gaps,result_payload,invalidated,invalidated_reason,corroborates_review_unit_result_id,corroborates_inventory_exclusion_id,created_at,source";
fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<UnitResult> {
	crate::ingress::require_agent_source(r, 15)?;
	Ok(UnitResult {
		result_id: r.get(0)?,
		unit_id: r.get(1)?,
		produced_by_job: r.get(2)?,
		commit_sha: crate::ingress::revision(r, 3)?,
		profile_version: r.get(4)?,
		disposition: parsed(r, 5)?,
		inspected_refs: crate::ingress::inspected_refs(r, 6)?,
		counterevidence: crate::ingress::optional_argument(r, 7)?,
		proof_gaps: crate::ingress::optional_argument(r, 8)?,
		payload: crate::ingress::agent_payload(r, 9)?,
		invalidated: r.get(10)?,
		invalidated_reason: crate::ingress::optional_reason(r, 11)?,
		corroborates_result: r.get(12)?,
		corroborates_exclusion: r.get(13)?,
		created_at: r.get(14)?,
	})
}
pub(crate) fn validate_stored_rows(conn: &Connection) -> Result<()> {
	crate::migrations::admission::scan(conn, "review_unit_results", COLUMNS, row)?;
	crate::migrations::admission::scan(conn, "review_unit_results", "result_digest", |_| {
		Ok::<_, rusqlite::Error>(())
	})
}
pub fn invalidate<S: Source>(
	tx: &Transaction<'_>, id: i64, reason: &BoundedText<Reason, S>,
) -> Result<()> {
	changed(tx.execute("UPDATE review_unit_results SET invalidated=1,invalidated_reason=?2 WHERE review_unit_result_id=?1 AND invalidated=0",params![id,reason.expose()])?,Conflict::Corroboration)
}
standalone! {insert<RevisionS>(new:&NewResult<'_, RevisionS>,now:i64)->i64;invalidate<S>(id:i64,reason:&BoundedText<Reason, S>)->();}
