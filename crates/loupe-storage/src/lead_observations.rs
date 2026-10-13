//! Immutable observations attached to a lead's stable identity.
use loupe_core::text::policy::{Payload, RevisionText};
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_provenance::{Agent, Db, Source};
use rusqlite::{params, Connection};

use crate::{leads, ownership, Entity, Error, Ownership, Result};
pub struct NewObservation<'a, RevisionS: Source> {
	pub lead_id: i64,
	pub submitted_by_job: Option<i64>,
	pub payload: &'a BoundedJson<Payload, Agent>,
	pub commit_sha: &'a BoundedText<RevisionText, RevisionS>,
}
// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug, Clone)]
pub struct Observation {
	pub observation_id: i64,
	pub lead_id: i64,
	pub submitted_by_job: Option<i64>,
	pub payload: BoundedJson<Payload, Agent>,
	pub commit_sha: BoundedText<RevisionText, Db>,
	pub created_at: i64,
}
pub fn insert<RevisionS: Source>(
	scope: &crate::scope::RepoScope<'_>, new: &NewObservation<'_, RevisionS>, now: i64,
) -> Result<i64> {
	scope.require_operator()?;
	let tx = scope.conn;
	let lead = leads::get(scope, new.lead_id)?.ok_or(Error::NotFound(Entity::Lead, new.lead_id))?;
	if let Some(job) = new.submitted_by_job {
		ownership::job_for_generation(tx, job, lead.generation_id, Ownership::ObservationJob)?;
	}
	tx.execute("INSERT INTO lead_observations (lead_id,submitted_by_job_id,observation_payload,observation_digest,commit_sha,created_at) SELECT ?1,?2,?3,?4,?5,?6 WHERE EXISTS(SELECT 1 FROM leads l JOIN review_generations g ON g.generation_id=l.generation_id WHERE l.lead_id=?1 AND g.repo_id=?7)",params![new.lead_id,new.submitted_by_job,new.payload.expose(),new.payload.digest().as_slice(),new.commit_sha.expose(),now,scope.repo_id])?;
	Ok(tx.last_insert_rowid())
}
pub fn list(scope: &crate::scope::RepoScope<'_>, lead: i64) -> Result<Vec<Observation>> {
	let tx = scope.conn;
	Ok(tx
		.prepare(&format!(
			"SELECT {COLUMNS} FROM lead_observations WHERE lead_id=?1 AND EXISTS(SELECT 1 FROM leads l JOIN review_generations g ON g.generation_id=l.generation_id WHERE l.lead_id=lead_observations.lead_id AND g.repo_id=?2) ORDER BY lead_observation_id"
		))?
		.query_map(params![lead,scope.repo_id], row)?
		.collect::<rusqlite::Result<_>>()?)
}
const COLUMNS: &str = "lead_observation_id,lead_id,submitted_by_job_id,observation_payload,commit_sha,created_at,source";
fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Observation> {
	crate::ingress::require_agent_source(r, 6)?;
	Ok(Observation {
		observation_id: r.get(0)?,
		lead_id: r.get(1)?,
		submitted_by_job: r.get(2)?,
		payload: crate::ingress::agent_payload(r, 3)?,
		commit_sha: crate::ingress::revision(r, 4)?,
		created_at: r.get(5)?,
	})
}
pub(crate) fn validate_stored_rows(conn: &Connection) -> Result<()> {
	crate::migrations::admission::scan(conn, "lead_observations", COLUMNS, row)?;
	crate::migrations::admission::scan(conn, "lead_observations", "observation_digest", |_| {
		Ok::<_, rusqlite::Error>(())
	})
}
