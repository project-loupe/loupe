//! Immutable observations attached to a lead's stable identity.
use loupe_core::text::policy::Payload;
use loupe_core::text::BoundedJson;
use rusqlite::{params, Connection, Transaction};

use crate::review::{parsed, standalone};
use crate::{leads, ownership, Entity, Error, Ownership, Result};
pub struct NewObservation<'a> {
	pub lead_id: i64,
	pub submitted_by_job: Option<i64>,
	pub payload: &'a BoundedJson<Payload>,
	pub commit_sha: &'a str,
}
#[derive(Debug, Clone)]
pub struct Observation {
	pub observation_id: i64,
	pub lead_id: i64,
	pub submitted_by_job: Option<i64>,
	pub payload: BoundedJson<Payload>,
	pub commit_sha: String,
	pub created_at: i64,
}
pub fn insert(tx: &Transaction<'_>, new: &NewObservation<'_>, now: i64) -> Result<i64> {
	let lead = leads::get(tx, new.lead_id)?.ok_or(Error::NotFound(Entity::Lead, new.lead_id))?;
	if let Some(job) = new.submitted_by_job {
		ownership::job_for_generation(tx, job, lead.generation_id, Ownership::ObservationJob)?;
	}
	tx.execute("INSERT INTO lead_observations (lead_id,submitted_by_job_id,observation_payload,observation_digest,commit_sha,created_at) VALUES (?1,?2,?3,?4,?5,?6)",params![new.lead_id,new.submitted_by_job,new.payload.expose(),new.payload.digest().as_slice(),new.commit_sha,now])?;
	Ok(tx.last_insert_rowid())
}
pub fn list(conn: &Connection, lead: i64) -> Result<Vec<Observation>> {
	Ok(conn.prepare("SELECT lead_observation_id,lead_id,submitted_by_job_id,observation_payload,commit_sha,created_at FROM lead_observations WHERE lead_id=?1 ORDER BY lead_observation_id")?.query_map([lead],|r|Ok(Observation{observation_id:r.get(0)?,lead_id:r.get(1)?,submitted_by_job:r.get(2)?,payload:parsed(r,3)?,commit_sha:r.get(4)?,created_at:r.get(5)?}))?.collect::<rusqlite::Result<_>>()?)
}
standalone! {insert(new:&NewObservation<'_>,now:i64)->i64;}
