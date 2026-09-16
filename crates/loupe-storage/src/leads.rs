//! Semantic identity attachment never discards a submitted observation.
use loupe_core::text::policy::{Payload, Reason};
use loupe_core::text::{BoundedJson, BoundedText};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::identity::Identity;
use crate::review::{changed, is_unique, optional, parsed, standalone, string_enum};
use crate::review_units::Priority;
use crate::{lead_observations, ownership, Conflict, Entity, Error, Ownership, Result};
string_enum!(Status { Open=>"open", Deferred=>"deferred", Closed=>"closed" });
string_enum!(Disposition { Promoted=>"promoted", Rejected=>"rejected", Duplicate=>"duplicate", Hardening=>"hardening", Stale=>"stale" });
pub struct NewLead<'a> {
	pub generation_id: i64,
	pub unit_id: Option<i64>,
	pub identity: &'a Identity,
	pub payload: &'a BoundedJson<Payload>,
	pub commit_sha: &'a str,
	pub priority: Priority,
	pub priority_proposal: Option<&'a BoundedJson<Payload>>,
	pub supersedes: Option<i64>,
	pub created_by_job: Option<i64>,
}
#[derive(Debug, Clone)]
pub struct Lead {
	pub lead_id: i64,
	pub generation_id: i64,
	pub unit_id: Option<i64>,
	pub status: Status,
	pub disposition: Option<Disposition>,
	pub defer_reason: Option<BoundedText<Reason>>,
	pub retry_condition: Option<BoundedText<Reason>>,
	pub priority: Priority,
	pub priority_proposal: Option<BoundedJson<Payload>>,
	pub identity: Identity,
	pub payload: BoundedJson<Payload>,
	pub commit_sha: String,
	pub needs_revalidation: bool,
	pub carry_depth: i64,
	pub supersedes: Option<i64>,
	pub duplicate_lead: Option<i64>,
	pub duplicate_finding: Option<i64>,
	pub promoted_finding: Option<i64>,
	pub created_by_job: Option<i64>,
	pub created_at: i64,
	pub closed_at: Option<i64>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submitted {
	Created(i64),
	Attached { lead_id: i64, status: Status },
	ClosedExists { lead_id: i64, disposition: Disposition, finding_id: Option<i64> },
}
pub enum Closure {
	Promoted { finding: i64 },
	Rejected,
	Duplicate { lead: Option<i64>, finding: Option<i64> },
	Hardening,
	Stale,
}
pub fn submit(tx: &Transaction<'_>, new: &NewLead<'_>, now: i64) -> Result<Submitted> {
	ownership::generation_repo(tx, new.generation_id)?;
	if let Some(unit) = new.unit_id {
		ownership::unit_in_generation(tx, unit, new.generation_id, Ownership::LeadUnit)?;
	}
	if let Some(job) = new.created_by_job {
		ownership::job_for_generation(tx, job, new.generation_id, Ownership::LeadJob)?;
	}
	if let Some(parent) = new.supersedes {
		ownership::lead_in_generation(tx, parent, new.generation_id, Ownership::SupersededLead)?;
		// Superseding records a stale-closed identity being resubmitted; any
		// other lead state would fabricate that history.
		let stale: bool = tx.query_row(
			"SELECT EXISTS(SELECT 1 FROM leads WHERE lead_id=?1 AND status='closed' AND disposition='stale')",
			[parent],
			|r| r.get(0),
		)?;
		if !stale {
			return Err(Error::Conflict(Conflict::LeadState));
		}
	}
	let fingerprint = new.identity.fingerprint();
	let supersedes=match new.supersedes{
  Some(id)=>Some(id),
  None=>tx.query_row("SELECT lead_id FROM leads WHERE generation_id=?1 AND identity_fingerprint=?2 AND status='closed' AND disposition='stale' ORDER BY lead_id DESC LIMIT 1",params![new.generation_id,fingerprint.as_slice()],|r|r.get(0)).optional()?
 };
	let result=tx.execute("INSERT INTO leads (generation_id,review_unit_id,priority_band,priority_proposal,identity_family,identity_anchor,identity_instance_key,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,supersedes_lead_id,created_by_job_id,created_at)
 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",params![new.generation_id,new.unit_id,new.priority.as_str(),new.priority_proposal.map(BoundedJson::expose),new.identity.family.expose(),new.identity.anchor.expose(),new.identity.instance.as_ref().map(|v|v.expose()),fingerprint.as_slice(),new.payload.expose(),new.payload.digest().as_slice(),new.commit_sha,supersedes,new.created_by_job,now]);
	match result {
		Ok(_) => Ok(Submitted::Created(tx.last_insert_rowid())),
		Err(error) if is_unique(&error, "leads.generation_id, leads.identity_fingerprint") => {
			let existing=tx.query_row(&format!("SELECT {COLUMNS} FROM leads WHERE generation_id=?1 AND identity_fingerprint=?2 AND (status<>'closed' OR disposition<>'stale')"),params![new.generation_id,fingerprint.as_slice()],row)?;
			lead_observations::insert(
				tx,
				&lead_observations::NewObservation {
					lead_id: existing.lead_id,
					submitted_by_job: new.created_by_job,
					payload: new.payload,
					commit_sha: new.commit_sha,
				},
				now,
			)?;
			match existing.status {
				Status::Open | Status::Deferred => {
					Ok(Submitted::Attached { lead_id: existing.lead_id, status: existing.status })
				},
				Status::Closed => {
					let disposition =
						existing.disposition.ok_or(Error::Conflict(Conflict::LeadState))?;
					Ok(Submitted::ClosedExists {
						lead_id: existing.lead_id,
						disposition,
						finding_id: if disposition == Disposition::Promoted {
							existing.promoted_finding
						} else {
							None
						},
					})
				},
			}
		},
		Err(error) => Err(error.into()),
	}
}
const COLUMNS:&str="lead_id,generation_id,review_unit_id,status,disposition,defer_reason,retry_condition,priority_band,priority_proposal,identity_family,identity_anchor,identity_instance_key,anchored_payload,commit_sha,needs_revalidation,carry_depth,supersedes_lead_id,duplicate_of_lead_id,duplicate_of_finding_id,promoted_finding_id,created_by_job_id,created_at,closed_at";
fn row(r: &Row<'_>) -> rusqlite::Result<Lead> {
	Ok(Lead {
		lead_id: r.get(0)?,
		generation_id: r.get(1)?,
		unit_id: r.get(2)?,
		status: parsed(r, 3)?,
		disposition: optional(r, 4)?,
		defer_reason: optional(r, 5)?,
		retry_condition: optional(r, 6)?,
		priority: parsed(r, 7)?,
		priority_proposal: optional(r, 8)?,
		identity: Identity {
			family: parsed(r, 9)?,
			anchor: parsed(r, 10)?,
			instance: optional(r, 11)?,
		},
		payload: parsed(r, 12)?,
		commit_sha: r.get(13)?,
		needs_revalidation: r.get(14)?,
		carry_depth: r.get(15)?,
		supersedes: r.get(16)?,
		duplicate_lead: r.get(17)?,
		duplicate_finding: r.get(18)?,
		promoted_finding: r.get(19)?,
		created_by_job: r.get(20)?,
		created_at: r.get(21)?,
		closed_at: r.get(22)?,
	})
}
pub fn get(conn: &Connection, id: i64) -> Result<Option<Lead>> {
	Ok(conn
		.query_row(&format!("SELECT {COLUMNS} FROM leads WHERE lead_id=?1"), [id], row)
		.optional()?)
}
pub fn list(conn: &Connection, generation: i64) -> Result<Vec<Lead>> {
	Ok(conn
		.prepare(&format!("SELECT {COLUMNS} FROM leads WHERE generation_id=?1 ORDER BY lead_id"))?
		.query_map([generation], row)?
		.collect::<rusqlite::Result<_>>()?)
}
pub fn close(tx: &Transaction<'_>, id: i64, closure: &Closure, now: i64) -> Result<()> {
	let lead = get(tx, id)?.ok_or(Error::NotFound(Entity::Lead, id))?;
	let repo = ownership::generation_repo(tx, lead.generation_id)?;
	let (disposition, duplicate_lead, duplicate_finding, promoted_finding) = match closure {
		Closure::Promoted { finding } => {
			ownership::finding(tx, *finding, repo, Ownership::PromotedFinding)?;
			(Disposition::Promoted, None, None, Some(*finding))
		},
		Closure::Duplicate { lead, finding } => {
			if lead.is_none() && finding.is_none() || *lead == Some(id) {
				return Err(Error::Conflict(Conflict::LeadState));
			}
			if let Some(other) = lead {
				ownership::lead_in_repo(tx, *other, repo, Ownership::DuplicateLead)?;
			}
			if let Some(other) = finding {
				ownership::finding(tx, *other, repo, Ownership::DuplicateFinding)?;
			}
			(Disposition::Duplicate, *lead, *finding, None)
		},
		Closure::Rejected => (Disposition::Rejected, None, None, None),
		Closure::Hardening => (Disposition::Hardening, None, None, None),
		Closure::Stale => (Disposition::Stale, None, None, None),
	};
	changed(tx.execute("UPDATE leads SET status='closed',disposition=?2,duplicate_of_lead_id=?3,duplicate_of_finding_id=?4,promoted_finding_id=?5,closed_at=?6 WHERE lead_id=?1 AND status IN ('open','deferred') AND (?2<>'stale' OR NOT EXISTS(SELECT 1 FROM jobs WHERE assigned_lead_id=?1 AND state IN ('queued','leased')))",params![id,disposition.as_str(),duplicate_lead,duplicate_finding,promoted_finding,now])?,Conflict::LeadState)
}
pub fn defer(
	tx: &Transaction<'_>, id: i64, reason: &BoundedText<Reason>,
	retry: Option<&BoundedText<Reason>>,
) -> Result<()> {
	changed(tx.execute("UPDATE leads SET status='deferred',defer_reason=?2,retry_condition=?3 WHERE lead_id=?1 AND status='open'",params![id,reason.expose(),retry.map(BoundedText::expose)])?,Conflict::LeadState)
}
pub fn reopen(tx: &Transaction<'_>, id: i64) -> Result<()> {
	changed(tx.execute("UPDATE leads SET status='open',defer_reason=NULL,retry_condition=NULL WHERE lead_id=?1 AND status='deferred'",[id])?,Conflict::LeadState)
}
pub fn mark_needs_revalidation(tx: &Transaction<'_>, id: i64) -> Result<()> {
	changed(tx.execute("UPDATE leads SET needs_revalidation=1 WHERE lead_id=?1 AND status IN ('open','deferred')",[id])?,Conflict::LeadState)
}
standalone! {submit(new:&NewLead<'_>,now:i64)->Submitted;close(id:i64,closure:&Closure,now:i64)->();
defer(id:i64,reason:&BoundedText<Reason>,retry:Option<&BoundedText<Reason>>)->();
reopen(id:i64)->();mark_needs_revalidation(id:i64)->();}
