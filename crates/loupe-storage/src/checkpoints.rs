//! Operation-qualified, canonical replay records in the caller's transaction.
use loupe_core::text::policy::{ClientKey, Payload};
use loupe_core::text::{BoundedJson, Identifier};
use rusqlite::{params, OptionalExtension, Transaction};

use crate::review::{is_unique, parsed, standalone, string_enum};
use crate::{Conflict, Error, Result};
string_enum!(Operation { SubmitReviewUnit=>"submit_review_unit", SubmitLead=>"submit_lead", SubmitUnitResult=>"submit_unit_result", SubmitObservation=>"submit_observation", StageArtifact=>"stage_proof_artifact", RecordExecution=>"record_execution", ValidateFixPatch=>"validate_fix_patch", SubmitSiblingLead=>"submit_sibling_lead", InitializeSurveyBatch=>"initialize_survey_batch" });
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recorded {
	Recorded,
	Replayed(BoundedJson<Payload>),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
	/// `body` ran and its response was recorded under the key.
	Fresh(BoundedJson<Payload>),
	/// A prior identical submission; `body` did not run.
	Replayed(BoundedJson<Payload>),
}
/// The whole replay sequence in one place, so a handler cannot forget the
/// leading lookup: a prior hit returns the stored response and never runs
/// `body`; a miss runs `body` (the domain writes) and records its response.
/// Everything happens in the caller's transaction. The caller must propagate
/// any error and roll back that transaction, including any writes by `body`;
/// this helper does not perform its own rollback.
pub fn run(
	tx: &Transaction<'_>, job: i64, op: Operation, key: &Identifier<ClientKey>, digest: &[u8; 32],
	now: i64, body: impl FnOnce(&Transaction<'_>) -> Result<BoundedJson<Payload>>,
) -> Result<Outcome> {
	if let Some(response) = lookup(tx, job, op, key, digest)? {
		return Ok(Outcome::Replayed(response));
	}
	let response = body(tx)?;
	match record_or_replay(tx, job, op, key, digest, &response, now)? {
		Recorded::Recorded => Ok(Outcome::Fresh(response)),
		// The lookup above ran inside this same write transaction, so a hit
		// here means `body` itself recorded the key: a caller bug, not a replay.
		Recorded::Replayed(_) => Err(Error::Conflict(Conflict::Checkpoint)),
	}
}
/// Check this before domain writes, inside the same lease-bound transaction.
/// A hit returns the original response; a miss permits mutation followed by
/// record_or_replay. Never commit intervening domain writes on a replay hit.
pub fn lookup(
	tx: &Transaction<'_>, job: i64, op: Operation, key: &Identifier<ClientKey>, digest: &[u8; 32],
) -> Result<Option<BoundedJson<Payload>>> {
	let qualified = format!("{}:{}", op.as_str(), key.expose());
	let record = tx
		.query_row(
			"SELECT operation, payload_digest, response FROM job_checkpoints
         WHERE job_id=?1 AND client_key=?2",
			params![job, qualified],
			|r| {
				Ok((
					r.get::<_, String>(0)?,
					r.get::<_, Vec<u8>>(1)?,
					parsed::<BoundedJson<Payload>>(r, 2)?,
				))
			},
		)
		.optional()?;
	let Some((stored_op, stored_digest, response)) = record else {
		return Ok(None);
	};
	if stored_op != op.as_str() || stored_digest != digest {
		return Err(Error::Conflict(Conflict::Checkpoint));
	}
	Ok(Some(response))
}
pub fn record_or_replay(
	tx: &Transaction<'_>, job: i64, op: Operation, key: &Identifier<ClientKey>, digest: &[u8; 32],
	response: &BoundedJson<Payload>, now: i64,
) -> Result<Recorded> {
	let qualified = format!("{}:{}", op.as_str(), key.expose());
	match tx.execute(
		"INSERT INTO job_checkpoints
            (job_id,client_key,operation,payload_digest,response,created_at)
         VALUES (?1,?2,?3,?4,?5,?6)",
		params![job, qualified, op.as_str(), digest.as_slice(), response.expose(), now],
	) {
		Ok(_) => Ok(Recorded::Recorded),
		Err(error) if is_unique(&error, "job_checkpoints.job_id, job_checkpoints.client_key") => {
			lookup(tx, job, op, key, digest)?.map(Recorded::Replayed).ok_or(Error::Sqlite(error))
		},
		Err(error) => Err(error.into()),
	}
}
standalone! {record_or_replay(job:i64,op:Operation,key:&Identifier<ClientKey>,digest:&[u8;32],response:&BoundedJson<Payload>,now:i64)->Recorded;}
