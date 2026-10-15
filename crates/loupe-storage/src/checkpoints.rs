//! Operation-qualified, canonical replay records in the caller's transaction.
use loupe_core::text::policy::{ClientKey, Payload};
use loupe_core::text::{BoundedJson, Identifier};
use loupe_provenance::{Db, Source};
use rusqlite::{params, Connection, OptionalExtension};

use crate::review::{is_unique, string_enum};
use crate::{Conflict, Error, Result};
string_enum!(Operation { SubmitReviewUnit=>"submit_review_unit", SubmitLead=>"submit_lead", SubmitUnitResult=>"submit_unit_result", SubmitObservation=>"submit_observation", StageArtifact=>"stage_proof_artifact", RecordExecution=>"record_execution", ValidateFixPatch=>"validate_fix_patch", SubmitSiblingLead=>"submit_sibling_lead", InitializeSurveyBatch=>"initialize_survey_batch" });
/// Stored bytes stay borrowed so a malformed digest cannot be truncated or
/// padded into an apparently valid replay. Operation identity is checked even
/// though the client key is also operation-qualified.
pub struct Stored<'a> {
	pub operation: &'a str,
	pub digest: &'a [u8],
}

// debug-ok: replay decisions are closed variants without checkpoint content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
	Miss,
	Hit,
	Conflict,
}

pub fn replay_decision(
	stored: Option<&Stored<'_>>, operation: Operation, digest: &[u8; 32],
) -> Replay {
	match stored {
		None => Replay::Miss,
		Some(stored) if stored.operation == operation.as_str() && stored.digest == digest => {
			Replay::Hit
		},
		Some(_) => Replay::Conflict,
	}
}
// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recorded {
	Recorded,
	Replayed(BoundedJson<Payload, Db>),
}
// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug)]
pub enum Outcome<S: Source> {
	/// `body` ran and its response was recorded under the key.
	Fresh(BoundedJson<Payload, S>),
	/// A prior identical submission; `body` did not run.
	Replayed(BoundedJson<Payload, Db>),
}
impl<S: Source> Clone for Outcome<S> {
	fn clone(&self) -> Self {
		match self {
			Self::Fresh(response) => Self::Fresh(response.clone()),
			Self::Replayed(response) => Self::Replayed(response.clone()),
		}
	}
}
impl<S: Source> PartialEq for Outcome<S> {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			(Self::Fresh(left), Self::Fresh(right)) => left == right,
			(Self::Replayed(left), Self::Replayed(right)) => left == right,
			_ => false,
		}
	}
}
impl<S: Source> Eq for Outcome<S> {}

/// The whole replay sequence in one place, so a handler cannot forget the
/// leading lookup: a prior hit returns the stored response and never runs
/// `body`; a miss runs `body` (the domain writes) and records its response.
/// Everything happens in the caller's transaction. The caller must propagate
/// any error and roll back that transaction, including any writes by `body`;
/// this helper does not perform its own rollback.
pub fn run<KeyS: Source, ResponseS: Source>(
	scope: &crate::scope::RepoScope<'_>, job: i64, op: Operation,
	key: &Identifier<ClientKey, KeyS>, digest: &[u8; 32], now: i64,
	body: impl FnOnce(&crate::scope::RepoScope<'_>) -> Result<BoundedJson<Payload, ResponseS>>,
) -> Result<Outcome<ResponseS>> {
	scope.require_operator()?;
	crate::jobs::get(scope, job)?.ok_or(Error::NotFound(crate::Entity::Job, job))?;
	if let Some(response) = lookup(scope, job, op, key, digest)? {
		return Ok(Outcome::Replayed(response));
	}
	let response = body(scope)?;
	match record_or_replay(scope, job, op, key, digest, &response, now)? {
		Recorded::Recorded => Ok(Outcome::Fresh(response)),
		// The lookup above ran inside this same write transaction, so a hit
		// here means `body` itself recorded the key: a caller bug, not a replay.
		Recorded::Replayed(_) => Err(Error::Conflict(Conflict::Checkpoint)),
	}
}
/// Check this before domain writes, inside the same lease-bound transaction.
/// A hit returns the original response; a miss permits mutation followed by
/// record_or_replay. Never commit intervening domain writes on a replay hit.
pub fn lookup<KeyS: Source>(
	scope: &crate::scope::RepoScope<'_>, job: i64, op: Operation,
	key: &Identifier<ClientKey, KeyS>, digest: &[u8; 32],
) -> Result<Option<BoundedJson<Payload, Db>>> {
	scope.require_operator()?;
	let tx = scope.conn;
	crate::jobs::get(scope, job)?.ok_or(Error::NotFound(crate::Entity::Job, job))?;
	let qualified = format!("{}:{}", op.as_str(), key.expose());
	let record = tx
		.query_row(
			"SELECT operation, payload_digest, response FROM job_checkpoints
         WHERE job_id=?1 AND client_key=?2 AND EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?3)",
			params![job,qualified,scope.repo_id],
			row,
		)
		.optional()?;
	let stored = record
		.as_ref()
		.map(|(operation, digest, _)| Stored { operation: operation.expose(), digest });
	match replay_decision(stored.as_ref(), op, digest) {
		Replay::Miss => Ok(None),
		Replay::Hit => Ok(record.map(|(_, _, response)| response)),
		Replay::Conflict => Err(Error::Conflict(Conflict::Checkpoint)),
	}
}
pub fn record_or_replay<KeyS: Source, ResponseS: Source>(
	scope: &crate::scope::RepoScope<'_>, job: i64, op: Operation,
	key: &Identifier<ClientKey, KeyS>, digest: &[u8; 32],
	response: &BoundedJson<Payload, ResponseS>, now: i64,
) -> Result<Recorded> {
	scope.require_operator()?;
	let tx = scope.conn;
	crate::jobs::get(scope, job)?.ok_or(Error::NotFound(crate::Entity::Job, job))?;
	let qualified = format!("{}:{}", op.as_str(), key.expose());
	match tx.execute(
		"INSERT INTO job_checkpoints
            (job_id,client_key,operation,payload_digest,response,created_at)
         SELECT ?1,?2,?3,?4,?5,?6 WHERE EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?7)",
		params![
			job,
			qualified,
			op.as_str(),
			digest.as_slice(),
			response.expose(),
			now,
			scope.repo_id
		],
	) {
		Ok(_) => Ok(Recorded::Recorded),
		Err(error) if is_unique(&error, "job_checkpoints.job_id, job_checkpoints.client_key") => {
			lookup(scope, job, op, key, digest)?.map(Recorded::Replayed).ok_or(Error::Sqlite(error))
		},
		Err(error) => Err(error.into()),
	}
}

/// Fixed host checkpoint. Neither the literal key nor the empty response is
/// represented as peer-authored content. Returns whether this was a replay.
pub(crate) fn initialize_survey_batch(
	tx: &Connection, repo: i64, job: i64, now: i64, body: impl FnOnce(&Connection) -> Result<()>,
) -> Result<bool> {
	use sha2::{Digest, Sha256};
	let digest: [u8; 32] = Sha256::digest(b"{}").into();
	let stored = tx.query_row(
		"SELECT operation,payload_digest,response FROM job_checkpoints WHERE job_id=?1 AND client_key='initialize_survey_batch:ordinary' AND EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?2)",
		[job,repo], row,
	).optional()?;
	if let Some((operation, prior_digest, _response)) = stored {
		return if replay_decision(
			Some(&Stored { operation: operation.expose(), digest: &prior_digest }),
			Operation::InitializeSurveyBatch,
			&digest,
		) == Replay::Hit
		{
			Ok(true)
		} else {
			Err(Error::Conflict(Conflict::Checkpoint))
		};
	}
	body(tx)?;
	tx.execute("INSERT INTO job_checkpoints(job_id,client_key,operation,payload_digest,response,created_at) SELECT ?1,'initialize_survey_batch:ordinary','initialize_survey_batch',?2,'{}',?3 WHERE EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?4)", params![job, digest.as_slice(), now,repo])?;
	Ok(false)
}

type CheckpointRow = (
	loupe_core::text::BoundedText<crate::ingress::CheckpointOperation, Db>,
	Vec<u8>,
	BoundedJson<Payload, Db>,
);
fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<CheckpointRow> {
	Ok((crate::ingress::operation(r, 0)?, r.get(1)?, crate::ingress::db_payload(r, 2)?))
}
pub(crate) fn validate_stored_rows(conn: &rusqlite::Connection) -> Result<()> {
	crate::migrations::admission::scan(
		conn,
		"job_checkpoints",
		"operation,payload_digest,response,client_key,job_checkpoint_id,job_id,created_at",
		|r| {
			let (operation, _, _) = row(r)?;
			crate::ingress::qualified_checkpoint_key(r, 3, operation.expose())
		},
	)
}

#[cfg(test)]
mod tests {
	use loupe_provenance::Agent;

	use super::*;

	#[test]
	fn outcome_traits_need_only_source() {
		fn cloned<S: Source>(value: &Outcome<S>) -> Outcome<S> {
			value.clone()
		}
		fn equal<S: Source>(left: &Outcome<S>, right: &Outcome<S>) -> bool {
			fn requires_eq<T: Eq>() {}
			requires_eq::<Outcome<S>>();
			left == right
		}

		let fresh = Outcome::Fresh(crate::test_support::json(r#"{"response":1}"#).unwrap());
		let replayed =
			Outcome::<Agent>::Replayed(crate::test_support::db_json(r#"{"response":1}"#).unwrap());
		assert!(equal(&fresh, &cloned(&fresh)));
		assert!(equal(&replayed, &cloned(&replayed)));
		assert!(!equal(&fresh, &replayed));
	}

	#[test]
	fn agent_outcome_equality_preserves_payload_and_variant() {
		let fresh = Outcome::Fresh(crate::test_support::json(r#"{"response":1}"#).unwrap());
		let fresh_equal = Outcome::Fresh(crate::test_support::json(r#"{"response":1}"#).unwrap());
		let fresh_different =
			Outcome::Fresh(crate::test_support::json(r#"{"response":2}"#).unwrap());
		let replayed =
			Outcome::<Agent>::Replayed(crate::test_support::db_json(r#"{"response":1}"#).unwrap());
		let replayed_equal =
			Outcome::<Agent>::Replayed(crate::test_support::db_json(r#"{"response":1}"#).unwrap());
		let replayed_different =
			Outcome::<Agent>::Replayed(crate::test_support::db_json(r#"{"response":2}"#).unwrap());

		assert_eq!(fresh, fresh_equal);
		assert_ne!(fresh, fresh_different);
		assert_eq!(replayed, replayed_equal);
		assert_ne!(replayed, replayed_different);
		assert_ne!(fresh, replayed);
		assert_ne!(replayed, fresh);
	}
}
