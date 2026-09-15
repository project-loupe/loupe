//! Terminal retries are authenticated by their original finishing capability.
use loupe_core::text::policy::{Payload, Reason, Title};
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_core::{JobKind, JobState};
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::review::{classify, optional, parsed, standalone, string_enum};
use crate::{Conflict, Entity, Error, Result};
// The receipt's phase is the job's kind; reusing `JobKind` keeps the two
// from drifting when a kind is added.
string_enum!(EvidenceRung { L1=>"L1", L2=>"L2", L3=>"L3", L4=>"L4" });
pub struct NewReceipt<'a> {
	pub job_id: i64,
	pub phase: JobKind,
	pub terminal_reason: &'a BoundedText<Reason>,
	pub subject_title: Option<&'a BoundedText<Title>>,
	pub subject_digest: Option<&'a [u8; 32]>,
	pub pinned_commit_sha: &'a str,
	pub effective_recipe: &'a BoundedJson<Payload>,
	pub result_digest: &'a [u8; 32],
	pub evidence_rung: Option<EvidenceRung>,
	pub result_counts: Option<&'a BoundedJson<Payload>>,
	pub finishing_capability_hash: Option<&'a [u8; 32]>,
}
#[derive(Clone)]
pub struct Receipt {
	pub receipt_id: i64,
	pub job_id: i64,
	pub phase: JobKind,
	pub terminal_reason: BoundedText<Reason>,
	pub subject_title: Option<BoundedText<Title>>,
	pub subject_digest: Option<Vec<u8>>,
	pub pinned_commit_sha: String,
	pub effective_recipe: BoundedJson<Payload>,
	pub result_digest: Vec<u8>,
	pub evidence_rung: Option<EvidenceRung>,
	pub result_counts: Option<BoundedJson<Payload>>,
	finishing_capability_hash: Option<Vec<u8>>,
	pub created_at: i64,
}
impl std::fmt::Debug for Receipt {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Receipt")
			.field("job_id", &self.job_id)
			.field("phase", &self.phase)
			.finish_non_exhaustive()
	}
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
	MissingJob,
	NonterminalJob,
	MissingReceipt,
	MissingCapability,
	WrongCapability,
	WrongDigest,
}
#[derive(Debug, Clone)]
pub enum Replayed {
	Receipt(Box<Receipt>),
	Reject(Reject),
}
/// Lease validation and the job's terminal transition belong to the caller.
pub fn insert(tx: &Transaction<'_>, new: &NewReceipt<'_>, now: i64) -> Result<i64> {
	let phase: String = tx
		.query_row("SELECT kind FROM jobs WHERE id=?1", [new.job_id], |r| r.get(0))
		.optional()?
		.ok_or(Error::NotFound(Entity::Job, new.job_id))?;
	if !new.phase.is_known() || phase != new.phase.as_str() {
		return Err(Error::Conflict(Conflict::TerminalReceipt));
	}
	tx.execute("INSERT INTO job_terminal_receipts (job_id,phase,terminal_reason,subject_title,subject_digest,pinned_commit_sha,effective_recipe,result_digest,evidence_rung,result_counts,finishing_capability_hash,created_at)
 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",params![new.job_id,new.phase.as_str(),new.terminal_reason.expose(),new.subject_title.map(BoundedText::expose),new.subject_digest.map(|d|d.as_slice()),new.pinned_commit_sha,new.effective_recipe.expose(),new.result_digest.as_slice(),new.evidence_rung.map(EvidenceRung::as_str),new.result_counts.map(BoundedJson::expose),new.finishing_capability_hash.map(|d|d.as_slice()),now])
 .map_err(|e|classify(e,"job_terminal_receipts.job_id",Conflict::TerminalReceipt))?;
	Ok(tx.last_insert_rowid())
}
pub fn get(conn: &Connection, job: i64) -> Result<Option<Receipt>> {
	Ok(conn.query_row("SELECT job_terminal_receipt_id,job_id,phase,terminal_reason,subject_title,subject_digest,pinned_commit_sha,effective_recipe,result_digest,evidence_rung,result_counts,finishing_capability_hash,created_at FROM job_terminal_receipts WHERE job_id=?1",[job],|r|Ok(Receipt{receipt_id:r.get(0)?,job_id:r.get(1)?,phase:parsed(r,2)?,terminal_reason:parsed(r,3)?,subject_title:optional(r,4)?,subject_digest:r.get(5)?,pinned_commit_sha:r.get(6)?,effective_recipe:parsed(r,7)?,result_digest:r.get(8)?,evidence_rung:optional(r,9)?,result_counts:optional(r,10)?,finishing_capability_hash:r.get(11)?,created_at:r.get(12)?})).optional()?)
}
pub fn replay_terminal(
	tx: &Transaction<'_>, job: i64, capability: &[u8; 32], digest: &[u8; 32],
) -> Result<Replayed> {
	let state: Option<JobState> =
		tx.query_row("SELECT state FROM jobs WHERE id=?1", [job], |r| parsed(r, 0)).optional()?;
	let Some(state) = state else {
		return Ok(Replayed::Reject(Reject::MissingJob));
	};
	if !state.is_terminal() {
		return Ok(Replayed::Reject(Reject::NonterminalJob));
	}
	let Some(receipt) = get(tx, job)? else {
		return Ok(Replayed::Reject(Reject::MissingReceipt));
	};
	let Some(stored) = &receipt.finishing_capability_hash else {
		return Ok(Replayed::Reject(Reject::MissingCapability));
	};
	if stored != capability {
		return Ok(Replayed::Reject(Reject::WrongCapability));
	}
	if receipt.result_digest != digest {
		return Ok(Replayed::Reject(Reject::WrongDigest));
	}
	Ok(Replayed::Receipt(Box::new(receipt)))
}
standalone! {insert(new:&NewReceipt<'_>,now:i64)->i64;}
