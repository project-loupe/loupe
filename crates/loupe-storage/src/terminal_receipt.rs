//! Terminal retries are authenticated by their original finishing capability.
use loupe_core::text::policy::{Payload, Reason, RevisionText, Title};
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_core::JobKind;
use loupe_provenance::{Db, Source};
use rusqlite::{params, Connection, OptionalExtension};

use crate::review::{is_unique, optional, string_enum};
use crate::{Conflict, Entity, Error, Result};
// The receipt's phase is the job's kind; reusing `JobKind` keeps the two
// from drifting when a kind is added.
string_enum!(EvidenceRung { L1=>"L1", L2=>"L2", L3=>"L3", L4=>"L4" });
pub struct NewReceipt<
	'a,
	MetaS: Source,
	ReasonS: Source,
	TitleS: Source,
	RecipeS: Source,
	CountsS: Source,
> {
	pub job_id: i64,
	pub phase: JobKind<MetaS>,
	pub terminal_reason: &'a BoundedText<Reason, ReasonS>,
	pub subject_title: Option<&'a BoundedText<Title, TitleS>>,
	pub subject_digest: Option<&'a [u8; 32]>,
	pub pinned_commit_sha: &'a BoundedText<RevisionText, MetaS>,
	pub effective_recipe: &'a BoundedJson<Payload, RecipeS>,
	pub result_digest: &'a [u8; 32],
	pub evidence_rung: Option<EvidenceRung>,
	pub result_counts: Option<&'a BoundedJson<Payload, CountsS>>,
	pub finishing_capability_hash: Option<&'a [u8; 32]>,
}
#[derive(Clone)]
pub struct Receipt {
	pub receipt_id: i64,
	pub job_id: i64,
	pub phase: JobKind<Db>,
	pub terminal_reason: BoundedText<Reason, Db>,
	pub subject_title: Option<BoundedText<Title, Db>>,
	pub subject_digest: Option<Vec<u8>>,
	pub pinned_commit_sha: BoundedText<RevisionText, Db>,
	pub effective_recipe: BoundedJson<Payload, Db>,
	pub result_digest: Vec<u8>,
	pub evidence_rung: Option<EvidenceRung>,
	pub result_counts: Option<BoundedJson<Payload, Db>>,
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
// debug-ok: rejection reasons are closed categories without capability hashes or payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
	Denied,
	WrongDigest,
}
// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug, Clone)]
pub enum Replayed {
	Receipt(Box<Receipt>),
	Reject(Reject),
}
/// Lease validation and the job's terminal transition belong to the caller.
pub fn insert<MetaS: Source, ReasonS: Source, TitleS: Source, RecipeS: Source, CountsS: Source>(
	scope: &crate::scope::RepoScope<'_>,
	new: &NewReceipt<'_, MetaS, ReasonS, TitleS, RecipeS, CountsS>, now: i64,
) -> Result<i64> {
	scope.require_operator()?;
	let tx = scope.conn;
	let phase = tx
		.query_row(
			"SELECT kind FROM jobs WHERE id=?1 AND repo_id=?2",
			params![new.job_id, scope.repo_id],
			|r| crate::ingress::job_kind_text(r, 0),
		)
		.optional()?
		.ok_or(Error::NotFound(Entity::Job, new.job_id))?;
	if !new.phase.is_known() || phase.expose() != new.phase.as_str() {
		return Err(Error::Conflict(Conflict::TerminalReceipt));
	}
	tx.execute("INSERT INTO job_terminal_receipts (job_id,phase,terminal_reason,subject_title,subject_digest,pinned_commit_sha,effective_recipe,result_digest,evidence_rung,result_counts,finishing_capability_hash,created_at)
 SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12 WHERE EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?13)",params![new.job_id,new.phase.as_str(),new.terminal_reason.expose(),new.subject_title.map(BoundedText::expose),new.subject_digest.map(|d|d.as_slice()),new.pinned_commit_sha.expose(),new.effective_recipe.expose(),new.result_digest.as_slice(),new.evidence_rung.map(EvidenceRung::as_str),new.result_counts.map(BoundedJson::expose),new.finishing_capability_hash.map(|d|d.as_slice()),now,scope.repo_id])
 .map_err(|error| {
     if is_unique(&error, "job_terminal_receipts.job_id")
         || is_unique(&error, "job_terminal_receipts.job_id, job_terminal_receipts.phase")
     {
         Error::Conflict(Conflict::TerminalReceipt)
     } else {
         error.into()
     }
 })?;
	Ok(tx.last_insert_rowid())
}
pub fn get(scope: &crate::scope::RepoScope<'_>, job: i64) -> Result<Option<Receipt>> {
	scope.require_operator()?;
	let tx = scope.conn;
	Ok(tx
		.query_row(
			&format!("SELECT {COLUMNS} FROM job_terminal_receipts WHERE job_id=?1 AND EXISTS(SELECT 1 FROM jobs WHERE id=?1 AND repo_id=?2)"),
			params![job,scope.repo_id],
			row,
		)
		.optional()?)
}
pub(crate) fn get_raw(conn: &Connection, job: i64) -> Result<Option<Receipt>> {
	Ok(conn
		.query_row(
			&format!("SELECT {COLUMNS} FROM job_terminal_receipts WHERE job_id=?1"),
			[job],
			row,
		)
		.optional()?)
}
const COLUMNS: &str = "job_terminal_receipt_id,job_id,phase,terminal_reason,subject_title,subject_digest,pinned_commit_sha,effective_recipe,result_digest,evidence_rung,result_counts,finishing_capability_hash,created_at";
fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Receipt> {
	// Keep the stored capability's SQL type checked without exposing it.
	let _: Option<Vec<u8>> = r.get(11)?;
	Ok(Receipt {
		receipt_id: r.get(0)?,
		job_id: r.get(1)?,
		phase: crate::ingress::job_kind(r, 2)?,
		terminal_reason: crate::ingress::reason(r, 3)?,
		subject_title: crate::ingress::optional_receipt_title(r, 4)?,
		subject_digest: r.get(5)?,
		pinned_commit_sha: crate::ingress::revision(r, 6)?,
		effective_recipe: crate::ingress::db_payload(r, 7)?,
		result_digest: r.get(8)?,
		evidence_rung: optional(r, 9)?,
		result_counts: crate::ingress::optional_db_payload(r, 10)?,
		created_at: r.get(12)?,
	})
}
pub(crate) fn validate_stored_rows(conn: &Connection) -> Result<()> {
	crate::migrations::admission::scan(conn, "job_terminal_receipts", COLUMNS, row)
}
/// Receipt-only authentication, independent of rebuildable campaign state.
/// Public callers use the identity-bound phase transaction facade.
pub(crate) fn replay_terminal(
	tx: &Connection, identity: crate::jobs::LeaseIdentity<'_>,
	phase: crate::review_authority::Phase, digest: &[u8; 32],
) -> Result<Replayed> {
	replay_decision(
		identity.capability_hash.len() == 32,
		|| {
			Ok(tx.query_row(
				"SELECT EXISTS(SELECT 1 FROM jobs j JOIN workers w ON w.id=j.worker_id
		 JOIN job_terminal_receipts r ON r.job_id=j.id
		 WHERE j.id=?1 AND j.worker_id=?2 AND w.kind='worker' AND w.revoked_at IS NULL
		 AND j.kind=?3 AND j.campaign_id IS NOT NULL AND r.phase=?3
		 AND r.finishing_capability_hash=?4 AND j.state IN ('succeeded','failed','cancelled'))",
				params![
					identity.job_id,
					identity.worker_id,
					phase.job_kind().as_str(),
					identity.capability_hash
				],
				|row| row.get(0),
			)?)
		},
		|| {
			Ok(tx.query_row(
				&format!("SELECT {COLUMNS} FROM job_terminal_receipts WHERE job_id=?1"),
				[identity.job_id],
				row,
			)?)
		},
		|receipt: &Receipt| receipt.result_digest.as_slice(),
		digest,
	)
	.map(|replayed| match replayed {
		Ok(receipt) => Replayed::Receipt(Box::new(receipt)),
		Err(reject) => Replayed::Reject(reject),
	})
}

/// Pure replay decision over the binding facts. Its only success value is
/// the loaded receipt, unchanged; it has no path to a state transition.
/// The receipt is loaded only after the finishing identity is bound.
pub(crate) fn replay_decision<R>(
	capability_well_formed: bool, bound: impl FnOnce() -> Result<bool>,
	load: impl FnOnce() -> Result<R>, stored_digest: impl Fn(&R) -> &[u8], digest: &[u8; 32],
) -> Result<std::result::Result<R, Reject>> {
	if !capability_well_formed || !bound()? {
		return Ok(Err(Reject::Denied));
	}
	let receipt = load()?;
	if stored_digest(&receipt) != digest {
		return Ok(Err(Reject::WrongDigest));
	}
	Ok(Ok(receipt))
}
