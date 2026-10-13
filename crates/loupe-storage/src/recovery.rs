//! Operator verification recovery owns candidate selection and one transaction.
use loupe_core::JobKind;
use loupe_provenance::{Db as DbSource, Ingress, Operator};

use crate::jobs::NewJob;
use crate::{findings, jobs, Db, Result};

pub fn cancel_job(
	db: &Db, _operator: &Ingress<Operator>, id: i64, now: i64,
) -> Result<jobs::CancelOutcome> {
	db.with_conn(|conn| Ok(jobs::cancel(conn, id, now)?))
}

pub fn retry_job(
	db: &Db, _operator: &Ingress<Operator>, id: i64, now: i64, deadline: i64,
) -> Result<jobs::RetryOutcome> {
	db.with_conn(|conn| Ok(jobs::retry_failed(conn, id, now, deadline)?))
}

pub struct RecoveryRequest {
	pub repo_id: Option<i64>,
	pub limit: Option<i64>,
	pub include_inconclusive: bool,
	pub dry_run: bool,
}

// debug-ok: recovery results contain only a dry-run flag and outcome counters.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RecoveryCounts {
	pub dry_run: bool,
	pub matched: u64,
	pub revived: u64,
	pub requeued_jobs: u64,
	pub created_jobs: u64,
	pub left_queued_or_leased: u64,
}

struct VerifyRetryCandidate {
	finding_id: i64,
	repo_id: i64,
	parent_job_id: i64,
}

pub fn retry_verification_candidates(
	db: &Db, _operator: &Ingress<Operator>, req: &RecoveryRequest, now: i64, budget_seconds: i64,
) -> Result<RecoveryCounts> {
	db.with_conn(|c| {
		let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
		let limit = req.limit.unwrap_or(-1);
		let candidates = {
			// Keep the three recovery modes in one query so the
			// repo/limit ordering is global rather than per-arm.
			// Active queued/leased verify jobs are counted later and
			// not mutated, which prevents duplicate verifier work.
			let mut stmt = tx.prepare(
				"SELECT f.id, f.repo_id, f.job_id
						   FROM findings f
						  WHERE f.verification_required = 1
						    AND EXISTS(SELECT 1 FROM jobs parent WHERE parent.id=f.job_id AND parent.repo_id=f.repo_id)
						    AND (?1 IS NULL OR f.repo_id = ?1)
						    AND (
						      (
						        f.state = 'dismissed'
						        AND EXISTS (
						          SELECT 1 FROM finding_verifications v
						           WHERE v.finding_id = f.id
						             AND v.job_id IS NULL
						             AND v.verdict = 'inconclusive'
						             AND v.notes = ?4
						        )
						      )
						      OR (
						        f.state = 'pending'
						        AND EXISTS (
						          SELECT 1 FROM jobs j
						           WHERE j.id = f.job_id
						             AND j.kind = 'scan'
						             AND j.state IN ('succeeded', 'failed', 'cancelled')
						             AND j.finished_at IS NOT NULL
						        )
						      )
						      OR f.state = 'validating'
						    )
						    AND NOT EXISTS (
						      SELECT 1 FROM finding_verifications v
						       WHERE v.finding_id = f.id
						         AND v.verdict IN ('confirmed', 'dismissed')
						    )
						    AND (
						      ?3 = 1
						      OR NOT EXISTS (
						        SELECT 1 FROM finding_verifications v
						         WHERE v.finding_id = f.id
						           AND v.job_id IS NOT NULL
						           AND v.verdict = 'inconclusive'
						      )
						    )
						  ORDER BY COALESCE(f.validating_deadline, f.created_at), f.id
						  LIMIT ?2",
			)?;
			let mut rows = stmt.query((
				req.repo_id,
				limit,
				req.include_inconclusive as i64,
				findings::VALIDATING_DEADLINE_EXPIRED_NOTE,
			))?;
			let mut out = Vec::new();
			while let Some(r) = rows.next()? {
				out.push(VerifyRetryCandidate {
					finding_id: r.get(0)?,
					repo_id: r.get(1)?,
					parent_job_id: r.get(2)?,
				});
			}
			out
		};

		let mut out = RecoveryCounts {
			dry_run: req.dry_run,
			matched: candidates.len() as u64,
			revived: 0,
			requeued_jobs: 0,
			created_jobs: 0,
			left_queued_or_leased: 0,
		};

		for candidate in candidates {
			let active_verify: bool = tx.query_row(
				"SELECT EXISTS(
					   SELECT 1 FROM jobs
					    WHERE kind = 'verify'
					      AND target_finding_id = ?1
					      AND repo_id = ?2
					      AND state IN ('queued','leased')
					)",
				[candidate.finding_id,candidate.repo_id],
				|r| r.get(0),
			)?;

			if active_verify {
				out.left_queued_or_leased += 1;
				continue;
			} else {
				out.revived += 1;
				let failed_job_id: Option<i64> = {
					let mut stmt = tx.prepare(
						"SELECT id FROM jobs
							  WHERE kind = 'verify'
							    AND target_finding_id = ?1
							    AND repo_id = ?2
							    AND state = 'failed'
							  ORDER BY enqueued_at DESC, id DESC
							  LIMIT 1",
					)?;
					let mut rows = stmt.query([candidate.finding_id,candidate.repo_id])?;
					match rows.next()? {
						Some(r) => Some(r.get(0)?),
						None => None,
					}
				};

				if let Some(job_id) = failed_job_id {
					out.requeued_jobs += 1;
					if !req.dry_run {
						jobs::requeue_failed(&tx, candidate.repo_id, job_id, now)?;
					}
				} else {
					out.created_jobs += 1;
					if !req.dry_run {
						jobs::enqueue_raw(
							&tx,
							&NewJob {
								repo_id: candidate.repo_id,
								kind: JobKind::<DbSource>::Verify,
								incremental: false,
								since_sha: None,
								parent_job_id: Some(candidate.parent_job_id),
								target_finding_id: Some(candidate.finding_id),
							},
							now,
						)?;
					}
				}
			}

			if !req.dry_run {
				findings::retry_verification(&tx, candidate.repo_id, candidate.finding_id, now + budget_seconds)?;
			}
		}

		if req.dry_run {
			tx.rollback()?;
		} else {
			tx.commit()?;
		}
		Ok(out)
	})
}
