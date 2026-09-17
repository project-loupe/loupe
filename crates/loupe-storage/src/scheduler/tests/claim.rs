use super::*;
use crate::generations;

fn claim_fixture() -> crate::Db {
	let db = fixture();
	db.with_conn(|conn| {
		crate::workers::insert(conn, "claim", crate::workers::WorkerKind::Worker, &[8; 32], 0)?;
		Ok(())
	})
	.unwrap();
	db
}

fn queue(db: &crate::Db, band: Band, priority: u32, at: i64) -> i64 {
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let recipe = recipe();
			let mut new = survey(&recipe);
			new.band = band;
			new.effective_priority = priority;
			new.eligible_at = at;
			enqueue_phase(tx, &new, at)
		})
	})
	.unwrap()
}

fn take(db: &crate::Db, now: i64, policy: &ClaimPolicy) -> Option<Claimed> {
	use std::sync::atomic::{AtomicU64, Ordering};
	static NEXT: AtomicU64 = AtomicU64::new(100);
	let mut hash = [0u8; 32];
	hash[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_le_bytes());
	let kinds = [JobKind::Scan, JobKind::Survey, JobKind::Drilldown, JobKind::Verify];
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			claim_kinds(
				tx,
				&ClaimRequest {
					worker_id: 1,
					kinds: &kinds,
					now,
					capability_hash: &hash,
					legacy_lease_seconds: 600,
					policy,
				},
				&kinds,
			)
		})
	})
	.unwrap()
}

fn units(db: &crate::Db) {
	db.with_conn(|conn| {
		for (offset,band) in ["background","normal","urgent","high","normal","urgent"].iter().enumerate() {
			conn.execute("INSERT INTO review_units (review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,priority_band,created_at) VALUES (?1,11,?2,'t','o','[]',?3,?1)", params![offset as i64+1,format!("unit-{offset}"),band])?;
		}
		Ok(())
	}).unwrap();
}

#[test]
fn public_claim_keeps_survey_and_drilldown_runtime_gated() {
	let db = claim_fixture();
	let id = queue(&db, Band::Normal, 0, 0);
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let kinds = [JobKind::Survey, JobKind::Drilldown, JobKind::Unknown("scan".into())];
			assert!(claim(
				tx,
				&ClaimRequest {
					worker_id: 1,
					kinds: &kinds,
					now: 1,
					capability_hash: &[1; 32],
					legacy_lease_seconds: 600,
					policy: &ClaimPolicy::default()
				}
			)?
			.is_none());
			Ok(())
		})
	})
	.unwrap();
	assert_eq!(take(&db, 1, &ClaimPolicy::default()).unwrap().job.id, id);
}

#[test]
fn bands_are_strict_and_aging_is_capped_within_a_band() {
	let db = claim_fixture();
	let ids = [Band::Background, Band::Normal, Band::High, Band::Urgent]
		.map(|band| queue(&db, band, 0, 0));
	for expected in ids.into_iter().rev() {
		let job = take(&db, 100, &ClaimPolicy::default()).unwrap();
		assert_eq!(job.job.id, expected);
		db.with_conn(|c| {
			c.execute("UPDATE jobs SET state='succeeded' WHERE id=?1", [expected])?;
			Ok(())
		})
		.unwrap();
	}
	let db = claim_fixture();
	let old = queue(&db, Band::Normal, 0, 0);
	let newer = queue(&db, Band::Normal, 3, 40);
	let policy = ClaimPolicy { priority_aging_interval_seconds: 10, ..ClaimPolicy::default() };
	assert_eq!(take(&db, 40, &policy).unwrap().job.id, old);
	db.with_conn(|c| {
		c.execute("UPDATE jobs SET state='succeeded' WHERE id=?1", [old])?;
		Ok(())
	})
	.unwrap();
	assert_eq!(take(&db, 40, &policy).unwrap().job.id, newer);
	let db = claim_fixture();
	queue(&db, Band::Normal, 0, 0);
	let high = queue(&db, Band::Normal, 9, 1000);
	assert_eq!(take(&db, 1000, &policy).unwrap().job.id, high, "age boost is capped at eight");
}

#[test]
fn campaign_state_deadline_and_backoff_gate_claims() {
	for state in ["cancelled", "finished", "active"] {
		let db = claim_fixture();
		queue(&db, Band::Normal, 0, 0);
		db.with_conn(|c| {
			c.execute("UPDATE review_campaigns SET state=?1 WHERE campaign_id=1", [state])?;
			Ok(())
		})
		.unwrap();
		assert!(take(&db, 10000, &ClaimPolicy::default()).is_none());
		if state != "active" {
			assert!(take(&db, 100, &ClaimPolicy::default()).is_none());
		}
	}
	let db = claim_fixture();
	queue(&db, Band::Normal, 0, 100);
	assert!(take(&db, 99, &ClaimPolicy::default()).is_none());
	assert!(take(&db, 100, &ClaimPolicy::default()).is_some());
}

#[test]
fn survey_batches_are_ordered_bounded_and_do_not_overlap() {
	let db = claim_fixture();
	units(&db);
	queue(&db, Band::Normal, 0, 0);
	queue(&db, Band::Normal, 0, 1);
	let policy = ClaimPolicy { active_surveys_per_repo: 2, ..ClaimPolicy::default() };
	let first = take(&db, 100, &policy).unwrap();
	assert_eq!(first.assigned_units, [3, 6, 4, 2]);
	assert!(!first.resumed);
	assert_eq!(first.job.hard_deadline_at, Some(1900));
	assert_eq!(first.job.submit_by, Some(1600));
	assert_eq!(first.job.soft_deadline_at, Some(1600));
	assert_eq!(first.job.lease_expires_at, Some(700));
	assert_eq!(take(&db, 100, &policy).unwrap().assigned_units, [5, 1]);
	db.with_conn(|c| {
		assert_eq!(
			c.query_row("SELECT COUNT(*) FROM review_units WHERE assignment_epoch=1", [], |r| r
				.get::<_, i64>(
				0
			))?,
			6
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn bootstrap_and_unpinned_surveys_skip_batches() {
	for unpinned in [false, true] {
		let db = claim_fixture();
		units(&db);
		let id = queue(&db, Band::Normal, 0, 0);
		db.with_conn(|c| {
			if unpinned {
				c.execute("UPDATE jobs SET generation_id=NULL WHERE id=?1", [id])?;
			} else {
				c.execute(
					"UPDATE jobs SET recipe=?2 WHERE id=?1",
					params![id, r#"{"version":1,"recipe":"bootstrap"}"#],
				)?;
			}
			Ok(())
		})
		.unwrap();
		let job = take(&db, 100, &ClaimPolicy::default()).unwrap();
		assert!(job.assigned_units.is_empty());
		assert!(!job.resumed);
	}
}

#[test]
fn a_retry_resumes_only_remaining_assignments_without_bumping_epochs() {
	let db = claim_fixture();
	units(&db);
	queue(&db, Band::Normal, 0, 0);
	let first = take(&db, 100, &ClaimPolicy::default()).unwrap();
	db.with_conn(|conn| {
		conn.execute(
			"UPDATE job_assigned_review_units SET completed=1 WHERE review_unit_id=3",
			[],
		)?;
		assert_eq!(jobs::reap_stale_leases(conn, 800)?, 1);
		Ok(())
	})
	.unwrap();
	assert!(take(&db, 859, &ClaimPolicy::default()).is_none());
	let resumed = take(&db, 900, &ClaimPolicy::default()).unwrap();
	assert_eq!(resumed.job.id, first.job.id);
	assert!(resumed.resumed);
	assert_eq!(resumed.assigned_units, [6, 4, 2]);
	assert_eq!(resumed.job.hard_deadline_at, Some(2700));
	db.with_conn(|conn| {
		assert_eq!(
			conn.query_row(
				"SELECT COUNT(*) FROM job_assigned_review_units WHERE job_id=?1",
				[first.job.id],
				|r| r.get::<_, i64>(0)
			)?,
			4
		);
		assert_eq!(
			conn.query_row("SELECT SUM(assignment_epoch) FROM review_units", [], |r| r
				.get::<_, i64>(0))?,
			4
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn live_lease_is_bounded_by_frozen_deadline_and_legacy_lease_is_unchanged() {
	let db = claim_fixture();
	let id = queue(&db, Band::Normal, 0, 0);
	let policy = ClaimPolicy { lease_seconds: 2400, ..ClaimPolicy::default() };
	let job = take(&db, 100, &policy).unwrap();
	assert_eq!(job.job.id, id);
	assert_eq!(job.job.hard_deadline_at, Some(1900));
	assert_eq!(job.job.lease_expires_at, Some(1960));
	db.with_conn(|c| {
		c.execute(
			"INSERT INTO jobs(repo_id,kind,state,enqueued_at) VALUES(1,'scan','queued',0)",
			[],
		)?;
		Ok(())
	})
	.unwrap();
	let legacy = take(&db, 100, &policy).unwrap();
	assert_eq!(legacy.job.lease_expires_at, Some(700));
	assert_eq!(legacy.job.hard_deadline_at, None);
	assert_eq!(legacy.job.submit_by, None);
}

#[test]
fn assignments_do_not_hide_missing_coverage() {
	let db = claim_fixture();
	units(&db);
	queue(&db, Band::Normal, 0, 0);
	assert_eq!(take(&db, 100, &ClaimPolicy::default()).unwrap().assigned_units.len(), 4);
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			assert_eq!(generations::coverage_rollup(tx, 11)?.missing_results, 6);
			generations::set_corroboration(tx, 11, generations::Corroboration::Satisfied)?;
			assert!(generations::set_coverage(tx, 11, generations::Coverage::Complete).is_err());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn only_current_conclusive_ordinary_evidence_excludes_units_from_batches() {
	for (mutation,expected) in [
		("",false),
		("UPDATE review_unit_results SET disposition='needs_follow_up'",true),
		("UPDATE review_unit_results SET invalidated=1",true),
		("UPDATE review_unit_results SET commit_sha='older'",true),
		("UPDATE review_unit_results SET profile_version=2",true),
		("UPDATE review_unit_results SET invalidated=1; INSERT INTO review_unit_results (review_unit_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,corroborates_review_unit_result_id,created_at) VALUES (1,'base',1,'no_lead_found','[]','{}',zeroblob(32),1,1)",true),
	] {
		let db = result_fixture();
		db.with_conn(|c| {crate::workers::insert(c,"claim",crate::workers::WorkerKind::Worker,&[8;32],0)?;c.execute_batch(mutation)?;Ok(())}).unwrap();
		queue(&db,Band::Normal,0,0);
		assert_eq!(!take(&db,100,&ClaimPolicy::default()).unwrap().assigned_units.is_empty(),expected,"{mutation}");
	}
}

fn result_fixture() -> crate::Db {
	let db = fixture();
	db.with_conn(|conn| {
		conn.execute_batch("INSERT INTO review_units (review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES (1,11,'u','t','o','[]',0);
		INSERT INTO review_unit_results (review_unit_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,created_at) VALUES (1,'base',1,'no_lead_found','[]','{}',zeroblob(32),0);")?;
		Ok(())
	}).unwrap();
	db
}

#[test]
fn old_profile_evidence_does_not_establish_current_coverage() {
	let db = result_fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			assert!(generations::coverage_rollup(tx, 11)?.complete());
			generations::set_profile(tx, 11, 2, &review_tests::payload())?;
			assert_eq!(
				generations::coverage_rollup(tx, 11)?.missing_results,
				1,
				"evidence at the old profile must not cover the current profile"
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn conclusive_evidence_supersedes_follow_up_in_rollup() {
	let db = result_fixture();
	db.with_conn(|conn| transaction::immediate(conn, |tx| {
		tx.execute("UPDATE review_unit_results SET disposition='needs_follow_up'", [])?;
		tx.execute("INSERT INTO review_unit_results (review_unit_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,created_at) VALUES (1,'base',1,'no_lead_found','[]','{}',zeroblob(32),1)", [])?;
		assert_eq!(generations::coverage_rollup(tx, 11)?.needs_follow_up, 0,
			"conclusive current-profile evidence must supersede earlier follow-up");
		assert!(generations::coverage_rollup(tx, 11)?.complete());
		Ok(())
	})).unwrap();
}

#[test]
fn legacy_claim_order_matches_recorded_base_sequence() {
	for accepts_verify in [true, false] {
		let db = fixture();
		db.with_conn(|conn| {
			let worker = crate::workers::insert(conn, "claim", crate::workers::WorkerKind::Worker, &[8;32], 0)?;
			for (i,(kind,time)) in [("verify",9),("scan",3),("scan",3),("verify",1),("scan",1),("verify",9),("scan",2),("verify",1),("scan",9),("scan",2),("verify",3),("scan",1)].iter().enumerate() {
				conn.execute("INSERT INTO jobs (id,repo_id,kind,state,enqueued_at) VALUES (?1,1,?2,'queued',?3)", params![1001+i as i64,kind,time])?;
			}
			let mut sequence = Vec::new();
			loop {
				let hash = vec![sequence.len() as u8; 32];
				let kinds = if accepts_verify { vec![JobKind::Scan,JobKind::Verify] } else { vec![JobKind::Scan] };
				let claimed = transaction::immediate(conn, |tx| claim(tx,&ClaimRequest{worker_id:worker,kinds:&kinds,now:100,capability_hash:&hash,legacy_lease_seconds:600,policy:&ClaimPolicy::default()}))?;
				let Some(Claimed{job,..}) = claimed else { break };
				sequence.push(job.id);
			}
			// Recorded with lease_next at main 7261a26, before replacing it.
			let expected = if accepts_verify { vec![1004,1008,1011,1001,1006,1005,1012,1007,1010,1002,1003,1009] }
			else { vec![1005,1012,1007,1010,1002,1003,1009] };
			assert_eq!(sequence, expected);
			println!("legacy accepts_verify={accepts_verify}: {sequence:?}");
			Ok(())
		}).unwrap();
	}
}

#[test]
fn public_claim_never_offers_campaign_rows_to_legacy_kinds() {
	// `verify` is a runtime kind for the legacy pipeline, but a campaign
	// verify job needs B4's phase handlers; until then a protocol-2 worker
	// advertising `verify:*` must never receive one.
	let db = claim_fixture();
	let verify = db
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				let recipe = recipe();
				let mut new = survey(&recipe);
				new.kind = JobKind::Verify;
				new.target_finding_id = Some(11);
				new.handoff = true;
				enqueue_phase(tx, &new, 0)
			})
		})
		.unwrap();
	let mut hash = [0u8; 32];
	hash[0] = 0xc1;
	let legacy = db
		.with_conn(|conn| {
			transaction::immediate(conn, |tx| {
				claim(
					tx,
					&ClaimRequest {
						worker_id: 1,
						kinds: &[JobKind::Scan, JobKind::Verify],
						now: 100,
						capability_hash: &hash,
						legacy_lease_seconds: 600,
						policy: &ClaimPolicy::default(),
					},
				)
			})
		})
		.unwrap();
	assert!(legacy.is_none(), "campaign verify leased to a legacy worker: {legacy:?}");
	let phase = take(&db, 100, &ClaimPolicy::default()).unwrap();
	assert_eq!(phase.job.id, verify);
}
