use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::*;

fn projects() -> crate::Db {
	let db = fixture();
	db.with_conn(|c| {
		for repo in [3,4] {
			c.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(?1,?2,'github.com','o',?2,'{\"kind\":\"manual\"}',0)",params![repo,format!("r{repo}")])?;
			c.execute("INSERT INTO review_generations(generation_id,repo_id,generation_commit_sha,state,workflow_contract_version,created_at) VALUES(?1,?2,'base','active',1,0)",params![repo*10+1,repo])?;
			c.execute("INSERT INTO review_campaigns(campaign_id,repo_id,recipe,trigger,target_commit_sha,generation_id,state,effective_policy,effective_policy_digest,deadline_at,created_at) SELECT ?1,?1,'incremental','manual','base',?2,'active',effective_policy,effective_policy_digest,10000,0 FROM review_campaigns WHERE campaign_id=1",params![repo,repo*10+1])?;
			c.execute("INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(?1,?2,'survey','succeeded',0)",params![repo*100+1,repo])?;
		}
		crate::workers::insert(c,"worker-1",crate::workers::WorkerKind::Worker,&[8;32],0)?;
		crate::workers::insert(c,"worker-2",crate::workers::WorkerKind::Worker,&[9;32],0)?;
		Ok(())
	}).unwrap();
	db
}

fn enqueue(db: &crate::Db, repo: i64, kind: JobKind, band: Band, priority: u32, at: i64) -> i64 {
	db.with_conn(|c| transaction::immediate(c, |tx| {
		let generation = repo*10+1;
		let mut lead = None;
		let mut finding = None;
		if kind == JobKind::Drilldown {
			let id: i64 = tx.query_row("SELECT COALESCE(MAX(lead_id),0)+1 FROM leads",[],|r|r.get(0))?;
			let mut fingerprint=[0u8;32];
			fingerprint[..8].copy_from_slice(&id.to_le_bytes());
			tx.execute("INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) VALUES(?1,?2,'f','a',?3,'{}',zeroblob(32),'base',0)",params![id,generation,fingerprint.as_slice()])?;
			lead=Some(id);
		}
		if kind == JobKind::Verify {
			let id: i64=tx.query_row("SELECT COALESCE(MAX(id),0)+1 FROM findings",[],|r|r.get(0))?;
			tx.execute("INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,created_at) VALUES(?1,?2,?3,'test','high','t','d',?4,'validating',0)",params![id,repo,repo*100+1,format!("finding-{id}")])?;
			finding=Some(id);
		}
		let recipe = recipe();
		enqueue_phase(tx,&NewPhaseJob{repo_id:repo,kind,campaign_id:repo,generation_id:Some(generation),assigned_lead_id:lead,target_finding_id:finding,continuation_of_job_id:None,band,effective_priority:priority,eligible_at:at,token_budget:None,recipe:&recipe,handoff:true},at)
	})).unwrap()
}

fn take(db: &crate::Db, kinds: &[JobKind], now: i64, policy: &ClaimPolicy) -> Option<Claimed> {
	static NEXT: AtomicU64 = AtomicU64::new(2000);
	let mut hash = [0u8; 32];
	hash[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_le_bytes());
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			claim_kinds(
				tx,
				&ClaimRequest {
					worker_id: 1,
					kinds,
					now,
					capability_hash: &hash,
					legacy_lease_seconds: 600,
					policy,
				},
				kinds,
			)
		})
	})
	.unwrap()
}

fn finish(db: &crate::Db, id: i64) {
	db.with_conn(|c| {
		c.execute("UPDATE jobs SET state='succeeded',finished_at=100 WHERE id=?1", [id])?;
		Ok(())
	})
	.unwrap();
}

const ALL: &[JobKind] = &[JobKind::Survey, JobKind::Drilldown, JobKind::Verify];

#[test]
fn band_order_remains_strict_across_four_repositories() {
	let db = projects();
	for (repo, band) in
		[(1, Band::Background), (2, Band::Normal), (3, Band::High), (4, Band::Urgent)]
	{
		enqueue(&db, repo, JobKind::Survey, band, 0, 0);
	}
	for repo in [4, 3, 2, 1] {
		let job = take(&db, ALL, 100, &ClaimPolicy::default()).unwrap();
		assert_eq!(job.job.repo_id, repo);
		finish(&db, job.job.id);
	}
}

#[test]
fn verification_anti_affinity_is_a_preference_not_a_filter() {
	let db = projects();
	let promoter = enqueue(&db, 1, JobKind::Drilldown, Band::Normal, 0, 0);
	let drilldown = take(&db, ALL, 100, &ClaimPolicy::default()).unwrap();
	assert_eq!(drilldown.job.id, promoter);
	finish(&db, promoter);
	let same = enqueue(&db, 1, JobKind::Verify, Band::Normal, 100, 0);
	let other = enqueue(&db, 1, JobKind::Verify, Band::Normal, 0, 1);
	db.with_conn(|c| {
		let finding=jobs::get(c,same)?.unwrap().target_finding_id.unwrap();
		c.execute("INSERT INTO finding_review_details(finding_id,repo_id,workflow_contract_version,profile_version,reviewed_commit_sha,identity_family,identity_anchor,identity_fingerprint,l2_argument,counterevidence,assumptions_gaps,confidence,submitted_rung,origin_lead_id,created_at) VALUES(?1,1,1,1,'base','family','anchor',zeroblob(32),'{}','counter','gaps','high','L2',?2,0)",params![finding,drilldown.job.assigned_lead_id])?;
		Ok(())
	}).unwrap();
	assert_eq!(take(&db, ALL, 100, &ClaimPolicy::default()).unwrap().job.id, other);
	finish(&db, other);
	assert_eq!(take(&db, ALL, 100, &ClaimPolicy::default()).unwrap().job.id, same);
}

#[test]
fn burst_counter_clears_on_coverage_or_a_borrowed_opportunity() {
	let db = projects();
	let policy = ClaimPolicy { urgency_burst_length: 2, ..ClaimPolicy::default() };
	for (kind, expected) in [
		(JobKind::Drilldown, 1),
		(JobKind::Verify, 2),
		(JobKind::Drilldown, 0),
		(JobKind::Drilldown, 1),
		(JobKind::Survey, 0),
	] {
		enqueue(&db, 1, kind, Band::Normal, 0, 0);
		let job = take(&db, ALL, 100, &policy).unwrap();
		finish(&db, job.job.id);
		db.with_conn(|c| {
			assert_eq!(
				c.query_row("SELECT burst FROM scheduler_repo_state WHERE repo_id=1", [], |r| r
					.get::<_, i64>(
					0
				))?,
				expected
			);
			Ok(())
		})
		.unwrap();
	}
}

#[test]
fn coverage_debt_does_not_promote_a_background_drilldown() {
	let db = projects();
	let policy = ClaimPolicy { urgency_burst_length: 2, ..ClaimPolicy::default() };
	for _ in 0..2 {
		enqueue(&db, 1, JobKind::Drilldown, Band::Normal, 0, 0);
		let job = take(&db, ALL, 100, &policy).unwrap();
		finish(&db, job.job.id);
	}
	enqueue(&db, 1, JobKind::Drilldown, Band::Background, 0, 0);
	let urgent = enqueue(&db, 2, JobKind::Drilldown, Band::Urgent, 0, 0);
	assert_eq!(take(&db, ALL, 100, &policy).unwrap().job.id, urgent);
}

#[test]
fn an_expired_survey_keeps_its_age_for_burst_promotion() {
	let db = projects();
	let policy = ClaimPolicy { urgency_burst_length: 2, ..ClaimPolicy::default() };
	let old = enqueue(&db, 1, JobKind::Survey, Band::Background, 0, 0);
	assert_eq!(take(&db, ALL, 100, &policy).unwrap().job.id, old);
	let new = enqueue(&db, 1, JobKind::Survey, Band::Urgent, 100, 1);
	for _ in 0..2 {
		enqueue(&db, 1, JobKind::Drilldown, Band::Urgent, 0, 0);
		let job = take(&db, &[JobKind::Drilldown], 100, &policy).unwrap();
		finish(&db, job.job.id);
	}
	db.with_conn(|c| {
		assert_eq!(jobs::reap_stale_leases(c, 800)?, 1);
		Ok(())
	})
	.unwrap();
	assert_eq!(take(&db, ALL, 900, &policy).unwrap().job.id, old);
	db.with_conn(|c| {
		assert_eq!(jobs::get(c, new)?.unwrap().state, JobState::Queued);
		Ok(())
	})
	.unwrap();
}

#[test]
fn concurrent_claims_consume_one_coverage_opportunity_once() {
	let db = Arc::new(projects());
	let policy = ClaimPolicy { urgency_burst_length: 2, ..ClaimPolicy::default() };
	for _ in 0..2 {
		enqueue(&db, 1, JobKind::Drilldown, Band::Normal, 0, 0);
		let job = take(&db, ALL, 100, &policy).unwrap();
		finish(&db, job.job.id);
	}
	let survey = enqueue(&db, 1, JobKind::Survey, Band::Background, 0, 0);
	let barrier = Arc::new(std::sync::Barrier::new(2));
	let threads: Vec<_> = (0..2)
		.map(|_| {
			let db = db.clone();
			let policy = policy.clone();
			let barrier = barrier.clone();
			std::thread::spawn(move || {
				barrier.wait();
				take(&db, ALL, 100, &policy).map(|c| c.job.id)
			})
		})
		.collect();
	let claims: Vec<_> = threads.into_iter().filter_map(|thread| thread.join().unwrap()).collect();
	assert_eq!(claims, [survey]);
	db.with_conn(|c| {
		assert_eq!(
			c.query_row("SELECT burst FROM scheduler_repo_state WHERE repo_id=1", [], |r| r
				.get::<_, i64>(0))?,
			0
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn scheduler_state_rolls_back_with_a_failed_claim() {
	let db = projects();
	let survey = enqueue(&db, 1, JobKind::Survey, Band::Normal, 0, 0);
	db.with_conn(|c| {
		c.execute_batch("CREATE TEMP TRIGGER fail_deadline BEFORE UPDATE OF hard_deadline_at ON jobs BEGIN SELECT RAISE(ABORT,'injected deadline failure'); END;")?;
		let error=transaction::immediate(c,|tx|claim_kinds(tx,&ClaimRequest{worker_id:1,kinds:ALL,now:100,capability_hash:&[55;32],legacy_lease_seconds:600,policy:&ClaimPolicy::default()},ALL));
		assert!(error.is_err());
		assert_eq!(jobs::get(c,survey)?.unwrap().state,JobState::Queued);
		assert_eq!(c.query_row("SELECT seq FROM scheduler_clock",[],|r|r.get::<_,i64>(0))?,0);
		assert_eq!(c.query_row("SELECT COUNT(*) FROM scheduler_repo_state",[],|r|r.get::<_,i64>(0))?,0);
		Ok(())
	}).unwrap();
}

#[test]
fn seeded_random_queue_respects_caps_reservations_and_finishes() {
	const SEED: u64 = 0xB3_20260916;
	let mut rng = SEED;
	let mut next = || {
		rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
		rng >> 32
	};
	let db = projects();
	let policy = ClaimPolicy { active_jobs_total: Some(4), ..ClaimPolicy::default() };
	let mut queue = Vec::new();
	for _ in 0..40 {
		let repo = (next() % 3 + 1) as i64;
		let kind = ALL[next() as usize % 3].clone();
		let band = [Band::Urgent, Band::High, Band::Normal, Band::Background][next() as usize % 4];
		let priority = (next() % 20) as u32;
		let at = (next() % 5 * 20) as i64;
		let id = enqueue(&db, repo, kind.clone(), band, priority, 0);
		db.with_conn(|c| {
			c.execute("UPDATE jobs SET eligible_at=?2 WHERE id=?1", params![id, at])?;
			Ok(())
		})
		.unwrap();
		queue.push((id, repo, kind, band, priority, at));
	}
	let mut running = Vec::new();
	let mut completed = 0;
	for step in 0..500 {
		let kind = ALL[next() as usize % 3].clone();
		let now = step * 10;
		let claim = take(&db, &[kind], now, &policy);
		let idle = claim.is_none();
		if let Some(job) = claim {
			running.push(job.job.id);
			db.with_conn(|c| {
				let mut stmt=c.prepare("SELECT repo_id,COUNT(*),SUM(kind='survey'),SUM(kind='drilldown'),SUM(kind='verify') FROM jobs WHERE state='leased' AND campaign_id IS NOT NULL GROUP BY repo_id")?;
				let counts=stmt.query_map([],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
				assert!(counts.iter().map(|x|x.1).sum::<i64>()<=4,"seed={SEED:x}, queue={queue:?}");
				for (repo,total,surveys,drilldowns,verifies) in counts {
					assert!(total<=3&&surveys<=1&&drilldowns<=2&&verifies<=2,"seed={SEED:x}, queue={queue:?}");
					let waiting:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM jobs WHERE repo_id=?1 AND kind='verify' AND state='queued' AND eligible_at<=?2)",params![repo,now],|r|r.get(0))?;
					if job.job.repo_id==repo&&job.job.kind!=JobKind::Verify&&waiting {
						assert!(total<=3-(1-verifies).max(0),"reservation: seed={SEED:x}, queue={queue:?}");
					}
				}
				Ok(())
			}).unwrap();
		}
		if !running.is_empty() && (idle || next() % 2 == 0) {
			let index = next() as usize % running.len();
			finish(&db, running.swap_remove(index));
			completed += 1;
		}
		if completed == 40 {
			break;
		}
	}
	assert_eq!(completed, 40, "seed={SEED:x}, queue={queue:?}, running={running:?}");
}

#[test]
fn one_slot_rotation_uses_claim_order_even_at_identical_timestamps() {
	let db = projects();
	for _ in 0..4 {
		enqueue(&db, 1, JobKind::Survey, Band::Normal, 100, 0);
		enqueue(&db, 2, JobKind::Survey, Band::Normal, 0, 1);
	}
	let policy = ClaimPolicy { active_jobs_total: Some(1), ..ClaimPolicy::default() };
	let mut sequence = Vec::new();
	for _ in 0..8 {
		let claimed = take(&db, ALL, 100, &policy).unwrap();
		sequence.push(claimed.job.repo_id);
		finish(&db, claimed.job.id);
	}
	assert_eq!(
		sequence,
		[1, 2, 1, 2, 1, 2, 1, 2],
		"a busy older repository must not monopolize one slot"
	);
}

#[test]
fn retry_claims_also_advance_repository_rotation() {
	let db = projects();
	let retried = enqueue(&db, 1, JobKind::Survey, Band::Normal, 100, 0);
	let first = take(&db, ALL, 100, &ClaimPolicy::default()).unwrap();
	assert_eq!(first.job.id, retried);
	db.with_conn(|c| {
		assert_eq!(jobs::reap_stale_leases(c, 800)?, 1);
		Ok(())
	})
	.unwrap();
	let b = enqueue(&db, 2, JobKind::Survey, Band::Normal, 0, 1);
	assert_eq!(take(&db, ALL, 900, &ClaimPolicy::default()).unwrap().job.id, b);
	finish(&db, b);
	assert_eq!(take(&db, ALL, 900, &ClaimPolicy::default()).unwrap().job.id, retried);
	finish(&db, retried);
	let next_a = enqueue(&db, 1, JobKind::Survey, Band::Normal, 100, 0);
	let next_b = enqueue(&db, 2, JobKind::Survey, Band::Normal, 0, 1);
	assert_eq!(
		take(&db, ALL, 900, &ClaimPolicy::default()).unwrap().job.id,
		next_b,
		"a retry must rotate like every other claim"
	);
	finish(&db, next_b);
	assert_eq!(take(&db, ALL, 900, &ClaimPolicy::default()).unwrap().job.id, next_a);
}

#[test]
fn burst_offers_the_oldest_survey_before_band_and_score() {
	let db = projects();
	let policy = ClaimPolicy { urgency_burst_length: 2, ..ClaimPolicy::default() };
	for kind in [JobKind::Drilldown, JobKind::Verify] {
		enqueue(&db, 1, kind, Band::Urgent, 100, 0);
		let claimed = take(&db, ALL, 100, &policy).unwrap();
		finish(&db, claimed.job.id);
	}
	let older = enqueue(&db, 1, JobKind::Survey, Band::Background, 0, 0);
	enqueue(&db, 1, JobKind::Survey, Band::Urgent, 100, 1);
	enqueue(&db, 2, JobKind::Drilldown, Band::Urgent, 100, 0);
	enqueue(&db, 1, JobKind::Drilldown, Band::Background, 0, 0);
	assert_eq!(
		take(&db, ALL, 100, &policy).unwrap().job.id,
		older,
		"coverage debt offers the oldest survey, not the highest-band survey"
	);
}

#[test]
fn caps_and_verification_reservations_are_eligibility_not_preferences() {
	let db = projects();
	for _ in 0..3 {
		enqueue(&db, 1, JobKind::Survey, Band::Normal, 0, 0);
	}
	let policy = ClaimPolicy {
		active_jobs_per_repo: 2,
		active_surveys_per_repo: 2,
		active_drilldowns_per_repo: 2,
		active_verifications_per_repo: 2,
		verify_reserved_slots: 1,
		..ClaimPolicy::default()
	};
	assert!(take(&db, ALL, 100, &policy).is_some());
	let verify = enqueue(&db, 1, JobKind::Verify, Band::Normal, 0, 0);
	assert!(
		take(&db, &[JobKind::Survey], 100, &policy).is_none(),
		"a non-verifier must leave the reserved slot free"
	);
	assert_eq!(take(&db, ALL, 100, &policy).unwrap().job.id, verify);
	assert!(take(&db, ALL, 100, &policy).is_none(), "repository cap must hold");
	let other = enqueue(&db, 2, JobKind::Survey, Band::Normal, 0, 0);
	let capped = ClaimPolicy { active_jobs_total: Some(2), ..policy.clone() };
	assert!(take(&db, ALL, 100, &capped).is_none(), "global cap must hold");
	assert_eq!(take(&db, ALL, 100, &policy).unwrap().job.id, other);
}

#[test]
fn reservation_is_borrowable_without_an_eligible_verify() {
	for future in [false, true] {
		let db = projects();
		let policy = ClaimPolicy {
			active_jobs_per_repo: 2,
			active_surveys_per_repo: 2,
			..ClaimPolicy::default()
		};
		enqueue(&db, 1, JobKind::Survey, Band::Normal, 0, 0);
		enqueue(&db, 1, JobKind::Survey, Band::Normal, 0, 0);
		if future {
			enqueue(&db, 1, JobKind::Verify, Band::Urgent, 100, 500);
		}
		assert!(take(&db, &[JobKind::Survey], 100, &policy).is_some());
		assert!(take(&db, &[JobKind::Survey], 100, &policy).is_some());
	}
}

#[test]
fn per_kind_caps_hold_and_less_busy_repositories_rotate_first() {
	for (kind, policy) in [
		(JobKind::Survey, ClaimPolicy::default()),
		(
			JobKind::Drilldown,
			ClaimPolicy { active_drilldowns_per_repo: 1, ..ClaimPolicy::default() },
		),
		(
			JobKind::Verify,
			ClaimPolicy { active_verifications_per_repo: 1, ..ClaimPolicy::default() },
		),
	] {
		let db = projects();
		enqueue(&db, 1, kind.clone(), Band::Normal, 100, 0);
		enqueue(&db, 1, kind.clone(), Band::Normal, 100, 0);
		let claimed = take(&db, ALL, 100, &policy).unwrap();
		assert_eq!(claimed.job.repo_id, 1);
		assert!(take(&db, ALL, 100, &policy).is_none(), "kind cap: {kind:?}");
		let next = enqueue(&db, 2, kind, Band::Normal, 0, 1);
		assert_eq!(take(&db, ALL, 100, &policy).unwrap().job.id, next);
	}
	let db = projects();
	let policy = ClaimPolicy { active_surveys_per_repo: 2, ..ClaimPolicy::default() };
	enqueue(&db, 1, JobKind::Survey, Band::Normal, 100, 0);
	take(&db, ALL, 100, &policy).unwrap();
	enqueue(&db, 1, JobKind::Survey, Band::Normal, 100, 0);
	let other = enqueue(&db, 2, JobKind::Survey, Band::Normal, 0, 1);
	assert_eq!(take(&db, ALL, 100, &policy).unwrap().job.id, other);
}
