use loupe_core::text::policy::{Payload, Reason};
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_core::{JobKind, JobState};
use rusqlite::params;

use super::*;
use crate::{jobs, review_tests, transaction, Conflict, Error, Ownership};

fn fixture() -> crate::Db {
	let db = review_tests::fixture();
	db.with_conn(|conn| {
		let policy = BoundedJson::<Payload>::new(&serde_json::to_string(&CampaignPolicy::default()).unwrap())?;
		conn.execute("UPDATE review_campaigns SET effective_policy=?1,effective_policy_digest=?2,deadline_at=10000", params![policy.expose(),policy.digest().as_slice()])?;
		conn.execute_batch("UPDATE jobs SET state='succeeded';
		INSERT INTO leads (lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at)
		VALUES (11,11,'f','a',zeroblob(32),'{}',zeroblob(32),'base',0),
		(12,12,'f','a',zeroblob(32),'{}',zeroblob(32),'next',0),
		(21,21,'f','a',zeroblob(32),'{}',zeroblob(32),'foreign',0);
		INSERT INTO findings (id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,created_at)
		VALUES (11,1,101,'test','high','t','d','f','validating',0),
		(21,2,201,'test','high','t','d','f','validating',0);")?;
		Ok(())
	}).unwrap();
	db
}

fn recipe() -> BoundedJson<Payload> {
	BoundedJson::new(
		r#"{"version":1,"phase":"survey","recipe":"coverage","assignment_key":"ordinary"}"#,
	)
	.unwrap()
}

fn survey(recipe: &BoundedJson<Payload>) -> NewPhaseJob<'_> {
	NewPhaseJob {
		repo_id: 1,
		kind: JobKind::Survey,
		campaign_id: 1,
		generation_id: Some(11),
		assigned_lead_id: None,
		target_finding_id: None,
		continuation_of_job_id: None,
		band: Band::Normal,
		effective_priority: 0,
		eligible_at: 0,
		token_budget: None,
		recipe,
		handoff: false,
	}
}

#[test]
fn phase_enqueue_checks_shape_ownership_and_round_trips_columns() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let recipe = recipe();
			let mut new = survey(&recipe);
			for kind in [JobKind::Scan, JobKind::Unknown("survey".into())] {
				new.kind = kind;
				assert!(matches!(enqueue_phase(tx, &new, 1), Err(Error::Validation(_))));
			}
			new.kind = JobKind::Drilldown;
			assert!(matches!(enqueue_phase(tx, &new, 1), Err(Error::Validation(_))));
			new.assigned_lead_id = Some(12);
			assert!(matches!(
				enqueue_phase(tx, &new, 1),
				Err(Error::Ownership(Ownership::JobLead))
			));
			new.assigned_lead_id = Some(21);
			assert!(matches!(
				enqueue_phase(tx, &new, 1),
				Err(Error::Ownership(Ownership::JobLead))
			));
			new.assigned_lead_id = Some(11);
			new.generation_id = Some(12);
			assert!(matches!(enqueue_phase(tx, &new, 1), Err(Error::Validation(_))));
			new.generation_id = Some(11);
			new.effective_priority = 2000;
			new.token_budget = Some(100);
			new.eligible_at = 20;
			let id = enqueue_phase(tx, &new, 1)?;
			let row = jobs::get(tx, id)?.unwrap();
			assert_eq!(row.campaign_id, Some(1));
			assert_eq!(row.generation_id, Some(11));
			assert_eq!(row.assigned_lead_id, Some(11));
			assert_eq!(row.effective_priority, Some(1000));
			assert_eq!(row.eligible_at, Some(20));
			assert_eq!(row.token_budget, Some(100));
			assert_eq!(row.scheduling_band, Some(Band::Normal));
			assert_eq!(row.recipe.as_ref(), Some(&recipe));
			assert_eq!(row.workflow_contract_version, Some(1));
			assert!(matches!(
				enqueue_phase(tx, &new, 1),
				Err(Error::Conflict(Conflict::ActiveDrilldown))
			));
			new.kind = JobKind::Verify;
			assert!(matches!(enqueue_phase(tx, &new, 1), Err(Error::Validation(_))));
			new.assigned_lead_id = None;
			assert!(matches!(enqueue_phase(tx, &new, 1), Err(Error::Validation(_))));
			new.target_finding_id = Some(21);
			assert!(matches!(
				enqueue_phase(tx, &new, 1),
				Err(Error::Ownership(Ownership::JobFinding))
			));
			new.target_finding_id = Some(11);
			enqueue_phase(tx, &new, 1)?;
			assert!(matches!(
				enqueue_phase(tx, &new, 1),
				Err(Error::Conflict(Conflict::ActiveVerify))
			));
			new = survey(&recipe);
			new.assigned_lead_id = Some(11);
			assert!(matches!(enqueue_phase(tx, &new, 1), Err(Error::Validation(_))));
			new.assigned_lead_id = None;
			new.target_finding_id = Some(11);
			assert!(matches!(enqueue_phase(tx, &new, 1), Err(Error::Validation(_))));
			new.target_finding_id = None;
			new.generation_id = None;
			assert!(matches!(enqueue_phase(tx, &new, 1), Err(Error::Validation(_))));
			tx.execute("UPDATE review_campaigns SET generation_id=NULL WHERE campaign_id=1", [])?;
			enqueue_phase(tx, &new, 1)?;
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn phase_enqueue_rejects_campaign_and_continuation_mismatches() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let recipe = recipe();
			let mut new = survey(&recipe);
			new.campaign_id = 2;
			assert!(matches!(
				enqueue_phase(tx, &new, 1),
				Err(Error::Conflict(Conflict::CampaignState))
			));
			new.campaign_id = 1;
			for state in ["cancelled", "finished"] {
				tx.execute("UPDATE review_campaigns SET state=?1 WHERE campaign_id=1", [state])?;
				assert!(matches!(
					enqueue_phase(tx, &new, 1),
					Err(Error::Conflict(Conflict::CampaignState))
				));
			}
			tx.execute("UPDATE review_campaigns SET state='active' WHERE campaign_id=1", [])?;
			assert!(matches!(
				enqueue_phase(tx, &new, 10000),
				Err(Error::Conflict(Conflict::CampaignState))
			));
			new.token_budget = Some(0);
			assert!(matches!(enqueue_phase(tx, &new, 1), Err(Error::Validation(_))));
			new.token_budget = Some(u64::MAX);
			assert!(matches!(enqueue_phase(tx, &new, 1), Err(Error::Validation(_))));
			new.token_budget = None;
			new.continuation_of_job_id = Some(201);
			assert!(matches!(
				enqueue_phase(tx, &new, 1),
				Err(Error::Ownership(Ownership::JobContinuation))
			));
			new.continuation_of_job_id = Some(101);
			tx.execute("UPDATE jobs SET state='leased' WHERE id=101", [])?;
			assert!(matches!(
				enqueue_phase(tx, &new, 1),
				Err(Error::Ownership(Ownership::JobContinuation))
			));
			tx.execute("UPDATE jobs SET state='succeeded',kind='verify' WHERE id=101", [])?;
			assert!(matches!(
				enqueue_phase(tx, &new, 1),
				Err(Error::Ownership(Ownership::JobContinuation))
			));
			tx.execute("UPDATE jobs SET kind='survey' WHERE id=101", [])?;
			let id = enqueue_phase(tx, &new, 1)?;
			assert_eq!(jobs::get(tx, id)?.unwrap().continuation_of_job_id, Some(101));
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn campaign_budget_reserves_handoffs_and_counts_terminal_jobs() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let policy = CampaignPolicy {
				campaign_max_jobs: 4,
				campaign_handoff_reserve: 1,
				..CampaignPolicy::default()
			};
			let value = BoundedJson::<Payload>::new(&serde_json::to_string(&policy).unwrap())?;
			tx.execute(
				"UPDATE review_campaigns SET effective_policy=?1 WHERE campaign_id=1",
				[value.expose()],
			)?;
			let recipe = recipe();
			let mut new = survey(&recipe);
			enqueue_phase(tx, &new, 1)?; // Two terminal jobs already count against the budget.
			new.handoff = true;
			assert!(matches!(
				enqueue_phase(tx, &new, 1),
				Err(Error::Conflict(Conflict::CampaignBudget))
			));
			new.kind = JobKind::Drilldown;
			new.assigned_lead_id = Some(11);
			enqueue_phase(tx, &new, 1)?;
			new.kind = JobKind::Verify;
			new.assigned_lead_id = None;
			new.target_finding_id = Some(11);
			assert!(matches!(
				enqueue_phase(tx, &new, 1),
				Err(Error::Conflict(Conflict::CampaignBudget))
			));
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn frozen_policy_round_trip_and_backoff_are_bounded() {
	let policy = CampaignPolicy::default();
	let snapshot = BoundedJson::<Payload>::new(&serde_json::to_string(&policy).unwrap()).unwrap();
	assert_eq!(CampaignPolicy::from_snapshot(&snapshot).unwrap(), policy);
	assert_eq!(
		(1..=8).map(|n| policy.retry_delay(n)).collect::<Vec<_>>(),
		[60, 120, 240, 480, 960, 1920, 3600, 3600]
	);
	assert_eq!(policy.retry_delay(u32::MAX), 3600);
	for raw in [
		"{}",
		&snapshot.expose().replace("\"version\":1", "\"version\":2"),
		&snapshot.expose().replace("\"max_attempts\":3", "\"max_attempts\":0"),
	] {
		assert!(matches!(
			CampaignPolicy::from_snapshot(&BoundedJson::new(raw).unwrap()),
			Err(Error::Conflict(Conflict::CampaignPolicy))
		));
	}
}

#[test]
fn retries_use_snapshot_limits_and_preserve_assignments() {
	let db = fixture();
	db.with_conn(|conn| transaction::immediate(conn, |tx| {
		let policy = CampaignPolicy { max_attempts: 5, ..CampaignPolicy::default() };
		let snapshot = BoundedJson::<Payload>::new(&serde_json::to_string(&policy).unwrap())?;
		tx.execute("UPDATE review_campaigns SET effective_policy=?1 WHERE campaign_id=1", [snapshot.expose()])?;
		tx.execute_batch("UPDATE jobs SET state='leased',attempts=4,hard_deadline_at=500,submit_by=400,soft_deadline_at=400,job_capability_hash=zeroblob(32) WHERE id=101;
		INSERT INTO review_units (review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES (1,11,'u','t','o','[]',0);
		INSERT INTO job_assigned_review_units VALUES (101,1,0,0);")?;
		let error = BoundedText::<Reason>::new("execution failure")?;
		assert_eq!(retry_or_fail(tx, 101, 100, &error)?, RetryOutcome::Requeued { eligible_at: 580 });
		let job = jobs::get(tx, 101)?.unwrap();
		assert_eq!(job.state, JobState::Queued);
		assert_eq!(job.eligible_at, Some(580));
		assert_eq!(job.hard_deadline_at, None);
		assert_eq!(job.submit_by, None);
		assert_eq!(job.soft_deadline_at, None);
		assert_eq!(tx.query_row("SELECT COUNT(*) FROM job_assigned_review_units WHERE job_id=101", [], |r|r.get::<_,i64>(0))?, 1);
		tx.execute("UPDATE jobs SET state='leased',attempts=5 WHERE id=101", [])?;
		assert_eq!(retry_or_fail(tx, 101, 1000, &error)?, RetryOutcome::Failed);
		assert_eq!(jobs::get(tx, 101)?.unwrap().error.as_deref(), Some("execution failure"));
		assert!(retry_or_fail(tx, 101, 1001, &error).is_err(), "terminal jobs must not be retried");
		Ok(())
	})).unwrap();
}

#[test]
fn queued_cancellation_leaves_leased_jobs_alone() {
	let db = fixture();
	db.with_conn(|conn| transaction::immediate(conn, |tx| {
		tx.execute_batch("UPDATE jobs SET state='queued' WHERE id=101; UPDATE jobs SET state='leased' WHERE id=102;")?;
		assert_eq!(cancel_queued_children(tx, 1, 100, &BoundedText::new("campaign deadline")?)?, 1);
		assert_eq!(jobs::get(tx, 101)?.unwrap().state, JobState::Cancelled);
		assert_eq!(jobs::get(tx, 101)?.unwrap().finished_at, Some(100));
		assert_eq!(jobs::get(tx, 102)?.unwrap().state, JobState::Leased);
		Ok(())
	})).unwrap();
}

#[test]
fn reaper_uses_campaign_attempts_without_changing_legacy_limits() {
	let db = fixture();
	db.with_conn(|conn| {
		let policy = CampaignPolicy { max_attempts: 5, ..CampaignPolicy::default() };
		let snapshot = BoundedJson::<Payload>::new(&serde_json::to_string(&policy).unwrap())?;
		conn.execute("UPDATE review_campaigns SET effective_policy=?1 WHERE campaign_id=1", [snapshot.expose()])?;
		conn.execute_batch("UPDATE jobs SET kind='verify',state='leased',lease_expires_at=100,attempts=3 WHERE id=101;
		INSERT INTO jobs (repo_id,kind,state,lease_expires_at,attempts,enqueued_at) VALUES (1,'scan','leased',100,3,0);")?;
		let legacy = conn.last_insert_rowid();
		assert_eq!(jobs::reap_stale_leases(conn, 101)?, 2);
		assert_eq!(jobs::get(conn, 101)?.unwrap().state, JobState::Queued);
		assert_eq!(jobs::get(conn, 101)?.unwrap().eligible_at, Some(341));
		assert_eq!(jobs::get(conn, legacy)?.unwrap().state, JobState::Failed);
		Ok(())
	}).unwrap();
}

#[test]
fn inactive_drilldown_reaping_releases_assignment_for_next_campaign() {
	let db = fixture();
	db.with_conn(|conn| {
		conn.execute_batch("UPDATE jobs SET kind='drilldown',assigned_lead_id=11,state='leased',lease_expires_at=100,attempts=1 WHERE id=101;
		UPDATE review_campaigns SET state='cancelled' WHERE campaign_id=1;")?;
		assert_eq!(jobs::reap_stale_leases(conn, 101)?, 1);
		assert_eq!(jobs::get(conn, 101)?.unwrap().state, JobState::Failed);
		transaction::immediate(conn, |tx| {
			let snapshot = BoundedJson::<Payload>::new(&serde_json::to_string(&CampaignPolicy::default()).unwrap())?;
			let campaign = crate::campaigns::create(tx, &crate::campaigns::NewCampaign {
				repo_id: 1, recipe: crate::campaigns::Recipe::Incremental, trigger: crate::campaigns::Trigger::Manual,
				requested_base_sha: None, target_commit_sha: "base", generation_id: Some(11), effective_policy: &snapshot,
				deadline_at: None, root_campaign_id: None, continuation_of_campaign_id: None,
			}, 102)?;
			let recipe = recipe();
			let mut new = survey(&recipe);
			new.campaign_id = campaign;
			new.kind = JobKind::Drilldown;
			new.assigned_lead_id = Some(11);
			enqueue_phase(tx, &new, 102)?;
			Ok(())
		})
	}).unwrap();
}

#[test]
fn reaper_never_requeues_children_of_inactive_campaigns() {
	let db = review_tests::fixture();
	db.with_conn(|conn| {
		conn.execute_batch(
			"UPDATE review_campaigns SET state='cancelled' WHERE campaign_id=1;
		UPDATE jobs SET kind='verify',state='leased',lease_expires_at=100,attempts=1 WHERE id=101;
		INSERT INTO jobs (repo_id,kind,state,lease_expires_at,attempts,enqueued_at)
		VALUES (1,'scan','leased',100,1,0);",
		)?;
		let legacy = conn.last_insert_rowid();
		assert_eq!(jobs::reap_stale_leases(conn, 101)?, 2);
		assert_eq!(
			jobs::get(conn, 101)?.unwrap().state,
			loupe_core::JobState::Failed,
			"an inactive campaign child must fail instead of becoming a queued orphan"
		);
		assert_eq!(jobs::get(conn, legacy)?.unwrap().state, loupe_core::JobState::Queued);
		let eligible: Option<i64> =
			conn.query_row("SELECT eligible_at FROM jobs WHERE id=?1", [legacy], |r| r.get(0))?;
		assert_eq!(eligible, None, "legacy requeues must not acquire campaign backoff");
		Ok(())
	})
	.unwrap();
}
mod claim;
mod fairness;

#[test]
fn scheduler_state_is_connection_local_and_ensure_is_idempotent() {
	let key = crate::secrets::MasterKey::for_tests();
	let memory = crate::Db::open_in_memory(&key).unwrap();
	memory.with_conn(|c| {
		assert_eq!(c.query_row("SELECT COUNT(*) FROM sqlite_temp_master WHERE type='table' AND name IN ('scheduler_clock','scheduler_repo_state')",[],|r|r.get::<_,i64>(0))?,2);
		Ok(())
	}).unwrap();
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("scheduler.db");
	let db = crate::Db::open(&path, &key).unwrap();
	db.with_conn(|c| {
		c.execute("UPDATE scheduler_clock SET seq=7", [])?;
		c.execute("INSERT INTO scheduler_repo_state VALUES(1,7,3)", [])?;
		ensure_state(c)?;
		assert_eq!(c.query_row("SELECT seq FROM scheduler_clock", [], |r| r.get::<_, i64>(0))?, 7);
		assert_eq!(
			c.query_row(
				"SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'scheduler_%'",
				[],
				|r| r.get::<_, i64>(0)
			)?,
			0
		);
		Ok(())
	})
	.unwrap();
	drop(db);
	crate::Db::open(&path, &key)
		.unwrap()
		.with_conn(|c| {
			assert_eq!(
				c.query_row("SELECT seq FROM scheduler_clock", [], |r| r.get::<_, i64>(0))?,
				0
			);
			assert_eq!(
				c.query_row("SELECT COUNT(*) FROM scheduler_repo_state", [], |r| r
					.get::<_, i64>(0))?,
				0
			);
			Ok(())
		})
		.unwrap();
}

#[test]
fn an_unreadable_campaign_snapshot_never_blocks_legacy_reaping() {
	let db = fixture();
	db.with_conn(|conn| {
		conn.execute_batch("UPDATE review_campaigns SET effective_policy='{}' WHERE campaign_id=1;
		UPDATE jobs SET kind='survey',state='leased',lease_expires_at=100,attempts=1 WHERE id=101;
		INSERT INTO jobs (repo_id,kind,state,lease_expires_at,attempts,enqueued_at) VALUES (1,'scan','leased',100,1,0);")?;
		let legacy = conn.last_insert_rowid();
		// The reaper must keep reclaiming legacy leases and must leave a
		// durable trace on the campaign job it could not decide about.
		assert_eq!(jobs::reap_stale_leases(conn, 101)?, 2);
		assert_eq!(jobs::get(conn, legacy)?.unwrap().state, JobState::Queued);
		let stuck = jobs::get(conn, 101)?.unwrap();
		assert_eq!(stuck.state, JobState::Failed);
		assert!(stuck.error.as_deref().is_some_and(|e| e.contains("CampaignPolicy")), "{:?}", stuck.error);
		assert_eq!(jobs::reap_stale_leases(conn, 102)?, 0);
		Ok(())
	}).unwrap();
}
