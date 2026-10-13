//! Server orchestration with explicit worker-state fixtures. Storage tests
//! exercise actual bootstrap/coverage/incremental claims without a reverse dependency.
use loupe_core::text::policy::Payload;
use loupe_core::{JobKind, JobState};
use loupe_storage::scheduler::{self, Band, NewPhaseJob};
use loupe_storage::{campaigns, generations, jobs, review_unit_results, transaction};
use rusqlite::{params, Transaction};

use crate::scheduler::CampaignPolicy as ReviewPolicy;
use crate::{campaign_workflow as campaign, server_campaign_support as common};

// Pinning only accepts complete object ids.
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// Campaign phase jobs have no public runtime handler, so this fixture
// supplies their lease state directly.
fn lease_fixture(
	tx: &Transaction<'_>, job_id: i64, worker: i64,
) -> loupe_storage::Result<jobs::JobRow> {
	assert_eq!(
		tx.execute(
			"UPDATE jobs SET state='leased',worker_id=?2 WHERE id=?1 AND state='queued'",
			params![job_id, worker],
		)?,
		1
	);
	Ok(jobs::get(&crate::test_support::scope(tx, 1), job_id)?.unwrap())
}

#[test]
fn bootstrap_to_coverage_preserves_the_profile_and_activation() {
	let db =
		loupe_storage::Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap();
	db.with_conn(|c| transaction::immediate(c, |tx| {
		tx.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(1,'u','github.com','o','r','{\"kind\":\"manual\"}',0)",[])?;
		let worker=loupe_storage::workers::insert(tx,&common::marked::operator::text("lifecycle"),loupe_storage::workers::WorkerKind::Worker,&[7;32],0)?;
		let opened=campaign::open(&crate::test_support::scope(tx,1),&campaign::OpenCampaign{trigger:"manual".parse().unwrap(),requested_ref:campaign::RequestedRef::Branch(&common::marked::operator::text("main")),base_sha:None,kind_hint:campaign::KindHint::Incremental},&ReviewPolicy::default(),0).unwrap();
		let campaign::Opened::Created{campaign_id,job_id}=opened else {panic!("new campaign")};
		let generation=campaign::pin(&crate::test_support::scope(tx,1),campaign_id,job_id,&common::marked::repo::text(SHA),1).unwrap();
		let bootstrap=lease_fixture(tx,job_id,worker)?;
		assert_eq!(bootstrap.kind,JobKind::Survey);
		assert_eq!(bootstrap.generation_id,Some(generation));
		let recipe:serde_json::Value=serde_json::from_str(bootstrap.recipe.as_ref().unwrap().expose()).unwrap();
		assert_eq!(recipe["recipe"],"bootstrap");
		common::assert_survey_recipe(tx, &bootstrap, "bootstrap");
		let payload=common::marked::agent::json::<Payload>("{}");
		generations::set_profile(&crate::test_support::scope(tx,1),generation,1,&payload)?;
		tx.execute("UPDATE review_generations SET inventory_digest=zeroblob(32) WHERE generation_id=?1",[generation])?;
		for (i,band) in ["background","normal","urgent","high","normal","urgent"].iter().enumerate() {
			tx.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,priority_band,created_at) VALUES(?1,?2,?3,'t','o','[]',?4,?1)",params![i as i64+1,generation,format!("unit-{i}"),band])?;
		}
		let refs=common::marked::agent::empty_refs();
		let record=|unit,job|review_unit_results::insert(&crate::test_support::scope(tx,1),&review_unit_results::NewResult{generation_id:generation,unit_id:unit,produced_by_job:Some(job),commit_sha:&common::marked::repo::text(SHA),profile_version:1,disposition:review_unit_results::Disposition::NoLeadFound,inspected_refs:&refs,counterevidence:None,proof_gaps:None,payload:&payload,corroborates_result:None,corroborates_exclusion:None},3);
		for unit in [1,2] {record(unit,job_id)?;}
		assert_eq!(campaign::replenish(&crate::test_support::scope(tx,1),campaign_id,3).unwrap(),None);
		// Model finalization's terminal transition and checkpoint envelope.
		tx.execute("UPDATE jobs SET state='succeeded',finished_at=3 WHERE id=?1",[job_id])?;
		campaign::activate_generation(&crate::test_support::scope(tx,1),campaign_id,3).unwrap();
		let coverage=campaign::replenish(&crate::test_support::scope(tx,1),campaign_id,3).unwrap().unwrap();
		let batch=lease_fixture(tx,coverage,worker)?;
		assert_eq!(batch.kind,JobKind::Survey);
		assert_eq!(batch.generation_id,Some(generation));
		assert_eq!(batch.continuation_of_job_id,Some(job_id));
		let recipe:serde_json::Value=serde_json::from_str(batch.recipe.as_ref().unwrap().expose()).unwrap();
		assert_eq!(recipe["recipe"],"coverage");
		common::assert_survey_recipe(tx, &batch, "coverage");
		// Supply completed worker results; storage's companion test checks
		// that the real claim selects exactly these four uncovered units.
		for unit in [3,6,4,5] {record(unit,coverage)?;}
		tx.execute("UPDATE jobs SET state='succeeded',finished_at=5 WHERE id=?1",[coverage])?;
		assert_eq!(campaign::replenish(&crate::test_support::scope(tx,1),campaign_id,5).unwrap(),None);
		assert!(generations::coverage_rollup(&crate::test_support::scope(tx,1),generation)?.complete());
		let after=generations::get(&crate::test_support::scope(tx,1),generation)?.unwrap();
		assert_eq!(after.profile_version,1);
		assert_eq!(after.activated_at,Some(3));
		assert_eq!(campaign::try_finish(&crate::test_support::scope(tx,1),campaign_id,5).unwrap(),Some(campaign::Finish::Completed));
		let row=campaigns::get(&crate::test_support::scope(tx,1),campaign_id)?.unwrap();
		assert_eq!(row.state,campaigns::State::Finished);
		assert!(row.terminal_counts.is_some());

		// The activated baseline survives campaign boundaries. The next
		// incremental survey reuses it, including profile and activation time.
		let opened=campaign::open(&crate::test_support::scope(tx,1),&campaign::OpenCampaign{trigger:"manual".parse().unwrap(),requested_ref:campaign::RequestedRef::Pinned(&common::marked::operator::text(SHA)),base_sha:Some(&common::marked::operator::text(SHA)),kind_hint:campaign::KindHint::Incremental},&ReviewPolicy::default(),6).unwrap();
		let campaign::Opened::Created{campaign_id:second,job_id:initial}=opened else {panic!("second campaign")};
		let row=campaigns::get(&crate::test_support::scope(tx,1),second)?.unwrap();
		assert_eq!(row.recipe,campaigns::Recipe::Incremental);
		assert_eq!(row.generation_id,Some(generation));
		let incremental=lease_fixture(tx,initial,worker)?;
		assert_eq!(incremental.kind,JobKind::Survey);
		assert_eq!(incremental.generation_id,Some(generation));
		let recipe:serde_json::Value=serde_json::from_str(incremental.recipe.as_ref().unwrap().expose()).unwrap();
		assert_eq!(recipe["recipe"],"incremental");
		common::assert_survey_recipe(tx, &incremental, "incremental");
		// Storage's companion claim test checks that this baseline yields
		// an empty incremental batch after all units have been completed.
		let recipe=common::marked::agent::json::<Payload>(r#"{"version":1,"phase":"survey","recipe":"incremental","assignment_key":"ordinary"}"#);
		let queued=scheduler::enqueue_phase(&crate::test_support::scope(tx,1),&NewPhaseJob{kind:JobKind::Survey,campaign_id:second,generation_id:Some(generation),assigned_lead_id:None,target_finding_id:None,continuation_of_job_id:None,band:Band::Normal,effective_priority:0,eligible_at:7,token_budget:None,recipe:loupe_storage::scheduler::PhaseRecipeInput::Submitted(&recipe),handoff:false},7)?;
		common::assert_survey_recipe(tx, &jobs::get(&crate::test_support::scope(tx,1), queued)?.unwrap(), "incremental");
		let deadline=row.deadline_at.unwrap();
		assert_eq!(campaign::try_finish(&crate::test_support::scope(tx,1),second,deadline).unwrap(),None);
		assert_eq!(jobs::get(&crate::test_support::scope(tx,1),queued)?.unwrap().state,JobState::Cancelled);
		assert_eq!(jobs::get(&crate::test_support::scope(tx,1),initial)?.unwrap().state,JobState::Leased);
		tx.execute("UPDATE jobs SET state='succeeded',finished_at=?2 WHERE id=?1",params![initial,deadline+1])?;
		assert_eq!(campaign::try_finish(&crate::test_support::scope(tx,1),second,deadline+1).unwrap(),Some(campaign::Finish::DeadlineReached));
		let after=generations::get(&crate::test_support::scope(tx,1),generation)?.unwrap();
		assert_eq!(after.profile_version,1);
		assert_eq!(after.generated_profile.as_ref().map(|v| v.expose()),Some(payload.expose()));
		assert_eq!(after.activated_at,Some(3));
		Ok(())
	})).unwrap();
}
