//! Server orchestration with explicit worker-state fixtures. Storage tests
//! exercise actual bootstrap/coverage/incremental claims without a reverse dependency.
use loupe_core::text::policy::Payload;
use loupe_core::text::BoundedJson;
use loupe_core::{JobKind, JobState};
use loupe_server::review::campaign;
use loupe_server::review::policy::ReviewPolicy;
use loupe_storage::scheduler::{self, Band, NewPhaseJob};
use loupe_storage::source_refs::InspectedRefs;
use loupe_storage::{campaigns, generations, jobs, review_unit_results, transaction};
use rusqlite::{params, Transaction};

// Pinning only accepts complete object ids.
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// B3 intentionally cannot lease phase jobs through the public runtime path.
// Once B4 enables it, the combined lifecycle test should use that path.
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
	Ok(jobs::get(tx, job_id)?.unwrap())
}

#[test]
fn bootstrap_to_coverage_preserves_the_profile_and_activation() {
	let db =
		loupe_storage::Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap();
	db.with_conn(|c| transaction::immediate(c, |tx| {
		tx.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(1,'u','github.com','o','r','{\"kind\":\"manual\"}',0)",[])?;
		let worker=loupe_storage::workers::insert(tx,"lifecycle",loupe_storage::workers::WorkerKind::Worker,&[7;32],0)?;
		let opened=campaign::open(tx,&campaign::OpenCampaign{repo_id:1,trigger:"manual".parse().unwrap(),requested_ref:campaign::RequestedRef::Branch("main"),base_sha:None,kind_hint:campaign::KindHint::Incremental},&ReviewPolicy::default(),0).unwrap();
		let campaign::Opened::Created{campaign_id,job_id}=opened else {panic!("new campaign")};
		let generation=campaign::pin(tx,campaign_id,job_id,SHA,1).unwrap();
		let bootstrap=lease_fixture(tx,job_id,worker)?;
		assert_eq!(bootstrap.kind,JobKind::Survey);
		assert_eq!(bootstrap.generation_id,Some(generation));
		let recipe:serde_json::Value=serde_json::from_str(bootstrap.recipe.as_ref().unwrap().expose()).unwrap();
		assert_eq!(recipe["recipe"],"bootstrap");
		let payload=BoundedJson::<Payload>::new("{}")?;
		generations::set_profile(tx,generation,1,&payload)?;
		tx.execute("UPDATE review_generations SET inventory_digest=zeroblob(32) WHERE generation_id=?1",[generation])?;
		for (i,band) in ["background","normal","urgent","high","normal","urgent"].iter().enumerate() {
			tx.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,priority_band,created_at) VALUES(?1,?2,?3,'t','o','[]',?4,?1)",params![i as i64+1,generation,format!("unit-{i}"),band])?;
		}
		let refs=InspectedRefs::new(vec![])?;
		let record=|unit,job|review_unit_results::insert(tx,&review_unit_results::NewResult{generation_id:generation,unit_id:unit,produced_by_job:Some(job),commit_sha:SHA,profile_version:1,disposition:review_unit_results::Disposition::NoLeadFound,inspected_refs:&refs,counterevidence:None,proof_gaps:None,payload:&payload,corroborates_result:None,corroborates_exclusion:None},3);
		for unit in [1,2] {record(unit,job_id)?;}
		assert_eq!(campaign::replenish(tx,campaign_id,3).unwrap(),None);
		// B5's finalize supplies the terminal transition and checkpoint envelope.
		tx.execute("UPDATE jobs SET state='succeeded',finished_at=3 WHERE id=?1",[job_id])?;
		campaign::activate_generation(tx,campaign_id,3).unwrap();
		let coverage=campaign::replenish(tx,campaign_id,3).unwrap().unwrap();
		let batch=lease_fixture(tx,coverage,worker)?;
		assert_eq!(batch.kind,JobKind::Survey);
		assert_eq!(batch.generation_id,Some(generation));
		assert_eq!(batch.continuation_of_job_id,Some(job_id));
		let recipe:serde_json::Value=serde_json::from_str(batch.recipe.as_ref().unwrap().expose()).unwrap();
		assert_eq!(recipe["recipe"],"coverage");
		// Supply completed worker results; storage's companion test checks
		// that the real claim selects exactly these four uncovered units.
		for unit in [3,6,4,5] {record(unit,coverage)?;}
		tx.execute("UPDATE jobs SET state='succeeded',finished_at=5 WHERE id=?1",[coverage])?;
		assert_eq!(campaign::replenish(tx,campaign_id,5).unwrap(),None);
		assert!(generations::coverage_rollup(tx,generation)?.complete());
		let after=generations::get(tx,generation)?.unwrap();
		assert_eq!(after.profile_version,1);
		assert_eq!(after.activated_at,Some(3));
		assert_eq!(campaign::try_finish(tx,campaign_id,5).unwrap(),Some(campaign::Finish::Completed));
		let row=campaigns::get(tx,campaign_id)?.unwrap();
		assert_eq!(row.state,campaigns::State::Finished);
		assert!(row.terminal_counts.is_some());

		// The activated baseline survives campaign boundaries. The next
		// incremental survey reuses it, including profile and activation time.
		let opened=campaign::open(tx,&campaign::OpenCampaign{repo_id:1,trigger:"manual".parse().unwrap(),requested_ref:campaign::RequestedRef::Pinned(SHA),base_sha:Some(SHA),kind_hint:campaign::KindHint::Incremental},&ReviewPolicy::default(),6).unwrap();
		let campaign::Opened::Created{campaign_id:second,job_id:initial}=opened else {panic!("second campaign")};
		let row=campaigns::get(tx,second)?.unwrap();
		assert_eq!(row.recipe,campaigns::Recipe::Incremental);
		assert_eq!(row.generation_id,Some(generation));
		let incremental=lease_fixture(tx,initial,worker)?;
		assert_eq!(incremental.kind,JobKind::Survey);
		assert_eq!(incremental.generation_id,Some(generation));
		let recipe:serde_json::Value=serde_json::from_str(incremental.recipe.as_ref().unwrap().expose()).unwrap();
		assert_eq!(recipe["recipe"],"incremental");
		// Storage's companion claim test checks that this baseline yields
		// an empty incremental batch after all units have been completed.
		let recipe=BoundedJson::<Payload>::new(r#"{"version":1,"phase":"survey","recipe":"incremental","assignment_key":"ordinary"}"#)?;
		let queued=scheduler::enqueue_phase(tx,&NewPhaseJob{repo_id:1,kind:JobKind::Survey,campaign_id:second,generation_id:Some(generation),assigned_lead_id:None,target_finding_id:None,continuation_of_job_id:None,band:Band::Normal,effective_priority:0,eligible_at:7,token_budget:None,recipe:&recipe,handoff:false},7)?;
		let deadline=row.deadline_at.unwrap();
		assert_eq!(campaign::try_finish(tx,second,deadline).unwrap(),None);
		assert_eq!(jobs::get(tx,queued)?.unwrap().state,JobState::Cancelled);
		assert_eq!(jobs::get(tx,initial)?.unwrap().state,JobState::Leased);
		tx.execute("UPDATE jobs SET state='succeeded',finished_at=?2 WHERE id=?1",params![initial,deadline+1])?;
		assert_eq!(campaign::try_finish(tx,second,deadline+1).unwrap(),Some(campaign::Finish::DeadlineReached));
		let after=generations::get(tx,generation)?.unwrap();
		assert_eq!(after.profile_version,1);
		assert_eq!(after.generated_profile.as_ref(),Some(&payload));
		assert_eq!(after.activated_at,Some(3));
		Ok(())
	})).unwrap();
}
