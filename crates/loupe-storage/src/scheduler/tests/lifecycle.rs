//! Real server orchestration plus the private storage phase claim path.
use loupe_server::review::campaign;
use loupe_server::review::policy::ReviewPolicy;

use super::*;
use crate::source_refs::InspectedRefs;
use crate::{generations, review_unit_results};

// Pinning only accepts complete object ids.
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn bootstrap_to_coverage_preserves_the_profile_and_activation() {
	let db = crate::Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
	db.with_conn(|c| transaction::immediate(c, |tx| {
		tx.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(1,'u','github.com','o','r','{\"kind\":\"manual\"}',0)",[])?;
		let worker=crate::workers::insert(tx,"lifecycle",crate::workers::WorkerKind::Worker,&[7;32],0)?;
		let opened=campaign::open(tx,&campaign::OpenCampaign{repo_id:1,trigger:"manual".parse().unwrap(),requested_ref:campaign::RequestedRef::Branch("main"),base_sha:None,kind_hint:campaign::KindHint::Incremental},&ReviewPolicy::default(),0).unwrap();
		let campaign::Opened::Created{campaign_id,job_id}=opened else {panic!("new campaign")};
		let generation=campaign::pin(tx,campaign_id,job_id,SHA,1).unwrap();
		let kinds=[JobKind::Survey];
		let policy=ClaimPolicy::default();
		let mut request=ClaimRequest{worker_id:worker,kinds:&kinds,now:2,capability_hash:&[4;32],legacy_lease_seconds:600,policy:&policy};
		let bootstrap=claim_kinds(tx,&request,&kinds)?.unwrap();
		assert_eq!(bootstrap.job.id,job_id);
		assert!(bootstrap.assigned_units.is_empty());
		generations::set_profile(tx,generation,1,&review_tests::payload())?;
		tx.execute("UPDATE review_generations SET inventory_digest=zeroblob(32) WHERE generation_id=?1",[generation])?;
		for (i,band) in ["background","normal","urgent","high","normal","urgent"].iter().enumerate() {
			tx.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,priority_band,created_at) VALUES(?1,?2,?3,'t','o','[]',?4,?1)",params![i as i64+1,generation,format!("unit-{i}"),band])?;
		}
		let refs=InspectedRefs::new(vec![])?;
		let payload=review_tests::payload();
		let record=|unit,job|review_unit_results::insert(tx,&review_unit_results::NewResult{generation_id:generation,unit_id:unit,produced_by_job:Some(job),commit_sha:SHA,profile_version:1,disposition:review_unit_results::Disposition::NoLeadFound,inspected_refs:&refs,counterevidence:None,proof_gaps:None,payload:&payload,corroborates_result:None,corroborates_exclusion:None},3);
		for unit in [1,2] {record(unit,job_id)?;}
		assert_eq!(campaign::replenish(tx,campaign_id,3).unwrap(),None);
		// B5's finalize supplies the terminal transition and checkpoint envelope.
		tx.execute("UPDATE jobs SET state='succeeded',finished_at=3 WHERE id=?1",[job_id])?;
		campaign::activate_generation(tx,campaign_id,3).unwrap();
		let coverage=campaign::replenish(tx,campaign_id,3).unwrap().unwrap();
		request.now=4;
		request.capability_hash=&[5;32];
		let batch=claim_kinds(tx,&request,&kinds)?.unwrap();
		assert_eq!(batch.job.id,coverage);
		assert_eq!(batch.assigned_units,[3,6,4,5]);
		let recipe:serde_json::Value=serde_json::from_str(batch.job.recipe.as_ref().unwrap().expose()).unwrap();
		assert_eq!(recipe["recipe"],"coverage");
		for unit in batch.assigned_units {record(unit,coverage)?;}
		tx.execute("UPDATE jobs SET state='succeeded',finished_at=5 WHERE id=?1",[coverage])?;
		assert_eq!(campaign::replenish(tx,campaign_id,5).unwrap(),None);
		assert!(generations::coverage_rollup(tx,generation)?.complete());
		let after=generations::get(tx,generation)?.unwrap();
		assert_eq!(after.profile_version,1);
		assert_eq!(after.activated_at,Some(3));
		Ok(())
	})).unwrap();
}
