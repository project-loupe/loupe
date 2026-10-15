//! Differential checks against independent SQL ownership predicates.
use rand_core::RngCore;
use rusqlite::params;

use crate::scope::{Scope, Subject, SubjectKind};
use crate::{ownership, transaction, Db, Error, Ownership};

#[derive(Clone, Copy)]
struct FixtureSubject {
	id: i64,
	repo: i64,
	campaign: i64,
}

fn compare(
	result: crate::Result<()>, pure: bool, old_sql: bool, relation: Ownership,
	counts: &mut [usize; 2],
) {
	assert_eq!(pure, old_sql, "pure ownership policy differs from original SQL for {relation:?}");
	assert_eq!(
		result.is_ok(),
		old_sql,
		"loaded SQL facts differ from original policy for {relation:?}"
	);
	if !old_sql {
		assert!(
			matches!(result, Err(Error::Ownership(actual)) if actual == relation),
			"foreign and missing rows must return the same ownership error"
		);
	}
	counts[usize::from(old_sql)] += 1;
}

#[test]
fn ownership_helpers_match_scope_on_randomized_sqlite_facts() {
	let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
	let mut random = rand_core::OsRng;
	let base = i64::from(random.next_u32()) * 100 + 1;
	let repos = [base, base + 1, base + 2];
	let mut subjects = Vec::new();
	db.with_conn(|conn| transaction::immediate(conn, |tx| {
		for repo in repos {
			tx.execute("INSERT INTO registered_repos (id,clone_url,host,owner,repo,reporting,created_at) VALUES (?1,?1,'github.com','owner',?1,'{\"kind\":\"manual\"}',0)", [repo])?;
			tx.execute("INSERT INTO review_campaigns (campaign_id,repo_id,recipe,trigger,target_commit_sha,state,effective_policy,effective_policy_digest,created_at) VALUES (?1,?1,'bootstrap','manual','head','active','{}',zeroblob(32),0)", [repo])?;
		}
		for index in 0..9 {
			let repo_index = if index < 3 { index } else { (random.next_u32() % 3) as usize };
			let repo = repos[repo_index];
			let id = base + 10 + index as i64;
			tx.execute("INSERT INTO review_generations (generation_id,repo_id,generation_commit_sha,state,workflow_contract_version,created_at) VALUES (?1,?2,'head','building',1,0)", params![id,repo])?;
			tx.execute("INSERT INTO review_units (review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES (?1,?1,'key','title','objective','[]',0)", [id])?;
			tx.execute("INSERT INTO leads (lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) VALUES (?1,?1,'family','anchor',zeroblob(32),'{}',zeroblob(32),'head',0)", [id])?;
			for shape in 0..3 {
				let generation = (shape == 0).then_some(id);
				let campaign = (shape != 2).then_some(repo);
				tx.execute("INSERT INTO jobs (id,repo_id,kind,state,campaign_id,generation_id,enqueued_at) VALUES (?1,?2,'survey','queued',?3,?4,0)", params![id*4+shape,repo,campaign,generation])?;
			}
			tx.execute("INSERT INTO findings (id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,created_at) VALUES (?1,?2,?3,'test','high','title','description',?1,0)",params![id,repo,id*4])?;
			subjects.push(FixtureSubject { id, repo, campaign: repo });
		}

		let mut counts = [[0; 2]; 8];
		for repo in repos.into_iter().chain([-1]) {
			let scope = Scope::repository(repo);
			for subject in subjects.iter().copied().map(Some).chain([None]) {
				let id = subject.map_or(-1, |s| s.id);
				let pure = subject.is_some_and(|s| scope.admits(&Subject::repository(s.repo), Ownership::Finding));
				let old = tx.query_row("SELECT EXISTS(SELECT 1 FROM findings WHERE id=?1 AND repo_id=?2)", params![id,repo], |r| r.get(0))?;
				compare(ownership::finding(tx,id,repo,Ownership::Finding),pure,old,Ownership::Finding,&mut counts[0]);
				let old = tx.query_row("SELECT EXISTS(SELECT 1 FROM review_units u JOIN review_generations g ON g.generation_id=u.generation_id WHERE u.review_unit_id=?1 AND g.repo_id=?2)", params![id,repo], |r| r.get(0))?;
				compare(ownership::unit_in_repo(tx,id,repo,Ownership::CarriedUnit),pure,old,Ownership::CarriedUnit,&mut counts[1]);
				let old = tx.query_row("SELECT EXISTS(SELECT 1 FROM leads l JOIN review_generations g ON g.generation_id=l.generation_id WHERE l.lead_id=?1 AND g.repo_id=?2)", params![id,repo], |r| r.get(0))?;
				compare(ownership::lead_in_repo(tx,id,repo,Ownership::JobLead),pure,old,Ownership::JobLead,&mut counts[2]);
				let old = tx.query_row("SELECT EXISTS(SELECT 1 FROM review_generations WHERE generation_id=?1 AND repo_id=?2)", params![id,repo], |r| r.get(0))?;
				compare(ownership::generation(tx,repo,id,Ownership::JobGeneration),pure,old,Ownership::JobGeneration,&mut counts[3]);
			}
			for campaign in repos.into_iter().chain([-1]) {
				let pure = campaign != -1 && scope.admits(&Subject::repository(campaign), Ownership::CampaignRoot);
				let old = tx.query_row("SELECT EXISTS(SELECT 1 FROM review_campaigns WHERE campaign_id=?1 AND repo_id=?2)",params![campaign,repo],|r|r.get(0))?;
				compare(ownership::campaign(tx,repo,campaign,Ownership::CampaignRoot),pure,old,Ownership::CampaignRoot,&mut counts[4]);
			}
		}
		for target in subjects.iter().copied().map(Some).chain([None]) {
			let generation = target.map_or(-1, |s| s.id);
			let scope = target.map(|s| Scope { generation: Some(s.id), ..Scope::repository(s.repo) });
			for subject in subjects.iter().copied().map(Some).chain([None]) {
				let id = subject.map_or(-1, |s| s.id);
				let pure = scope.zip(subject).is_some_and(|(scope,s)| scope.admits(&Subject { generation: Some(s.id), ..Subject::repository(s.repo) },Ownership::ResultUnit));
				let old = tx.query_row("SELECT EXISTS(SELECT 1 FROM review_units WHERE review_unit_id=?1 AND generation_id=?2)",params![id,generation],|r|r.get(0))?;
				compare(ownership::unit_in_generation(tx,id,generation,Ownership::ResultUnit),pure,old,Ownership::ResultUnit,&mut counts[5]);
				let old = tx.query_row("SELECT EXISTS(SELECT 1 FROM leads WHERE lead_id=?1 AND generation_id=?2)",params![id,generation],|r|r.get(0))?;
				compare(ownership::lead_in_generation(tx,id,generation,Ownership::JobLead),pure,old,Ownership::JobLead,&mut counts[6]);
				for shape in 0..3 {
					let job = subject.map_or(-1, |s| s.id*4+shape);
					let pure = scope.zip(subject).is_some_and(|(scope,s)| scope.admits(&Subject { repo:s.repo, generation:(shape==0).then_some(s.id), campaign:(shape!=2).then_some(s.campaign), kind:SubjectKind::Job {campaign_repo:(shape!=2).then_some(s.repo)} }, Ownership::UnitJob));
					let old = tx.query_row("SELECT EXISTS(SELECT 1 FROM jobs j JOIN review_generations g ON g.generation_id=?2 WHERE j.id=?1 AND j.repo_id=g.repo_id AND (j.generation_id=g.generation_id OR (j.generation_id IS NULL AND EXISTS(SELECT 1 FROM review_campaigns c WHERE c.campaign_id=j.campaign_id AND c.repo_id=g.repo_id))))", params![job,generation],|r|r.get(0))?;
					compare(ownership::job_for_generation(tx,job,generation,Ownership::UnitJob),pure,old,Ownership::UnitJob,&mut counts[7]);
				}
			}
		}
		for (helper, [denied, admitted]) in counts.into_iter().enumerate() {
			assert!(denied > 0 && admitted > 0, "helper {helper} must exercise both policy outcomes");
		}
		Ok(())
	})).unwrap();
}
