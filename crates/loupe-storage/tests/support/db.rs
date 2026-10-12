use loupe_core::{Finding, Severity};
use loupe_storage::{findings, Db};

pub fn finding() -> Finding {
	Finding {
		scanner_id: "fixture".into(),
		severity: Severity::High,
		title: "same".into(),
		description: "same".into(),
		file_path: Some("src/cafe\u{301}.rs".into()),
		line_start: Some(1),
		line_end: None,
		cwe: None,
		patch_unified: None,
		poc_unified: Some(String::new()),
		fingerprint: "fixture".into(),
	}
}

pub fn seed(db: &Db, finding: &Finding, refs: &str) -> i64 {
	db.with_conn(|conn| {
		conn.execute_batch(
			"INSERT INTO registered_repos
			(id,clone_url,host,owner,repo,reporting,created_at)
			VALUES (1,'u','github.com','owner','repo','{\"kind\":\"manual\"}',0);
			INSERT INTO review_generations
			(generation_id,repo_id,generation_commit_sha,state,workflow_contract_version,created_at)
			VALUES (11,1,'base','active',1,0);
			INSERT INTO jobs (id,repo_id,kind,state,enqueued_at)
			VALUES (1,1,'scan','queued',0);",
		)?;
		conn.execute(
			"INSERT INTO review_units
			(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at)
			VALUES (1,11,'fixture','title','objective',?1,0)",
			[refs],
		)?;
		Ok(findings::insert_or_ignore(conn, 1, 1, finding, false, 0)?.unwrap())
	})
	.unwrap()
}
