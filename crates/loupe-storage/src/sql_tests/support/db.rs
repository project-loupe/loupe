use loupe_core::Severity;
use loupe_storage::Db;

/// Raw historical SQL fixture, including values rejected by current admission.
/// This test-only record is not an ingress decoder or a source-bearing DTO.
#[derive(serde::Serialize)]
pub struct Finding {
	pub scanner_id: String,
	pub severity: Severity,
	pub title: String,
	pub description: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub file_path: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub line_start: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub line_end: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub cwe: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub patch_unified: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub poc_unified: Option<String>,
	pub fingerprint: String,
}

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
		conn.execute("INSERT INTO findings(repo_id,job_id,scanner_id,severity,title,description,file_path,line_start,line_end,cwe,patch_unified,poc_unified,fingerprint,state,verification_required,created_at,report_identity) VALUES(1,1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'pending',0,0,?12)", rusqlite::params![finding.scanner_id,finding.severity.as_str(),finding.title,finding.description,finding.file_path,finding.line_start,finding.line_end,finding.cwe,finding.patch_unified,finding.poc_unified,finding.fingerprint,[1u8;16].as_slice()])?;
		Ok(conn.last_insert_rowid())
	})
	.unwrap()
}
