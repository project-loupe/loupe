//! Synthetic report fixtures admitted by actual SQL and Server response owners.
use std::sync::OnceLock;

use loupe_cli::fuzz_support::{observe_response, ResponseCase, ResponseValue};
use loupe_core::Finding;
use loupe_provenance::Agent;
use loupe_storage::repos::RepoRow;
use serde_json::{json, Value};

fn database() -> &'static loupe_storage::Db {
	static DB: OnceLock<loupe_storage::Db> = OnceLock::new();
	DB.get_or_init(|| {
		let db = loupe_storage::Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests())
			.unwrap_or_else(|e| panic!("report fixture database: {e}"));
		db.with_conn(|conn| {
			conn.execute(
				"INSERT INTO registered_repos
                (id,clone_url,host,owner,repo,scanner_config,reporting,created_at,last_scanned_sha)
                VALUES (1,'https://github.com/example/repo.git','github.com','example','repo',
                'null','{\"kind\":\"manual\"}',0,'reviewed-sha')",
				[],
			)?;
			Ok(())
		})
		.unwrap_or_else(|e| panic!("report fixture repository: {e}"));
		db
	})
}

/// Stored Operator configuration becomes Db only through the real row reader.
pub fn repo_with_reporting(reporting: Value) -> loupe_storage::Result<RepoRow> {
	database().with_conn(|conn| {
		conn.execute(
			"UPDATE registered_repos SET reporting=?1 WHERE id=1",
			[reporting.to_string()],
		)?;
		loupe_storage::repos::get(conn, 1)?.ok_or_else(|| panic!("report fixture row missing"))
	})
}

pub fn repo() -> RepoRow {
	repo_with_reporting(json!({"kind":"manual"}))
		.unwrap_or_else(|e| panic!("report fixture admission: {e}"))
}

/// Private historical finding schema, then an actual named Server decoder.
/// The fixture invents a Server envelope around designated Agent content;
/// carried fields retain the decoder's Agent owner into the real reporter.
pub fn finding(raw: &[u8]) -> Option<Finding<Agent>> {
	let old: crate::cli_response_oracle::wire::Finding = serde_json::from_slice(raw).ok()?;
	let mut wire = serde_json::to_value(old).ok()?;
	let envelope = json!({"protocol_version":2,"id":1,"repo_id":1,"job_id":1,
        "state":"confirmed","verification_required":false,"created_at":0});
	wire.as_object_mut()?.extend(envelope.as_object()?.clone());
	let bytes = serde_json::to_vec(&wire).ok()?;
	let expected = crate::cli_response_oracle::legacy(ResponseCase::GetFinding, &bytes)
		.is_ok_and(|v| crate::cli_response_oracle::policies(&v));
	let actual = observe_response(ResponseCase::GetFinding, &bytes).result;
	assert_eq!(actual.is_ok(), expected, "report fixture source admission");
	let Ok(ResponseValue::Finding(f)) = actual else { return None };
	Some(Finding {
		scanner_id: f.scanner_id,
		severity: f.severity,
		title: f.title,
		description: f.description,
		file_path: f.file_path,
		line_start: f.line_start,
		line_end: f.line_end,
		cwe: f.cwe,
		patch_unified: f.patch_unified,
		poc_unified: f.poc_unified,
		fingerprint: f.fingerprint,
	})
}
