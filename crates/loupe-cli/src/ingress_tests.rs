//! Tests at the actual CLI argument/HTTP boundaries.
use legacy::{
	FindingDetail, GithubAppResponse, GithubReportingAuth, ListReposResponse, ReportingSummary,
};
use serde_json::{json, Value};

use super::*;
use crate::ingress::test_support::{received, respond};
use crate::legacy_responses as legacy;

const PAT: &str = "FAKE_CLI_ARG_PAT_abcdefghijklmnopqrstuvwxyz0123456789";

fn pat_cli(command: &str) -> Cli {
	let mut args = vec!["loupectl", "repo", command];
	match command {
		"add" => args.extend([
			"--clone-url",
			"local",
			"--target-owner",
			"acme",
			"--target-repo",
			"issues",
		]),
		"set-github-reporting" => {
			args.extend(["1", "--target-owner", "acme", "--target-repo", "issues"])
		},
		"rotate-pat" => args.push("1"),
		_ => unreachable!(),
	}
	args.extend(["--pat", PAT]);
	Cli::try_parse_from(args).unwrap()
}

fn assert_pat_redacted(command: &str) {
	let cli = pat_cli(command);
	for rendered in [format!("{cli:?}"), format!("{cli:#?}")] {
		assert!(!rendered.contains(PAT), "actual {command} argument Debug disclosed the PAT");
	}
}

#[test]
fn repo_add_argument_debug_keeps_pat_secret() {
	assert_pat_redacted("add");
}
#[test]
fn repo_rotate_argument_debug_keeps_pat_secret() {
	assert_pat_redacted("rotate-pat");
}
#[test]
fn repo_reporting_argument_debug_keeps_pat_secret() {
	assert_pat_redacted("set-github-reporting");
}

fn summary() -> Value {
	json!({"id":1,"repo_id":2,"job_id":3,"scanner_id":" regex ","severity":"high",
		"title":" visible-é *markup* ","fingerprint":"future-format","state":"confirmed",
		"verification_required":false,"created_at":0})
}

fn job() -> Value {
	json!({"job_id":1,"repo_id":2,"kind":"future-kind","state":"queued",
		"incremental":false,"attempts":0,"enqueued_at":0})
}

#[tokio::test]
async fn original_optional_defaults_survive_actual_response_owners() {
	let old_job = job().to_string();
	for decode in [ingress::get_job, ingress::retry_job, ingress::cancel_job] {
		let decoded = decode(received(old_job.as_bytes()).await).unwrap();
		assert_eq!(decoded.worker_id, None);
		assert_eq!(decoded.lease_expires_at, None);
		assert_eq!(decoded.started_at, None);
		assert_eq!(decoded.finished_at, None);
		assert_eq!(decoded.error, None);
		assert_eq!(decoded.since_sha, None);
		assert_eq!(decoded.head_sha, None);
		assert_eq!(decoded.parent_job_id, None);
		assert_eq!(decoded.target_finding_id, None);
		assert_eq!(serde_json::to_value(decoded).unwrap(), job());
	}
	let list = ingress::list_jobs(received(format!("[{old_job}]").as_bytes()).await).unwrap();
	assert_eq!(serde_json::to_value(&list).unwrap(), json!([job()]));

	let base = json!({"id":1,"clone_url":"local","host":"host","owner":"owner",
		"repo":"repo","verification_enabled":false,"created_at":0});
	for reporting in [
		None,
		Some(Value::Null),
		Some(json!({"kind":"github_issue",
		"target_owner":"owner","target_repo":"issues"})),
	] {
		let mut row = base.clone();
		if let Some(reporting) = &reporting {
			row["reporting"] = reporting.clone();
		}
		let body = json!({"protocol_version":2,"repos":[row]}).to_string();
		let decoded = ingress::list_repos(received(body.as_bytes()).await).unwrap();
		let mut expected = base.clone();
		if reporting.as_ref().is_some_and(|value| !value.is_null()) {
			assert!(matches!(
				decoded.repos[0].reporting,
				Some(loupe_proto::ReportingSummary::GithubIssue {
					auth: loupe_proto::GithubReportingAuth::Pat,
					..
				})
			));
			expected["reporting"] = json!({"kind":"github_issue", "target_owner":"owner",
				"target_repo":"issues", "auth":"pat"});
		} else {
			assert!(decoded.repos[0].reporting.is_none());
		}
		assert_eq!(
			serde_json::to_value(decoded).unwrap(),
			json!({"protocol_version":2,"repos":[expected]})
		);
	}
	for auth in ["app", "pat"] {
		let mut row = base.clone();
		row["reporting"] = json!({"kind":"github_issue", "target_owner":"acme",
			"target_repo":"tracker", "auth":auth});
		let body = json!({"protocol_version":2,"repos":[row]}).to_string();
		let decoded = ingress::list_repos(received(body.as_bytes()).await).unwrap();
		let encoded = serde_json::to_value(decoded).unwrap();
		assert_eq!(
			encoded["repos"][0]["reporting"],
			json!({"kind":"github_issue",
			"target_owner":"acme", "target_repo":"tracker", "auth":auth})
		);
		assert_eq!(encoded, json!({"protocol_version":2,"repos":[row]}));
	}
}

// Missing optional fields are admitted by each response's production decoder.
#[tokio::test]
async fn original_job_parentage_and_failure_fields_survive_response_owners() {
	let verify = json!({"job_id":5,"repo_id":2,"kind":"verify","state":"leased",
		"incremental":false,"head_sha":"abc123","parent_job_id":1,
		"target_finding_id":42,"attempts":0,"enqueued_at":1700000100});
	let failed = json!({"job_id":1,"repo_id":2,"kind":"scan","state":"failed",
		"incremental":false,"attempts":3,"enqueued_at":1700000000,"worker_id":7,
		"lease_expires_at":1700000600,"started_at":1700000010,"finished_at":1700000400,
		"error":"lease expired after max attempts"});
	for expected in [&verify, &failed] {
		let wire = serde_json::to_vec(expected).unwrap();
		for decode in [ingress::get_job, ingress::retry_job, ingress::cancel_job] {
			let decoded = decode(received(&wire).await).unwrap();
			assert_eq!(serde_json::to_value(&decoded).unwrap(), *expected);
			if expected == &failed {
				assert_eq!(decoded.finished_at.unwrap() - decoded.started_at.unwrap(), 390);
			} else {
				assert_eq!(decoded.parent_job_id, Some(1));
				assert_eq!(decoded.target_finding_id, Some(42));
				assert_eq!(decoded.head_sha.as_ref().map(|value| value.expose()), Some("abc123"));
			}
		}
	}
	let expected = json!([verify, failed]);
	let decoded =
		ingress::list_jobs(received(&serde_json::to_vec(&expected).unwrap()).await).unwrap();
	assert_eq!(serde_json::to_value(&decoded).unwrap(), expected);
	assert_eq!(decoded[1].finished_at.unwrap() - decoded[1].started_at.unwrap(), 390);
}

#[tokio::test]
async fn actual_finding_reader_rejects_newly_invalid_fields() {
	let mut admitted = Vec::new();
	for (field, value) in [
		("title", "title\u{1b}sentinel".to_owned()),
		("scanner_id", "scanner\nrow".to_owned()),
		("fingerprint", "fingerprint\tcolumn".to_owned()),
		("file_path", "../outside".to_owned()),
		("file_path", "p".repeat(513)),
		("approved_by_cn", "audit\rrow".to_owned()),
		("rejected_by_cn", "audit\u{85}row".to_owned()),
		("title", "t".repeat(2 * 1024 * 1024 + 1)),
	] {
		let mut finding = summary();
		finding[field] = value.into();
		let body = json!({"protocol_version":2,"findings":[finding]}).to_string();
		let (base, server) = respond(body.into_bytes()).await;
		let result = finding_list(&reqwest::Client::new(), &base, 2, None).await;
		server.await.unwrap();
		if result.is_ok() {
			admitted.push(field);
		}
	}
	assert!(
		admitted.is_empty(),
		"actual finding response reader admitted forbidden fields: {admitted:?}"
	);
}

#[tokio::test]
async fn actual_metadata_readers_reject_newly_invalid_text() {
	let mut admitted = Vec::new();
	let mut value = job();
	value["kind"] = "future\nkind".into();
	let (base, server) = respond(value.to_string().into_bytes()).await;
	if job_retry(&reqwest::Client::new(), &base, 1).await.is_ok() {
		admitted.push("job.kind");
	}
	server.await.unwrap();
	let mut value = job();
	value["error"] = "diagnostic\u{1b}escape".into();
	let (base, server) = respond(value.to_string().into_bytes()).await;
	if job_cancel(&reqwest::Client::new(), &base, 1).await.is_ok() {
		admitted.push("job.error");
	}
	server.await.unwrap();
	let body = json!({"protocol_version":2,"app":{"app_id":7,"slug":"app\nrow"}});
	let (base, server) = respond(body.to_string().into_bytes()).await;
	if github_app_show(&reqwest::Client::new(), &base).await.is_ok() {
		admitted.push("app.slug");
	}
	server.await.unwrap();
	assert!(admitted.is_empty(), "actual metadata readers admitted forbidden fields: {admitted:?}");
}

#[test]
fn actual_config_parsers_reject_newly_invalid_text() {
	let mut admitted = Vec::new();
	for args in [
		vec!["loupectl", "repo", "add", "--clone-url", "local\nurl", "--no-reporting"],
		vec!["loupectl", "worker", "register", "--name", "worker\tname"],
		vec!["loupectl", "finding", "search", "1", "query\u{1b}escape"],
		vec!["loupectl", "cert", "mint-server", "--hostname", "host\nname"],
	] {
		if Cli::try_parse_from(args.clone()).is_ok() {
			admitted.push(args[1]);
		}
	}
	assert!(admitted.is_empty(), "actual Config parsers admitted forbidden fields: {admitted:?}");
}

#[tokio::test]
async fn existing_wire_and_text_compatibility_control() {
	let finding = summary();
	let body = json!({"protocol_version":65535,"findings":[finding],"ignored":{"future":true}});
	let (base, server) = respond(body.to_string().into_bytes()).await;
	let Cli { cmd: Cmd::Finding(FindingCmd::Search { query, .. }), .. } =
		Cli::try_parse_from(["loupectl", "finding", "search", "2", "query\nwords"]).unwrap()
	else {
		unreachable!()
	};
	finding_search(&reqwest::Client::new(), &base, 2, &query, -1).await.unwrap();
	server.await.unwrap();
	let mut value = job();
	value["head_sha"] = "base".into();
	value["error"] = " exact\r\n\tNFD-e\u{301}\n\n\n ".into();
	let (base, server) = respond(value.to_string().into_bytes()).await;
	job_get(&reqwest::Client::new(), &base, 1).await.unwrap();
	server.await.unwrap();
}

#[test]
fn original_response_schema_controls() {
	let raw = r#"{"protocol_version":65535,"repos":[{"id":1,"clone_url":"local","host":" host ","owner":"owner","repo":"repo","verification_enabled":false,"created_at":0,"reporting":{"target_owner":"same","target_repo":"same","kind":"github_issue"}}]}"#;
	let repos: ListReposResponse = serde_json::from_str(raw).unwrap();
	assert!(matches!(
		repos.repos[0].reporting,
		Some(ReportingSummary::GithubIssue { auth: GithubReportingAuth::Pat, .. })
	));
	let summary = summary();
	let mut detail = summary.as_object().unwrap().clone();
	detail.insert("protocol_version".into(), 2.into());
	detail.insert("description".into(), "\r\n\tNFD-e\u{301}".into());
	detail.insert("poc_unified".into(), "".into());
	detail.insert("patch_unified".into(), Value::Null);
	let detail: FindingDetail = serde_json::from_value(Value::Object(detail)).unwrap();
	assert_eq!(detail.poc_unified.as_deref(), Some(""));
	assert_eq!(detail.patch_unified, None);
	assert_eq!(detail.description, "\r\n\tNFD-e\u{301}");
	assert!(serde_json::from_str::<GithubAppResponse>(r#"[2]"#).unwrap().app.is_none());
	assert!(serde_json::from_str::<GithubAppResponse>(
		r#"{"protocol_version":2,"protocol_version":2}"#
	)
	.is_err());
	assert!(serde_json::from_str::<loupe_core::Severity>(r#"{"high":null}"#).is_ok());
	assert!(serde_json::from_str::<ReportingSummary>(r#"{"kind":{"manual":null}}"#).is_err());
	let nested = format!("{}0{}", "[".repeat(140), "]".repeat(140));
	let unknown = format!(r#"{{"protocol_version":2,"ignored":{nested}}}"#);
	assert!(serde_json::from_str::<GithubAppResponse>(&unknown).is_ok());
}

#[tokio::test]
async fn response_schema_matrix_matches_original_dtos() {
	macro_rules! compare {
		($raw:expr, $old:ty, $reader:path) => {{
			let raw = $raw;
			let old = serde_json::from_str::<$old>(&raw);
			let new = $reader(received(raw.as_bytes()).await);
			assert_eq!(old.is_ok(), new.is_ok(), "schema admission differs: {raw}");
			if let (Ok(old), Ok(new)) = (old, new) {
				assert_eq!(
					serde_json::to_value(old).unwrap(),
					serde_json::to_value(new).unwrap(),
					"schema output differs: {raw}"
				);
			}
		}};
	}
	let prefix = r#"{"protocol_version":2,"repos":[{"id":1,"clone_url":"local","host":" host ","owner":"owner","repo":"repo","verification_enabled":false,"created_at":0,"reporting":"#;
	for reporting in [
		r#"{"kind":"manual"}"#,
		r#"["manual"]"#,
		r#"["manual",0]"#,
		r#"{"kind":{"manual":null}}"#,
		r#"{"kind":"manual","kind":"manual"}"#,
		r#"{"kind":"manual","ignored":0,"ignored":1}"#,
		r#"{"target_owner":"same","target_repo":"same","kind":"github_issue"}"#,
		r#"["github_issue","same","same"]"#,
		r#"["github_issue","same","same",{"pat":null}]"#,
		r#"{"kind":"github_issue","target_owner":"","target_repo":"","auth":null}"#,
		r#"{"kind":"email","to":["same","same"],"from":null,"subject_prefix":""}"#,
		r#"["email",["same"],null,""]"#,
		r#"{"kind":"email","to":["x"],"to":["x"]}"#,
		r#"{"kind":"manual","ignored":1e999}"#,
		r#"{"kind":"manual","ignored":"\uD800"}"#,
		"null",
	] {
		compare!(format!("{prefix}{reporting}}}]}}"), ListReposResponse, ingress::list_repos);
	}
	for depth in 120..=130 {
		let nested = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
		let reporting = format!(r#"{{"kind":"manual","ignored":{nested}}}"#);
		compare!(format!("{prefix}{reporting}}}]}}"), ListReposResponse, ingress::list_repos);
	}
	for raw in [
		r#"[2]"#.to_owned(),
		r#"[2,null]"#.to_owned(),
		r#"[2,[7," exact "]]"#.to_owned(),
		r#"{"protocol_version":2,"protocol_version":2}"#.to_owned(),
		r#"{"protocol_version":2.0}"#.to_owned(),
		r#"{"protocol_version":2e0}"#.to_owned(),
		r#"{"protocol_version":65536}"#.to_owned(),
		r#"{"protocol_version":-1}"#.to_owned(),
		format!(r#"{{"protocol_version":2,"ignored":{}0{}}}"#, "[".repeat(140), "]".repeat(140)),
		r#"{"protocol_version":2,"ignored":1e999}"#.to_owned(),
	] {
		compare!(raw, GithubAppResponse, ingress::show_github_app);
	}
	for raw in [job().to_string(), r#"[1,2,"future",{"queued":null},false,null,"",null,null,0,0]"#.to_owned(),
		r#"{"job_id":1,"repo_id":2,"kind":"","state":"queued","incremental":false,"attempts":4294967296,"enqueued_at":0}"#.to_owned()]
	{ compare!(raw, legacy::JobInfo, ingress::get_job); }
}

#[tokio::test]
async fn concrete_response_owners_keep_wire_and_credential_shapes() {
	let registered =
		ingress::register_repo(received(br#"{"protocol_version":65535,"repo_id":-1}"#).await)
			.unwrap();
	assert_eq!((registered.protocol_version, registered.repo_id), (65535, -1));
	let scan = ingress::scan_repo(received(br#"[65535,9]"#).await).unwrap();
	assert_eq!((scan.protocol_version, scan.job_id), (65535, 9));
	let retry =
		ingress::retry_verification(received(br#"{"protocol_version":65535,"dry_run":true,"matched":7,"revived":0,"requeued_jobs":0,"created_jobs":0,"left_queued_or_leased":0}"#).await)
			.unwrap();
	assert_eq!(retry.matched, 7);
	let list = format!("[{}]", job());
	assert_eq!(ingress::list_jobs(received(list.as_bytes()).await).unwrap().len(), 1);
	let key = "FAKE-PEM-e\u{301}\r\n\t\\\"";
	let raw = json!({"protocol_version":65535,"worker_id":4,"client_cert_pem":" cert ","client_key_pem":key,"ca_cert_pem":key}).to_string();
	let bundle = ingress::register_worker_bundle(received(raw.as_bytes()).await).unwrap();
	assert_eq!(bundle.client_cert_pem, " cert ");
	assert_eq!(bundle.client_key_pem.expose(), key);
	assert_eq!(bundle.ca_cert_pem.expose(), key);
	let encoded = bundle.credential_json_pretty().unwrap();
	assert_eq!(
		serde_json::from_slice::<Value>(encoded.expose()).unwrap(),
		serde_json::from_str::<Value>(&raw).unwrap()
	);
	assert!(!format!("{bundle:?}").contains("FAKE-PEM"));
	assert!(ingress::discard(received(b"arbitrary ignored success bytes\xff").await).is_ok());
}

#[tokio::test]
async fn detail_optional_and_positional_schema_controls() {
	let row = vec![
		json!(2),
		json!(1),
		json!(2),
		json!(3),
		json!("scanner"),
		json!({"high":null}),
		json!("title"),
		json!(" exact\r\n\tNFD-e\u{301}"),
		Value::Null,
		Value::Null,
		Value::Null,
		Value::Null,
		Value::Null,
		Value::Null,
		json!("fingerprint"),
		json!("confirmed"),
		json!(false),
		json!(0),
		Value::Null,
		json!(""),
		Value::Null,
		json!(""),
	];
	for length in 0..=row.len() {
		let raw = serde_json::to_string(&row[..length]).unwrap();
		let old = serde_json::from_str::<FindingDetail>(&raw);
		let new = ingress::get_finding(received(raw.as_bytes()).await);
		assert_eq!(old.is_ok(), new.is_ok(), "detail sequence prefix length {length}");
		if let (Ok(old), Ok(new)) = (old, new) {
			assert_eq!(serde_json::to_value(old).unwrap(), serde_json::to_value(new).unwrap());
		}
	}
	for optional in
		[None, Some(Value::Null), Some(json!("")), Some(json!("\r\n\t NFD-e\u{301}\n\n\n"))]
	{
		let mut row = summary();
		row["protocol_version"] = 2.into();
		row["description"] = "".into();
		if let Some(value) = optional {
			row["patch_unified"] = value.clone();
			row["poc_unified"] = value;
		}
		let raw = row.to_string();
		let old = serde_json::from_str::<FindingDetail>(&raw).unwrap();
		let new = ingress::get_finding(received(raw.as_bytes()).await).unwrap();
		assert_eq!(serde_json::to_value(old).unwrap(), serde_json::to_value(new).unwrap());
	}
}

#[tokio::test]
async fn response_text_boundaries_and_closed_error_chains() {
	let cap = 2 * 1024 * 1024;
	for (field, value) in [("title", "t".repeat(cap)), ("file_path", "p".repeat(512))] {
		let mut row = summary();
		row[field] = value.clone().into();
		let raw = json!({"protocol_version":2,"findings":[row]}).to_string();
		let result = ingress::list_findings(received(raw.as_bytes()).await).unwrap();
		assert_eq!(serde_json::to_value(result).unwrap()["findings"][0][field], value);
	}
	for value in ["REJECTED_FIELD_SENTINEL\u{1b}".to_owned(), "\u{85}".repeat(cap + 1)] {
		let mut row = summary();
		row["title"] = value.into();
		let raw = json!({"protocol_version":2,"findings":[row]}).to_string();
		let error = ingress::list_findings(received(raw.as_bytes()).await).unwrap_err();
		let expected = "server response violates schema or field policy";
		for message in [format!("{error}"), format!("{error:#}")] {
			assert_eq!(message, expected);
		}
		assert_eq!(error.chain().count(), 1);
		// Alternate Debug inspects the wrapped error without anyhow's backtrace.
		assert_eq!(format!("{error:#?}"), format!("{expected:?}"));
	}
}
