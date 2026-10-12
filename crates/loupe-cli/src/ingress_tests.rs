//! Tests at the actual CLI argument/HTTP boundaries.
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

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

async fn respond(body: Vec<u8>) -> (reqwest::Url, tokio::task::JoinHandle<()>) {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let task = tokio::spawn(async move {
		let (mut socket, _) = listener.accept().await.unwrap();
		let mut request = [0; 4096];
		assert!(socket.read(&mut request).await.unwrap() > 0);
		let headers = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nX-Loupe-Protocol: deliberately-invalid\r\nConnection: close\r\n\r\n", body.len());
		socket.write_all(headers.as_bytes()).await.unwrap();
		socket.write_all(&body).await.unwrap();
	});
	(reqwest::Url::parse(&format!("http://{addr}/")).unwrap(), task)
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
	finding_search(&reqwest::Client::new(), &base, 2, "query\nwords", -1).await.unwrap();
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

/// Test traffic enters through the production collector and its sole Server mint.
pub(crate) async fn received(
	raw: &[u8],
) -> loupe_provenance::Untrusted<bytes::Bytes, loupe_provenance::Server> {
	let (base, task) = respond(raw.to_vec()).await;
	let response = reqwest::Client::new().get(base).send().await.unwrap();
	let body = ingress::receive(response, "fixture").await.unwrap();
	task.await.unwrap();
	body
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
		compare!(
			format!("{prefix}{reporting}}}]}}"),
			ListReposResponse,
			ingress::list_repos_legacy
		);
	}
	for depth in 120..=130 {
		let nested = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
		let reporting = format!(r#"{{"kind":"manual","ignored":{nested}}}"#);
		compare!(
			format!("{prefix}{reporting}}}]}}"),
			ListReposResponse,
			ingress::list_repos_legacy
		);
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
		compare!(raw, GithubAppResponse, ingress::show_github_app_legacy);
	}
	for raw in [job().to_string(), r#"[1,2,"future",{"queued":null},false,null,"",null,null,0,0]"#.to_owned(),
		r#"{"job_id":1,"repo_id":2,"kind":"","state":"queued","incremental":false,"attempts":4294967296,"enqueued_at":0}"#.to_owned()]
	{ compare!(raw, loupe_proto::JobInfo, ingress::get_job_legacy); }
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
	assert_eq!(ingress::list_jobs_legacy(received(list.as_bytes()).await).unwrap().len(), 1);
	let key = "FAKE-PEM-e\u{301}\r\n\t\\\"";
	let raw = json!({"protocol_version":65535,"worker_id":4,"client_cert_pem":" cert ","client_key_pem":key,"ca_cert_pem":key}).to_string();
	let bundle = ingress::register_worker_bundle_legacy(received(raw.as_bytes()).await).unwrap();
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
		let new = ingress::get_finding_legacy(received(raw.as_bytes()).await);
		assert_eq!(old.is_ok(), new.is_ok(), "detail sequence prefix length {length}");
		if let (Ok(old), Ok(new)) = (old, new) {
			assert_eq!(old, new);
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
		let new = ingress::get_finding_legacy(received(raw.as_bytes()).await).unwrap();
		assert_eq!(old, new);
	}
}

#[tokio::test]
async fn response_text_boundaries_and_closed_error_chains() {
	let cap = 2 * 1024 * 1024;
	for (field, value) in [("title", "t".repeat(cap)), ("file_path", "p".repeat(512))] {
		let mut row = summary();
		row[field] = value.clone().into();
		let raw = json!({"protocol_version":2,"findings":[row]}).to_string();
		let result = ingress::list_findings_legacy(received(raw.as_bytes()).await).unwrap();
		assert_eq!(serde_json::to_value(result).unwrap()["findings"][0][field], value);
	}
	for value in ["REJECTED_FIELD_SENTINEL\u{1b}".to_owned(), "\u{85}".repeat(cap + 1)] {
		let mut row = summary();
		row["title"] = value.into();
		let raw = json!({"protocol_version":2,"findings":[row]}).to_string();
		let error = ingress::list_findings_legacy(received(raw.as_bytes()).await).unwrap_err();
		let expected = "server response violates schema or field policy";
		for message in [format!("{error}"), format!("{error:#}")] {
			assert_eq!(message, expected);
		}
		assert_eq!(error.chain().count(), 1);
		// Alternate Debug inspects the wrapped error without anyhow's backtrace.
		assert_eq!(format!("{error:#?}"), format!("{expected:?}"));
	}
}
