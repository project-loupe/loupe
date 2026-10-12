//! End-to-end dispatcher test: stand up a tiny axum stub that pretends
//! to be the GitHub Issues API, point a `GithubReporter` at it, run a
//! scan job against an in-memory DB, and prove the issue body lands in
//! the stub with the expected shape.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use common::wire::{
	CompleteOutcome, CompleteRequest, Finding, FindingsBatch, LeaseRequest, LeaseResponse,
	RegisterRepoRequest, RegisterWorkerRequest, RegisterWorkerResponse, ReportingSetup,
	ScanRequest, SetGithubAppRequest, JOB_CAPABILITY_HEADER, PROTOCOL_VERSION,
};
use git2::{Repository, Signature};
use loupe_core::Severity;
use loupe_server::init::run_init;
use loupe_server::reporters::github_app::testing::APP_PRIVATE_KEY_PEM;
use loupe_server::reporters::GithubReporter;
use loupe_server::{serve, AppState, Config};
use loupe_storage::Db;
use loupe_tls::Ca;
use loupe_worker::scanners::RegexSecretsScanner;
use loupe_worker::{RepoCache, Runner, Scanner, ServerClient};
use tokio_util::sync::CancellationToken;

/// App id the stub's `GET /app` reports; the app-mode test registers the
/// fixture key under this id.
const STUB_APP_ID: u64 = 4242;
const STUB_INSTALLATION_ID: u64 = 42;
const STUB_INSTALLATION_TOKEN: &str = "ghs_stub_installation_token";

#[derive(Clone, Default)]
struct GithubStubState {
	captured: Arc<Mutex<Vec<CapturedIssue>>>,
	labels: Arc<Mutex<Vec<CapturedLabel>>>,
	/// Authorization headers seen on the app-authenticated endpoints
	/// (`GET /app`, installation lookup, token mint), in call order.
	app_auths: Arc<Mutex<Vec<String>>>,
	/// Bodies of `POST /app/installations/{id}/access_tokens`.
	token_requests: Arc<Mutex<Vec<serde_json::Value>>>,
}

fn bearer_of(headers: &axum::http::HeaderMap) -> String {
	headers
		.get(axum::http::header::AUTHORIZATION)
		.and_then(|v| v.to_str().ok())
		.unwrap_or("")
		.to_owned()
}

async fn stub_get_app(
	State(stub): State<GithubStubState>, headers: axum::http::HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
	stub.app_auths.lock().unwrap().push(bearer_of(&headers));
	(StatusCode::OK, Json(serde_json::json!({"id": STUB_APP_ID, "slug": "loupe-reporter"})))
}

async fn stub_get_installation(
	State(stub): State<GithubStubState>,
	axum::extract::Path((_owner, repo)): axum::extract::Path<(String, String)>,
	headers: axum::http::HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
	stub.app_auths.lock().unwrap().push(bearer_of(&headers));
	if repo == "tracker" {
		(StatusCode::OK, Json(serde_json::json!({"id": STUB_INSTALLATION_ID})))
	} else {
		(StatusCode::NOT_FOUND, Json(serde_json::json!({"message": "Not Found"})))
	}
}

async fn stub_mint_token(
	State(stub): State<GithubStubState>,
	axum::extract::Path(installation_id): axum::extract::Path<u64>, headers: axum::http::HeaderMap,
	Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
	stub.app_auths.lock().unwrap().push(bearer_of(&headers));
	stub.token_requests.lock().unwrap().push(body);
	assert_eq!(installation_id, STUB_INSTALLATION_ID);
	(
		StatusCode::CREATED,
		Json(serde_json::json!({
			"token": STUB_INSTALLATION_TOKEN,
			"expires_at": "2099-01-01T00:00:00Z",
		})),
	)
}

#[derive(Debug, Clone)]
struct CapturedIssue {
	owner: String,
	repo: String,
	auth: String,
	body: serde_json::Value,
}

#[derive(Debug, Clone)]
struct CapturedLabel {
	owner: String,
	repo: String,
	body: serde_json::Value,
}

async fn stub_create_label(
	State(stub): State<GithubStubState>,
	axum::extract::Path((owner, repo)): axum::extract::Path<(String, String)>,
	Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
	stub.labels.lock().unwrap().push(CapturedLabel { owner, repo, body: body.clone() });
	(StatusCode::CREATED, Json(body))
}

async fn stub_create_issue(
	State(stub): State<GithubStubState>,
	axum::extract::Path((owner, repo)): axum::extract::Path<(String, String)>,
	headers: axum::http::HeaderMap, Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
	let auth = headers
		.get(axum::http::header::AUTHORIZATION)
		.and_then(|v| v.to_str().ok())
		.unwrap_or("")
		.to_owned();
	stub.captured.lock().unwrap().push(CapturedIssue { owner, repo, auth, body });
	(
		StatusCode::CREATED,
		Json(serde_json::json!({"number": 7, "html_url": "https://stub/issues/7"})),
	)
}

async fn spawn_github_stub() -> (SocketAddr, GithubStubState, tokio::task::JoinHandle<()>) {
	let stub = GithubStubState::default();
	let app = Router::new()
		.route("/repos/{owner}/{repo}/labels", post(stub_create_label))
		.route("/repos/{owner}/{repo}/issues", post(stub_create_issue))
		.route("/app", get(stub_get_app))
		.route("/repos/{owner}/{repo}/installation", get(stub_get_installation))
		.route("/app/installations/{id}/access_tokens", post(stub_mint_token))
		.with_state(stub.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let join = tokio::spawn(async move {
		axum::serve(listener, app).await.unwrap();
	});
	(addr, stub, join)
}

mod common;
use common::{pem_to_certificate, pem_to_identity};

fn make_planted_repo() -> (tempfile::TempDir, String) {
	let tmp = tempfile::tempdir().unwrap();
	let repo = Repository::init(tmp.path()).unwrap();
	std::fs::write(tmp.path().join("config.rs"), "const KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";\n")
		.unwrap();
	let mut index = repo.index().unwrap();
	index.add_path(std::path::Path::new("config.rs")).unwrap();
	index.write().unwrap();
	let tree_oid = index.write_tree().unwrap();
	let tree = repo.find_tree(tree_oid).unwrap();
	let sig = Signature::now("loupe-test", "loupe-test@example.com").unwrap();
	repo.commit(Some("HEAD"), &sig, &sig, "plant", &tree, &[]).unwrap();
	let url = format!("file://{}", tmp.path().display());
	(tmp, url)
}

#[tokio::test]
async fn dispatcher_opens_a_github_issue_after_a_succeeded_scan() {
	let (_repo_tmp, clone_url) = make_planted_repo();
	let (stub_addr, stub_state, _stub_join) = spawn_github_stub().await;
	let stub_base = format!("http://{stub_addr}");

	// Stand up loupe-server with a GithubReporter pointed at the stub.
	let server_dir = tempfile::tempdir().unwrap();
	let init = run_init(
		&common::config_path(server_dir.path()),
		&[common::config_hostname("loupe-server")],
		None,
	)
	.unwrap();

	let ca = Ca::from_pem(
		&std::fs::read_to_string(init.layout.ca_cert.as_path()).unwrap(),
		&std::fs::read_to_string(init.layout.ca_key.as_path()).unwrap(),
	)
	.unwrap();
	let server_cert_pem = std::fs::read_to_string(init.layout.server_cert.as_path()).unwrap();
	let server_key_pem = std::fs::read_to_string(init.layout.server_key.as_path()).unwrap();
	let ca_cert_pem = std::fs::read_to_string(init.layout.ca_cert.as_path()).unwrap();
	let ca_key_pem = std::fs::read_to_string(init.layout.ca_key.as_path()).unwrap();

	let cfg = Config {
		bind_addr: "127.0.0.1:0".parse().unwrap(),
		db_path: init.layout.db_path.clone(),
		server_cert_pem: common::config_pem(&server_cert_pem),
		server_key_pem: common::config_pem(&server_key_pem),
		ca_cert_pem: common::config_pem(&ca_cert_pem),
		ca_key_pem: common::config_pem(&ca_key_pem),
	};
	let db = Arc::new(Db::open(init.layout.db_path.as_path(), &init.master_key).unwrap());
	let reporter = Arc::new(GithubReporter::with_base(&stub_base).unwrap());
	// SQLCipher seals the whole DB under `init.master_key`; the dispatch
	// path therefore reads / decrypts the PAT transparently. The
	// "raw bytes don't appear in the file" assertion lives in
	// `loupe-storage`'s `db.rs` test, not here.
	let state = AppState::new(db.clone(), Arc::new(ca), reporter);
	let server = serve(cfg, state).await.unwrap();
	let addr = server.local_addr;

	// Admin client
	let admin = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&ca_cert_pem))
		.identity(pem_to_identity(&init.admin_bundle.cert_pem, init.admin_bundle.key_pem.expose()))
		.resolve("loupe-server", addr)
		.use_rustls_tls()
		.build()
		.unwrap();

	let resp = admin
		.post("https://loupe-server/v1/repos")
		.json(&RegisterRepoRequest {
			protocol_version: PROTOCOL_VERSION,
			clone_url: "https://github.com/loupe/test-target.git".into(),
			branch: None,
			scan_interval_seconds: None,
			reporting: ReportingSetup::GithubIssue {
				target_owner: "acme".into(),
				target_repo: "tracker".into(),
				github_pat: Some(loupe_provenance::Secret::new("ghp_test_pat_value".into())),
			},
			scanner_config: serde_json::Value::Null,
			verification_enabled: Some(false),
			require_approval: None,
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201);
	let body: serde_json::Value = resp.json().await.unwrap();
	let repo_id = body["repo_id"].as_i64().unwrap();
	db.with_conn(|c| {
		c.execute(
			"UPDATE registered_repos SET clone_url = ?1 WHERE id = ?2",
			(&clone_url, repo_id),
		)?;
		Ok(())
	})
	.unwrap();

	let resp = admin
		.post("https://loupe-server/v1/workers")
		.json(&RegisterWorkerRequest { protocol_version: PROTOCOL_VERSION, name: "w1".into() })
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201);
	let bundle: RegisterWorkerResponse = resp.json().await.unwrap();
	let raw = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&ca_cert_pem))
		.identity(pem_to_identity(&bundle.client_cert_pem, bundle.client_key_pem.expose()))
		.resolve("loupe-server", addr)
		.use_rustls_tls()
		.build()
		.unwrap();
	let server_client =
		Arc::new(ServerClient::from_parts(raw, "https://loupe-server/".parse().unwrap()));

	// Scan, run, verify dispatch.
	admin
		.post(format!("https://loupe-server/v1/repos/{}/scan", repo_id))
		.json(&ScanRequest { protocol_version: PROTOCOL_VERSION, incremental: false })
		.send()
		.await
		.unwrap();

	let cache_dir = tempfile::tempdir().unwrap();
	let cache = Arc::new(RepoCache::new(cache_dir.path().to_path_buf(), u64::MAX, None).unwrap());
	let scanners: Vec<Arc<dyn Scanner>> = vec![Arc::new(RegexSecretsScanner::new())];
	let runner = Runner::new(server_client, cache, scanners);
	let cancel = CancellationToken::new();
	let stepped = runner.step(&cancel).await.unwrap();
	assert!(stepped);

	// Stub captured exactly one issue, addressed to the right repo,
	// with the PAT, and mentioning our finding's title.
	let captured = stub_state.captured.lock().unwrap().clone();
	assert_eq!(captured.len(), 1, "expected exactly one issue, got {}", captured.len());
	let issue = &captured[0];
	assert_eq!(issue.owner, "acme");
	assert_eq!(issue.repo, "tracker");
	assert_eq!(issue.auth, "Bearer ghp_test_pat_value");
	let body_str = issue.body.to_string();
	let issue_body = issue.body["body"].as_str().expect("issue body string");
	assert_eq!(
		issue.body["labels"],
		serde_json::json!(["loupe", "severity:high"]),
		"issue body: {body_str}"
	);
	assert!(body_str.contains("AWS access key"), "issue body: {body_str}");
	let reviewed_sha: String = db
		.with_conn(|c| {
			Ok(c.query_row("SELECT head_sha FROM jobs WHERE repo_id = ?1", [repo_id], |r| {
				r.get(0)
			})?)
		})
		.unwrap();
	assert!(
		issue_body.contains(&format!("- reviewed revision: `{reviewed_sha}`")),
		"issue body: {issue_body}"
	);

	let labels = stub_state.labels.lock().unwrap().clone();
	assert_eq!(labels.len(), 1);
	assert_eq!(labels[0].owner, "acme");
	assert_eq!(labels[0].repo, "tracker");
	assert_eq!(labels[0].body["name"], "severity:high");
	assert_eq!(labels[0].body["color"], "d93f0b");

	// Findings table marked reported.
	let reported_count: i64 = db
		.with_conn(|c| {
			Ok(c.query_row("SELECT COUNT(*) FROM findings WHERE state = 'reported'", [], |r| {
				r.get(0)
			})?)
		})
		.unwrap();
	assert_eq!(reported_count, 1);

	// On-disk encryption check: the SQLCipher-sealed file must not
	// contain the PAT in the clear. (The DAO-level "raw .sqlite is
	// ciphertext" guarantee is also tested in `loupe-storage::db`
	// tests; this one proves it survives a real dispatch path.)
	let raw = std::fs::read(init.layout.db_path.as_path()).unwrap();
	assert!(
		!raw.windows(b"ghp_test_pat_value".len()).any(|w| w == b"ghp_test_pat_value"),
		"plaintext PAT must not survive in the encrypted db file"
	);

	server.shutdown().await;
}

#[tokio::test]
async fn dispatch_only_marks_confirmed_findings_reported() {
	let (stub_addr, stub_state, _stub_join) = spawn_github_stub().await;
	let stub_base = format!("http://{stub_addr}");

	let server_dir = tempfile::tempdir().unwrap();
	let init = run_init(
		&common::config_path(server_dir.path()),
		&[common::config_hostname("loupe-server")],
		None,
	)
	.unwrap();

	let ca = Ca::from_pem(
		&std::fs::read_to_string(init.layout.ca_cert.as_path()).unwrap(),
		&std::fs::read_to_string(init.layout.ca_key.as_path()).unwrap(),
	)
	.unwrap();
	let server_cert_pem = std::fs::read_to_string(init.layout.server_cert.as_path()).unwrap();
	let server_key_pem = std::fs::read_to_string(init.layout.server_key.as_path()).unwrap();
	let ca_cert_pem = std::fs::read_to_string(init.layout.ca_cert.as_path()).unwrap();
	let ca_key_pem = std::fs::read_to_string(init.layout.ca_key.as_path()).unwrap();

	let cfg = Config {
		bind_addr: "127.0.0.1:0".parse().unwrap(),
		db_path: init.layout.db_path.clone(),
		server_cert_pem: common::config_pem(&server_cert_pem),
		server_key_pem: common::config_pem(&server_key_pem),
		ca_cert_pem: common::config_pem(&ca_cert_pem),
		ca_key_pem: common::config_pem(&ca_key_pem),
	};
	let db = Arc::new(Db::open(init.layout.db_path.as_path(), &init.master_key).unwrap());
	let reporter = Arc::new(GithubReporter::with_base(&stub_base).unwrap());
	let state = AppState::new(db.clone(), Arc::new(ca), reporter);
	let server = serve(cfg, state).await.unwrap();
	let addr = server.local_addr;

	let admin = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&ca_cert_pem))
		.identity(pem_to_identity(&init.admin_bundle.cert_pem, init.admin_bundle.key_pem.expose()))
		.resolve("loupe-server", addr)
		.use_rustls_tls()
		.build()
		.unwrap();

	let resp = admin
		.post("https://loupe-server/v1/repos")
		.json(&RegisterRepoRequest {
			protocol_version: PROTOCOL_VERSION,
			clone_url: "https://github.com/loupe/test-target.git".into(),
			branch: None,
			scan_interval_seconds: None,
			reporting: ReportingSetup::GithubIssue {
				target_owner: "acme".into(),
				target_repo: "tracker".into(),
				github_pat: Some(loupe_provenance::Secret::new("ghp_test_pat_value".into())),
			},
			scanner_config: serde_json::Value::Null,
			verification_enabled: Some(false),
			require_approval: None,
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201);
	let body: serde_json::Value = resp.json().await.unwrap();
	let repo_id = body["repo_id"].as_i64().unwrap();

	let resp = admin
		.post("https://loupe-server/v1/workers")
		.json(&RegisterWorkerRequest { protocol_version: PROTOCOL_VERSION, name: "w1".into() })
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201);
	let bundle: RegisterWorkerResponse = resp.json().await.unwrap();
	let worker = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&ca_cert_pem))
		.identity(pem_to_identity(&bundle.client_cert_pem, bundle.client_key_pem.expose()))
		.resolve("loupe-server", addr)
		.use_rustls_tls()
		.build()
		.unwrap();

	let resp = admin
		.post(format!("https://loupe-server/v1/repos/{repo_id}/scan"))
		.json(&ScanRequest { protocol_version: PROTOCOL_VERSION, incremental: false })
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201);

	let resp = worker
		.post("https://loupe-server/v1/jobs/lease")
		.json(&LeaseRequest {
			protocol_version: PROTOCOL_VERSION,
			capabilities: vec!["scan:secrets".into()],
			wait_seconds: 0,
		})
		.send()
		.await
		.unwrap();
	assert!(resp.status().is_success());
	let env = match resp.json::<LeaseResponse>().await.unwrap() {
		LeaseResponse::Lease(env) => *env,
		LeaseResponse::Empty { .. } => panic!("expected a scan lease"),
	};

	let confirmed = Finding {
		scanner_id: "test".into(),
		severity: Severity::High,
		title: "Confirmed finding".into(),
		description: "This one should be dispatched".into(),
		file_path: Some("src/a.rs".into()),
		line_start: Some(1),
		line_end: Some(1),
		cwe: None,
		patch_unified: None,
		poc_unified: None,
		fingerprint: "confirmed-fp".into(),
	};
	let second_confirmed = Finding {
		scanner_id: "test".into(),
		severity: Severity::Critical,
		title: "Second confirmed finding with a direct title".into(),
		description: "This one should be dispatched separately".into(),
		file_path: Some("src/critical.rs".into()),
		line_start: Some(9),
		line_end: Some(11),
		cwe: None,
		patch_unified: None,
		poc_unified: None,
		fingerprint: "second-confirmed-fp".into(),
	};
	let resp = worker
		.post(format!("https://loupe-server/v1/jobs/{}/findings", env.job_id))
		.header(JOB_CAPABILITY_HEADER, env.job_capability.expose_secret())
		.json(&FindingsBatch {
			protocol_version: PROTOCOL_VERSION,
			findings: vec![confirmed, second_confirmed],
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);

	db.with_conn(|c| {
		c.execute("UPDATE registered_repos SET verification_enabled = 1 WHERE id = ?1", [repo_id])?;
		Ok(())
	})
	.unwrap();

	let validating = Finding {
		scanner_id: "test".into(),
		severity: Severity::Medium,
		title: "Validating finding".into(),
		description: "This one still needs verifier review".into(),
		file_path: Some("src/b.rs".into()),
		line_start: Some(2),
		line_end: Some(2),
		cwe: None,
		patch_unified: None,
		poc_unified: None,
		fingerprint: "validating-fp".into(),
	};
	let resp = worker
		.post(format!("https://loupe-server/v1/jobs/{}/findings", env.job_id))
		.header(JOB_CAPABILITY_HEADER, env.job_capability.expose_secret())
		.json(&FindingsBatch { protocol_version: PROTOCOL_VERSION, findings: vec![validating] })
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);

	let resp = worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", env.job_id))
		.header(JOB_CAPABILITY_HEADER, env.job_capability.expose_secret())
		.json(&CompleteRequest {
			protocol_version: PROTOCOL_VERSION,
			outcome: CompleteOutcome::Succeeded,
			head_sha: Some("abc123".into()),
			error: None,
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);

	let states: Vec<(String, String)> = db
		.with_conn(|c| {
			let mut stmt =
				c.prepare("SELECT fingerprint, state FROM findings ORDER BY fingerprint")?;
			let rows =
				stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
			let mut out = Vec::new();
			for row in rows {
				out.push(row?);
			}
			Ok(out)
		})
		.unwrap();
	assert_eq!(
		states,
		vec![
			("confirmed-fp".to_owned(), "reported".to_owned()),
			("second-confirmed-fp".to_owned(), "reported".to_owned()),
			("validating-fp".to_owned(), "validating".to_owned()),
		]
	);
	let captured = stub_state.captured.lock().unwrap().clone();
	assert_eq!(captured.len(), 2);
	let titles: Vec<_> =
		captured.iter().map(|issue| issue.body["title"].as_str().unwrap_or("")).collect();
	assert_eq!(titles, vec!["Confirmed finding", "Second confirmed finding with a direct title"]);
	assert!(titles.iter().all(|title| !title.contains("[loupe]")), "titles: {titles:?}");
	let issue_labels: Vec<_> = captured.iter().map(|issue| issue.body["labels"].clone()).collect();
	assert_eq!(
		issue_labels,
		vec![
			serde_json::json!(["loupe", "severity:high"]),
			serde_json::json!(["loupe", "severity:critical"])
		]
	);
	let labels = stub_state.labels.lock().unwrap().clone();
	let label_specs: Vec<_> =
		labels.iter().map(|l| (l.body["name"].clone(), l.body["color"].clone())).collect();
	assert_eq!(
		label_specs,
		vec![
			("severity:high".into(), "d93f0b".into()),
			("severity:critical".into(), "b60205".into())
		]
	);

	server.shutdown().await;
}

/// A repo registered without a PAT reports through the server's GitHub
/// App: the dispatcher signs an app JWT, resolves the tracker's
/// installation, mints a repo-scoped token, and files labels and issues
/// with that token. No PAT secret exists anywhere.
#[tokio::test]
async fn dispatcher_files_issues_through_the_github_app_without_a_pat() {
	let (_repo_tmp, clone_url) = make_planted_repo();
	let (stub_addr, stub_state, _stub_join) = spawn_github_stub().await;
	let stub_base = format!("http://{stub_addr}");

	let server_dir = tempfile::tempdir().unwrap();
	let init = run_init(
		&common::config_path(server_dir.path()),
		&[common::config_hostname("loupe-server")],
		None,
	)
	.unwrap();
	let ca = Ca::from_pem(
		&std::fs::read_to_string(init.layout.ca_cert.as_path()).unwrap(),
		&std::fs::read_to_string(init.layout.ca_key.as_path()).unwrap(),
	)
	.unwrap();
	let ca_cert_pem = std::fs::read_to_string(init.layout.ca_cert.as_path()).unwrap();
	let cfg = Config {
		bind_addr: "127.0.0.1:0".parse().unwrap(),
		db_path: init.layout.db_path.clone(),
		server_cert_pem: init.layout.server_cert.read_tls_pem().unwrap(),
		server_key_pem: init.layout.server_key.read_tls_pem().unwrap(),
		ca_cert_pem: common::config_pem(&ca_cert_pem),
		ca_key_pem: init.layout.ca_key.read_tls_pem().unwrap(),
	};
	let db = Arc::new(Db::open(init.layout.db_path.as_path(), &init.master_key).unwrap());
	let reporter = Arc::new(GithubReporter::with_base(&stub_base).unwrap());
	let state = AppState::new(db.clone(), Arc::new(ca), reporter);
	let server = serve(cfg, state).await.unwrap();
	let addr = server.local_addr;

	let admin = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&ca_cert_pem))
		.identity(pem_to_identity(&init.admin_bundle.cert_pem, init.admin_bundle.key_pem.expose()))
		.resolve("loupe-server", addr)
		.use_rustls_tls()
		.build()
		.unwrap();

	// Configure the app through the real route; the stub's GET /app
	// verifies the key like GitHub would.
	let resp = admin
		.put("https://loupe-server/v1/github-app")
		.json(&SetGithubAppRequest {
			protocol_version: PROTOCOL_VERSION,
			app_id: STUB_APP_ID,
			private_key_pem: loupe_provenance::Secret::new(APP_PRIVATE_KEY_PEM.into()),
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204, "{}", resp.text().await.unwrap());

	let resp = admin
		.post("https://loupe-server/v1/repos")
		.json(&RegisterRepoRequest {
			protocol_version: PROTOCOL_VERSION,
			clone_url: "https://github.com/loupe/test-target.git".into(),
			branch: None,
			scan_interval_seconds: None,
			reporting: ReportingSetup::GithubIssue {
				target_owner: "acme".into(),
				target_repo: "tracker".into(),
				github_pat: None,
			},
			scanner_config: serde_json::Value::Null,
			verification_enabled: Some(false),
			require_approval: None,
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
	let body: serde_json::Value = resp.json().await.unwrap();
	let repo_id = body["repo_id"].as_i64().unwrap();
	db.with_conn(|c| {
		c.execute(
			"UPDATE registered_repos SET clone_url = ?1 WHERE id = ?2",
			(&clone_url, repo_id),
		)?;
		Ok(())
	})
	.unwrap();

	let resp = admin
		.post("https://loupe-server/v1/workers")
		.json(&RegisterWorkerRequest { protocol_version: PROTOCOL_VERSION, name: "w1".into() })
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201);
	let bundle: RegisterWorkerResponse = resp.json().await.unwrap();
	let raw = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&ca_cert_pem))
		.identity(pem_to_identity(&bundle.client_cert_pem, bundle.client_key_pem.expose()))
		.resolve("loupe-server", addr)
		.use_rustls_tls()
		.build()
		.unwrap();
	let server_client =
		Arc::new(ServerClient::from_parts(raw, "https://loupe-server/".parse().unwrap()));

	admin
		.post(format!("https://loupe-server/v1/repos/{repo_id}/scan"))
		.json(&ScanRequest { protocol_version: PROTOCOL_VERSION, incremental: false })
		.send()
		.await
		.unwrap();
	let cache_dir = tempfile::tempdir().unwrap();
	let cache = Arc::new(RepoCache::new(cache_dir.path().to_path_buf(), u64::MAX, None).unwrap());
	let scanners: Vec<Arc<dyn Scanner>> = vec![Arc::new(RegexSecretsScanner::new())];
	let runner = Runner::new(server_client, cache, scanners);
	assert!(runner.step(&CancellationToken::new()).await.unwrap());

	// The issue and its label were filed with the installation token,
	// never with an app JWT and never with anything PAT-shaped.
	let captured = stub_state.captured.lock().unwrap().clone();
	assert_eq!(captured.len(), 1, "expected exactly one issue, got {}", captured.len());
	assert_eq!(captured[0].owner, "acme");
	assert_eq!(captured[0].repo, "tracker");
	assert_eq!(captured[0].auth, format!("Bearer {STUB_INSTALLATION_TOKEN}"));
	let labels = stub_state.labels.lock().unwrap().clone();
	assert_eq!(labels.len(), 1);
	assert_eq!(labels[0].body["name"], "severity:high");

	// GET /app at configuration time, then one installation lookup and
	// one mint at dispatch, all authenticated with a three-segment JWT.
	let app_auths = stub_state.app_auths.lock().unwrap().clone();
	assert_eq!(app_auths.len(), 3, "app calls: {app_auths:?}");
	for auth in &app_auths {
		let jwt = auth.strip_prefix("Bearer ").expect("bearer JWT");
		assert_eq!(jwt.split('.').count(), 3, "not a compact JWT: {auth}");
	}
	let token_requests = stub_state.token_requests.lock().unwrap().clone();
	assert_eq!(
		token_requests,
		vec![serde_json::json!({
			"repositories": ["tracker"],
			"permissions": {"issues": "write"},
		})],
		"the installation token must be scoped to the tracker and to issues"
	);

	// No PAT row was ever created; the finding is reported.
	let pat_rows: i64 = db
		.with_conn(|c| {
			Ok(c.query_row("SELECT COUNT(*) FROM secrets WHERE kind = 'github_pat'", [], |r| {
				r.get(0)
			})?)
		})
		.unwrap();
	assert_eq!(pat_rows, 0);
	let reported_count: i64 = db
		.with_conn(|c| {
			Ok(c.query_row("SELECT COUNT(*) FROM findings WHERE state = 'reported'", [], |r| {
				r.get(0)
			})?)
		})
		.unwrap();
	assert_eq!(reported_count, 1);

	server.shutdown().await;
}

/// The `allowed_target_owners` list is enforced when a finding is
/// dispatched, not only when a repo is registered: a row that targets a
/// foreign owner (registered before the list was tightened, or edited
/// behind the server's back) must not be able to file an issue there.
#[tokio::test]
async fn dispatch_refuses_app_mode_targets_outside_the_owner_allowlist() {
	let (stub_addr, stub_state, _stub_join) = spawn_github_stub().await;
	let stub_base = format!("http://{stub_addr}");

	let server_dir = tempfile::tempdir().unwrap();
	let init = run_init(
		&common::config_path(server_dir.path()),
		&[common::config_hostname("loupe-server")],
		None,
	)
	.unwrap();
	let ca = Ca::from_pem(
		&std::fs::read_to_string(init.layout.ca_cert.as_path()).unwrap(),
		&std::fs::read_to_string(init.layout.ca_key.as_path()).unwrap(),
	)
	.unwrap();
	let ca_cert_pem = std::fs::read_to_string(init.layout.ca_cert.as_path()).unwrap();
	let cfg = Config {
		bind_addr: "127.0.0.1:0".parse().unwrap(),
		db_path: init.layout.db_path.clone(),
		server_cert_pem: init.layout.server_cert.read_tls_pem().unwrap(),
		server_key_pem: init.layout.server_key.read_tls_pem().unwrap(),
		ca_cert_pem: common::config_pem(&ca_cert_pem),
		ca_key_pem: init.layout.ca_key.read_tls_pem().unwrap(),
	};
	let db = Arc::new(Db::open(init.layout.db_path.as_path(), &init.master_key).unwrap());
	let reporter = Arc::new(GithubReporter::with_base(&stub_base).unwrap());
	let state = AppState::new(db.clone(), Arc::new(ca), reporter)
		.with_github_app_allowed_owners(common::allowed_owners(Some(vec!["acme".into()])));
	let server = serve(cfg, state).await.unwrap();
	let addr = server.local_addr;
	let admin = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&ca_cert_pem))
		.identity(pem_to_identity(&init.admin_bundle.cert_pem, init.admin_bundle.key_pem.expose()))
		.resolve("loupe-server", addr)
		.use_rustls_tls()
		.build()
		.unwrap();

	let resp = admin
		.put("https://loupe-server/v1/github-app")
		.json(&SetGithubAppRequest {
			protocol_version: PROTOCOL_VERSION,
			app_id: STUB_APP_ID,
			private_key_pem: loupe_provenance::Secret::new(APP_PRIVATE_KEY_PEM.into()),
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204, "{}", resp.text().await.unwrap());

	// Register against the allowed owner, then re-point the stored row
	// at a foreign tracker behind the registration checks.
	let resp = admin
		.post("https://loupe-server/v1/repos")
		.json(&RegisterRepoRequest {
			protocol_version: PROTOCOL_VERSION,
			clone_url: "https://github.com/loupe/test-target.git".into(),
			branch: None,
			scan_interval_seconds: None,
			reporting: ReportingSetup::GithubIssue {
				target_owner: "acme".into(),
				target_repo: "tracker".into(),
				github_pat: None,
			},
			scanner_config: serde_json::Value::Null,
			verification_enabled: Some(false),
			require_approval: None,
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
	let body: serde_json::Value = resp.json().await.unwrap();
	let repo_id = body["repo_id"].as_i64().unwrap();
	let finding_id: i64 = db
		.with_conn(|c| {
			c.execute(
				"UPDATE registered_repos SET reporting = ?1 WHERE id = ?2",
				(
					r#"{"kind":"github_issue","target_owner":"evil","target_repo":"tracker"}"#,
					repo_id,
				),
			)?;
			c.execute(
				"INSERT INTO jobs (repo_id, kind, state, enqueued_at) VALUES (?1, 'scan', 'succeeded', 0)",
				[repo_id],
			)?;
			let job_id = c.last_insert_rowid();
			c.execute(
				"INSERT INTO findings (repo_id, job_id, scanner_id, severity, title, description,
				    fingerprint, state, verification_required, created_at, report_identity)
				 VALUES (?1, ?2, 'regex-secrets', 'high', 'leaked key', 'd', 'fp', 'confirmed', 0, 0, randomblob(16))",
				(repo_id, job_id),
			)?;
			Ok(c.last_insert_rowid())
		})
		.unwrap();

	let resp = admin
		.post(format!("https://loupe-server/v1/findings/{finding_id}/retry-report"))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 500, "dispatch to a foreign owner must fail");
	let body = resp.text().await.unwrap();
	assert!(body.contains("evil") && body.contains("acme"), "error must name both: {body}");

	let state_now: String = db
		.with_conn(|c| {
			Ok(c.query_row("SELECT state FROM findings WHERE id = ?1", [finding_id], |r| r.get(0))?)
		})
		.unwrap();
	assert_eq!(state_now, "confirmed", "finding must stay unreported");
	assert!(stub_state.captured.lock().unwrap().is_empty(), "no issue may reach GitHub");
	assert!(stub_state.labels.lock().unwrap().is_empty(), "no label may reach GitHub");
	assert_eq!(
		stub_state.app_auths.lock().unwrap().len(),
		1,
		"only the configuration-time GET /app may hit the app endpoints"
	);

	server.shutdown().await;
}
