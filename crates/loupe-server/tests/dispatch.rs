//! End-to-end dispatcher test: stand up a tiny axum stub that pretends
//! to be the GitHub Issues API, point a `GithubReporter` at it, run a
//! scan job against an in-memory DB, and prove the issue body lands in
//! the stub with the expected shape.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use git2::{Repository, Signature};
use loupe_proto::{
	RegisterRepoRequest, RegisterWorkerRequest, RegisterWorkerResponse, ReportingSetup,
	ScanRequest, PROTOCOL_VERSION,
};
use loupe_server::init::run_init;
use loupe_server::reporters::GithubReporter;
use loupe_server::{serve, AppState, Config};
use loupe_storage::Db;
use loupe_tls::Ca;
use loupe_worker::scanners::RegexSecretsScanner;
use loupe_worker::{RepoCache, Runner, Scanner, ServerClient};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
struct GithubStubState {
	captured: Arc<Mutex<Vec<CapturedIssue>>>,
}

#[derive(Debug, Clone)]
struct CapturedIssue {
	owner: String,
	repo: String,
	auth: String,
	body: serde_json::Value,
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
		.route("/repos/{owner}/{repo}/issues", post(stub_create_issue))
		.with_state(stub.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let join = tokio::spawn(async move {
		axum::serve(listener, app).await.unwrap();
	});
	(addr, stub, join)
}

fn pem_to_certificate(pem: &str) -> reqwest::Certificate {
	reqwest::Certificate::from_pem(pem.as_bytes()).unwrap()
}
fn pem_to_identity(cert_pem: &str, key_pem: &str) -> reqwest::Identity {
	let mut combined = String::with_capacity(cert_pem.len() + key_pem.len() + 1);
	combined.push_str(cert_pem);
	if !cert_pem.ends_with('\n') {
		combined.push('\n');
	}
	combined.push_str(key_pem);
	reqwest::Identity::from_pem(combined.as_bytes()).unwrap()
}

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
	let init = run_init(server_dir.path(), &["loupe-server".to_owned()]).unwrap();

	let ca = Ca::from_pem(
		&std::fs::read_to_string(&init.layout.ca_cert).unwrap(),
		&std::fs::read_to_string(&init.layout.ca_key).unwrap(),
	)
	.unwrap();
	let server_cert_pem = std::fs::read_to_string(&init.layout.server_cert).unwrap();
	let server_key_pem = std::fs::read_to_string(&init.layout.server_key).unwrap();
	let ca_cert_pem = std::fs::read_to_string(&init.layout.ca_cert).unwrap();
	let ca_key_pem = std::fs::read_to_string(&init.layout.ca_key).unwrap();

	let cfg = Config {
		bind_addr: "127.0.0.1:0".parse().unwrap(),
		db_path: init.layout.db_path.clone(),
		server_cert_pem,
		server_key_pem,
		ca_cert_pem: ca_cert_pem.clone(),
		ca_key_pem,
	};
	let db = Arc::new(Db::open(&init.layout.db_path).unwrap());
	let reporter = Arc::new(GithubReporter::with_base(&stub_base).unwrap());
	let state = AppState::new(db.clone(), Arc::new(ca), reporter);
	let server = serve(cfg, state).await.unwrap();
	let addr = server.local_addr;

	// Admin client
	let admin = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&ca_cert_pem))
		.identity(pem_to_identity(&init.admin_bundle.cert_pem, &init.admin_bundle.key_pem))
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
				github_pat: "ghp_test_pat_value".into(),
			},
			scanner_config: serde_json::Value::Null,
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
		.identity(pem_to_identity(&bundle.client_cert_pem, &bundle.client_key_pem))
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
	let cache = Arc::new(RepoCache::new(cache_dir.path().to_path_buf(), u64::MAX).unwrap());
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
	assert!(body_str.contains("AWS access key"), "issue body: {body_str}");

	// Findings table marked reported.
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
