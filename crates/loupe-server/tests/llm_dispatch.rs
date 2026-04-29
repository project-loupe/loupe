//! End-to-end test: full server + worker pipeline driven by the LLM
//! code-review scanner with a stub backend, dispatching through to a
//! fake-GitHub stub.
//!
//! Sibling to `dispatch.rs` (which exercises the regex scanner). This
//! test proves that the LLM scanner's `poc_unified` output makes it
//! all the way to the rendered issue body.

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
use loupe_worker::llm::testing::StubLlmBackend;
use loupe_worker::llm::LlmRequest;
use loupe_worker::scanners::LlmCodeReviewScanner;
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
	body: serde_json::Value,
}

async fn stub_create_issue(
	State(stub): State<GithubStubState>,
	axum::extract::Path((owner, repo)): axum::extract::Path<(String, String)>,
	Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
	stub.captured.lock().unwrap().push(CapturedIssue { owner, repo, body });
	(
		StatusCode::CREATED,
		Json(serde_json::json!({"number": 1, "html_url": "https://stub/issues/1"})),
	)
}

async fn spawn_github_stub() -> (SocketAddr, GithubStubState, tokio::task::JoinHandle<()>) {
	let stub = GithubStubState::default();
	let app = Router::new()
		.route("/repos/{owner}/{repo}/issues", post(stub_create_issue))
		.with_state(stub.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let join = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
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

/// Build a tiny git repo on disk with a planted-vulnerable Rust file at
/// HEAD. The LLM scanner (with a stub backend) will "find" the bug
/// regardless of the file's content; we still write something realistic
/// so the worktree walk yields one candidate.
fn make_planted_repo() -> (tempfile::TempDir, String) {
	let tmp = tempfile::tempdir().unwrap();
	let repo = Repository::init(tmp.path()).unwrap();
	std::fs::write(
		tmp.path().join("Cargo.toml"),
		"[package]\nname = \"sample\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
	)
	.unwrap();
	std::fs::create_dir_all(tmp.path().join("src")).unwrap();
	std::fs::write(
		tmp.path().join("src/lib.rs"),
		"pub fn idx(arr: &[u8], i: usize) -> u8 { arr[i] }\n",
	)
	.unwrap();
	let mut index = repo.index().unwrap();
	index.add_path(std::path::Path::new("Cargo.toml")).unwrap();
	index.add_path(std::path::Path::new("src/lib.rs")).unwrap();
	index.write().unwrap();
	let tree_oid = index.write_tree().unwrap();
	let tree = repo.find_tree(tree_oid).unwrap();
	let sig = Signature::now("loupe-test", "loupe-test@example.com").unwrap();
	repo.commit(Some("HEAD"), &sig, &sig, "plant", &tree, &[]).unwrap();
	let url = format!("file://{}", tmp.path().display());
	(tmp, url)
}

#[tokio::test]
async fn llm_scanner_full_pipeline_dispatches_via_github() {
	let (_repo_tmp, clone_url) = make_planted_repo();
	let (stub_addr, stub_state, _stub_join) = spawn_github_stub().await;
	let stub_base = format!("http://{stub_addr}");

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
				github_pat: "ghp_pat".into(),
			},
			scanner_config: serde_json::Value::Null,
			verification_enabled: false,
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

	admin
		.post(format!("https://loupe-server/v1/repos/{}/scan", repo_id))
		.json(&ScanRequest { protocol_version: PROTOCOL_VERSION, incremental: false })
		.send()
		.await
		.unwrap();

	// Stub LLM backend: discovery returns one finding, validation
	// confirms it with a small PoC diff. We tell the two prompts apart
	// by the "validating a vulnerability report" phrase the validation
	// template begins with.
	let stub_backend = Arc::new(StubLlmBackend::new("stub", |req: &LlmRequest| {
		if req.prompt.contains("validating a vulnerability report") {
			Ok(r#"{"verdict":"confirmed","notes":"reproduced","poc_unified":"--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -0,0 +1 @@\n+#[test] fn oob_panic() { idx(&[], 0); }\n"}"#.to_owned())
		} else {
			Ok(r#"{"found":true,"severity":"high","title":"Out-of-bounds index in idx","file":"src/lib.rs","line_start":1,"line_end":1,"description":"`idx` indexes the slice without bounds checking, causing a panic on empty input.","cwe":"CWE-129"}"#.to_owned())
		}
	}));
	let cache_dir = tempfile::tempdir().unwrap();
	let cache = Arc::new(RepoCache::new(cache_dir.path().to_path_buf(), u64::MAX).unwrap());
	let scanners: Vec<Arc<dyn Scanner>> = vec![Arc::new(LlmCodeReviewScanner::new(stub_backend))];
	let runner = Runner::new(server_client, cache, scanners);
	let cancel = CancellationToken::new();
	let stepped = runner.step(&cancel).await.unwrap();
	assert!(stepped, "runner should have leased and run the queued job");

	// Server-side: the job is succeeded, exactly one finding landed,
	// and it carries our PoC.
	let finding_count: i64 = db
		.with_conn(|c| Ok(c.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))?))
		.unwrap();
	assert_eq!(finding_count, 1);

	let (poc, scanner_id, severity): (Option<String>, String, String) = db
		.with_conn(|c| {
			Ok(c.query_row(
				"SELECT poc_unified, scanner_id, severity FROM findings LIMIT 1",
				[],
				|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
			)?)
		})
		.unwrap();
	assert_eq!(scanner_id, "llm-code-review");
	assert_eq!(severity, "high");
	let poc = poc.expect("poc_unified must be populated");
	assert!(poc.contains("#[test] fn oob_panic"), "got: {poc}");

	// Dispatcher: GitHub stub captured exactly one issue addressed to
	// the target tracker, with the finding title in the body.
	let captured = stub_state.captured.lock().unwrap().clone();
	assert_eq!(captured.len(), 1);
	let issue = &captured[0];
	assert_eq!(issue.owner, "acme");
	assert_eq!(issue.repo, "tracker");
	let issue_body = issue.body["body"].as_str().unwrap_or("");
	let issue_title = issue.body["title"].as_str().unwrap_or("");
	assert!(issue_title.contains("high finding"), "title: {issue_title}");
	assert!(issue_body.contains("Out-of-bounds index"), "body: {issue_body}");
	assert!(issue_body.contains("llm-code-review"), "body: {issue_body}");

	server.shutdown().await;
}
