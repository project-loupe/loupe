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
use loupe_core::{Finding, Severity};
use loupe_proto::{
	CompleteOutcome, CompleteRequest, FindingsBatch, LeaseRequest, LeaseResponse,
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
	let init = run_init(server_dir.path(), &["loupe-server".to_owned()], None).unwrap();

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
	let db = Arc::new(Db::open(&init.layout.db_path, &init.master_key).unwrap());
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
			verification_enabled: false,
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

	// On-disk encryption check: the SQLCipher-sealed file must not
	// contain the PAT in the clear. (The DAO-level "raw .sqlite is
	// ciphertext" guarantee is also tested in `loupe-storage::db`
	// tests; this one proves it survives a real dispatch path.)
	let raw = std::fs::read(&init.layout.db_path).unwrap();
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
	let init = run_init(server_dir.path(), &["loupe-server".to_owned()], None).unwrap();

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
	let db = Arc::new(Db::open(&init.layout.db_path, &init.master_key).unwrap());
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
				github_pat: "ghp_test_pat_value".into(),
			},
			scanner_config: serde_json::Value::Null,
			verification_enabled: false,
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
		.identity(pem_to_identity(&bundle.client_cert_pem, &bundle.client_key_pem))
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
		.json(&FindingsBatch { protocol_version: PROTOCOL_VERSION, findings: vec![validating] })
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);

	let resp = worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", env.job_id))
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
	assert_eq!(
		titles,
		vec!["high: Confirmed finding", "critical: Second confirmed finding with a direct title"]
	);
	assert!(titles.iter().all(|title| !title.contains("[loupe]")), "titles: {titles:?}");

	server.shutdown().await;
}
