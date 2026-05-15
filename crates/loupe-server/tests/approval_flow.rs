//! End-to-end coverage for the human-in-the-loop approval gate.
//!
//! Stands up a real `loupe-server` with `require_approval_default = true`,
//! a stubbed GitHub Issues API, runs a scan, and proves:
//!
//! * the finding parks in `awaiting_approval` and the stub captures
//!   nothing during the scan;
//! * `POST /v1/findings/{id}/approve` releases the held finding,
//!   stamps the audit columns, and the dispatcher fires the reporter;
//! * `POST /v1/findings/{id}/reject` on a different held finding
//!   transitions it to terminal `dismissed` without dispatching;
//! * a per-repo `require_approval = false` opt-out beats the global
//!   default, so an opted-out repo dispatches immediately even when
//!   the server-wide default is on.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use git2::{Repository, Signature};
use loupe_proto::{
	RegisterRepoRequest, RegisterWorkerRequest, RegisterWorkerResponse, ReportingSetup,
	ScanRequest, SetRepoGithubReportingRequest, PROTOCOL_VERSION,
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
}

async fn stub_create_issue(
	State(stub): State<GithubStubState>,
	axum::extract::Path((owner, repo)): axum::extract::Path<(String, String)>,
	Json(_body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
	stub.captured.lock().unwrap().push(CapturedIssue { owner, repo });
	(
		StatusCode::CREATED,
		Json(serde_json::json!({"number": 7, "html_url": "https://stub/issues/7"})),
	)
}

async fn spawn_github_stub() -> (SocketAddr, GithubStubState) {
	let stub = GithubStubState::default();
	let app = Router::new()
		.route("/repos/{owner}/{repo}/issues", post(stub_create_issue))
		.with_state(stub.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	(addr, stub)
}

mod common;
use common::{pem_to_certificate, pem_to_identity};

fn make_planted_repo(unique: &str) -> (tempfile::TempDir, String) {
	let tmp = tempfile::tempdir().unwrap();
	let repo = Repository::init(tmp.path()).unwrap();
	std::fs::write(
		tmp.path().join("config.rs"),
		format!("// {unique}\nconst KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";\n"),
	)
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

struct Harness {
	server: loupe_server::ServeHandle,
	addr: SocketAddr,
	admin: reqwest::Client,
	db: Arc<Db>,
	stub: GithubStubState,
	server_dir: tempfile::TempDir,
	ca_cert_pem: String,
}

async fn boot_server_with_default(require_approval_default: bool) -> Harness {
	let (stub_addr, stub) = spawn_github_stub().await;
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
	let state = AppState::new(db.clone(), Arc::new(ca), reporter)
		.with_require_approval_default(require_approval_default);
	let server = serve(cfg, state).await.unwrap();
	let addr = server.local_addr;

	let admin = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&ca_cert_pem))
		.identity(pem_to_identity(&init.admin_bundle.cert_pem, &init.admin_bundle.key_pem))
		.resolve("loupe-server", addr)
		.use_rustls_tls()
		.build()
		.unwrap();

	Harness { server, addr, admin, db, stub, server_dir, ca_cert_pem }
}

async fn register_repo(
	h: &Harness, clone_url: &str, require_approval: Option<bool>, target_repo: &str,
) -> i64 {
	register_with(
		h,
		clone_url,
		require_approval,
		target_repo,
		ReportingSetup::GithubIssue {
			target_owner: "acme".into(),
			target_repo: target_repo.into(),
			github_pat: "ghp_test_pat".into(),
		},
	)
	.await
}

async fn register_manual_repo(
	h: &Harness, clone_url: &str, require_approval: Option<bool>, label: &str,
) -> i64 {
	register_with(h, clone_url, require_approval, label, ReportingSetup::Manual).await
}

async fn register_with(
	h: &Harness, clone_url: &str, require_approval: Option<bool>, target_repo: &str,
	reporting: ReportingSetup,
) -> i64 {
	let resp = h
		.admin
		.post("https://loupe-server/v1/repos")
		.json(&RegisterRepoRequest {
			protocol_version: PROTOCOL_VERSION,
			// We patch this to the local file:// path after registration so
			// the URL parser still sees a github.com host on the way in.
			clone_url: format!("https://github.com/loupe/{target_repo}.git"),
			branch: None,
			scan_interval_seconds: None,
			reporting,
			scanner_config: serde_json::Value::Null,
			verification_enabled: false,
			require_approval,
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201);
	let body: serde_json::Value = resp.json().await.unwrap();
	let repo_id = body["repo_id"].as_i64().unwrap();
	h.db.with_conn(|c| {
		c.execute(
			"UPDATE registered_repos SET clone_url = ?1 WHERE id = ?2",
			(clone_url, repo_id),
		)?;
		Ok(())
	})
	.unwrap();
	repo_id
}

async fn make_worker_runner(h: &Harness) -> (Runner, tempfile::TempDir) {
	let resp = h
		.admin
		.post("https://loupe-server/v1/workers")
		.json(&RegisterWorkerRequest { protocol_version: PROTOCOL_VERSION, name: "w1".into() })
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201);
	let bundle: RegisterWorkerResponse = resp.json().await.unwrap();
	let raw = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&h.ca_cert_pem))
		.identity(pem_to_identity(&bundle.client_cert_pem, &bundle.client_key_pem))
		.resolve("loupe-server", h.addr)
		.use_rustls_tls()
		.build()
		.unwrap();
	let server_client =
		Arc::new(ServerClient::from_parts(raw, "https://loupe-server/".parse().unwrap()));
	let cache_dir = tempfile::tempdir().unwrap();
	let cache = Arc::new(RepoCache::new(cache_dir.path().to_path_buf(), u64::MAX).unwrap());
	let scanners: Vec<Arc<dyn Scanner>> = vec![Arc::new(RegexSecretsScanner::new())];
	(Runner::new(server_client, cache, scanners), cache_dir)
}

async fn trigger_scan_and_run(h: &Harness, repo_id: i64) {
	h.admin
		.post(format!("https://loupe-server/v1/repos/{repo_id}/scan"))
		.json(&ScanRequest { protocol_version: PROTOCOL_VERSION, incremental: false })
		.send()
		.await
		.unwrap();
	let (runner, _cache_dir) = make_worker_runner(h).await;
	let cancel = CancellationToken::new();
	let stepped = runner.step(&cancel).await.unwrap();
	assert!(stepped, "worker did not complete a job");
}

#[tokio::test]
async fn require_approval_default_holds_findings_until_approved() {
	let (_repo_tmp, clone_url) = make_planted_repo("approve");
	let h = boot_server_with_default(true).await;
	let repo_id = register_repo(&h, &clone_url, None, "approve-target").await;

	trigger_scan_and_run(&h, repo_id).await;

	// During the scan, no issue may have been filed — finding is parked.
	assert!(
		h.stub.captured.lock().unwrap().is_empty(),
		"approval-required finding must not auto-dispatch"
	);
	let (id, state, approved_at): (i64, String, Option<i64>) =
		h.db.with_conn(|c| {
			Ok(c.query_row(
				"SELECT id, state, approved_at FROM findings WHERE repo_id = ?1",
				[repo_id],
				|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
			)?)
		})
		.unwrap();
	assert_eq!(state, "awaiting_approval");
	assert!(approved_at.is_none());

	// Operator approves → dispatcher fires → issue lands in stub.
	let resp = h
		.admin
		.post(format!("https://loupe-server/v1/findings/{id}/approve"))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);

	let issues = h.stub.captured.lock().unwrap().clone();
	assert_eq!(issues.len(), 1, "approve did not trigger a single dispatch");
	assert_eq!(issues[0].owner, "acme");
	assert_eq!(issues[0].repo, "approve-target");

	let (state, approved_at, approved_by): (String, Option<i64>, Option<String>) =
		h.db.with_conn(|c| {
			Ok(c.query_row(
				"SELECT state, approved_at, approved_by_cn FROM findings WHERE id = ?1",
				[id],
				|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
			)?)
		})
		.unwrap();
	assert_eq!(state, "reported");
	assert!(approved_at.is_some(), "approved_at must be stamped");
	assert_eq!(
		approved_by.as_deref(),
		Some("admin"),
		"approved_by_cn must record the admin's worker name (the init-time admin's name)"
	);

	h.server.shutdown().await;
	drop(h.server_dir);
}

#[tokio::test]
async fn rejecting_a_held_finding_dismisses_without_dispatch() {
	let (_repo_tmp, clone_url) = make_planted_repo("reject");
	let h = boot_server_with_default(true).await;
	let repo_id = register_repo(&h, &clone_url, None, "reject-target").await;

	trigger_scan_and_run(&h, repo_id).await;

	let id: i64 =
		h.db.with_conn(|c| {
			Ok(c.query_row(
				"SELECT id FROM findings WHERE repo_id = ?1 AND state = 'awaiting_approval'",
				[repo_id],
				|r| r.get(0),
			)?)
		})
		.unwrap();

	let resp =
		h.admin.post(format!("https://loupe-server/v1/findings/{id}/reject")).send().await.unwrap();
	assert_eq!(resp.status(), 204);

	assert!(
		h.stub.captured.lock().unwrap().is_empty(),
		"reject must not dispatch — issue should never reach the reporter"
	);
	let (state, rejected_at, rejected_by): (String, Option<i64>, Option<String>) =
		h.db.with_conn(|c| {
			Ok(c.query_row(
				"SELECT state, rejected_at, rejected_by_cn FROM findings WHERE id = ?1",
				[id],
				|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
			)?)
		})
		.unwrap();
	assert_eq!(state, "dismissed");
	assert!(rejected_at.is_some(), "rejected_at must be stamped");
	assert_eq!(rejected_by.as_deref(), Some("admin"));

	// Re-rejecting must report 409 — the finding is no longer pending.
	let resp =
		h.admin.post(format!("https://loupe-server/v1/findings/{id}/reject")).send().await.unwrap();
	assert_eq!(resp.status(), 409);

	h.server.shutdown().await;
	drop(h.server_dir);
}

#[tokio::test]
async fn per_repo_opt_out_beats_global_default() {
	let (_repo_tmp, clone_url) = make_planted_repo("optout");
	let h = boot_server_with_default(true).await;
	// Pin require_approval = false at registration time.
	let repo_id = register_repo(&h, &clone_url, Some(false), "optout-target").await;

	trigger_scan_and_run(&h, repo_id).await;

	let issues = h.stub.captured.lock().unwrap().clone();
	assert_eq!(
		issues.len(),
		1,
		"per-repo require_approval=false must dispatch immediately even when the server default is on"
	);

	let state: String =
		h.db.with_conn(|c| {
			Ok(c.query_row("SELECT state FROM findings WHERE repo_id = ?1", [repo_id], |r| {
				r.get(0)
			})?)
		})
		.unwrap();
	assert_eq!(state, "reported");

	h.server.shutdown().await;
	drop(h.server_dir);
}

#[tokio::test]
async fn manual_mode_leaves_approved_findings_confirmed_without_calling_the_reporter() {
	let (_repo_tmp, clone_url) = make_planted_repo("manual");
	// Server default off, but we register the repo with `Manual` and
	// pin require_approval = true so the operator gets to triage
	// before the dispatcher stamps `reported`.
	let h = boot_server_with_default(false).await;
	let repo_id = register_manual_repo(&h, &clone_url, Some(true), "manual-mode").await;

	trigger_scan_and_run(&h, repo_id).await;

	// Approval gate held the finding, so the GitHub stub must still be
	// untouched at this point.
	assert!(
		h.stub.captured.lock().unwrap().is_empty(),
		"manual mode + require_approval must hold the finding before approve"
	);
	let id: i64 =
		h.db.with_conn(|c| {
			Ok(c.query_row(
				"SELECT id FROM findings WHERE repo_id = ?1 AND state = 'awaiting_approval'",
				[repo_id],
				|r| r.get(0),
			)?)
		})
		.unwrap();

	// Approve. The dispatcher should short-circuit on Manual and leave
	// the finding confirmed without ever touching the GitHub stub.
	let resp = h
		.admin
		.post(format!("https://loupe-server/v1/findings/{id}/approve"))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);

	assert!(
		h.stub.captured.lock().unwrap().is_empty(),
		"manual mode must not call the reporter even after approve"
	);
	let (state, reported_at, approved_by): (String, Option<i64>, Option<String>) =
		h.db.with_conn(|c| {
			Ok(c.query_row(
				"SELECT state, reported_at, approved_by_cn FROM findings WHERE id = ?1",
				[id],
				|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
			)?)
		})
		.unwrap();
	assert_eq!(state, "confirmed");
	assert!(reported_at.is_none(), "reported_at must wait for an actual reporter");
	assert_eq!(approved_by.as_deref(), Some("admin"));

	h.server.shutdown().await;
	drop(h.server_dir);
}

#[tokio::test]
async fn manual_repo_can_add_reporting_and_retry_confirmed_findings() {
	let (_repo_tmp, clone_url) = make_planted_repo("late-reporting");
	let h = boot_server_with_default(false).await;
	let repo_id = register_manual_repo(&h, &clone_url, Some(false), "late-reporting").await;

	trigger_scan_and_run(&h, repo_id).await;

	assert!(
		h.stub.captured.lock().unwrap().is_empty(),
		"manual repo must not dispatch before reporting is configured"
	);
	let id: i64 =
		h.db.with_conn(|c| {
			Ok(c.query_row(
				"SELECT id FROM findings WHERE repo_id = ?1 AND state = 'confirmed'",
				[repo_id],
				|r| r.get(0),
			)?)
		})
		.unwrap();

	let resp = h
		.admin
		.post(format!("https://loupe-server/v1/findings/{id}/retry-report"))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 409, "retry must require a configured reporter");

	let resp = h
		.admin
		.put(format!("https://loupe-server/v1/repos/{repo_id}/reporting/github"))
		.json(&SetRepoGithubReportingRequest {
			protocol_version: PROTOCOL_VERSION,
			target_owner: "acme".into(),
			target_repo: "late-target".into(),
			github_pat: "ghp_late_pat".into(),
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);

	let resp = h
		.admin
		.post(format!("https://loupe-server/v1/findings/{id}/retry-report"))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);

	let issues = h.stub.captured.lock().unwrap().clone();
	assert_eq!(issues.len(), 1, "retry did not dispatch exactly once");
	assert_eq!(issues[0].owner, "acme");
	assert_eq!(issues[0].repo, "late-target");

	let state: String =
		h.db.with_conn(|c| {
			Ok(c.query_row("SELECT state FROM findings WHERE id = ?1", [id], |r| r.get(0))?)
		})
		.unwrap();
	assert_eq!(state, "reported");

	let resp = h
		.admin
		.post(format!("https://loupe-server/v1/findings/{id}/retry-report"))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);
	assert_eq!(
		h.stub.captured.lock().unwrap().len(),
		1,
		"reported finding must not be dispatched again"
	);

	h.server.shutdown().await;
	drop(h.server_dir);
}
