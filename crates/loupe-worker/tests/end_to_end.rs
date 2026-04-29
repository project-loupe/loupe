//! End-to-end worker test: spin up loupe-server in-process, register a
//! repo (clone URL pointed at a local git repo on disk), mint a worker,
//! kick a scan, run a single Runner step, and prove the worker's
//! scanner produced a finding and completed the job.

use std::net::SocketAddr;
use std::sync::Arc;

use git2::{Repository, Signature};
use loupe_proto::{
	RegisterRepoRequest, RegisterWorkerRequest, RegisterWorkerResponse, ReportingSetup,
	ScanRequest, PROTOCOL_VERSION,
};
use loupe_server::init::run_init;
use loupe_server::{serve, AppState, Config};
use loupe_storage::Db;
use loupe_tls::Ca;
use loupe_worker::scanners::RegexSecretsScanner;
use loupe_worker::{RepoCache, Runner, Scanner, ServerClient};
use tokio_util::sync::CancellationToken;

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

/// Make a tiny git repo on disk with a planted AKIA token committed at HEAD.
/// Returns (TempDir holding the repo, file:// clone URL).
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
async fn worker_runs_a_scan_and_emits_a_finding() {
	let (_repo_tmp, clone_url) = make_planted_repo();
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
	let state = AppState::new(db.clone(), Arc::new(ca));
	let server_handle = serve(cfg, state).await.unwrap();
	let addr: SocketAddr = server_handle.local_addr;

	// Admin client: register a (faked) https URL via the route, then
	// rewrite the row in-place to point at our local file:// repo so
	// the worker's git2 fetch hits the filesystem.
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
				target_owner: "x".into(),
				target_repo: "y".into(),
				github_pat: "ghp".into(),
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

	// Build the worker's reqwest client with `.resolve("loupe-server", addr)` and
	// hand it to ServerClient via `from_parts`.
	let raw = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&ca_cert_pem))
		.identity(pem_to_identity(&bundle.client_cert_pem, &bundle.client_key_pem))
		.resolve("loupe-server", addr)
		.use_rustls_tls()
		.build()
		.unwrap();
	let server_client =
		Arc::new(ServerClient::from_parts(raw, "https://loupe-server/".parse().unwrap()));

	// Trigger a scan.
	let resp = admin
		.post(format!("https://loupe-server/v1/repos/{}/scan", repo_id))
		.json(&ScanRequest { protocol_version: PROTOCOL_VERSION, incremental: false })
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201);

	let cache_dir = tempfile::tempdir().unwrap();
	let cache = Arc::new(RepoCache::new(cache_dir.path().to_path_buf(), u64::MAX).unwrap());
	let scanners: Vec<Arc<dyn Scanner>> = vec![Arc::new(RegexSecretsScanner::new())];
	let runner = Runner::new(server_client, cache, scanners);

	let cancel = CancellationToken::new();
	let stepped = runner.step(&cancel).await.unwrap();
	assert!(stepped, "runner should have leased and run the queued job");

	let count: i64 = db
		.with_conn(|c| Ok(c.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))?))
		.unwrap();
	assert_eq!(count, 1, "expected exactly one finding");

	let state: String = db
		.with_conn(|c| {
			Ok(c.query_row("SELECT state FROM jobs LIMIT 1", [], |r| r.get::<_, String>(0))?)
		})
		.unwrap();
	assert_eq!(state, "succeeded");

	let head_sha: Option<String> = db
		.with_conn(|c| {
			Ok(c.query_row("SELECT head_sha FROM jobs LIMIT 1", [], |r| {
				r.get::<_, Option<String>>(0)
			})?)
		})
		.unwrap();
	assert!(head_sha.is_some(), "head_sha should have been persisted on success");

	server_handle.shutdown().await;
}
