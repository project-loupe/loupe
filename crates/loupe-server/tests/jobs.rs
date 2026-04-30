//! End-to-end test for the worker-side job state machine: enqueue,
//! lease, heartbeat, submit a finding, complete. Covers the role
//! gating (admin can't lease; worker can't enqueue) and the dedup
//! semantics (same fingerprint twice ⇒ one row).

use std::net::SocketAddr;
use std::sync::Arc;

use loupe_core::Severity;
use loupe_proto::{
	CompleteOutcome, CompleteRequest, FindingsBatch, LeaseRequest, LeaseResponse,
	RegisterRepoRequest, RegisterWorkerRequest, RegisterWorkerResponse, ReportingSetup,
	ScanRequest, ScanResponse, PROTOCOL_VERSION,
};
use loupe_server::init::run_init;
use loupe_server::{serve, AppState, Config};
use loupe_storage::Db;
use loupe_tls::Ca;

mod common;
use common::{pem_to_certificate, pem_to_identity};

fn client(ca_cert_pem: &str, cert_pem: &str, key_pem: &str, addr: SocketAddr) -> reqwest::Client {
	reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(ca_cert_pem))
		.identity(pem_to_identity(cert_pem, key_pem))
		.resolve("loupe-server", addr)
		.use_rustls_tls()
		.build()
		.unwrap()
}

#[allow(dead_code)]
struct Fixture {
	handle: loupe_server::ServeHandle,
	addr: SocketAddr,
	db: Arc<Db>,
	admin: reqwest::Client,
	worker: reqwest::Client,
	repo_id: i64,
}

async fn bring_up_with_repo_and_worker() -> Fixture {
	let tmp = tempfile::tempdir().unwrap();
	let init = run_init(tmp.path(), &["loupe-server".to_owned()], None).unwrap();

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
	let state = AppState::new(
		db.clone(),
		Arc::new(ca),
		Arc::new(loupe_server::reporters::GithubReporter::new().unwrap()),
	);
	let handle = serve(cfg, state).await.unwrap();
	let addr = handle.local_addr;
	std::mem::forget(tmp);

	let admin = client(&ca_cert_pem, &init.admin_bundle.cert_pem, &init.admin_bundle.key_pem, addr);

	// Register a repo via the admin route, so we hit the real path.
	let req = RegisterRepoRequest {
		protocol_version: PROTOCOL_VERSION,
		clone_url: "https://github.com/acme/widget.git".into(),
		branch: Some("main".into()),
		scan_interval_seconds: None,
		reporting: ReportingSetup::GithubIssue {
			target_owner: "acme".into(),
			target_repo: "tracker".into(),
			github_pat: "ghp".into(),
		},
		scanner_config: serde_json::Value::Null,
		verification_enabled: false,
		require_approval: None,
	};
	let resp = admin.post("https://loupe-server/v1/repos").json(&req).send().await.unwrap();
	assert_eq!(resp.status(), 201);
	let body: serde_json::Value = resp.json().await.unwrap();
	let repo_id = body["repo_id"].as_i64().unwrap();

	// Mint a worker.
	let resp = admin
		.post("https://loupe-server/v1/workers")
		.json(&RegisterWorkerRequest { protocol_version: PROTOCOL_VERSION, name: "w1".into() })
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201);
	let bundle: RegisterWorkerResponse = resp.json().await.unwrap();
	let worker = client(&ca_cert_pem, &bundle.client_cert_pem, &bundle.client_key_pem, addr);

	Fixture { handle, addr, db, admin, worker, repo_id }
}

#[tokio::test]
async fn end_to_end_scan_lifecycle() {
	let f = bring_up_with_repo_and_worker().await;

	// Admin enqueues a scan.
	let resp = f
		.admin
		.post(format!("https://loupe-server/v1/repos/{}/scan", f.repo_id))
		.json(&ScanRequest { protocol_version: PROTOCOL_VERSION, incremental: false })
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201);
	let scan: ScanResponse = resp.json().await.unwrap();

	// Worker leases.
	let resp = f
		.worker
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
	let body: LeaseResponse = resp.json().await.unwrap();
	let env = match body {
		LeaseResponse::Lease(e) => *e,
		LeaseResponse::Empty { .. } => panic!("queue should not be empty"),
	};
	assert_eq!(env.job_id, scan.job_id);
	assert_eq!(env.repo.clone_url, "https://github.com/acme/widget.git");

	// Heartbeat extends the lease.
	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/heartbeat", env.job_id))
		.send()
		.await
		.unwrap();
	assert!(resp.status().is_success());

	// Submit a finding (twice — second one must be a dedup no-op).
	let f1 = loupe_core::Finding {
		scanner_id: "regex".into(),
		severity: Severity::High,
		title: "AWS access key".into(),
		description: "Found AKIA token".into(),
		file_path: Some("src/x.rs".into()),
		line_start: Some(1),
		line_end: Some(1),
		cwe: None,
		patch_unified: None,
		poc_unified: None,
		fingerprint: "fp1".into(),
	};
	for _ in 0..2 {
		let resp = f
			.worker
			.post(format!("https://loupe-server/v1/jobs/{}/findings", env.job_id))
			.json(&FindingsBatch { protocol_version: PROTOCOL_VERSION, findings: vec![f1.clone()] })
			.send()
			.await
			.unwrap();
		assert_eq!(resp.status(), 204);
	}

	// Complete with success.
	let resp = f
		.worker
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

	// Findings table has exactly one row (dedup worked).
	let count: i64 =
		f.db.with_conn(|c| Ok(c.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))?))
			.unwrap();
	assert_eq!(count, 1);

	// Job is succeeded; repo's last_scanned_sha is updated.
	let job = f
		.admin
		.get(format!("https://loupe-server/v1/jobs/{}", env.job_id))
		.send()
		.await
		.unwrap()
		.json::<serde_json::Value>()
		.await
		.unwrap();
	assert_eq!(job["state"], "succeeded");
	assert_eq!(job["head_sha"], "abc123");

	// scan_history row was written.
	let history_count: i64 =
		f.db.with_conn(|c| Ok(c.query_row("SELECT COUNT(*) FROM scan_history", [], |r| r.get(0))?))
			.unwrap();
	assert_eq!(history_count, 1);

	f.handle.shutdown().await;
}

#[tokio::test]
async fn admin_cannot_lease_jobs() {
	let f = bring_up_with_repo_and_worker().await;
	let resp = f
		.admin
		.post("https://loupe-server/v1/jobs/lease")
		.json(&LeaseRequest {
			protocol_version: PROTOCOL_VERSION,
			capabilities: vec![],
			wait_seconds: 0,
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 403, "admin cert must not be allowed to lease");
	f.handle.shutdown().await;
}

#[tokio::test]
async fn worker_cannot_enqueue_scans() {
	let f = bring_up_with_repo_and_worker().await;
	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/repos/{}/scan", f.repo_id))
		.json(&ScanRequest { protocol_version: PROTOCOL_VERSION, incremental: false })
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 403);
	f.handle.shutdown().await;
}

#[tokio::test]
async fn long_poll_lease_wakes_on_enqueue() {
	let f = bring_up_with_repo_and_worker().await;

	// Worker starts a long-poll *before* anything's queued.
	let lease_fut = f
		.worker
		.post("https://loupe-server/v1/jobs/lease")
		.json(&LeaseRequest {
			protocol_version: PROTOCOL_VERSION,
			capabilities: vec![],
			wait_seconds: 5,
		})
		.send();

	// Briefly give the lease handler time to register on the notifier.
	let admin = f.admin.clone();
	let repo_id = f.repo_id;
	let enqueue_task = async move {
		tokio::time::sleep(std::time::Duration::from_millis(50)).await;
		admin
			.post(format!("https://loupe-server/v1/repos/{}/scan", repo_id))
			.json(&ScanRequest { protocol_version: PROTOCOL_VERSION, incremental: false })
			.send()
			.await
			.unwrap();
	};

	let started = tokio::time::Instant::now();
	let (lease_resp, _) = tokio::join!(lease_fut, enqueue_task);
	let elapsed = started.elapsed();

	let resp = lease_resp.unwrap();
	assert!(resp.status().is_success());
	let body: LeaseResponse = resp.json().await.unwrap();
	assert!(matches!(body, LeaseResponse::Lease(_)), "long-poll must wake with a job");
	assert!(elapsed < std::time::Duration::from_secs(2), "long-poll woke quickly: {elapsed:?}");

	f.handle.shutdown().await;
}

#[tokio::test]
async fn empty_queue_returns_empty_lease_response() {
	let f = bring_up_with_repo_and_worker().await;
	let resp = f
		.worker
		.post("https://loupe-server/v1/jobs/lease")
		.json(&LeaseRequest {
			protocol_version: PROTOCOL_VERSION,
			capabilities: vec![],
			wait_seconds: 0,
		})
		.send()
		.await
		.unwrap();
	assert!(resp.status().is_success());
	let body: LeaseResponse = resp.json().await.unwrap();
	assert!(matches!(body, LeaseResponse::Empty { .. }));
	f.handle.shutdown().await;
}
