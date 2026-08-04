//! End-to-end test for the worker-side job state machine: enqueue,
//! lease, heartbeat, submit a finding, complete. Covers the role
//! gating (admin can't lease; worker can't enqueue) and the dedup
//! semantics (same fingerprint twice ⇒ one row).

use std::net::SocketAddr;
use std::sync::Arc;

use loupe_core::{Finding, JobState, Severity, Verdict};
use loupe_proto::{
	CompleteOutcome, CompleteRequest, FindingDetail, FindingsBatch, HeartbeatRequest, JobInfo,
	LeaseEnvelope, LeasePayload, LeaseRequest, LeaseResponse, ListFindingsResponse,
	RegisterRepoRequest, RegisterWorkerRequest, RegisterWorkerResponse, ReportingSetup,
	RetryVerifyRequest, RetryVerifyResponse, ScanRequest, ScanResponse, VerdictSubmission,
	PROTOCOL_VERSION,
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
	ca_cert_pem: String,
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
		clone_token: None,
		branch: Some("main".into()),
		scan_interval_seconds: None,
		reporting: ReportingSetup::GithubIssue {
			target_owner: "acme".into(),
			target_repo: "tracker".into(),
			github_pat: "ghp".into(),
		},
		scanner_config: serde_json::Value::Null,
		verification_enabled: Some(false),
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

	Fixture { handle, addr, db, admin, worker, repo_id, ca_cert_pem }
}

async fn register_repo(f: &Fixture, clone_url: &str, target_repo: &str) -> i64 {
	let req = RegisterRepoRequest {
		protocol_version: PROTOCOL_VERSION,
		clone_url: clone_url.into(),
		clone_token: None,
		branch: Some("main".into()),
		scan_interval_seconds: None,
		reporting: ReportingSetup::GithubIssue {
			target_owner: "acme".into(),
			target_repo: target_repo.into(),
			github_pat: "ghp".into(),
		},
		scanner_config: serde_json::Value::Null,
		verification_enabled: Some(false),
		require_approval: None,
	};
	let resp = f.admin.post("https://loupe-server/v1/repos").json(&req).send().await.unwrap();
	assert_eq!(resp.status(), 201);
	let body: serde_json::Value = resp.json().await.unwrap();
	body["repo_id"].as_i64().unwrap()
}

async fn register_worker(f: &Fixture, name: &str) -> reqwest::Client {
	let resp = f
		.admin
		.post("https://loupe-server/v1/workers")
		.json(&RegisterWorkerRequest { protocol_version: PROTOCOL_VERSION, name: name.into() })
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201);
	let bundle: RegisterWorkerResponse = resp.json().await.unwrap();
	client(&f.ca_cert_pem, &bundle.client_cert_pem, &bundle.client_key_pem, f.addr)
}

async fn enqueue_scan(f: &Fixture, repo_id: i64) -> ScanResponse {
	let resp = f
		.admin
		.post(format!("https://loupe-server/v1/repos/{repo_id}/scan"))
		.json(&ScanRequest { protocol_version: PROTOCOL_VERSION, incremental: false })
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201);
	resp.json().await.unwrap()
}

async fn lease_job(worker: &reqwest::Client) -> LeaseEnvelope {
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
	match resp.json::<LeaseResponse>().await.unwrap() {
		LeaseResponse::Lease(env) => *env,
		LeaseResponse::Empty { .. } => panic!("queue should not be empty"),
	}
}

async fn lease_verify_job(worker: &reqwest::Client) -> LeaseEnvelope {
	let resp = worker
		.post("https://loupe-server/v1/jobs/lease")
		.json(&LeaseRequest {
			protocol_version: PROTOCOL_VERSION,
			capabilities: vec!["verify:llm".into()],
			wait_seconds: 0,
		})
		.send()
		.await
		.unwrap();
	assert!(resp.status().is_success());
	match resp.json::<LeaseResponse>().await.unwrap() {
		LeaseResponse::Lease(env) => *env,
		LeaseResponse::Empty { .. } => panic!("verify queue should not be empty"),
	}
}

async fn submit_finding(worker: &reqwest::Client, job_id: i64, finding: Finding) {
	let resp = worker
		.post(format!("https://loupe-server/v1/jobs/{job_id}/findings"))
		.json(&FindingsBatch { protocol_version: PROTOCOL_VERSION, findings: vec![finding] })
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);
}

async fn submit_many_findings(worker: &reqwest::Client, job_id: i64, count: usize) {
	for i in 0..count {
		submit_finding(worker, job_id, finding(&format!("Finding {i:03}"), &format!("fp-{i:03}")))
			.await;
	}
}

fn finding(title: &str, fingerprint: &str) -> Finding {
	Finding {
		scanner_id: "regex".into(),
		severity: Severity::High,
		title: title.into(),
		description: format!("{title} description"),
		file_path: Some("src/x.rs".into()),
		line_start: Some(1),
		line_end: Some(1),
		cwe: None,
		patch_unified: None,
		poc_unified: None,
		fingerprint: fingerprint.into(),
	}
}

#[tokio::test]
async fn list_routes_accept_positive_limits() {
	let f = bring_up_with_repo_and_worker().await;
	let repo_b = register_repo(&f, "https://github.com/acme/b.git", "tracker-b").await;
	let repo_c = register_repo(&f, "https://github.com/acme/c.git", "tracker-c").await;

	let repos = f.admin.get("https://loupe-server/v1/repos?limit=2").send().await.unwrap();
	assert!(repos.status().is_success());
	let repos: loupe_proto::ListReposResponse = repos.json().await.unwrap();
	assert_eq!(repos.repos.len(), 2);

	enqueue_scan(&f, f.repo_id).await;
	enqueue_scan(&f, repo_b).await;
	enqueue_scan(&f, repo_c).await;

	let jobs = f.admin.get("https://loupe-server/v1/jobs?limit=2").send().await.unwrap();
	assert!(jobs.status().is_success());
	let jobs: Vec<JobInfo> = jobs.json().await.unwrap();
	assert_eq!(jobs.len(), 2);

	f.handle.shutdown().await;
}

#[tokio::test]
async fn list_routes_reject_non_positive_limits() {
	let f = bring_up_with_repo_and_worker().await;
	let paths = [
		"/v1/repos?limit=0".to_owned(),
		"/v1/jobs?limit=-1".to_owned(),
		format!("/v1/repos/{}/findings?limit=0", f.repo_id),
	];

	for path in paths {
		let resp = f.admin.get(format!("https://loupe-server{path}")).send().await.unwrap();
		assert_eq!(resp.status(), 400, "{path} should reject non-positive limits");
		let body = resp.text().await.unwrap();
		assert!(body.contains("limit must be positive"), "unexpected body for {path}: {body}");
	}

	f.handle.shutdown().await;
}

#[tokio::test]
async fn finding_list_limit_can_exceed_default_page() {
	let f = bring_up_with_repo_and_worker().await;
	let scan = enqueue_scan(&f, f.repo_id).await;
	let env = lease_job(&f.worker).await;
	assert_eq!(env.job_id, scan.job_id);
	submit_many_findings(&f.worker, env.job_id, 101).await;

	let default_resp = f
		.admin
		.get(format!("https://loupe-server/v1/repos/{}/findings", f.repo_id))
		.send()
		.await
		.unwrap();
	assert!(default_resp.status().is_success());
	let default_body: ListFindingsResponse = default_resp.json().await.unwrap();
	assert_eq!(default_body.findings.len(), 100);

	let resp = f
		.admin
		.get(format!("https://loupe-server/v1/repos/{}/findings?limit=101", f.repo_id))
		.send()
		.await
		.unwrap();
	assert!(resp.status().is_success());
	let body: ListFindingsResponse = resp.json().await.unwrap();
	assert_eq!(body.findings.len(), 101);

	f.handle.shutdown().await;
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
async fn failed_scan_discards_pending_findings_so_retry_can_insert_them() {
	let f = bring_up_with_repo_and_worker().await;
	f.db.with_conn(|c| {
		Ok(c.execute(
			"UPDATE registered_repos SET verification_enabled = 1 WHERE id = ?1",
			[f.repo_id],
		)?)
	})
	.unwrap();

	let failed_scan = enqueue_scan(&f, f.repo_id).await;
	let failed_env = lease_job(&f.worker).await;
	assert_eq!(failed_env.job_id, failed_scan.job_id);
	submit_finding(&f.worker, failed_env.job_id, finding("Partial scan finding", "fp-retryable"))
		.await;
	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", failed_env.job_id))
		.json(&CompleteRequest {
			protocol_version: PROTOCOL_VERSION,
			outcome: CompleteOutcome::Failed,
			head_sha: None,
			error: Some("scanner failed after submitting findings".into()),
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);

	let failed_job_findings: i64 =
		f.db.with_conn(|c| {
			Ok(c.query_row(
				"SELECT COUNT(*) FROM findings WHERE job_id = ?1",
				[failed_env.job_id],
				|r| r.get(0),
			)?)
		})
		.unwrap();
	assert_eq!(failed_job_findings, 0, "failed scans must not leave dedup-blocking findings");

	let retried_scan = enqueue_scan(&f, f.repo_id).await;
	let retried_env = lease_job(&f.worker).await;
	assert_eq!(retried_env.job_id, retried_scan.job_id);
	submit_finding(&f.worker, retried_env.job_id, finding("Partial scan finding", "fp-retryable"))
		.await;
	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", retried_env.job_id))
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

	let (finding_job_id, finding_state, verify_jobs): (i64, String, i64) =
		f.db.with_conn(|c| {
			let (finding_id, finding_job_id, finding_state): (i64, i64, String) = c.query_row(
				"SELECT id, job_id, state FROM findings WHERE fingerprint = 'fp-retryable'",
				[],
				|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
			)?;
			let verify_jobs = c.query_row(
				"SELECT COUNT(*) FROM jobs
				  WHERE kind = 'verify'
				    AND parent_job_id = ?1
				    AND target_finding_id = ?2",
				(retried_env.job_id, finding_id),
				|r| r.get(0),
			)?;
			Ok((finding_job_id, finding_state, verify_jobs))
		})
		.unwrap();
	assert_eq!(finding_job_id, retried_env.job_id);
	assert_eq!(finding_state, "validating");
	assert_eq!(verify_jobs, 1);

	f.handle.shutdown().await;
}

#[tokio::test]
async fn scan_success_without_head_sha_is_rejected_without_mutating_job() {
	let f = bring_up_with_repo_and_worker().await;
	let scan = enqueue_scan(&f, f.repo_id).await;
	let env = lease_job(&f.worker).await;
	assert_eq!(env.job_id, scan.job_id);

	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", env.job_id))
		.json(&CompleteRequest {
			protocol_version: PROTOCOL_VERSION,
			outcome: CompleteOutcome::Succeeded,
			head_sha: None,
			error: None,
		})
		.send()
		.await
		.unwrap();
	let status = resp.status();
	let body = resp.text().await.unwrap_or_default();
	assert_eq!(status, 400, "{body}");
	assert!(body.contains("head_sha"), "response should explain missing head_sha: {body}");

	let (state, finished_at, lease_expires_at, history_count): (
		String,
		Option<i64>,
		Option<i64>,
		i64,
	) = f.db
		.with_conn(|c| {
			let (state, finished_at, lease_expires_at) = c.query_row(
				"SELECT state, finished_at, lease_expires_at FROM jobs WHERE id = ?1",
				[env.job_id],
				|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
			)?;
			let history_count = c.query_row(
				"SELECT COUNT(*) FROM scan_history WHERE job_id = ?1",
				[env.job_id],
				|r| r.get(0),
			)?;
			Ok((state, finished_at, lease_expires_at, history_count))
		})
		.unwrap();
	assert_eq!(state, "leased");
	assert!(finished_at.is_none());
	assert!(lease_expires_at.is_some());
	assert_eq!(history_count, 0);

	f.handle.shutdown().await;
}

#[tokio::test]
async fn verify_success_without_verdict_is_rejected_without_mutating_job() {
	let f = bring_up_with_repo_and_worker().await;
	f.db.with_conn(|c| {
		Ok(c.execute(
			"UPDATE registered_repos SET verification_enabled = 1 WHERE id = ?1",
			[f.repo_id],
		)?)
	})
	.unwrap();

	let scan = enqueue_scan(&f, f.repo_id).await;
	let scan_env = lease_job(&f.worker).await;
	assert_eq!(scan_env.job_id, scan.job_id);
	submit_finding(&f.worker, scan_env.job_id, finding("Needs verdict", "fp-needs-verdict")).await;
	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", scan_env.job_id))
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

	let verify_env = lease_verify_job(&f.worker).await;
	let finding_id = match &verify_env.payload {
		LeasePayload::Verify { finding_id, .. } => *finding_id,
		other => panic!("expected verify payload, got {other:?}"),
	};
	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", verify_env.job_id))
		.json(&CompleteRequest {
			protocol_version: PROTOCOL_VERSION,
			outcome: CompleteOutcome::Succeeded,
			head_sha: Some("abc123".into()),
			error: None,
		})
		.send()
		.await
		.unwrap();
	let status = resp.status();
	let body = resp.text().await.unwrap_or_default();
	assert_eq!(status, 409, "{body}");
	assert!(body.contains("verdict"), "response should explain missing verdict: {body}");

	let (job_state, finding_state, verdict_count): (String, String, i64) =
		f.db.with_conn(|c| {
			let job_state =
				c.query_row("SELECT state FROM jobs WHERE id = ?1", [verify_env.job_id], |r| {
					r.get(0)
				})?;
			let finding_state =
				c.query_row("SELECT state FROM findings WHERE id = ?1", [finding_id], |r| {
					r.get(0)
				})?;
			let verdict_count = c.query_row(
				"SELECT COUNT(*) FROM finding_verifications WHERE job_id = ?1",
				[verify_env.job_id],
				|r| r.get(0),
			)?;
			Ok((job_state, finding_state, verdict_count))
		})
		.unwrap();
	assert_eq!(job_state, "leased");
	assert_eq!(finding_state, "validating");
	assert_eq!(verdict_count, 0);

	f.handle.shutdown().await;
}

#[tokio::test]
async fn verify_success_after_verdict_is_still_accepted() {
	let f = bring_up_with_repo_and_worker().await;
	f.db.with_conn(|c| {
		Ok(c.execute(
			"UPDATE registered_repos SET verification_enabled = 1 WHERE id = ?1",
			[f.repo_id],
		)?)
	})
	.unwrap();

	let scan = enqueue_scan(&f, f.repo_id).await;
	let scan_env = lease_job(&f.worker).await;
	assert_eq!(scan_env.job_id, scan.job_id);
	submit_finding(&f.worker, scan_env.job_id, finding("Dismissed verdict", "fp-dismissed-ok"))
		.await;
	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", scan_env.job_id))
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

	let verify_env = lease_verify_job(&f.worker).await;
	let finding_id = match &verify_env.payload {
		LeasePayload::Verify { finding_id, .. } => *finding_id,
		other => panic!("expected verify payload, got {other:?}"),
	};
	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/verdict", verify_env.job_id))
		.json(&VerdictSubmission {
			protocol_version: PROTOCOL_VERSION,
			verdict: Verdict::Dismissed { notes: Some("false positive".into()) },
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);

	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", verify_env.job_id))
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

	let (job_state, finding_state): (String, String) =
		f.db.with_conn(|c| {
			let job_state =
				c.query_row("SELECT state FROM jobs WHERE id = ?1", [verify_env.job_id], |r| {
					r.get(0)
				})?;
			let finding_state =
				c.query_row("SELECT state FROM findings WHERE id = ?1", [finding_id], |r| {
					r.get(0)
				})?;
			Ok((job_state, finding_state))
		})
		.unwrap();
	assert_eq!(job_state, "succeeded");
	assert_eq!(finding_state, "dismissed");

	f.handle.shutdown().await;
}

#[tokio::test]
async fn admin_can_cancel_queued_job() {
	let f = bring_up_with_repo_and_worker().await;
	let scan = enqueue_scan(&f, f.repo_id).await;

	let resp = f
		.admin
		.post(format!("https://loupe-server/v1/jobs/{}/cancel", scan.job_id))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 200);
	let job: JobInfo = resp.json().await.unwrap();
	assert_eq!(job.job_id, scan.job_id);
	assert_eq!(job.state, JobState::Cancelled);

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
	assert!(matches!(body, LeaseResponse::Empty { .. }));

	let resp = f
		.admin
		.post(format!("https://loupe-server/v1/jobs/{}/cancel", scan.job_id))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 409);

	f.handle.shutdown().await;
}

#[tokio::test]
async fn cancel_leased_scan_discards_pending_findings_and_invalidates_worker() {
	let f = bring_up_with_repo_and_worker().await;
	let scan = enqueue_scan(&f, f.repo_id).await;
	let env = lease_job(&f.worker).await;
	assert_eq!(env.job_id, scan.job_id);
	submit_finding(&f.worker, env.job_id, finding("Cancelled scan finding", "fp-cancel-scan"))
		.await;

	let resp = f
		.admin
		.post(format!("https://loupe-server/v1/jobs/{}/cancel", env.job_id))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 200);
	let job: JobInfo = resp.json().await.unwrap();
	assert_eq!(job.state, JobState::Cancelled);

	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/heartbeat", env.job_id))
		.json(&HeartbeatRequest { protocol_version: PROTOCOL_VERSION })
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 403);

	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", env.job_id))
		.json(&CompleteRequest {
			protocol_version: PROTOCOL_VERSION,
			outcome: CompleteOutcome::Failed,
			head_sha: None,
			error: Some("worker lost race to cancel".into()),
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 403);

	let pending_findings: i64 =
		f.db.with_conn(|c| {
			Ok(c.query_row("SELECT COUNT(*) FROM findings WHERE job_id = ?1", [env.job_id], |r| {
				r.get(0)
			})?)
		})
		.unwrap();
	assert_eq!(pending_findings, 0);

	f.handle.shutdown().await;
}

#[tokio::test]
async fn cancel_verify_job_leaves_target_finding_validating() {
	let f = bring_up_with_repo_and_worker().await;
	f.db.with_conn(|c| {
		Ok(c.execute(
			"UPDATE registered_repos SET verification_enabled = 1 WHERE id = ?1",
			[f.repo_id],
		)?)
	})
	.unwrap();

	let scan = enqueue_scan(&f, f.repo_id).await;
	let scan_env = lease_job(&f.worker).await;
	assert_eq!(scan_env.job_id, scan.job_id);
	submit_finding(&f.worker, scan_env.job_id, finding("Cancel verify", "fp-cancel-verify")).await;
	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", scan_env.job_id))
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

	let verify_env = lease_verify_job(&f.worker).await;
	let finding_id = match &verify_env.payload {
		LeasePayload::Verify { finding_id, .. } => *finding_id,
		other => panic!("expected verify payload, got {other:?}"),
	};
	let resp = f
		.admin
		.post(format!("https://loupe-server/v1/jobs/{}/cancel", verify_env.job_id))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 200);

	let (job_state, finding_state): (String, String) =
		f.db.with_conn(|c| {
			let job_state =
				c.query_row("SELECT state FROM jobs WHERE id = ?1", [verify_env.job_id], |r| {
					r.get(0)
				})?;
			let finding_state =
				c.query_row("SELECT state FROM findings WHERE id = ?1", [finding_id], |r| {
					r.get(0)
				})?;
			Ok((job_state, finding_state))
		})
		.unwrap();
	assert_eq!(job_state, "cancelled");
	assert_eq!(finding_state, "validating");

	f.handle.shutdown().await;
}

#[tokio::test]
async fn cancel_rejects_terminal_jobs() {
	let f = bring_up_with_repo_and_worker().await;
	let scan = enqueue_scan(&f, f.repo_id).await;
	let env = lease_job(&f.worker).await;
	assert_eq!(env.job_id, scan.job_id);
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

	let resp = f
		.admin
		.post(format!("https://loupe-server/v1/jobs/{}/cancel", env.job_id))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 409);

	f.handle.shutdown().await;
}

#[tokio::test]
async fn admin_can_retry_failed_verify_job() {
	let f = bring_up_with_repo_and_worker().await;
	f.db.with_conn(|c| {
		Ok(c.execute(
			"UPDATE registered_repos SET verification_enabled = 1 WHERE id = ?1",
			[f.repo_id],
		)?)
	})
	.unwrap();

	let scan = enqueue_scan(&f, f.repo_id).await;
	let scan_env = lease_job(&f.worker).await;
	assert_eq!(scan_env.job_id, scan.job_id);
	submit_finding(&f.worker, scan_env.job_id, finding("Needs verification", "fp-verify")).await;

	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", scan_env.job_id))
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

	let verify_env = lease_verify_job(&f.worker).await;
	let finding_id = match &verify_env.payload {
		LeasePayload::Verify { finding_id, reviewed_sha, .. } => {
			assert_eq!(reviewed_sha.as_deref(), Some("abc123"));
			*finding_id
		},
		other => panic!("expected verify payload, got {other:?}"),
	};

	let before_deadline: i64 =
		f.db.with_conn(|c| {
			Ok(c.query_row(
				"SELECT validating_deadline FROM findings WHERE id = ?1",
				[finding_id],
				|r| r.get(0),
			)?)
		})
		.unwrap();

	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", verify_env.job_id))
		.json(&CompleteRequest {
			protocol_version: PROTOCOL_VERSION,
			outcome: CompleteOutcome::Failed,
			head_sha: None,
			error: Some("codex CLI exited with exit status: 1".into()),
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);

	let retried: serde_json::Value = f
		.admin
		.post(format!("https://loupe-server/v1/jobs/{}/retry", verify_env.job_id))
		.send()
		.await
		.unwrap()
		.error_for_status()
		.unwrap()
		.json()
		.await
		.unwrap();
	assert_eq!(retried["job_id"], verify_env.job_id);
	assert_eq!(retried["state"], "queued");
	assert_eq!(retried["attempts"], 0);

	let (state, attempts, error, after_deadline): (String, i64, Option<String>, i64) =
		f.db.with_conn(|c| {
			Ok(c.query_row(
				"SELECT j.state, j.attempts, j.error, f.validating_deadline
				   FROM jobs j
				   JOIN findings f ON f.id = j.target_finding_id
				  WHERE j.id = ?1",
				[verify_env.job_id],
				|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
			)?)
		})
		.unwrap();
	assert_eq!(state, "queued");
	assert_eq!(attempts, 0);
	assert!(error.is_none());
	assert!(after_deadline >= before_deadline);

	let retried_env = lease_verify_job(&f.worker).await;
	assert_eq!(retried_env.job_id, verify_env.job_id);

	f.handle.shutdown().await;
}

#[tokio::test]
async fn terminal_inconclusive_verdict_dismisses_finding_immediately() {
	let f = bring_up_with_repo_and_worker().await;
	f.db.with_conn(|c| {
		Ok(c.execute(
			"UPDATE registered_repos SET verification_enabled = 1 WHERE id = ?1",
			[f.repo_id],
		)?)
	})
	.unwrap();

	let scan = enqueue_scan(&f, f.repo_id).await;
	let scan_env = lease_job(&f.worker).await;
	assert_eq!(scan_env.job_id, scan.job_id);
	submit_finding(&f.worker, scan_env.job_id, finding("Missing revision", "fp-missing-rev")).await;

	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", scan_env.job_id))
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

	let verify_env = lease_verify_job(&f.worker).await;
	let finding_id = match &verify_env.payload {
		LeasePayload::Verify { finding_id, reviewed_sha, .. } => {
			assert_eq!(reviewed_sha.as_deref(), Some("abc123"));
			*finding_id
		},
		other => panic!("expected verify payload, got {other:?}"),
	};

	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/verdict", verify_env.job_id))
		.json(&VerdictSubmission {
			protocol_version: PROTOCOL_VERSION,
			verdict: Verdict::Inconclusive {
				reason: "original revision unavailable".into(),
				terminal: true,
			},
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);

	let (state, dismissed_at, verdict): (String, Option<i64>, String) =
		f.db.with_conn(|c| {
			Ok(c.query_row(
				"SELECT f.state, f.dismissed_at, v.verdict
				   FROM findings f
				   JOIN finding_verifications v ON v.finding_id = f.id
				  WHERE f.id = ?1",
				[finding_id],
				|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
			)?)
		})
		.unwrap();
	assert_eq!(state, "dismissed");
	assert!(dismissed_at.is_some());
	assert_eq!(verdict, "inconclusive");

	f.handle.shutdown().await;
}

#[tokio::test]
async fn retry_revives_deadline_dismissed_verify_target() {
	let f = bring_up_with_repo_and_worker().await;
	f.db.with_conn(|c| {
		Ok(c.execute(
			"UPDATE registered_repos SET verification_enabled = 1 WHERE id = ?1",
			[f.repo_id],
		)?)
	})
	.unwrap();

	let scan = enqueue_scan(&f, f.repo_id).await;
	let scan_env = lease_job(&f.worker).await;
	assert_eq!(scan_env.job_id, scan.job_id);
	submit_finding(&f.worker, scan_env.job_id, finding("Deadline retry", "fp-deadline")).await;

	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", scan_env.job_id))
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

	let verify_env = lease_verify_job(&f.worker).await;
	let finding_id = match &verify_env.payload {
		LeasePayload::Verify { finding_id, .. } => *finding_id,
		other => panic!("expected verify payload, got {other:?}"),
	};

	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", verify_env.job_id))
		.json(&CompleteRequest {
			protocol_version: PROTOCOL_VERSION,
			outcome: CompleteOutcome::Failed,
			head_sha: None,
			error: Some("codex CLI exited with exit status: 1".into()),
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);

	f.db.with_conn(|c| {
		c.execute("UPDATE findings SET validating_deadline = 100 WHERE id = ?1", [finding_id])?;
		Ok(loupe_storage::findings::reap_stale_validating(c, 200)?)
	})
	.unwrap();
	let dismissed: String =
		f.db.with_conn(|c| {
			Ok(c.query_row("SELECT state FROM findings WHERE id = ?1", [finding_id], |r| r.get(0))?)
		})
		.unwrap();
	assert_eq!(dismissed, "dismissed");

	let retried: serde_json::Value = f
		.admin
		.post(format!("https://loupe-server/v1/jobs/{}/retry", verify_env.job_id))
		.send()
		.await
		.unwrap()
		.error_for_status()
		.unwrap()
		.json()
		.await
		.unwrap();
	assert_eq!(retried["job_id"], verify_env.job_id);
	assert_eq!(retried["state"], "queued");

	let (state, dismissed_at): (String, Option<i64>) =
		f.db.with_conn(|c| {
			Ok(c.query_row(
				"SELECT state, dismissed_at FROM findings WHERE id = ?1",
				[finding_id],
				|r| Ok((r.get(0)?, r.get(1)?)),
			)?)
		})
		.unwrap();
	assert_eq!(state, "validating");
	assert!(dismissed_at.is_none());

	f.handle.shutdown().await;
}

#[tokio::test]
async fn retry_verify_recovers_deadline_dismissed_but_not_verifier_dismissed_findings() {
	let f = bring_up_with_repo_and_worker().await;
	f.db.with_conn(|c| {
		Ok(c.execute(
			"UPDATE registered_repos SET verification_enabled = 1 WHERE id = ?1",
			[f.repo_id],
		)?)
	})
	.unwrap();

	let scan = enqueue_scan(&f, f.repo_id).await;
	let scan_env = lease_job(&f.worker).await;
	assert_eq!(scan_env.job_id, scan.job_id);
	submit_finding(&f.worker, scan_env.job_id, finding("Failed verify", "fp-failed-verify")).await;
	submit_finding(&f.worker, scan_env.job_id, finding("Queued verify", "fp-queued-verify")).await;
	submit_finding(
		&f.worker,
		scan_env.job_id,
		finding("Verifier dismissed", "fp-verifier-dismissed"),
	)
	.await;

	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", scan_env.job_id))
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

	let failed_env = lease_verify_job(&f.worker).await;
	let failed_finding_id = match &failed_env.payload {
		LeasePayload::Verify { finding_id, .. } => *finding_id,
		other => panic!("expected verify payload, got {other:?}"),
	};
	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", failed_env.job_id))
		.json(&CompleteRequest {
			protocol_version: PROTOCOL_VERSION,
			outcome: CompleteOutcome::Failed,
			head_sha: None,
			error: Some("verifier failed".into()),
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);

	let queued_verify_job_id: i64 =
		f.db.with_conn(|c| {
			Ok(c.query_row(
				"SELECT id FROM jobs
				  WHERE kind = 'verify'
				    AND state = 'queued'
				    AND target_finding_id != ?1",
				[failed_finding_id],
				|r| r.get(0),
			)?)
		})
		.unwrap();

	let (terminal_finding_id, terminal_verify_job_id): (i64, i64) =
		f.db.with_conn(|c| {
			Ok(c.query_row(
				"SELECT f.id, j.id
				   FROM findings f
				   JOIN jobs j ON j.target_finding_id = f.id
				  WHERE f.fingerprint = 'fp-verifier-dismissed'
				    AND j.kind = 'verify'",
				[],
				|r| Ok((r.get(0)?, r.get(1)?)),
			)?)
		})
		.unwrap();

	f.db.with_conn(|c| {
		c.execute(
			"INSERT INTO finding_verifications
			   (finding_id, job_id, verdict, notes, created_at)
			 VALUES (?1, ?2, 'dismissed', 'verifier rejected it', 100)",
			(terminal_finding_id, terminal_verify_job_id),
		)?;
		c.execute(
			"UPDATE findings SET state = 'dismissed', dismissed_at = 100 WHERE id = ?1",
			[terminal_finding_id],
		)?;
		c.execute(
			"UPDATE jobs SET state = 'succeeded', finished_at = 100 WHERE id = ?1",
			[terminal_verify_job_id],
		)?;
		Ok(())
	})
	.unwrap();

	f.db.with_conn(|c| {
		c.execute(
			"UPDATE findings
			    SET validating_deadline = 100
			  WHERE repo_id = ?1
			    AND state = 'validating'",
			[f.repo_id],
		)?;
		Ok(loupe_storage::findings::reap_stale_validating(c, 200)?)
	})
	.unwrap();

	let dry_run: RetryVerifyResponse = f
		.admin
		.post("https://loupe-server/v1/findings/retry-verify")
		.json(&RetryVerifyRequest {
			protocol_version: PROTOCOL_VERSION,
			dry_run: true,
			include_inconclusive: false,
			repo_id: Some(f.repo_id),
			limit: None,
		})
		.send()
		.await
		.unwrap()
		.error_for_status()
		.unwrap()
		.json()
		.await
		.unwrap();
	assert!(dry_run.dry_run);
	assert_eq!(dry_run.matched, 2);
	assert_eq!(dry_run.revived, 1);
	assert_eq!(dry_run.requeued_jobs, 1);
	assert_eq!(dry_run.created_jobs, 0);
	assert_eq!(dry_run.left_queued_or_leased, 1);

	let dismissed_count: i64 =
		f.db.with_conn(|c| {
			Ok(c.query_row(
				"SELECT COUNT(*) FROM findings WHERE repo_id = ?1 AND state = 'dismissed'",
				[f.repo_id],
				|r| r.get(0),
			)?)
		})
		.unwrap();
	assert_eq!(dismissed_count, 3, "dry-run must not revive findings");

	let applied: RetryVerifyResponse = f
		.admin
		.post("https://loupe-server/v1/findings/retry-verify")
		.json(&RetryVerifyRequest {
			protocol_version: PROTOCOL_VERSION,
			dry_run: false,
			include_inconclusive: false,
			repo_id: Some(f.repo_id),
			limit: None,
		})
		.send()
		.await
		.unwrap()
		.error_for_status()
		.unwrap()
		.json()
		.await
		.unwrap();
	assert!(!applied.dry_run);
	assert_eq!(applied.matched, 2);
	assert_eq!(applied.revived, 1);
	assert_eq!(applied.requeued_jobs, 1);
	assert_eq!(applied.created_jobs, 0);
	assert_eq!(applied.left_queued_or_leased, 1);

	let (failed_state, queued_state, terminal_state): (String, String, String) =
		f.db.with_conn(|c| {
			let failed_state = c.query_row(
				"SELECT state FROM findings WHERE id = ?1",
				[failed_finding_id],
				|r| r.get(0),
			)?;
			let queued_state = c.query_row(
				"SELECT f.state
				   FROM findings f
				   JOIN jobs j ON j.target_finding_id = f.id
				  WHERE j.id = ?1",
				[queued_verify_job_id],
				|r| r.get(0),
			)?;
			let terminal_state = c.query_row(
				"SELECT state FROM findings WHERE id = ?1",
				[terminal_finding_id],
				|r| r.get(0),
			)?;
			Ok((failed_state, queued_state, terminal_state))
		})
		.unwrap();
	assert_eq!(failed_state, "validating");
	assert_eq!(queued_state, "dismissed", "active verify work must not be touched");
	assert_eq!(terminal_state, "dismissed", "verifier-dismissed findings must stay terminal");

	let (failed_job_state, queued_job_state, terminal_job_state): (String, String, String) =
		f.db.with_conn(|c| {
			let failed_state =
				c.query_row("SELECT state FROM jobs WHERE id = ?1", [failed_env.job_id], |r| {
					r.get(0)
				})?;
			let queued_state =
				c.query_row("SELECT state FROM jobs WHERE id = ?1", [queued_verify_job_id], |r| {
					r.get(0)
				})?;
			let terminal_state = c.query_row(
				"SELECT state FROM jobs WHERE id = ?1",
				[terminal_verify_job_id],
				|r| r.get(0),
			)?;
			Ok((failed_state, queued_state, terminal_state))
		})
		.unwrap();
	assert_eq!(failed_job_state, "queued");
	assert_eq!(queued_job_state, "queued");
	assert_eq!(terminal_job_state, "succeeded");

	f.handle.shutdown().await;
}

#[tokio::test]
async fn retry_verify_refreshes_validating_findings_without_active_verify_jobs() {
	let f = bring_up_with_repo_and_worker().await;
	f.db.with_conn(|c| {
		Ok(c.execute(
			"UPDATE registered_repos SET verification_enabled = 1 WHERE id = ?1",
			[f.repo_id],
		)?)
	})
	.unwrap();

	let scan = enqueue_scan(&f, f.repo_id).await;
	let scan_env = lease_job(&f.worker).await;
	assert_eq!(scan_env.job_id, scan.job_id);
	for (title, fingerprint) in [
		("Failed verify", "fp-refresh-failed"),
		("Inconclusive verify", "fp-refresh-inconclusive"),
		("Queued verify", "fp-refresh-queued"),
		("Leased verify", "fp-refresh-leased"),
		("Confirmed finding", "fp-refresh-confirmed"),
		("Dismissed finding", "fp-refresh-dismissed"),
		("Reported finding", "fp-refresh-reported"),
	] {
		submit_finding(&f.worker, scan_env.job_id, finding(title, fingerprint)).await;
	}
	let resp = f
		.worker
		.post(format!("https://loupe-server/v1/jobs/{}/complete", scan_env.job_id))
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

	let rows: Vec<(String, i64, i64)> =
		f.db.with_conn(|c| {
			let mut stmt = c.prepare(
				"SELECT f.fingerprint, f.id, j.id
				   FROM findings f
				   JOIN jobs j ON j.target_finding_id = f.id
				  WHERE f.repo_id = ?1
				    AND j.kind = 'verify'",
			)?;
			let rows = stmt.query_map([f.repo_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
			Ok(rows.collect::<Result<Vec<_>, _>>()?)
		})
		.unwrap();
	let ids = |fingerprint: &str| -> (i64, i64) {
		rows.iter()
			.find(|(fp, _, _)| fp == fingerprint)
			.map(|(_, finding_id, job_id)| (*finding_id, *job_id))
			.unwrap_or_else(|| panic!("missing finding/job for {fingerprint}"))
	};
	let (failed_id, failed_job) = ids("fp-refresh-failed");
	let (inconclusive_id, inconclusive_job) = ids("fp-refresh-inconclusive");
	let (queued_id, queued_job) = ids("fp-refresh-queued");
	let (leased_id, leased_job) = ids("fp-refresh-leased");
	let (confirmed_id, confirmed_job) = ids("fp-refresh-confirmed");
	let (dismissed_id, dismissed_job) = ids("fp-refresh-dismissed");
	let (reported_id, reported_job) = ids("fp-refresh-reported");

	f.db.with_conn(|c| {
		for finding_id in [
			failed_id,
			inconclusive_id,
			queued_id,
			leased_id,
			confirmed_id,
			dismissed_id,
			reported_id,
		] {
			c.execute(
				"UPDATE findings SET validating_deadline = 1000 WHERE id = ?1",
				[finding_id],
			)?;
		}
		c.execute(
			"UPDATE jobs
			   SET state = 'failed', finished_at = 100, error = 'verifier failed'
			 WHERE id = ?1",
			[failed_job],
		)?;
		c.execute(
			"UPDATE jobs
			   SET state = 'succeeded', finished_at = 100
			 WHERE id = ?1",
			[inconclusive_job],
		)?;
		c.execute(
			"INSERT INTO finding_verifications
			   (finding_id, job_id, verdict, notes, created_at)
			 VALUES (?1, ?2, 'inconclusive', ?3, ?4)",
			(inconclusive_id, inconclusive_job, "verifier could not decide", 100_i64),
		)?;
		let worker_id: i64 =
			c.query_row("SELECT id FROM workers WHERE name = 'w1'", [], |r| r.get(0))?;
		c.execute(
			"UPDATE jobs
			   SET state = 'leased',
			       worker_id = ?2,
			       lease_expires_at = 9999999999,
			       attempts = 1,
			       started_at = 100
			 WHERE id = ?1",
			(leased_job, worker_id),
		)?;
		c.execute(
			"UPDATE jobs
			   SET state = 'failed', finished_at = 100, error = 'terminal finding'
			 WHERE id IN (?1, ?2, ?3)",
			(confirmed_job, dismissed_job, reported_job),
		)?;
		c.execute(
			"UPDATE findings SET state = 'confirmed', confirmed_at = 100 WHERE id = ?1",
			[confirmed_id],
		)?;
		c.execute(
			"UPDATE findings SET state = 'dismissed', dismissed_at = 100 WHERE id = ?1",
			[dismissed_id],
		)?;
		c.execute(
			"INSERT INTO finding_verifications
			   (finding_id, job_id, verdict, notes, created_at)
			 VALUES (?1, ?2, 'dismissed', 'verifier rejected it', 100)",
			(dismissed_id, dismissed_job),
		)?;
		c.execute(
			"UPDATE findings SET state = 'reported', reported_at = 100 WHERE id = ?1",
			[reported_id],
		)?;
		Ok(())
	})
	.unwrap();

	let applied: RetryVerifyResponse = f
		.admin
		.post("https://loupe-server/v1/findings/retry-verify")
		.json(&RetryVerifyRequest {
			protocol_version: PROTOCOL_VERSION,
			dry_run: false,
			include_inconclusive: false,
			repo_id: Some(f.repo_id),
			limit: None,
		})
		.send()
		.await
		.unwrap()
		.error_for_status()
		.unwrap()
		.json()
		.await
		.unwrap();
	assert_eq!(applied.matched, 3);
	assert_eq!(applied.revived, 1);
	assert_eq!(applied.requeued_jobs, 1);
	assert_eq!(applied.created_jobs, 0);
	assert_eq!(applied.left_queued_or_leased, 2);

	let (failed_job_state, inconclusive_queued, queued_job_state, queued_deadline, leased_deadline): (
		String,
		i64,
		String,
		i64,
		i64,
	) = f
		.db
		.with_conn(|c| {
			let failed_job_state =
				c.query_row("SELECT state FROM jobs WHERE id = ?1", [failed_job], |r| r.get(0))?;
			let inconclusive_queued = c.query_row(
				"SELECT COUNT(*) FROM jobs
				  WHERE kind = 'verify'
				    AND target_finding_id = ?1
				    AND state = 'queued'",
				[inconclusive_id],
				|r| r.get(0),
			)?;
			let queued_job_state =
				c.query_row("SELECT state FROM jobs WHERE id = ?1", [queued_job], |r| r.get(0))?;
			let queued_deadline = c.query_row(
				"SELECT validating_deadline FROM findings WHERE id = ?1",
				[queued_id],
				|r| r.get(0),
			)?;
			let leased_deadline = c.query_row(
				"SELECT validating_deadline FROM findings WHERE id = ?1",
				[leased_id],
				|r| r.get(0),
			)?;
			Ok((
				failed_job_state,
				inconclusive_queued,
				queued_job_state,
				queued_deadline,
				leased_deadline,
			))
		})
		.unwrap();
	assert_eq!(failed_job_state, "queued");
	assert_eq!(inconclusive_queued, 0, "inconclusive findings require the explicit flag");
	assert_eq!(queued_job_state, "queued");
	assert_eq!(queued_deadline, 1000, "queued verify work must not be refreshed");
	assert_eq!(leased_deadline, 1000, "leased verify work must not be refreshed");

	let include: RetryVerifyResponse = f
		.admin
		.post("https://loupe-server/v1/findings/retry-verify")
		.json(&RetryVerifyRequest {
			protocol_version: PROTOCOL_VERSION,
			dry_run: false,
			include_inconclusive: true,
			repo_id: Some(f.repo_id),
			limit: None,
		})
		.send()
		.await
		.unwrap()
		.error_for_status()
		.unwrap()
		.json()
		.await
		.unwrap();
	assert_eq!(include.matched, 4);
	assert_eq!(include.revived, 1);
	assert_eq!(include.requeued_jobs, 0);
	assert_eq!(include.created_jobs, 1);
	assert_eq!(include.left_queued_or_leased, 3);

	let (inconclusive_queued, confirmed_state, dismissed_state, reported_state, terminal_jobs): (
		i64,
		String,
		String,
		String,
		i64,
	) = f.db
		.with_conn(|c| {
			let inconclusive_queued = c.query_row(
				"SELECT COUNT(*) FROM jobs
				  WHERE kind = 'verify'
				    AND target_finding_id = ?1
				    AND state = 'queued'",
				[inconclusive_id],
				|r| r.get(0),
			)?;
			let confirmed_state =
				c.query_row("SELECT state FROM findings WHERE id = ?1", [confirmed_id], |r| {
					r.get(0)
				})?;
			let dismissed_state =
				c.query_row("SELECT state FROM findings WHERE id = ?1", [dismissed_id], |r| {
					r.get(0)
				})?;
			let reported_state =
				c.query_row("SELECT state FROM findings WHERE id = ?1", [reported_id], |r| {
					r.get(0)
				})?;
			let terminal_jobs = c.query_row(
				"SELECT COUNT(*) FROM jobs
				  WHERE id IN (?1, ?2, ?3)
				    AND state = 'failed'",
				(confirmed_job, dismissed_job, reported_job),
				|r| r.get(0),
			)?;
			Ok((
				inconclusive_queued,
				confirmed_state,
				dismissed_state,
				reported_state,
				terminal_jobs,
			))
		})
		.unwrap();
	assert_eq!(inconclusive_queued, 1);
	assert_eq!(confirmed_state, "confirmed");
	assert_eq!(dismissed_state, "dismissed");
	assert_eq!(reported_state, "reported");
	assert_eq!(terminal_jobs, 3, "terminal findings' verify jobs must not be retried");

	f.handle.shutdown().await;
}

#[tokio::test]
async fn retry_verify_recovers_legacy_stranded_pending_findings() {
	let f = bring_up_with_repo_and_worker().await;
	f.db.with_conn(|c| {
		Ok(c.execute(
			"UPDATE registered_repos SET verification_enabled = 1 WHERE id = ?1",
			[f.repo_id],
		)?)
	})
	.unwrap();

	let scan = enqueue_scan(&f, f.repo_id).await;
	let env = lease_job(&f.worker).await;
	assert_eq!(env.job_id, scan.job_id);
	submit_finding(&f.worker, env.job_id, finding("Stranded pending", "fp-stranded")).await;
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

	let stranded_id: i64 =
		f.db.with_conn(|c| {
			let finding_id = c.query_row(
				"SELECT id FROM findings WHERE fingerprint = 'fp-stranded'",
				[],
				|r| r.get(0),
			)?;
			c.execute(
				"UPDATE findings
				    SET state = 'pending',
				        validating_deadline = NULL
				  WHERE id = ?1",
				[finding_id],
			)?;
			c.execute(
				"DELETE FROM jobs WHERE kind = 'verify' AND target_finding_id = ?1",
				[finding_id],
			)?;
			Ok(finding_id)
		})
		.unwrap();

	let active_scan = enqueue_scan(&f, f.repo_id).await;
	let active_env = lease_job(&f.worker).await;
	assert_eq!(active_env.job_id, active_scan.job_id);
	submit_finding(&f.worker, active_env.job_id, finding("Still scanning", "fp-active")).await;

	let active_id: i64 =
		f.db.with_conn(|c| {
			Ok(c.query_row("SELECT id FROM findings WHERE fingerprint = 'fp-active'", [], |r| {
				r.get(0)
			})?)
		})
		.unwrap();

	let dry_run: RetryVerifyResponse = f
		.admin
		.post("https://loupe-server/v1/findings/retry-verify")
		.json(&RetryVerifyRequest {
			protocol_version: PROTOCOL_VERSION,
			dry_run: true,
			include_inconclusive: false,
			repo_id: Some(f.repo_id),
			limit: None,
		})
		.send()
		.await
		.unwrap()
		.error_for_status()
		.unwrap()
		.json()
		.await
		.unwrap();
	assert!(dry_run.dry_run);
	assert_eq!(dry_run.matched, 1);
	assert_eq!(dry_run.revived, 1);
	assert_eq!(dry_run.created_jobs, 1);
	assert_eq!(dry_run.requeued_jobs, 0);
	assert_eq!(dry_run.left_queued_or_leased, 0);

	let (stranded_state, active_state, verify_jobs): (String, String, i64) =
		f.db.with_conn(|c| {
			let stranded_state =
				c.query_row("SELECT state FROM findings WHERE id = ?1", [stranded_id], |r| {
					r.get(0)
				})?;
			let active_state =
				c.query_row("SELECT state FROM findings WHERE id = ?1", [active_id], |r| r.get(0))?;
			let verify_jobs = c.query_row(
				"SELECT COUNT(*) FROM jobs
				  WHERE kind = 'verify'
				    AND target_finding_id IN (?1, ?2)",
				(stranded_id, active_id),
				|r| r.get(0),
			)?;
			Ok((stranded_state, active_state, verify_jobs))
		})
		.unwrap();
	assert_eq!(stranded_state, "pending");
	assert_eq!(active_state, "pending");
	assert_eq!(verify_jobs, 0, "dry-run must not enqueue verification jobs");

	let applied: RetryVerifyResponse = f
		.admin
		.post("https://loupe-server/v1/findings/retry-verify")
		.json(&RetryVerifyRequest {
			protocol_version: PROTOCOL_VERSION,
			dry_run: false,
			include_inconclusive: false,
			repo_id: Some(f.repo_id),
			limit: None,
		})
		.send()
		.await
		.unwrap()
		.error_for_status()
		.unwrap()
		.json()
		.await
		.unwrap();
	assert!(!applied.dry_run);
	assert_eq!(applied.matched, 1);
	assert_eq!(applied.revived, 1);
	assert_eq!(applied.created_jobs, 1);
	assert_eq!(applied.requeued_jobs, 0);
	assert_eq!(applied.left_queued_or_leased, 0);

	let (stranded_state, stranded_deadline, active_state, active_deadline, verify_job_id): (
		String,
		Option<i64>,
		String,
		Option<i64>,
		i64,
	) = f.db
		.with_conn(|c| {
			let (stranded_state, stranded_deadline) = c.query_row(
				"SELECT state, validating_deadline FROM findings WHERE id = ?1",
				[stranded_id],
				|r| Ok((r.get(0)?, r.get(1)?)),
			)?;
			let (active_state, active_deadline) = c.query_row(
				"SELECT state, validating_deadline FROM findings WHERE id = ?1",
				[active_id],
				|r| Ok((r.get(0)?, r.get(1)?)),
			)?;
			let verify_job_id = c.query_row(
				"SELECT id FROM jobs
				  WHERE kind = 'verify'
				    AND state = 'queued'
				    AND parent_job_id = ?1
				    AND target_finding_id = ?2",
				(env.job_id, stranded_id),
				|r| r.get(0),
			)?;
			Ok((stranded_state, stranded_deadline, active_state, active_deadline, verify_job_id))
		})
		.unwrap();
	assert_eq!(stranded_state, "validating");
	assert!(stranded_deadline.is_some());
	assert_eq!(active_state, "pending", "in-flight scan findings must not be recovered early");
	assert!(active_deadline.is_none());

	let verify_env = lease_verify_job(&f.worker).await;
	assert_eq!(verify_env.job_id, verify_job_id);
	match &verify_env.payload {
		LeasePayload::Verify { finding_id, .. } => assert_eq!(*finding_id, stranded_id),
		other => panic!("expected verify payload, got {other:?}"),
	}

	f.handle.shutdown().await;
}

#[tokio::test]
async fn prior_finding_routes_require_active_lease_for_that_repo() {
	let f = bring_up_with_repo_and_worker().await;
	let repo_b = register_repo(&f, "https://github.com/acme/other.git", "other-tracker").await;
	let worker2 = register_worker(&f, "w2").await;

	let scan_a = enqueue_scan(&f, f.repo_id).await;
	let env_a = lease_job(&f.worker).await;
	assert_eq!(env_a.job_id, scan_a.job_id);
	assert_eq!(env_a.repo_id, f.repo_id);
	submit_finding(&f.worker, env_a.job_id, finding("Alpha overflow", "fp-alpha")).await;

	let scan_b = enqueue_scan(&f, repo_b).await;
	let env_b = lease_job(&worker2).await;
	assert_eq!(env_b.job_id, scan_b.job_id);
	assert_eq!(env_b.repo_id, repo_b);
	submit_finding(&worker2, env_b.job_id, finding("Beta overflow", "fp-beta")).await;

	let resp = f
		.worker
		.get(format!(
			"https://loupe-server/v1/repos/{}/findings/search?q=Alpha&limit=10",
			f.repo_id
		))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 200);
	let hits: ListFindingsResponse = resp.json().await.unwrap();
	assert_eq!(hits.findings.len(), 1);
	let finding_a_id = hits.findings[0].id;

	let resp = f
		.worker
		.get(format!("https://loupe-server/v1/findings/{finding_a_id}"))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 200);
	let detail: FindingDetail = resp.json().await.unwrap();
	assert_eq!(detail.title, "Alpha overflow");

	let resp = f
		.worker
		.get(format!("https://loupe-server/v1/repos/{repo_b}/findings/search?q=Beta&limit=10"))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 403, "worker must not search another repo's findings");

	let resp = worker2
		.get(format!("https://loupe-server/v1/repos/{repo_b}/findings/search?q=Beta&limit=10"))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 200);
	let hits_b: ListFindingsResponse = resp.json().await.unwrap();
	assert_eq!(hits_b.findings.len(), 1);
	let finding_b_id = hits_b.findings[0].id;

	let resp = f
		.worker
		.get(format!("https://loupe-server/v1/findings/{finding_b_id}"))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 403, "worker must not fetch another repo's finding body");

	let resp = f
		.admin
		.get(format!("https://loupe-server/v1/repos/{repo_b}/findings/search?q=Beta&limit=10"))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 200, "admin search access should not require a worker lease");

	let resp = f
		.admin
		.get(format!("https://loupe-server/v1/findings/{finding_b_id}"))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 200, "admin review access should not require a worker lease");

	f.db.with_conn(|c| {
		Ok(c.execute("UPDATE jobs SET lease_expires_at = 0 WHERE id = ?1", [env_a.job_id])?)
	})
	.unwrap();
	let resp = f
		.worker
		.get(format!(
			"https://loupe-server/v1/repos/{}/findings/search?q=Alpha&limit=10",
			f.repo_id
		))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 403, "expired leases must not authorize prior-finding search");

	let resp = f
		.worker
		.get(format!("https://loupe-server/v1/findings/{finding_a_id}"))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 403, "expired leases must not authorize finding detail reads");

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
