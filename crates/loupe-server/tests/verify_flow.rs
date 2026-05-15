//! End-to-end verification flow: LLM discovery scanner finds a bug,
//! validates it internally, ships the finding to the server. The
//! server, because the repo has `verification_enabled = true`, marks
//! the finding `validating` and enqueues a verify job. The same
//! Runner picks the verify job up (it advertises `verify:llm`), runs
//! `LlmVerifierScanner::verify`, and POSTs a verdict. The server
//! flips the finding to `confirmed` and the dispatcher fires only
//! then — proving the gate-on-confirmed semantics.
//!
//! Two scenarios: confirmed (issue lands) and dismissed (no issue).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use git2::{Repository, Signature};
use loupe_core::{Finding, Severity, Verdict, VerdictPatch};
use loupe_proto::{
	FindingsBatch, RegisterRepoRequest, RegisterWorkerRequest, RegisterWorkerResponse,
	ReportingSetup, ScanRequest, PROTOCOL_VERSION,
};
use serde::Deserialize;

/// Test-input shape mirroring what the verifier agent would call
/// `submit_verdict` (and optionally `submit_patch`) with. The stub
/// backend in `run_flow` parses one of these out of the
/// `verify_response` string each test passes in, builds a real
/// `Verdict`, and POSTs it via the worker mTLS client — same wire
/// shape the production MCP child uses at session-end flush.
#[derive(Debug, Deserialize)]
struct VerifyStubInput {
	verdict: String,
	notes: String,
	#[serde(default)]
	patch: Option<VerifyStubPatch>,
}

#[derive(Debug, Deserialize)]
struct VerifyStubPatch {
	patch_unified: String,
	notes: String,
}

impl VerifyStubInput {
	fn into_verdict(self) -> Verdict {
		match self.verdict.as_str() {
			"confirmed" => Verdict::Confirmed {
				notes: Some(self.notes),
				patch: self
					.patch
					.map(|p| VerdictPatch { patch_unified: p.patch_unified, notes: p.notes }),
			},
			"dismissed" => Verdict::Dismissed { notes: Some(self.notes) },
			"inconclusive" => Verdict::Inconclusive { reason: self.notes },
			other => panic!("unknown verdict in test input: {other}"),
		}
	}
}
use loupe_server::init::run_init;
use loupe_server::reporters::GithubReporter;
use loupe_server::{serve, AppState, Config};
use loupe_storage::Db;
use loupe_tls::Ca;
use loupe_worker::llm::testing::StubLlmBackend;
use loupe_worker::llm::LlmRequest;
use loupe_worker::scanners::{LlmCodeReviewScanner, LlmVerifierScanner};
use loupe_worker::{RepoCache, Runner, Scanner, ServerClient};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
struct GithubStubState {
	captured: Arc<Mutex<Vec<serde_json::Value>>>,
}

async fn stub_create_issue(
	State(stub): State<GithubStubState>,
	axum::extract::Path((_owner, _repo)): axum::extract::Path<(String, String)>,
	Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
	stub.captured.lock().unwrap().push(body);
	(
		StatusCode::CREATED,
		Json(serde_json::json!({"number": 1, "html_url": "https://stub/issues/1"})),
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

/// Run the verify flow end-to-end. `verify_response` controls what the
/// stub backend returns for the VERIFY prompt; pass a confirmed
/// payload for the happy-path test or a dismissed payload for the
/// rejection test.
async fn run_flow(
	verify_response: &'static str,
) -> (Arc<Db>, GithubStubState, loupe_server::ServeHandle) {
	let (_repo_tmp, clone_url) = make_planted_repo();
	let (stub_addr, stub_state) = spawn_github_stub().await;
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
				github_pat: "ghp_pat".into(),
			},
			scanner_config: serde_json::Value::Null,
			verification_enabled: true,
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

	admin
		.post(format!("https://loupe-server/v1/repos/{}/scan", repo_id))
		.json(&ScanRequest { protocol_version: PROTOCOL_VERSION, incremental: false })
		.send()
		.await
		.unwrap();

	// Stub backend: two paths, both simulating what the agent's
	// MCP child would POST in production.
	//   * Discovery — the agent's `submit_finding` tool POSTs to
	//     `/v1/jobs/{job_id}/findings`; the stub does the same call
	//     directly.
	//   * Verify — the agent's `submit_verdict` (and optional
	//     `submit_patch`) get buffered by the MCP server and
	//     flushed at session end as a single
	//     `POST /v1/jobs/{job_id}/verdict` carrying
	//     `Verdict::Confirmed { ..., patch: Some(...) }`. The stub
	//     parses the test-supplied JSON into a real `Verdict` and
	//     POSTs it.
	let server_client_for_stub = server_client.clone();
	let backend = Arc::new(StubLlmBackend::new_async("stub", move |req: LlmRequest| {
		let server_client = server_client_for_stub.clone();
		async move {
			if req.prompt.contains("independent second opinion") {
				let job_id = req.job_id.expect("verify sessions must carry a job_id");
				assert!(
					req.finding_id.is_some(),
					"verify sessions must carry finding_id (otherwise MCP wouldn't \
					 enter verify mode); got finding_id=None",
				);
				let stub: VerifyStubInput = serde_json::from_str(verify_response)
					.expect("verify_response must be valid VerifyStubInput JSON");
				let verdict = stub.into_verdict();
				server_client
					.submit_verdict(
						job_id,
						&loupe_proto::VerdictSubmission {
							protocol_version: PROTOCOL_VERSION,
							verdict,
						},
					)
					.await?;
				return Ok(String::new());
			}
			// Discovery: simulate the agent calling submit_finding.
			let job_id = req.job_id.expect("discovery sessions must carry a job_id");
			let finding = Finding {
				scanner_id: "llm-code-review".into(),
				severity: Severity::High,
				title: "OOB index".into(),
				description: "unchecked index".into(),
				file_path: Some("src/lib.rs".into()),
				line_start: Some(1),
				line_end: Some(1),
				cwe: Some("CWE-129".into()),
				patch_unified: None,
				poc_unified: Some(
					"--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -0,0 +1 @@\n\
					 +#[test] fn oob() { idx(&[], 0); }\n"
						.into(),
				),
				fingerprint: "test-fp-oob-idx".into(),
			};
			let batch =
				FindingsBatch { protocol_version: PROTOCOL_VERSION, findings: vec![finding] };
			server_client.submit_findings(job_id, &batch).await?;
			Ok(String::new())
		}
	}));

	let cache_dir = tempfile::tempdir().unwrap();
	let cache = Arc::new(RepoCache::new(cache_dir.path().to_path_buf(), u64::MAX).unwrap());
	let scanners: Vec<Arc<dyn Scanner>> = vec![
		Arc::new(LlmCodeReviewScanner::new(backend.clone())),
		Arc::new(LlmVerifierScanner::new(backend)),
	];
	let runner = Runner::new(server_client, cache, scanners);
	let cancel = CancellationToken::new();

	// Step 1: scan job → discovery + validation → finding lands as
	// validating, verify job enqueued.
	assert!(runner.step(&cancel).await.unwrap(), "scan step ran");
	// Step 2: verify job → verdict submitted; on confirm the finding
	// flips and dispatches.
	assert!(runner.step(&cancel).await.unwrap(), "verify step ran");

	(db, stub_state, server)
}

#[tokio::test]
async fn confirmed_verdict_dispatches_the_finding() {
	let (db, stub, server) =
		run_flow(r#"{"verdict":"confirmed","notes":"OOB confirmed on empty slice"}"#).await;

	// Finding is reported (the dispatch path stamps state='reported').
	let state: String = db
		.with_conn(|c| {
			Ok(c.query_row("SELECT state FROM findings LIMIT 1", [], |r| r.get::<_, String>(0))?)
		})
		.unwrap();
	assert_eq!(state, "reported");

	// Verifications row recorded the verdict (with the verifier's
	// real job_id, not NULL — that's the reaper's signature).
	let (count, with_job): (i64, i64) = db
		.with_conn(|c| {
			Ok(c.query_row(
				"SELECT COUNT(*), SUM(CASE WHEN job_id IS NOT NULL THEN 1 ELSE 0 END)
				 FROM finding_verifications",
				[],
				|r| Ok((r.get(0)?, r.get(1)?)),
			)?)
		})
		.unwrap();
	assert_eq!(count, 1);
	assert_eq!(with_job, 1, "verifier-issued verdict must carry a job_id");

	// GitHub stub captured exactly one issue.
	let captured = stub.captured.lock().unwrap().clone();
	assert_eq!(captured.len(), 1);
	assert_eq!(captured[0]["title"].as_str().unwrap(), "high: OOB index");

	server.shutdown().await;
}

#[tokio::test]
async fn confirmed_verdict_with_patch_attaches_diff_and_audit() {
	// End-to-end coverage of the patch-attachment path: the
	// verifier returns a Confirmed verdict carrying a candidate
	// fix; the server lands the diff, the rationale, and the
	// patch_proposed_* audit columns inside the same tx as the
	// verdict insert + state transition; the dispatcher reads the
	// row *after* the tx commits, so the auto-filed GitHub issue
	// includes the patch.
	let (db, stub, server) = run_flow(
		r#"{
			"verdict": "confirmed",
			"notes": "OOB confirmed on empty slice",
			"patch": {
				"patch_unified": "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1,3 @@\n-pub fn idx(arr: &[u8], i: usize) -> u8 { arr[i] }\n+pub fn idx(arr: &[u8], i: usize) -> u8 {\n+    if i < arr.len() { arr[i] } else { 0 }\n+}\n",
				"notes": "guard the index lookup so an empty slice can't panic"
			}
		}"#,
	)
	.await;

	let row: (String, Option<String>, Option<String>, Option<String>, Option<i64>) = db
		.with_conn(|c| {
			Ok(c.query_row(
				"SELECT state, patch_unified, patch_notes, patch_proposed_by_cn, patch_proposed_at
				 FROM findings LIMIT 1",
				[],
				|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
			)?)
		})
		.unwrap();
	let (state, patch_unified, patch_notes, by_cn, at) = row;
	assert_eq!(state, "reported");
	let patch = patch_unified.expect("patch_unified must be set when verdict carries a patch");
	assert!(patch.contains("if i < arr.len()"), "stored diff must match what the verdict carried");
	assert_eq!(
		patch_notes.as_deref(),
		Some("guard the index lookup so an empty slice can't panic")
	);
	assert_eq!(by_cn.as_deref(), Some("w1"), "audit must record the verifier worker's name");
	assert!(at.is_some(), "patch_proposed_at must be stamped");

	// GitHub stub got the issue (already covered by the confirmed-
	// without-patch test); just sanity-check the body now carries
	// the diff so the human reviewer sees the fix on the issue.
	let captured = stub.captured.lock().unwrap().clone();
	assert_eq!(captured.len(), 1);
	let body = captured[0]["body"].as_str().unwrap();
	assert!(
		body.contains("if i < arr.len()"),
		"GitHub issue body must embed the proposed diff; got: {body}"
	);

	server.shutdown().await;
}

#[tokio::test]
async fn dismissed_verdict_blocks_dispatch() {
	let (db, stub, server) =
		run_flow(r#"{"verdict":"dismissed","notes":"false positive — ignore"}"#).await;

	let state: String = db
		.with_conn(|c| {
			Ok(c.query_row("SELECT state FROM findings LIMIT 1", [], |r| r.get::<_, String>(0))?)
		})
		.unwrap();
	assert_eq!(state, "dismissed");

	// And no issue was dispatched.
	let captured = stub.captured.lock().unwrap().clone();
	assert!(captured.is_empty(), "dismissed verdict must NOT dispatch; got: {captured:?}");

	server.shutdown().await;
}
