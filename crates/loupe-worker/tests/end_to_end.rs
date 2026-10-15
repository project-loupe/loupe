//! End-to-end worker test: spin up loupe-server in-process, register a
//! repo (clone URL pointed at a local git repo on disk), mint a worker,
//! kick a scan, run a single Runner step, and prove the worker's
//! scanner produced a finding and completed the job.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::builder::TypedValueParser;
use git2::{Repository, Signature};
use loupe_core::text::BoundedText;
use loupe_core::{ReportingDestination, ScannerDocument};
use loupe_proto::{RegisterWorkerResponse, ScanRequest, ScanResponse, PROTOCOL_VERSION};
use loupe_provenance::{Ingress, Mark, Operator, Secret, Untrusted, Unvalidated, Validate};
use loupe_server::config::{HostnameParser, PathParser};
use loupe_server::init::run_init;
use loupe_server::{serve, AppState, Config};
use loupe_storage::repos::NewRepo;
use loupe_storage::{registry, Db};
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

/// The HTTPS-only registration route cannot select this local fixture. Admit
/// its authored Operator values, then use the production registry transaction.
struct LocalRepository;
impl Validate<&str, Operator> for LocalRepository {
	type Output = NewRepo<Operator>;
	type Error = loupe_core::text::Error;
	fn validate<'a>(
		self, input: Unvalidated<'a, &str>, mark: Mark<'a, Operator>,
	) -> Result<Self::Output, Self::Error> {
		Ok(NewRepo {
			clone_url: BoundedText::new(&mark, input.get())?,
			host: BoundedText::new(&mark, "github.com")?,
			owner: BoundedText::new(&mark, "loupe")?,
			repo: BoundedText::new(&mark, "test-target")?,
			default_branch: None,
			scan_interval_seconds: None,
			scanner_config: ScannerDocument::registered(&mark, serde_json::Value::Null),
			reporting: ReportingDestination::GithubIssue {
				target_owner: BoundedText::new(&mark, "x")?,
				target_repo: BoundedText::new(&mark, "y")?,
				pat_secret_id: None,
			},
			verification_enabled: false,
			require_approval: None,
		})
	}
}

fn fixture_operator() -> Ingress<Operator> {
	// SAFETY: this test authors the local repository's synthetic Operator input.
	#[allow(unsafe_code)]
	unsafe {
		Ingress::new()
	}
}

#[tokio::test]
async fn worker_runs_a_scan_and_emits_a_finding() {
	let (_repo_tmp, clone_url) = make_planted_repo();
	let server_dir = tempfile::tempdir().unwrap();
	let command = clap::Command::new("fixture");
	let server_path = PathParser.parse_ref(&command, None, server_dir.path().as_os_str()).unwrap();
	let hostname =
		HostnameParser.parse_ref(&command, None, std::ffi::OsStr::new("loupe-server")).unwrap();
	let init = run_init(&server_path, &[hostname], None).unwrap();

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
		ca_cert_pem: init.layout.ca_cert.read_tls_pem().unwrap(),
		ca_key_pem: init.layout.ca_key.read_tls_pem().unwrap(),
	};
	let db = Arc::new(Db::open(init.layout.db_path.as_path(), &init.master_key).unwrap());
	let state = AppState::new(
		db.clone(),
		Arc::new(ca),
		Arc::new(loupe_server::reporters::GithubReporter::new().unwrap()),
	);
	let server_handle = serve(cfg, state).await.unwrap();
	let addr: SocketAddr = server_handle.local_addr;

	// Admin client drives the real worker registration, scan and read routes.
	let admin = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&ca_cert_pem))
		.identity(pem_to_identity(&init.admin_bundle.cert_pem, init.admin_bundle.key_pem.expose()))
		.resolve("loupe-server", addr)
		.use_rustls_tls()
		.build()
		.unwrap();

	let repository =
		Untrusted::new(clone_url.as_str(), fixture_operator()).validate(LocalRepository).unwrap();
	let registry::ReportingWrite::Done(repo_id) = registry::register_repository(
		&db,
		&fixture_operator(),
		&repository,
		Some(&Secret::new("ghp".into())),
		0,
	)
	.unwrap() else {
		panic!("fixture PAT registration must succeed")
	};

	let resp = admin
		.post("https://loupe-server/v1/workers")
		.json(&serde_json::json!({"protocol_version": PROTOCOL_VERSION, "name": "w1"}))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201);
	let bundle: RegisterWorkerResponse = resp.json().await.unwrap();

	// Build the worker's reqwest client with `.resolve("loupe-server", addr)` and
	// hand it to ServerClient via `from_parts`.
	let raw = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&ca_cert_pem))
		.identity(pem_to_identity(&bundle.client_cert_pem, bundle.client_key_pem.expose()))
		.resolve("loupe-server", addr)
		.use_rustls_tls()
		.build()
		.unwrap();
	let server_client =
		Arc::new(ServerClient::from_parts(raw, "https://loupe-server/".parse().unwrap()));

	let resp = admin
		.post(format!("https://loupe-server/v1/repos/{}/scan", repo_id))
		.json(&ScanRequest { protocol_version: PROTOCOL_VERSION, incremental: false })
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201);
	let queued: ScanResponse = resp.json().await.unwrap();

	let cache_dir = tempfile::tempdir().unwrap();
	let cache = Arc::new(RepoCache::new(cache_dir.path().to_path_buf(), u64::MAX, None).unwrap());
	let scanners: Vec<Arc<dyn Scanner>> = vec![Arc::new(RegexSecretsScanner::new())];
	let runner = Runner::new(server_client, cache, scanners);

	let cancel = CancellationToken::new();
	let stepped = runner.step(&cancel).await.unwrap();
	assert!(stepped, "runner should have leased and run the queued job");

	let findings: serde_json::Value = admin
		.get(format!("https://loupe-server/v1/repos/{repo_id}/findings"))
		.send()
		.await
		.unwrap()
		.error_for_status()
		.unwrap()
		.json()
		.await
		.unwrap();
	assert_eq!(findings["findings"].as_array().unwrap().len(), 1, "expected exactly one finding");
	assert_eq!(findings["findings"][0]["repo_id"].as_i64(), Some(repo_id));
	assert_eq!(findings["findings"][0]["job_id"].as_i64(), Some(queued.job_id));

	let job: serde_json::Value = admin
		.get(format!("https://loupe-server/v1/jobs/{}", queued.job_id))
		.send()
		.await
		.unwrap()
		.error_for_status()
		.unwrap()
		.json()
		.await
		.unwrap();
	assert_eq!(job["state"].as_str(), Some("succeeded"));
	assert!(job["head_sha"].as_str().is_some(), "head_sha should have been persisted on success");

	server_handle.shutdown().await;
}
