//! End-to-end test for the email reporter: spin up a fake sendmail
//! script that captures stdin to a file, register a repo with email
//! reporting, run a scan, and prove the captured message has the
//! expected From/To/Subject and includes the finding.

use std::sync::Arc;

use git2::{Repository, Signature};
use loupe_proto::{
	RegisterRepoRequest, RegisterWorkerRequest, RegisterWorkerResponse, ReportingSetup,
	ScanRequest, PROTOCOL_VERSION,
};
use loupe_server::init::run_init;
use loupe_server::reporters::{EmailReporter, GithubReporter};
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

/// Plant a fake sendmail script under tmp that copies its stdin to
/// `out`. Returns the path to invoke and the path it'll write to.
fn write_fake_sendmail(tmp: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
	let out = tmp.join("captured.eml");
	let bin = tmp.join("fake_sendmail.sh");
	let script = format!("#!/bin/sh\ncat - > {}\n", out.display());
	std::fs::write(&bin, script).unwrap();
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let mut perms = std::fs::metadata(&bin).unwrap().permissions();
		perms.set_mode(0o755);
		std::fs::set_permissions(&bin, perms).unwrap();
	}
	(bin, out)
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
async fn email_reporter_invokes_sendmail_with_findings() {
	let (_repo_tmp, clone_url) = make_planted_repo();
	let scratch = tempfile::tempdir().unwrap();
	let (sendmail_bin, captured_path) = write_fake_sendmail(scratch.path());

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
	let state = AppState::new(db.clone(), Arc::new(ca), Arc::new(GithubReporter::new().unwrap()))
		.with_email_reporter(EmailReporter::with_bin(&sendmail_bin));
	let server = serve(cfg, state).await.unwrap();
	let addr = server.local_addr;

	let admin = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&ca_cert_pem))
		.identity(pem_to_identity(&init.admin_bundle.cert_pem, &init.admin_bundle.key_pem))
		.resolve("loupe-server", addr)
		.use_rustls_tls()
		.build()
		.unwrap();

	// Register a repo with Email reporting.
	let resp = admin
		.post("https://loupe-server/v1/repos")
		.json(&RegisterRepoRequest {
			protocol_version: PROTOCOL_VERSION,
			clone_url: "https://github.com/loupe/test-target.git".into(),
			branch: None,
			scan_interval_seconds: None,
			reporting: ReportingSetup::Email {
				to: vec!["security@example.com".into()],
				from: Some("loupe@example.com".into()),
				subject_prefix: Some("[scan]".into()),
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

	// Mint a worker, run a scan.
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

	let cache_dir = tempfile::tempdir().unwrap();
	let cache = Arc::new(RepoCache::new(cache_dir.path().to_path_buf(), u64::MAX).unwrap());
	let scanners: Vec<Arc<dyn Scanner>> = vec![Arc::new(RegexSecretsScanner::new())];
	let runner = Runner::new(server_client, cache, scanners);
	let cancel = CancellationToken::new();
	let stepped = runner.step(&cancel).await.unwrap();
	assert!(stepped);

	// Captured file must exist and contain the right headers + the finding.
	let captured = std::fs::read_to_string(&captured_path).expect("captured email");
	assert!(captured.contains("From: loupe@example.com"), "got: {captured}");
	assert!(captured.contains("To: security@example.com"));
	assert!(captured.contains("Subject: [scan]"));
	assert!(captured.contains("AWS access key"), "captured: {captured}");

	server.shutdown().await;
}
