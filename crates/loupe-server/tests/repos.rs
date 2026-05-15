//! End-to-end test for the repo registration / listing / deregistration
//! admin routes. Verifies that the inline `github_pat` is moved into the
//! secrets table and that the wire `RegisterRepoRequest` never leaks
//! storage-internal fields.

use std::net::SocketAddr;
use std::sync::Arc;

use loupe_core::ReportingDestination;
use loupe_proto::{
	ListReposResponse, RegisterRepoRequest, ReportingSetup, RotateRepoPatRequest,
	SetRepoGithubReportingRequest, PROTOCOL_VERSION,
};
use loupe_server::init::run_init;
use loupe_server::{serve, AppState, Config};
use loupe_storage::{secrets, Db};
use loupe_tls::Ca;

mod common;
use common::{pem_to_certificate, pem_to_identity};

fn admin_client(
	ca_cert_pem: &str, cert_pem: &str, key_pem: &str, addr: SocketAddr,
) -> reqwest::Client {
	reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(ca_cert_pem))
		.identity(pem_to_identity(cert_pem, key_pem))
		.resolve("loupe-server", addr)
		.use_rustls_tls()
		.build()
		.unwrap()
}

struct Fixture {
	handle: loupe_server::ServeHandle,
	addr: SocketAddr,
	ca_cert_pem: String,
	admin_cert_pem: String,
	admin_key_pem: String,
	db: Arc<Db>,
}

async fn bring_up() -> Fixture {
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
	let admin_cert_pem = init.admin_bundle.cert_pem.clone();
	let admin_key_pem = init.admin_bundle.key_pem.clone();

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

	Fixture { handle, addr, ca_cert_pem, admin_cert_pem, admin_key_pem, db }
}

async fn create_repo(admin: &reqwest::Client, reporting: ReportingSetup) -> i64 {
	let req = RegisterRepoRequest {
		protocol_version: PROTOCOL_VERSION,
		clone_url: "https://github.com/acme/widget.git".into(),
		branch: Some("main".into()),
		scan_interval_seconds: Some(3600),
		reporting,
		scanner_config: serde_json::json!({"regex": {"enabled": true}}),
		verification_enabled: true,
		require_approval: Some(false),
	};
	let resp = admin.post("https://loupe-server/v1/repos").json(&req).send().await.unwrap();
	assert_eq!(resp.status(), 201, "create repo: {}", resp.status());
	let body: serde_json::Value = resp.json().await.unwrap();
	let repo_id = body["repo_id"].as_i64().unwrap();
	assert!(repo_id > 0);
	repo_id
}

fn repo_reporting(db: &Db, repo_id: i64) -> ReportingDestination {
	let reporting_json: String = db
		.with_conn(|c| {
			let s = c.query_row(
				"SELECT reporting FROM registered_repos WHERE id = ?1",
				[repo_id],
				|r| r.get::<_, String>(0),
			)?;
			Ok(s)
		})
		.unwrap();
	serde_json::from_str(&reporting_json).unwrap()
}

fn secret_value(db: &Db, id: i64) -> Option<Vec<u8>> {
	db.with_conn(|c| Ok(secrets::read(c, id)?)).unwrap()
}

#[tokio::test]
async fn admin_can_register_list_and_delete_a_repo() {
	let f = bring_up().await;
	let admin = admin_client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);

	let req = RegisterRepoRequest {
		protocol_version: PROTOCOL_VERSION,
		clone_url: "https://github.com/acme/widget.git".into(),
		branch: Some("main".into()),
		scan_interval_seconds: Some(3600),
		reporting: ReportingSetup::GithubIssue {
			target_owner: "acme".into(),
			target_repo: "tracker".into(),
			github_pat: "ghp_secret_value".into(),
		},
		scanner_config: serde_json::json!({"regex": {"enabled": true}}),
		verification_enabled: true,
		require_approval: Some(false),
	};
	let resp = admin.post("https://loupe-server/v1/repos").json(&req).send().await.unwrap();
	assert_eq!(resp.status(), 201, "create repo: {}", resp.status());
	let body: serde_json::Value = resp.json().await.unwrap();
	let repo_id = body["repo_id"].as_i64().unwrap();
	assert!(repo_id > 0);

	// PAT was stored in the secrets table, not in the repos `reporting`
	// JSON. Verify by reading directly from the DB.
	let stored_secret: Vec<u8> =
		f.db.with_conn(|c| {
			let s = c.query_row(
				"SELECT value FROM secrets WHERE kind='github_pat' LIMIT 1",
				[],
				|r| r.get::<_, Vec<u8>>(0),
			)?;
			Ok(s)
		})
		.unwrap();
	assert_eq!(stored_secret, b"ghp_secret_value");

	let reporting_json: String =
		f.db.with_conn(|c| {
			let s = c.query_row(
				&format!("SELECT reporting FROM registered_repos WHERE id = {repo_id}"),
				[],
				|r| r.get::<_, String>(0),
			)?;
			Ok(s)
		})
		.unwrap();
	assert!(
		!reporting_json.contains("ghp_secret_value"),
		"PAT must not be persisted in registered_repos.reporting"
	);
	assert!(reporting_json.contains("pat_secret_id"));

	// List shows it.
	let resp = admin.get("https://loupe-server/v1/repos").send().await.unwrap();
	assert!(resp.status().is_success());
	let body: ListReposResponse = resp.json().await.unwrap();
	assert_eq!(body.repos.len(), 1);
	assert_eq!(body.repos[0].clone_url, "https://github.com/acme/widget.git");
	assert_eq!(body.repos[0].host, "github.com");
	assert_eq!(body.repos[0].disabled_at, None);
	assert!(body.repos[0].verification_enabled);
	assert_eq!(body.repos[0].require_approval, Some(false));

	// Delete cascades.
	let resp =
		admin.delete(format!("https://loupe-server/v1/repos/{}", repo_id)).send().await.unwrap();
	assert_eq!(resp.status(), 204);

	let resp = admin.get("https://loupe-server/v1/repos").send().await.unwrap();
	let body: ListReposResponse = resp.json().await.unwrap();
	assert!(body.repos.is_empty());

	f.handle.shutdown().await;
}

#[tokio::test]
async fn admin_can_rotate_a_repo_github_pat() {
	let f = bring_up().await;
	let admin = admin_client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);

	let repo_id = create_repo(
		&admin,
		ReportingSetup::GithubIssue {
			target_owner: "acme".into(),
			target_repo: "tracker".into(),
			github_pat: "ghp_old".into(),
		},
	)
	.await;
	let old_secret_id = match repo_reporting(&f.db, repo_id) {
		ReportingDestination::GithubIssue { target_owner, target_repo, pat_secret_id } => {
			assert_eq!(target_owner, "acme");
			assert_eq!(target_repo, "tracker");
			pat_secret_id
		},
		other => panic!("expected GitHub reporting, got {other:?}"),
	};
	assert_eq!(secret_value(&f.db, old_secret_id).unwrap(), b"ghp_old");

	let req =
		RotateRepoPatRequest { protocol_version: PROTOCOL_VERSION, github_pat: "ghp_new".into() };
	let resp = admin
		.post(format!("https://loupe-server/v1/repos/{repo_id}/reporting/github-pat"))
		.json(&req)
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204, "rotate PAT: {}", resp.status());

	let new_secret_id = match repo_reporting(&f.db, repo_id) {
		ReportingDestination::GithubIssue { target_owner, target_repo, pat_secret_id } => {
			assert_eq!(target_owner, "acme");
			assert_eq!(target_repo, "tracker");
			pat_secret_id
		},
		other => panic!("expected GitHub reporting, got {other:?}"),
	};
	assert_ne!(new_secret_id, old_secret_id);
	assert_eq!(secret_value(&f.db, new_secret_id).unwrap(), b"ghp_new");
	assert_eq!(secret_value(&f.db, old_secret_id), None);

	f.handle.shutdown().await;
}

#[tokio::test]
async fn rotating_pat_requires_github_issue_reporting() {
	let f = bring_up().await;
	let admin = admin_client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);
	let repo_id = create_repo(&admin, ReportingSetup::Manual).await;
	let req =
		RotateRepoPatRequest { protocol_version: PROTOCOL_VERSION, github_pat: "ghp_new".into() };

	let resp = admin
		.post(format!("https://loupe-server/v1/repos/{repo_id}/reporting/github-pat"))
		.json(&req)
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 400);

	let resp = admin
		.post("https://loupe-server/v1/repos/999/reporting/github-pat")
		.json(&req)
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 404);

	f.handle.shutdown().await;
}

#[tokio::test]
async fn admin_can_set_github_reporting_on_a_manual_repo() {
	let f = bring_up().await;
	let admin = admin_client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);
	let repo_id = create_repo(&admin, ReportingSetup::Manual).await;

	let req = SetRepoGithubReportingRequest {
		protocol_version: PROTOCOL_VERSION,
		target_owner: "acme".into(),
		target_repo: "tracker".into(),
		github_pat: "ghp_first".into(),
	};
	let resp = admin
		.put(format!("https://loupe-server/v1/repos/{repo_id}/reporting/github"))
		.json(&req)
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204, "set GitHub reporting: {}", resp.status());
	let first_secret_id = match repo_reporting(&f.db, repo_id) {
		ReportingDestination::GithubIssue { target_owner, target_repo, pat_secret_id } => {
			assert_eq!(target_owner, "acme");
			assert_eq!(target_repo, "tracker");
			pat_secret_id
		},
		other => panic!("expected GitHub reporting, got {other:?}"),
	};
	assert_eq!(secret_value(&f.db, first_secret_id).unwrap(), b"ghp_first");

	let req = SetRepoGithubReportingRequest {
		protocol_version: PROTOCOL_VERSION,
		target_owner: "acme".into(),
		target_repo: "new-tracker".into(),
		github_pat: "ghp_second".into(),
	};
	let resp = admin
		.put(format!("https://loupe-server/v1/repos/{repo_id}/reporting/github"))
		.json(&req)
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204, "replace GitHub reporting: {}", resp.status());
	let second_secret_id = match repo_reporting(&f.db, repo_id) {
		ReportingDestination::GithubIssue { target_owner, target_repo, pat_secret_id } => {
			assert_eq!(target_owner, "acme");
			assert_eq!(target_repo, "new-tracker");
			pat_secret_id
		},
		other => panic!("expected GitHub reporting, got {other:?}"),
	};
	assert_ne!(second_secret_id, first_secret_id);
	assert_eq!(secret_value(&f.db, second_secret_id).unwrap(), b"ghp_second");
	assert_eq!(secret_value(&f.db, first_secret_id), None);

	f.handle.shutdown().await;
}

#[tokio::test]
async fn registering_with_non_https_clone_url_400s() {
	let f = bring_up().await;
	let admin = admin_client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);

	for clone_url in ["git@github.com:acme/widget.git", "http://github.com/acme/widget.git"] {
		let req = RegisterRepoRequest {
			protocol_version: PROTOCOL_VERSION,
			clone_url: clone_url.into(),
			branch: None,
			scan_interval_seconds: None,
			reporting: ReportingSetup::GithubIssue {
				target_owner: "a".into(),
				target_repo: "b".into(),
				github_pat: "ghp".into(),
			},
			scanner_config: serde_json::Value::Null,
			verification_enabled: false,
			require_approval: None,
		};
		let resp = admin.post("https://loupe-server/v1/repos").json(&req).send().await.unwrap();
		assert_eq!(resp.status(), 400, "{clone_url} should be rejected");
	}
	f.handle.shutdown().await;
}
