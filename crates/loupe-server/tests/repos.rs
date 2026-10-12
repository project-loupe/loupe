//! End-to-end test for the repo registration / listing / deregistration
//! admin routes. Verifies that the inline `github_pat` is moved into the
//! secrets table and that the wire `RegisterRepoRequest` never leaks
//! storage-internal fields.

use std::net::SocketAddr;
use std::sync::Arc;

use loupe_core::ReportingDestination;
use loupe_proto::{
	GithubReportingAuth, ListReposResponse, RegisterRepoRequest, ReportingSetup, ReportingSummary,
	RotateRepoPatRequest, SetRepoGithubReportingRequest, PROTOCOL_VERSION,
};
use loupe_server::init::run_init;
use loupe_server::reporters::github_app::testing::APP_PRIVATE_KEY_PEM;
use loupe_server::{serve, AppState, Config};
use loupe_storage::github_app::{self, StoredGithubApp};
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
	bring_up_with(false, None).await
}

async fn bring_up_with_verification_default(verification_default: bool) -> Fixture {
	bring_up_with(verification_default, None).await
}

/// Bring the server up with `[github_app] allowed_target_owners` set.
async fn bring_up_with_allowed_owners(owners: &[&str]) -> Fixture {
	bring_up_with(false, Some(owners.iter().map(|o| (*o).to_owned()).collect())).await
}

/// Store the fixture GitHub App key directly in the secrets table, the
/// way `PUT /v1/github-app` would after verifying it against GitHub.
/// These tests never dispatch, so no stub GitHub is needed.
fn store_github_app(db: &Db) {
	db.with_conn(|c| {
		Ok(github_app::set(
			c,
			&StoredGithubApp {
				app_id: 4242,
				slug: "loupe-reporter".into(),
				private_key_pem: APP_PRIVATE_KEY_PEM.into(),
			},
			0,
		)?)
	})
	.unwrap();
}

async fn bring_up_with(
	verification_default: bool, github_app_allowed_owners: Option<Vec<String>>,
) -> Fixture {
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
	)
	.with_verification_default(verification_default)
	.with_github_app_allowed_owners(github_app_allowed_owners);
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
		verification_enabled: Some(true),
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
			github_pat: Some(loupe_provenance::Secret::new("ghp_secret_value".into())),
		},
		scanner_config: serde_json::json!({"regex": {"enabled": true}}),
		verification_enabled: Some(true),
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
	// The listing reports which reporter is configured, with the
	// non-secret targets but never the storage-side secret id.
	assert_eq!(
		body.repos[0].reporting,
		Some(ReportingSummary::GithubIssue {
			target_owner: "acme".into(),
			target_repo: "tracker".into(),
			auth: GithubReportingAuth::Pat,
		})
	);

	// Delete cascades.
	let resp =
		admin.delete(format!("https://loupe-server/v1/repos/{}", repo_id)).send().await.unwrap();
	assert_eq!(resp.status(), 204);

	let resp = admin.get("https://loupe-server/v1/repos").send().await.unwrap();
	let body: ListReposResponse = resp.json().await.unwrap();
	assert!(body.repos.is_empty());

	f.handle.shutdown().await;
}

/// The repo listing has to tell a client *which* reporter each repo uses —
/// PAT rotation only applies to `github_issue`, and the server 400s a
/// rotation against anything else — while never exposing the PAT itself or
/// the `secrets` row id it lives behind.
#[tokio::test]
async fn repo_listing_reports_reporter_kind_without_secrets() {
	let f = bring_up().await;
	let admin = admin_client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);

	let cases = [
		(
			"https://github.com/acme/gh.git",
			ReportingSetup::GithubIssue {
				target_owner: "acme".into(),
				target_repo: "tracker".into(),
				github_pat: Some(loupe_provenance::Secret::new("ghp_do_not_leak".into())),
			},
		),
		(
			"https://github.com/acme/mail.git",
			ReportingSetup::Email {
				to: vec!["sec@acme.test".into()],
				from: Some("loupe@acme.test".into()),
				subject_prefix: Some("[loupe]".into()),
			},
		),
		("https://github.com/acme/manual.git", ReportingSetup::Manual),
	];
	for (clone_url, reporting) in cases {
		let req = RegisterRepoRequest::new(clone_url, reporting);
		let resp = admin.post("https://loupe-server/v1/repos").json(&req).send().await.unwrap();
		assert_eq!(resp.status(), 201, "create {clone_url}: {}", resp.status());
	}

	// Assert on the raw body, not just the deserialized DTO: a leak would
	// be a stray JSON key, which a typed round-trip would silently drop.
	let raw =
		admin.get("https://loupe-server/v1/repos").send().await.unwrap().text().await.unwrap();
	assert!(!raw.contains("ghp_do_not_leak"), "PAT leaked into the repo listing: {raw}");
	assert!(!raw.contains("pat_secret_id"), "secret id leaked into the repo listing: {raw}");

	let body: ListReposResponse = serde_json::from_str(&raw).unwrap();
	let by_repo = |name: &str| {
		body.repos
			.iter()
			.find(|r| r.repo == name)
			.unwrap_or_else(|| panic!("no repo {name}"))
			.clone()
	};
	assert_eq!(
		by_repo("gh").reporting,
		Some(ReportingSummary::GithubIssue {
			target_owner: "acme".into(),
			target_repo: "tracker".into(),
			auth: GithubReportingAuth::Pat,
		})
	);
	assert_eq!(
		by_repo("mail").reporting,
		Some(ReportingSummary::Email {
			to: vec!["sec@acme.test".into()],
			from: Some("loupe@acme.test".into()),
			subject_prefix: Some("[loupe]".into()),
		})
	);
	assert_eq!(by_repo("manual").reporting, Some(ReportingSummary::Manual));

	f.handle.shutdown().await;
}

#[tokio::test]
async fn repo_registration_inherits_verification_default_unless_pinned() {
	let f = bring_up_with_verification_default(true).await;
	let admin = admin_client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);

	let inherited = RegisterRepoRequest {
		protocol_version: PROTOCOL_VERSION,
		clone_url: "https://github.com/acme/inherit.git".into(),
		branch: None,
		scan_interval_seconds: None,
		reporting: ReportingSetup::Manual,
		scanner_config: serde_json::Value::Null,
		verification_enabled: None,
		require_approval: None,
	};
	let resp = admin.post("https://loupe-server/v1/repos").json(&inherited).send().await.unwrap();
	assert_eq!(resp.status(), 201, "create inherited repo: {}", resp.status());

	let pinned = RegisterRepoRequest {
		protocol_version: PROTOCOL_VERSION,
		clone_url: "https://github.com/acme/pinned.git".into(),
		branch: None,
		scan_interval_seconds: None,
		reporting: ReportingSetup::Manual,
		scanner_config: serde_json::Value::Null,
		verification_enabled: Some(false),
		require_approval: None,
	};
	let resp = admin.post("https://loupe-server/v1/repos").json(&pinned).send().await.unwrap();
	assert_eq!(resp.status(), 201, "create pinned repo: {}", resp.status());

	let resp = admin.get("https://loupe-server/v1/repos").send().await.unwrap();
	assert!(resp.status().is_success());
	let body: ListReposResponse = resp.json().await.unwrap();
	let inherited =
		body.repos.iter().find(|repo| repo.repo == "inherit").expect("inherited repo listed");
	let pinned = body.repos.iter().find(|repo| repo.repo == "pinned").expect("pinned repo listed");
	assert!(inherited.verification_enabled);
	assert!(!pinned.verification_enabled);

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
			github_pat: Some(loupe_provenance::Secret::new("ghp_old".into())),
		},
	)
	.await;
	let old_secret_id = match repo_reporting(&f.db, repo_id) {
		ReportingDestination::GithubIssue {
			target_owner,
			target_repo,
			pat_secret_id: Some(pat_secret_id),
		} => {
			assert_eq!(target_owner, "acme");
			assert_eq!(target_repo, "tracker");
			pat_secret_id
		},
		other => panic!("expected GitHub reporting, got {other:?}"),
	};
	assert_eq!(secret_value(&f.db, old_secret_id).unwrap(), b"ghp_old");

	let req = RotateRepoPatRequest {
		protocol_version: PROTOCOL_VERSION,
		github_pat: loupe_provenance::Secret::new("ghp_new".into()),
	};
	let resp = admin
		.post(format!("https://loupe-server/v1/repos/{repo_id}/reporting/github-pat"))
		.json(&req)
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204, "rotate PAT: {}", resp.status());

	let new_secret_id = match repo_reporting(&f.db, repo_id) {
		ReportingDestination::GithubIssue {
			target_owner,
			target_repo,
			pat_secret_id: Some(pat_secret_id),
		} => {
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
	let req = RotateRepoPatRequest {
		protocol_version: PROTOCOL_VERSION,
		github_pat: loupe_provenance::Secret::new("ghp_new".into()),
	};

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
		github_pat: Some(loupe_provenance::Secret::new("ghp_first".into())),
	};
	let resp = admin
		.put(format!("https://loupe-server/v1/repos/{repo_id}/reporting/github"))
		.json(&req)
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204, "set GitHub reporting: {}", resp.status());
	let first_secret_id = match repo_reporting(&f.db, repo_id) {
		ReportingDestination::GithubIssue {
			target_owner,
			target_repo,
			pat_secret_id: Some(pat_secret_id),
		} => {
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
		github_pat: Some(loupe_provenance::Secret::new("ghp_second".into())),
	};
	let resp = admin
		.put(format!("https://loupe-server/v1/repos/{repo_id}/reporting/github"))
		.json(&req)
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204, "replace GitHub reporting: {}", resp.status());
	let second_secret_id = match repo_reporting(&f.db, repo_id) {
		ReportingDestination::GithubIssue {
			target_owner,
			target_repo,
			pat_secret_id: Some(pat_secret_id),
		} => {
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
				github_pat: Some(loupe_provenance::Secret::new("ghp".into())),
			},
			scanner_config: serde_json::Value::Null,
			verification_enabled: Some(false),
			require_approval: None,
		};
		let resp = admin.post("https://loupe-server/v1/repos").json(&req).send().await.unwrap();
		assert_eq!(resp.status(), 400, "{clone_url} should be rejected");
	}
	f.handle.shutdown().await;
}

fn app_mode_setup(owner: &str) -> ReportingSetup {
	ReportingSetup::GithubIssue {
		target_owner: owner.into(),
		target_repo: "tracker".into(),
		github_pat: None,
	}
}

#[tokio::test]
async fn registering_without_a_pat_requires_a_configured_github_app() {
	let f = bring_up().await;
	let admin = admin_client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);

	let req =
		RegisterRepoRequest::new("https://github.com/acme/widget.git", app_mode_setup("acme"));
	let resp = admin.post("https://loupe-server/v1/repos").json(&req).send().await.unwrap();
	assert_eq!(resp.status(), 400);
	let body = resp.text().await.unwrap();
	assert!(
		body.contains("no GitHub App configured") && body.contains("loupectl github-app set"),
		"error must say how to fix it: {body}"
	);
	let listing: ListReposResponse =
		admin.get("https://loupe-server/v1/repos").send().await.unwrap().json().await.unwrap();
	assert!(listing.repos.is_empty(), "a rejected registration must not leave a repo behind");

	f.handle.shutdown().await;
}

#[tokio::test]
async fn registering_without_a_pat_uses_the_github_app() {
	let f = bring_up().await;
	store_github_app(&f.db);
	let admin = admin_client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);

	let repo_id = create_repo(&admin, app_mode_setup("acme")).await;
	assert_eq!(
		repo_reporting(&f.db, repo_id),
		ReportingDestination::GithubIssue {
			target_owner: "acme".into(),
			target_repo: "tracker".into(),
			pat_secret_id: None,
		}
	);
	let pat_rows: i64 =
		f.db.with_conn(|c| {
			Ok(c.query_row("SELECT COUNT(*) FROM secrets WHERE kind = 'github_pat'", [], |r| {
				r.get(0)
			})?)
		})
		.unwrap();
	assert_eq!(pat_rows, 0, "app mode must not create a PAT secret");

	let raw =
		admin.get("https://loupe-server/v1/repos").send().await.unwrap().text().await.unwrap();
	assert!(!raw.contains("pat_secret_id"), "secret id leaked into the repo listing: {raw}");
	let listing: ListReposResponse = serde_json::from_str(&raw).unwrap();
	assert_eq!(
		listing.repos[0].reporting,
		Some(ReportingSummary::GithubIssue {
			target_owner: "acme".into(),
			target_repo: "tracker".into(),
			auth: GithubReportingAuth::App,
		})
	);
	assert!(raw.contains(r#""auth":"app""#), "listing: {raw}");

	f.handle.shutdown().await;
}

#[tokio::test]
async fn switching_a_pat_repo_to_the_github_app_drops_the_orphaned_pat() {
	let f = bring_up().await;
	store_github_app(&f.db);
	let admin = admin_client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);

	let repo_id = create_repo(
		&admin,
		ReportingSetup::GithubIssue {
			target_owner: "acme".into(),
			target_repo: "tracker".into(),
			github_pat: Some(loupe_provenance::Secret::new("ghp_old".into())),
		},
	)
	.await;
	let old_secret_id = match repo_reporting(&f.db, repo_id) {
		ReportingDestination::GithubIssue { pat_secret_id: Some(id), .. } => id,
		other => panic!("expected a PAT-backed destination, got {other:?}"),
	};
	assert_eq!(secret_value(&f.db, old_secret_id).unwrap(), b"ghp_old");

	let req = SetRepoGithubReportingRequest {
		protocol_version: PROTOCOL_VERSION,
		target_owner: "acme".into(),
		target_repo: "tracker".into(),
		github_pat: None,
	};
	let resp = admin
		.put(format!("https://loupe-server/v1/repos/{repo_id}/reporting/github"))
		.json(&req)
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204, "switch to app: {}", resp.status());
	assert_eq!(
		repo_reporting(&f.db, repo_id),
		ReportingDestination::GithubIssue {
			target_owner: "acme".into(),
			target_repo: "tracker".into(),
			pat_secret_id: None,
		}
	);
	assert_eq!(secret_value(&f.db, old_secret_id), None, "orphaned PAT must be dropped");

	let listing: ListReposResponse =
		admin.get("https://loupe-server/v1/repos").send().await.unwrap().json().await.unwrap();
	assert!(matches!(
		listing.repos[0].reporting,
		Some(ReportingSummary::GithubIssue { auth: GithubReportingAuth::App, .. })
	));

	// Rotating a PAT no longer applies; the error points at the way back.
	let resp = admin
		.post(format!("https://loupe-server/v1/repos/{repo_id}/reporting/github-pat"))
		.json(&RotateRepoPatRequest {
			protocol_version: PROTOCOL_VERSION,
			github_pat: loupe_provenance::Secret::new("ghp_x".into()),
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 400);
	let body = resp.text().await.unwrap();
	assert!(body.contains("reports through the GitHub App"), "{body}");
	assert!(body.contains("set-github-reporting"), "{body}");

	// And the way back works: a PAT switches the repo off the app again.
	let req = SetRepoGithubReportingRequest {
		protocol_version: PROTOCOL_VERSION,
		target_owner: "acme".into(),
		target_repo: "tracker".into(),
		github_pat: Some(loupe_provenance::Secret::new("ghp_back".into())),
	};
	let resp = admin
		.put(format!("https://loupe-server/v1/repos/{repo_id}/reporting/github"))
		.json(&req)
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);
	match repo_reporting(&f.db, repo_id) {
		ReportingDestination::GithubIssue { pat_secret_id: Some(id), .. } => {
			assert_eq!(secret_value(&f.db, id).unwrap(), b"ghp_back");
		},
		other => panic!("expected a PAT-backed destination, got {other:?}"),
	}

	f.handle.shutdown().await;
}

#[tokio::test]
async fn switching_to_the_github_app_requires_a_configured_app() {
	let f = bring_up().await;
	let admin = admin_client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);
	let repo_id = create_repo(&admin, ReportingSetup::Manual).await;

	let req = SetRepoGithubReportingRequest {
		protocol_version: PROTOCOL_VERSION,
		target_owner: "acme".into(),
		target_repo: "tracker".into(),
		github_pat: None,
	};
	let resp = admin
		.put(format!("https://loupe-server/v1/repos/{repo_id}/reporting/github"))
		.json(&req)
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 400);
	assert!(resp.text().await.unwrap().contains("no GitHub App configured"));
	assert_eq!(repo_reporting(&f.db, repo_id), ReportingDestination::Manual);

	f.handle.shutdown().await;
}

#[tokio::test]
async fn app_mode_destinations_honor_the_owner_allowlist() {
	let f = bring_up_with_allowed_owners(&["Acme", "acme-labs"]).await;
	store_github_app(&f.db);
	let admin = admin_client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);

	// A foreign owner is refused in app mode …
	let req =
		RegisterRepoRequest::new("https://github.com/acme/widget.git", app_mode_setup("evilcorp"));
	let resp = admin.post("https://loupe-server/v1/repos").json(&req).send().await.unwrap();
	assert_eq!(resp.status(), 400);
	let body = resp.text().await.unwrap();
	assert!(body.contains("evilcorp") && body.contains("Acme, acme-labs"), "{body}");

	// … but a PAT-backed destination is the PAT's business, not the list's.
	let repo_id = create_repo(
		&admin,
		ReportingSetup::GithubIssue {
			target_owner: "evilcorp".into(),
			target_repo: "tracker".into(),
			github_pat: Some(loupe_provenance::Secret::new("ghp_scoped".into())),
		},
	)
	.await;
	let resp =
		admin.delete(format!("https://loupe-server/v1/repos/{repo_id}")).send().await.unwrap();
	assert_eq!(resp.status(), 204);

	// A listed owner passes regardless of case.
	let repo_id = create_repo(&admin, app_mode_setup("ACME")).await;
	assert!(matches!(
		repo_reporting(&f.db, repo_id),
		ReportingDestination::GithubIssue { pat_secret_id: None, .. }
	));

	// The same rule applies when switching an existing repo.
	let req = SetRepoGithubReportingRequest {
		protocol_version: PROTOCOL_VERSION,
		target_owner: "evilcorp".into(),
		target_repo: "tracker".into(),
		github_pat: None,
	};
	let resp = admin
		.put(format!("https://loupe-server/v1/repos/{repo_id}/reporting/github"))
		.json(&req)
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 400);

	f.handle.shutdown().await;
}

#[tokio::test]
async fn clearing_the_github_app_is_refused_while_repos_use_it() {
	let f = bring_up().await;
	store_github_app(&f.db);
	let admin = admin_client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);
	let repo_id = create_repo(&admin, app_mode_setup("acme")).await;

	let resp = admin.delete("https://loupe-server/v1/github-app").send().await.unwrap();
	assert_eq!(resp.status(), 409);
	let body = resp.text().await.unwrap();
	assert!(body.contains("1 repo(s) still report through the GitHub App"), "{body}");
	assert!(
		f.db.with_conn(|c| Ok(github_app::get(c)?)).unwrap().is_some(),
		"a refused clear must leave the credential in place"
	);

	// Once the last app-mode repo is gone, clearing works.
	let resp =
		admin.delete(format!("https://loupe-server/v1/repos/{repo_id}")).send().await.unwrap();
	assert_eq!(resp.status(), 204);
	let resp = admin.delete("https://loupe-server/v1/github-app").send().await.unwrap();
	assert_eq!(resp.status(), 204);

	f.handle.shutdown().await;
}
