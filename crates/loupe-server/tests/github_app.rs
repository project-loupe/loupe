//! End-to-end test for the GitHub App credential routes. A tiny axum
//! stub plays GitHub's `GET /app` so the server can verify a key before
//! storing it; the fixture key from `reporters::github_app::testing`
//! stands in for one downloaded from a real app.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use common::wire::{
	GithubAppResponse, RegisterWorkerRequest, RegisterWorkerResponse, SetGithubAppRequest,
	PROTOCOL_VERSION,
};
use loupe_server::init::run_init;
use loupe_server::reporters::github_app::testing::APP_PRIVATE_KEY_PEM;
use loupe_server::reporters::GithubReporter;
use loupe_server::{serve, AppState, Config};
use loupe_storage::Db;
use loupe_tls::Ca;

mod common;
use common::{pem_to_certificate, pem_to_identity};

#[derive(Clone)]
struct AppStub {
	app_id: Arc<Mutex<u64>>,
	calls: Arc<Mutex<Vec<String>>>,
}

async fn stub_get_app(
	State(stub): State<AppStub>, headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
	let auth = headers
		.get(axum::http::header::AUTHORIZATION)
		.and_then(|v| v.to_str().ok())
		.unwrap_or("")
		.to_owned();
	stub.calls.lock().unwrap().push(auth);
	let id = *stub.app_id.lock().unwrap();
	(StatusCode::OK, Json(serde_json::json!({"id": id, "slug": "loupe-reporter"})))
}

async fn spawn_app_stub(app_id: u64) -> (SocketAddr, AppStub) {
	let stub =
		AppStub { app_id: Arc::new(Mutex::new(app_id)), calls: Arc::new(Mutex::new(vec![])) };
	let app = Router::new().route("/app", get(stub_get_app)).with_state(stub.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	(addr, stub)
}

struct Fixture {
	handle: loupe_server::ServeHandle,
	admin: reqwest::Client,
	ca_cert_pem: String,
	db_path: std::path::PathBuf,
	stub: AppStub,
}

impl Fixture {
	/// Mint a worker certificate through the admin API and return a
	/// client that authenticates with it.
	async fn worker_client(&self) -> reqwest::Client {
		let resp = self
			.admin
			.post("https://loupe-server/v1/workers")
			.json(&RegisterWorkerRequest { protocol_version: PROTOCOL_VERSION, name: "w1".into() })
			.send()
			.await
			.unwrap();
		assert_eq!(resp.status(), 201);
		let bundle: RegisterWorkerResponse = resp.json().await.unwrap();
		reqwest::Client::builder()
			.add_root_certificate(pem_to_certificate(&self.ca_cert_pem))
			.identity(pem_to_identity(&bundle.client_cert_pem, bundle.client_key_pem.expose()))
			.resolve("loupe-server", self.handle.local_addr)
			.use_rustls_tls()
			.build()
			.unwrap()
	}
}

async fn bring_up(stub_app_id: u64) -> Fixture {
	let (stub_addr, stub) = spawn_app_stub(stub_app_id).await;
	let tmp = tempfile::tempdir().unwrap();
	let init = run_init(
		&common::config_path(tmp.path()),
		&[common::config_hostname("loupe-server")],
		None,
	)
	.unwrap();
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
		ca_cert_pem: common::config_pem(&ca_cert_pem),
		ca_key_pem: init.layout.ca_key.read_tls_pem().unwrap(),
	};
	let db = Arc::new(Db::open(init.layout.db_path.as_path(), &init.master_key).unwrap());
	let reporter = Arc::new(GithubReporter::with_base(&format!("http://{stub_addr}")).unwrap());
	let state = AppState::new(db, Arc::new(ca), reporter);
	let handle = serve(cfg, state).await.unwrap();
	let admin = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&ca_cert_pem))
		.identity(pem_to_identity(&init.admin_bundle.cert_pem, init.admin_bundle.key_pem.expose()))
		.resolve("loupe-server", handle.local_addr)
		.use_rustls_tls()
		.build()
		.unwrap();
	let db_path = init.layout.db_path.as_path().to_path_buf();
	std::mem::forget(tmp);
	Fixture { handle, admin, ca_cert_pem, db_path, stub }
}

async fn put_app(admin: &reqwest::Client, app_id: u64, pem: &str) -> reqwest::Response {
	admin
		.put("https://loupe-server/v1/github-app")
		.json(&SetGithubAppRequest {
			protocol_version: PROTOCOL_VERSION,
			app_id,
			private_key_pem: loupe_provenance::Secret::new(pem.to_owned()),
		})
		.send()
		.await
		.unwrap()
}

async fn get_app(admin: &reqwest::Client) -> GithubAppResponse {
	let resp = admin.get("https://loupe-server/v1/github-app").send().await.unwrap();
	assert_eq!(resp.status(), 200);
	resp.json().await.unwrap()
}

#[tokio::test]
async fn stores_a_verified_app_credential_and_reports_it_without_the_key() {
	let f = bring_up(42).await;
	assert_eq!(get_app(&f.admin).await.app, None, "fresh server has no app");

	let resp = put_app(&f.admin, 42, APP_PRIVATE_KEY_PEM).await;
	assert_eq!(resp.status(), 204, "{}", resp.text().await.unwrap_or_default());

	let calls = f.stub.calls.lock().unwrap().clone();
	assert_eq!(calls.len(), 1, "server must verify the key against GET /app once");
	let jwt = calls[0].strip_prefix("Bearer ").expect("bearer auth on GET /app");
	assert_eq!(jwt.split('.').count(), 3, "GET /app must carry the app JWT: {jwt}");

	let body = get_app(&f.admin).await;
	let app = body.app.expect("app configured");
	assert_eq!(app.app_id, 42);
	assert_eq!(app.slug, "loupe-reporter");
	let raw_body = f
		.admin
		.get("https://loupe-server/v1/github-app")
		.send()
		.await
		.unwrap()
		.text()
		.await
		.unwrap();
	assert!(!raw_body.contains("PRIVATE KEY"), "response must not leak the key: {raw_body}");

	let raw = std::fs::read(&f.db_path).unwrap();
	let needle = b"BEGIN RSA PRIVATE KEY";
	assert!(
		!raw.windows(needle.len()).any(|w| w == needle),
		"plaintext PEM must not survive in the encrypted db file"
	);

	f.handle.shutdown().await;
}

#[tokio::test]
async fn rejects_an_unparseable_key_without_calling_github() {
	let f = bring_up(42).await;
	let resp = put_app(
		&f.admin,
		42,
		"-----BEGIN RSA PRIVATE KEY-----\nnope\n-----END RSA PRIVATE KEY-----\n",
	)
	.await;
	assert_eq!(resp.status(), 400);
	let body = resp.text().await.unwrap();
	assert!(body.contains("invalid GitHub App private key"), "body: {body}");
	assert!(f.stub.calls.lock().unwrap().is_empty(), "no GitHub call for a bad key");
	assert_eq!(get_app(&f.admin).await.app, None);

	let resp = put_app(&f.admin, 0, APP_PRIVATE_KEY_PEM).await;
	assert_eq!(resp.status(), 400);
	assert!(f.stub.calls.lock().unwrap().is_empty());

	f.handle.shutdown().await;
}

#[tokio::test]
async fn rejects_a_key_that_belongs_to_a_different_app() {
	let f = bring_up(7).await;
	let resp = put_app(&f.admin, 42, APP_PRIVATE_KEY_PEM).await;
	assert_eq!(resp.status(), 400);
	let body = resp.text().await.unwrap();
	assert!(body.contains("belongs to GitHub App 7"), "body: {body}");
	assert_eq!(get_app(&f.admin).await.app, None, "mismatched credential must not be stored");

	f.handle.shutdown().await;
}

#[tokio::test]
async fn clear_removes_the_credential_and_is_not_idempotent() {
	let f = bring_up(42).await;
	assert_eq!(put_app(&f.admin, 42, APP_PRIVATE_KEY_PEM).await.status(), 204);

	let resp = f.admin.delete("https://loupe-server/v1/github-app").send().await.unwrap();
	assert_eq!(resp.status(), 204);
	assert_eq!(get_app(&f.admin).await.app, None);

	let resp = f.admin.delete("https://loupe-server/v1/github-app").send().await.unwrap();
	assert_eq!(resp.status(), 404);

	f.handle.shutdown().await;
}

/// The credential routes sit behind `require_admin`: a worker
/// certificate authenticates but must not read, replace, or clear the
/// app key.
#[tokio::test]
async fn worker_certificates_cannot_touch_the_github_app() {
	let f = bring_up(42).await;
	assert_eq!(put_app(&f.admin, 42, APP_PRIVATE_KEY_PEM).await.status(), 204);
	let worker = f.worker_client().await;

	let resp = worker.get("https://loupe-server/v1/github-app").send().await.unwrap();
	assert_eq!(resp.status(), 403, "worker GET");

	let resp = worker
		.put("https://loupe-server/v1/github-app")
		.json(&SetGithubAppRequest {
			protocol_version: PROTOCOL_VERSION,
			app_id: 42,
			private_key_pem: loupe_provenance::Secret::new(APP_PRIVATE_KEY_PEM.into()),
		})
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 403, "worker PUT");

	let resp = worker.delete("https://loupe-server/v1/github-app").send().await.unwrap();
	assert_eq!(resp.status(), 403, "worker DELETE");

	// Nothing changed: the admin still sees the app, and GitHub was only
	// consulted once, for the admin's PUT.
	assert_eq!(get_app(&f.admin).await.app.map(|a| a.app_id), Some(42));
	assert_eq!(f.stub.calls.lock().unwrap().len(), 1);

	f.handle.shutdown().await;
}
