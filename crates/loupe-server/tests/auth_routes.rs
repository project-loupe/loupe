//! Exercises the auth middleware and admin-only routes end-to-end:
//! registers an admin via init, verifies /v1/whoami resolves correctly,
//! mints a worker over /v1/workers, confirms the new worker can hit
//! /v1/whoami, revokes it, and confirms revocation breaks subsequent
//! mTLS calls.

use std::net::SocketAddr;
use std::sync::Arc;

use common::wire::{RegisterWorkerRequest, PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use loupe_server::init::run_init;
use loupe_server::{serve, AppState, Config};
use loupe_storage::Db;
use loupe_tls::Ca;

mod common;
use common::{pem_to_certificate, pem_to_identity};
use loupe_proto::RegisterWorkerResponse;

fn client(ca_cert_pem: &str, cert_pem: &str, key_pem: &str, addr: SocketAddr) -> reqwest::Client {
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
}

async fn bring_up() -> Fixture {
	bring_up_with_mixed_ca(false).await
}

async fn bring_up_with_mixed_ca(mixed: bool) -> Fixture {
	let tmp = tempfile::tempdir().unwrap();
	let init = run_init(
		&common::config_path(tmp.path()),
		&[common::config_hostname("loupe-server")],
		None,
	)
	.unwrap();

	let mut ca_input = std::fs::read_to_string(init.layout.ca_cert.as_path()).unwrap();
	if mixed {
		ca_input.push_str(init.ca_key_pem.expose());
	}
	let ca =
		Ca::from_pem(&ca_input, &std::fs::read_to_string(init.layout.ca_key.as_path()).unwrap())
			.unwrap();

	let server_cert_pem = std::fs::read_to_string(init.layout.server_cert.as_path()).unwrap();
	let server_key_pem = std::fs::read_to_string(init.layout.server_key.as_path()).unwrap();
	let ca_cert_pem = ca_input;
	let ca_key_pem = std::fs::read_to_string(init.layout.ca_key.as_path()).unwrap();
	let admin_cert_pem = init.admin_bundle.cert_pem.clone();
	let admin_key_pem = init.admin_bundle.key_pem.expose().to_owned();

	let cfg = Config {
		bind_addr: "127.0.0.1:0".parse().unwrap(),
		db_path: init.layout.db_path.clone(),
		server_cert_pem: common::config_pem(&server_cert_pem),
		server_key_pem: common::config_pem(&server_key_pem),
		ca_cert_pem: common::config_pem(&ca_cert_pem),
		ca_key_pem: common::config_pem(&ca_key_pem),
	};
	let db = Arc::new(Db::open(init.layout.db_path.as_path(), &init.master_key).unwrap());
	let state = AppState::new(
		db,
		Arc::new(ca),
		Arc::new(loupe_server::reporters::GithubReporter::new().unwrap()),
	);
	let handle = serve(cfg, state).await.unwrap();
	let addr = handle.local_addr;

	std::mem::forget(tmp); // keep the dir alive across the test; it's in tmpfs anyway

	Fixture { handle, addr, ca_cert_pem, admin_cert_pem, admin_key_pem }
}

#[tokio::test]
async fn registration_http_preserves_mixed_ca_export_and_guarded_dto() {
	let f = bring_up_with_mixed_ca(true).await;
	assert!(f.ca_cert_pem.contains("BEGIN PRIVATE KEY"));
	let admin = client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);
	let response = admin
		.post("https://loupe-server/v1/workers")
		.json(&RegisterWorkerRequest {
			protocol_version: PROTOCOL_VERSION,
			name: "mixed-ca-worker".into(),
		})
		.send()
		.await
		.unwrap();
	assert_eq!(response.status(), 201);
	assert_eq!(response.headers()["content-type"], "application/json");
	assert_eq!(response.headers()[PROTOCOL_VERSION_HEADER], PROTOCOL_VERSION.to_string());
	let bundle: RegisterWorkerResponse = response.json().await.unwrap();
	assert_eq!(bundle.ca_cert_pem.expose(), &f.ca_cert_pem);
	assert_eq!(bundle.protocol_version, PROTOCOL_VERSION);
	assert!(bundle.worker_id > 0);
	assert_eq!(format!("{:?}", bundle.client_key_pem), "[redacted]");
	assert_eq!(format!("{:?}", bundle.ca_cert_pem), "[redacted]");
	let encoded = bundle.credential_json_pretty().unwrap();
	let back: RegisterWorkerResponse = serde_json::from_slice(encoded.expose()).unwrap();
	assert_eq!(back.client_key_pem.expose(), bundle.client_key_pem.expose());
	assert_eq!(back.client_cert_pem, bundle.client_cert_pem);
	assert_eq!(back.ca_cert_pem.expose(), bundle.ca_cert_pem.expose());
	assert_eq!(back.worker_id, bundle.worker_id);
	let worker = client(
		bundle.ca_cert_pem.expose(),
		&bundle.client_cert_pem,
		bundle.client_key_pem.expose(),
		f.addr,
	);
	let response = worker.get("https://loupe-server/v1/whoami").send().await.unwrap();
	assert!(response.status().is_success());
	let body: serde_json::Value = response.json().await.unwrap();
	assert_eq!(body["kind"], "worker");
	assert_eq!(body["name"], "mixed-ca-worker");
	f.handle.shutdown().await;
}

#[tokio::test]
async fn whoami_resolves_admin_role() {
	let f = bring_up().await;
	let c = client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);
	let resp = c.get("https://loupe-server/v1/whoami").send().await.unwrap();
	assert!(resp.status().is_success(), "whoami returned {}", resp.status());
	let expected_protocol = PROTOCOL_VERSION.to_string();
	assert_eq!(
		resp.headers().get(PROTOCOL_VERSION_HEADER).and_then(|v| v.to_str().ok()),
		Some(expected_protocol.as_str())
	);
	let body: serde_json::Value = resp.json().await.unwrap();
	assert_eq!(body["kind"], "admin");
	assert_eq!(body["name"], "admin");

	f.handle.shutdown().await;
}

#[tokio::test]
async fn admin_mints_worker_then_revokes_it() {
	let f = bring_up().await;
	let admin = client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);

	// Mint a worker.
	let req = RegisterWorkerRequest { protocol_version: PROTOCOL_VERSION, name: "w1".into() };
	let resp = admin.post("https://loupe-server/v1/workers").json(&req).send().await.unwrap();
	assert_eq!(resp.status(), 201, "register worker: {}", resp.status());
	assert_eq!(resp.headers()["content-type"], "application/json");
	assert_eq!(resp.headers()[PROTOCOL_VERSION_HEADER], PROTOCOL_VERSION.to_string());
	let bundle: RegisterWorkerResponse = resp.json().await.unwrap();
	assert!(bundle.worker_id > 0);
	assert!(bundle.client_cert_pem.contains("BEGIN CERTIFICATE"));

	// New worker can hit /v1/whoami and resolves as kind=worker.
	let worker =
		client(&f.ca_cert_pem, &bundle.client_cert_pem, bundle.client_key_pem.expose(), f.addr);
	let resp = worker.get("https://loupe-server/v1/whoami").send().await.unwrap();
	assert!(resp.status().is_success());
	let body: serde_json::Value = resp.json().await.unwrap();
	assert_eq!(body["kind"], "worker");
	assert_eq!(body["name"], "w1");

	// Worker cannot hit admin-only routes.
	let denied = worker
		.post("https://loupe-server/v1/workers")
		.json(&RegisterWorkerRequest { protocol_version: PROTOCOL_VERSION, name: "w2".into() })
		.send()
		.await
		.unwrap();
	assert_eq!(denied.status(), 403, "worker must be forbidden from admin route");

	// Admin revokes.
	let resp = admin
		.delete(format!("https://loupe-server/v1/workers/{}", bundle.worker_id))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 204);

	// Revoked worker no longer authenticates.
	let resp = worker.get("https://loupe-server/v1/whoami").send().await.unwrap();
	assert_eq!(resp.status(), 401, "revoked worker must 401");

	f.handle.shutdown().await;
}

#[tokio::test]
async fn unknown_client_cert_is_rejected_at_auth() {
	let f = bring_up().await;
	// Mint a cert that the server's CA didn't sign — but use the right CA
	// for server verification, so the client trusts the server's identity
	// and the request actually reaches the auth middleware.
	let foreign_ca = Ca::new("foreign").unwrap();
	let foreign = foreign_ca.mint_client("intruder").unwrap();

	let intruder = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&f.ca_cert_pem))
		.identity(pem_to_identity(&foreign.cert_pem, foreign.key_pem.expose()))
		.resolve("loupe-server", f.addr)
		.use_rustls_tls()
		.build()
		.unwrap();

	// Server's client-cert verifier should reject at the TLS handshake;
	// reqwest surfaces this as an error rather than a status code.
	let result = intruder.get("https://loupe-server/v1/whoami").send().await;
	assert!(result.is_err(), "foreign cert must not handshake; got {result:?}");

	f.handle.shutdown().await;
}
