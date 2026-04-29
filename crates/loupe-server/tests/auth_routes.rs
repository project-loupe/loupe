//! Exercises the auth middleware and admin-only routes end-to-end:
//! registers an admin via init, verifies /v1/whoami resolves correctly,
//! mints a worker over /v1/workers, confirms the new worker can hit
//! /v1/whoami, revokes it, and confirms revocation breaks subsequent
//! mTLS calls.

use std::net::SocketAddr;
use std::sync::Arc;

use loupe_proto::{
	RegisterWorkerRequest, RegisterWorkerResponse, PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER,
};
use loupe_server::init::run_init;
use loupe_server::{serve, AppState, Config};
use loupe_storage::Db;
use loupe_tls::Ca;

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
	let tmp = tempfile::tempdir().unwrap();
	let init = run_init(tmp.path(), &["loupe-server".to_owned()]).unwrap();

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
	let db = Arc::new(Db::open(&init.layout.db_path).unwrap());
	let state = AppState::new(db, Arc::new(ca));
	let handle = serve(cfg, state).await.unwrap();
	let addr = handle.local_addr;

	std::mem::forget(tmp); // keep the dir alive across the test; it's in tmpfs anyway

	Fixture { handle, addr, ca_cert_pem, admin_cert_pem, admin_key_pem }
}

#[tokio::test]
async fn whoami_resolves_admin_role() {
	let f = bring_up().await;
	let c = client(&f.ca_cert_pem, &f.admin_cert_pem, &f.admin_key_pem, f.addr);
	let resp = c.get("https://loupe-server/v1/whoami").send().await.unwrap();
	assert!(resp.status().is_success(), "whoami returned {}", resp.status());
	assert_eq!(
		resp.headers().get(PROTOCOL_VERSION_HEADER).and_then(|v| v.to_str().ok()),
		Some("1")
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
	let bundle: RegisterWorkerResponse = resp.json().await.unwrap();
	assert!(bundle.worker_id > 0);
	assert!(bundle.client_cert_pem.contains("BEGIN CERTIFICATE"));

	// New worker can hit /v1/whoami and resolves as kind=worker.
	let worker = client(&f.ca_cert_pem, &bundle.client_cert_pem, &bundle.client_key_pem, f.addr);
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
		.identity(pem_to_identity(&foreign.cert_pem, &foreign.key_pem))
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
