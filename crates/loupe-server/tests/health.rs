//! Spin up loupe-server with a freshly minted CA + server cert and make
//! a real mTLS request to `/v1/health` from a reqwest client carrying a
//! minted client cert.

use std::net::SocketAddr;
use std::sync::Arc;

use loupe_proto::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use loupe_server::{serve, AppState, Config};
use loupe_storage::secrets::MasterKey;
use loupe_storage::Db;
use loupe_tls::Ca;
use reqwest::tls::CertificateRevocationList;

mod common;
use common::{pem_to_certificate, pem_to_identity};

async fn bring_up() -> (loupe_server::ServeHandle, reqwest::Client, SocketAddr) {
	let ca = Ca::new("loupe-test-ca").unwrap();
	let server_cert = ca.mint_server("loupe-server", &["loupe-server".into()]).unwrap();
	let client_cert = ca.mint_client("admin").unwrap();
	let ca_cert_pem = ca.cert_pem().to_owned();
	let ca_key_pem = ca.key_pem().to_owned();

	let cfg = Config {
		bind_addr: "127.0.0.1:0".parse().unwrap(),
		db_path: ":memory:".into(),
		server_cert_pem: server_cert.cert_pem,
		server_key_pem: server_cert.key_pem,
		ca_cert_pem: ca_cert_pem.clone(),
		ca_key_pem,
	};
	let db = Arc::new(Db::open_in_memory(&MasterKey::for_tests()).unwrap());
	let state = AppState::new(
		db,
		Arc::new(ca),
		Arc::new(loupe_server::reporters::GithubReporter::new().unwrap()),
	);
	let handle = serve(cfg, state).await.unwrap();
	let local = handle.local_addr;

	let _ = CertificateRevocationList::from_pem; // just makes sure tls feature flags compile

	let client = reqwest::Client::builder()
		.add_root_certificate(pem_to_certificate(&ca_cert_pem))
		.identity(pem_to_identity(&client_cert.cert_pem, &client_cert.key_pem))
		.resolve("loupe-server", local)
		.use_rustls_tls()
		.build()
		.unwrap();
	(handle, client, local)
}

#[tokio::test]
async fn health_endpoint_returns_protocol_version() {
	let (handle, client, _addr) = bring_up().await;
	let resp =
		client.get("https://loupe-server/v1/health").send().await.expect("request to /v1/health");
	assert!(resp.status().is_success(), "got {}", resp.status());
	assert_eq!(resp.headers().get("x-loupe-protocol").and_then(|v| v.to_str().ok()), Some("1"));

	let body: serde_json::Value = resp.json().await.unwrap();
	assert_eq!(body["status"], "ok");
	assert_eq!(body["protocol_version"], 1);

	handle.shutdown().await;
}

#[tokio::test]
async fn server_rejects_unsupported_protocol_header() {
	let (handle, client, _addr) = bring_up().await;
	let resp = client
		.get("https://loupe-server/v1/health")
		.header(PROTOCOL_VERSION_HEADER, (PROTOCOL_VERSION + 1).to_string())
		.send()
		.await
		.expect("request to /v1/health");
	assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
	assert_eq!(
		resp.headers().get(PROTOCOL_VERSION_HEADER).and_then(|v| v.to_str().ok()),
		Some("1")
	);
	let body = resp.text().await.unwrap();
	assert!(body.contains("unsupported"), "got: {body}");

	handle.shutdown().await;
}

#[tokio::test]
async fn server_rejects_client_with_foreign_cert() {
	let (handle, _, addr) = bring_up().await;

	// Fresh CA the server doesn't trust.
	let foreign_ca = Ca::new("foreign-ca").unwrap();
	let foreign_cert = foreign_ca.mint_client("intruder").unwrap();
	let server_ca = handle.local_addr; // re-using bring_up's CA isn't exposed; just use foreign CA both ways
	let _ = server_ca;

	let intruder = reqwest::Client::builder()
		.danger_accept_invalid_certs(true) // skip server-cert verification — we only care about *our* identity being rejected
		.identity(pem_to_identity(&foreign_cert.cert_pem, &foreign_cert.key_pem))
		.resolve("loupe-server", addr)
		.use_rustls_tls()
		.build()
		.unwrap();

	let result = intruder.get("https://loupe-server/v1/health").send().await;
	assert!(result.is_err(), "foreign cert should not handshake; got {result:?}");
	handle.shutdown().await;
}
