//! End-to-end mTLS handshake test: spin up a server bound to localhost,
//! connect with both an authorised client cert and an unauthorised one,
//! and confirm the verifier accepts/rejects accordingly.

use std::sync::Arc;

use loupe_tls::{client_config, server_config, Ca};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const PAYLOAD: &[u8] = b"hello mtls";

async fn spawn_server(server_cfg: rustls::ServerConfig) -> std::net::SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("local_addr");
	let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
	tokio::spawn(async move {
		// Single-shot: accept one connection then exit.
		let (sock, _) = listener.accept().await.expect("accept");
		let mut tls = match acceptor.accept(sock).await {
			Ok(t) => t,
			Err(_) => return,
		};
		let _ = tls.write_all(PAYLOAD).await;
		let _ = tls.shutdown().await;
	});
	addr
}

async fn try_client(
	addr: std::net::SocketAddr, client_cfg: rustls::ClientConfig,
) -> std::io::Result<Vec<u8>> {
	let connector = TlsConnector::from(Arc::new(client_cfg));
	let sock = TcpStream::connect(addr).await?;
	let server_name = ServerName::try_from("loupe-server").unwrap();
	let mut tls = connector.connect(server_name, sock).await?;
	let mut buf = Vec::new();
	tls.read_to_end(&mut buf).await?;
	Ok(buf)
}

#[tokio::test]
async fn authorised_client_handshakes_and_reads_payload() {
	let ca = Ca::new("loupe-test-ca").unwrap();
	let server_cert = ca.mint_server("loupe-server", &["loupe-server".into()]).unwrap();
	let client_cert = ca.mint_client("worker-1").unwrap();

	let server_cfg =
		server_config(&server_cert.cert_pem, &server_cert.key_pem, ca.cert_pem()).unwrap();
	let client_cfg =
		client_config(&client_cert.cert_pem, &client_cert.key_pem, ca.cert_pem()).unwrap();

	let addr = spawn_server(server_cfg).await;
	let payload = try_client(addr, client_cfg).await.expect("handshake should succeed");
	assert_eq!(payload, PAYLOAD);
}

#[tokio::test]
async fn client_with_foreign_ca_is_rejected_by_server() {
	let ca_a = Ca::new("loupe-ca-A").unwrap();
	let ca_b = Ca::new("loupe-ca-B").unwrap();
	let server_cert = ca_a.mint_server("loupe-server", &["loupe-server".into()]).unwrap();
	let foreign_client_cert = ca_b.mint_client("intruder").unwrap(); // signed by the WRONG CA

	let server_cfg =
		server_config(&server_cert.cert_pem, &server_cert.key_pem, ca_a.cert_pem()).unwrap();

	// The client trusts ca_a for the server cert but presents a cert
	// that ca_a never signed.
	let client_cfg =
		client_config(&foreign_client_cert.cert_pem, &foreign_client_cert.key_pem, ca_a.cert_pem())
			.unwrap();

	let addr = spawn_server(server_cfg).await;
	let result = try_client(addr, client_cfg).await;
	assert!(result.is_err(), "handshake should have failed; got: {result:?}");
}
