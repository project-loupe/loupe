//! Compatibility checks between reqwest and the shared TLS identity adapter.
//! Generated credentials are disposable test fixtures.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use loupe_tls::{reqwest_client_config, server_config, Ca};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn legacy_client(cert: &str, key: &str, ca: &str) -> Result<reqwest::Client> {
	let mut combined = cert.to_owned();
	if !combined.ends_with('\n') {
		combined.push('\n');
	}
	combined.push_str(key);
	let identity = reqwest::Identity::from_pem(combined.as_bytes())?;
	let root = reqwest::Certificate::from_pem(ca.as_bytes())?;
	Ok(reqwest::Client::builder()
		.add_root_certificate(root)
		.identity(identity)
		.use_rustls_tls()
		.no_proxy()
		.timeout(Duration::from_secs(5))
		.build()?)
}

fn client(cert: &str, key: &str, ca: &str) -> Result<reqwest::Client> {
	// Both constructors are exercised for every grammar/admission control.
	// Only the shared adapter is dispatched by the real handshake tests below.
	let previous = legacy_client(cert, key, ca);
	let candidate = reqwest_client_config(cert, key, ca).and_then(|config| {
		Ok(reqwest::Client::builder()
			.use_preconfigured_tls(config)
			.no_proxy()
			.timeout(Duration::from_secs(5))
			.build()?)
	});
	assert_eq!(candidate.is_ok(), previous.is_ok(), "identity/root admission changed");
	candidate
}

#[test]
fn identity_selects_last_key_and_requires_certificate_and_key() {
	let ca = Ca::new("throwaway-reqwest-key-order-ca").unwrap();
	let matching = ca.mint_client("matching").unwrap();
	let other = ca.mint_client("other").unwrap();
	let matching_last = format!("{}{}", other.key_pem.expose(), matching.key_pem.expose());
	let other_last = format!("{}{}", matching.key_pem.expose(), other.key_pem.expose());
	assert!(client(&matching.cert_pem, &matching_last, ca.cert_pem()).is_ok());
	assert!(client(&matching.cert_pem, &other_last, ca.cert_pem()).is_err());
	assert!(client("", matching.key_pem.expose(), ca.cert_pem()).is_err());
	assert!(client(&matching.cert_pem, "", ca.cert_pem()).is_err());
}

#[test]
fn identity_preserves_sections_and_missing_newline_semantics() {
	let ca = Ca::new("throwaway-reqwest-sections-ca").unwrap();
	let bundle = ca.mint_client("client").unwrap();
	let unknown = "-----BEGIN UNKNOWN-----\nAQID\n-----END UNKNOWN-----\n";
	let public_key = "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n";
	assert!(client(
		&format!("{unknown}{}", bundle.cert_pem),
		bundle.key_pem.expose(),
		ca.cert_pem()
	)
	.is_ok());
	assert!(client(
		&format!("{public_key}{}", bundle.cert_pem),
		bundle.key_pem.expose(),
		ca.cert_pem()
	)
	.is_err());
	assert!(client(
		bundle.cert_pem.trim_end_matches(['\r', '\n']),
		bundle.key_pem.expose(),
		ca.cert_pem()
	)
	.is_ok());
	assert!(client(&bundle.cert_pem, "-----BEGIN PRIVATE KEY malformed\n", ca.cert_pem()).is_err());
}

#[test]
fn roots_preserve_empty_unknown_malformed_and_bundle_admission() {
	let ca = Ca::new("throwaway-reqwest-roots-ca").unwrap();
	let other = Ca::new("throwaway-reqwest-other-ca").unwrap();
	let bundle = ca.mint_client("client").unwrap();
	for roots in ["", "not a PEM block", "-----BEGIN UNKNOWN-----\nAQID\n-----END UNKNOWN-----\n"] {
		assert!(client(&bundle.cert_pem, bundle.key_pem.expose(), roots).is_ok());
	}
	for roots in [
		"-----BEGIN CERTIFICATE malformed\n",
		"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
	] {
		assert!(client(&bundle.cert_pem, bundle.key_pem.expose(), roots).is_err());
	}
	let roots = format!("{}{}", ca.cert_pem(), other.cert_pem());
	assert!(client(&bundle.cert_pem, bundle.key_pem.expose(), &roots).is_ok());
}

#[test]
fn mixed_root_bundles_preserve_legacy_admission_at_all_positions() {
	let first = Ca::new("throwaway-mixed-root-first").unwrap();
	let second = Ca::new("throwaway-mixed-root-second").unwrap();
	let identity = first.mint_client("client").unwrap();
	for extra in [
		include_str!("fixtures/throwaway-rsa-pkcs1.pem"),
		include_str!("fixtures/throwaway-rsa-pkcs8.pem"),
		include_str!("fixtures/throwaway-ec-sec1.pem"),
		"-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n",
		"-----BEGIN UNKNOWN-----\nAQID\n-----END UNKNOWN-----\n",
	] {
		for roots in [
			format!("{extra}{}{}", first.cert_pem(), second.cert_pem()),
			format!("{}{extra}{}", first.cert_pem(), second.cert_pem()),
			format!("{}{}{extra}", first.cert_pem(), second.cert_pem()),
			extra.to_owned(),
		] {
			assert!(client(&identity.cert_pem, identity.key_pem.expose(), &roots).is_ok());
		}
	}
}

#[derive(Debug)]
struct Peer {
	alpn: Option<Vec<u8>>,
	chain: Vec<Vec<u8>>,
	version: Option<rustls::ProtocolVersion>,
}

async fn exchange(
	client: reqwest::Client, mut server: rustls::ServerConfig,
) -> (Result<Vec<u8>>, Option<Peer>) {
	server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let port = listener.local_addr().unwrap().port();
	let task = tokio::spawn(async move {
		let (socket, _) = listener.accept().await.unwrap();
		let Ok(mut tls) = TlsAcceptor::from(Arc::new(server)).accept(socket).await else {
			return None;
		};
		let peer = Peer {
			alpn: tls.get_ref().1.alpn_protocol().map(ToOwned::to_owned),
			version: tls.get_ref().1.protocol_version(),
			chain: tls
				.get_ref()
				.1
				.peer_certificates()
				.unwrap_or_default()
				.iter()
				.map(|cert| cert.to_vec())
				.collect(),
		};
		let mut request = Vec::new();
		while !request.ends_with(b"\r\n\r\n") {
			let mut byte = [0u8; 1];
			if tls.read_exact(&mut byte).await.is_err() || request.len() == 16 * 1024 {
				return None;
			}
			request.push(byte[0]);
		}
		tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			.await
			.unwrap();
		let _ = tls.shutdown().await;
		Some(peer)
	});
	let result = async {
		let response = client.get(format!("https://localhost:{port}/")).send().await?;
		assert_eq!(response.status(), reqwest::StatusCode::OK);
		Ok(response.bytes().await?.to_vec())
	}
	.await;
	let peer = tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
	(result, peer)
}

#[tokio::test]
async fn reqwest_mtls_preserves_http11_and_certificate_chain_order() {
	let ca = Ca::new("throwaway-reqwest-handshake-ca").unwrap();
	let server = ca.mint_server("server", &["localhost".into()]).unwrap();
	let leaf = ca.mint_client("client").unwrap();
	let chain = format!("{}{}", leaf.cert_pem, ca.cert_pem());
	let expected: Vec<_> =
		rustls_pemfile::certs(&mut chain.as_bytes()).map(|cert| cert.unwrap().to_vec()).collect();
	let client = client(&chain, leaf.key_pem.expose(), ca.cert_pem()).unwrap();
	let server = server_config(&server.cert_pem, server.key_pem.expose(), ca.cert_pem()).unwrap();
	let (response, peer) = exchange(client, server).await;
	assert_eq!(response.unwrap(), b"ok");
	let peer = peer.unwrap();
	assert_eq!(peer.alpn.as_deref(), Some(&b"http/1.1"[..]));
	assert_eq!(peer.chain, expected);
}

#[tokio::test]
async fn reqwest_rejects_wrong_server_ca_and_hostname() {
	let ca = Ca::new("throwaway-reqwest-server-ca").unwrap();
	let foreign = Ca::new("throwaway-reqwest-foreign-ca").unwrap();
	let leaf = ca.mint_client("client").unwrap();
	for (hostname, trust) in [("localhost", foreign.cert_pem()), ("wrong-hostname", ca.cert_pem())]
	{
		let server = ca.mint_server("server", &[hostname.into()]).unwrap();
		let client = client(&leaf.cert_pem, leaf.key_pem.expose(), trust).unwrap();
		let server =
			server_config(&server.cert_pem, server.key_pem.expose(), ca.cert_pem()).unwrap();
		let (response, _) = exchange(client, server).await;
		assert!(response.is_err(), "untrusted CA or wrong hostname must fail");
	}
}

#[tokio::test]
async fn reqwest_preserves_tls12_and_tls13() {
	let ca = Ca::new("throwaway-protocol-ca").unwrap();
	let server = ca.mint_server("server", &["localhost".into()]).unwrap();
	let leaf = ca.mint_client("client").unwrap();
	for (version, expected) in [
		(&rustls::version::TLS12, rustls::ProtocolVersion::TLSv1_2),
		(&rustls::version::TLS13, rustls::ProtocolVersion::TLSv1_3),
	] {
		let client = client(&leaf.cert_pem, leaf.key_pem.expose(), ca.cert_pem()).unwrap();
		// A test-only restricted peer proves both protocol versions are enabled
		// by the shared adapter; no custom certificate verifier is involved.
		let mut roots = rustls::RootCertStore::empty();
		for cert in rustls_pemfile::certs(&mut ca.cert_pem().as_bytes()) {
			roots.add(cert.unwrap()).unwrap();
		}
		let provider = Arc::new(rustls::crypto::ring::default_provider());
		let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
			Arc::new(roots),
			provider.clone(),
		)
		.build()
		.unwrap();
		let certs = rustls_pemfile::certs(&mut server.cert_pem.as_bytes())
			.collect::<std::result::Result<Vec<_>, _>>()
			.unwrap();
		let key =
			rustls_pemfile::private_key(&mut server.key_pem.expose().as_bytes()).unwrap().unwrap();
		let config = rustls::ServerConfig::builder_with_provider(provider)
			.with_protocol_versions(&[version])
			.unwrap()
			.with_client_cert_verifier(verifier)
			.with_single_cert(certs, key)
			.unwrap();
		let (response, peer) = exchange(client, config).await;
		assert_eq!(response.unwrap(), b"ok");
		assert_eq!(peer.unwrap().version, Some(expected));
	}
}

fn expired_cert(ca: &Ca, server: bool) -> (String, String) {
	let ca_key = rcgen::KeyPair::from_pem(ca.key_pem().expose()).unwrap();
	let ca_cert = rcgen::CertificateParams::from_ca_cert_pem(ca.cert_pem())
		.unwrap()
		.self_signed(&ca_key)
		.unwrap();
	let key = rcgen::KeyPair::generate().unwrap();
	let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
	params.not_before = rcgen::date_time_ymd(2000, 1, 1);
	params.not_after = rcgen::date_time_ymd(2001, 1, 1);
	params.extended_key_usages = vec![if server {
		rcgen::ExtendedKeyUsagePurpose::ServerAuth
	} else {
		rcgen::ExtendedKeyUsagePurpose::ClientAuth
	}];
	let cert = params.signed_by(&key, &ca_cert, &ca_key).unwrap();
	(cert.pem(), key.serialize_pem())
}

#[tokio::test]
async fn reqwest_rejects_missing_client_identity_and_expired_certificates() {
	let ca = Ca::new("throwaway-expiry-ca").unwrap();
	let server = ca.mint_server("server", &["localhost".into()]).unwrap();
	let leaf = ca.mint_client("client").unwrap();
	let anonymous = reqwest::Client::builder()
		.add_root_certificate(reqwest::Certificate::from_pem(ca.cert_pem().as_bytes()).unwrap())
		.use_rustls_tls()
		.no_proxy()
		.timeout(Duration::from_secs(5))
		.build()
		.unwrap();
	let config = server_config(&server.cert_pem, server.key_pem.expose(), ca.cert_pem()).unwrap();
	assert!(exchange(anonymous, config).await.0.is_err(), "client identity is mandatory");
	let (expired_server, expired_server_key) = expired_cert(&ca, true);
	let client = client(&leaf.cert_pem, leaf.key_pem.expose(), ca.cert_pem()).unwrap();
	let config = server_config(&expired_server, &expired_server_key, ca.cert_pem()).unwrap();
	assert!(exchange(client, config).await.0.is_err(), "expired server must fail verification");
	let (expired_client, expired_client_key) = expired_cert(&ca, false);
	let client = self::client(&expired_client, &expired_client_key, ca.cert_pem()).unwrap();
	let config = server_config(&server.cert_pem, server.key_pem.expose(), ca.cert_pem()).unwrap();
	assert!(exchange(client, config).await.0.is_err(), "expired client must fail verification");
}
