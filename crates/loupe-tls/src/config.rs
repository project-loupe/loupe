use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::provider::ensure_provider_installed;

/// Build a server-side mTLS config that requires the client to present a
/// cert chained back to `ca_pem_for_client_verification`.
pub fn server_config(
	server_cert_pem: &str, server_key_pem: &str, ca_pem_for_client_verification: &str,
) -> Result<ServerConfig> {
	ensure_provider_installed();

	let cert_chain = parse_certs(server_cert_pem).context("parsing server cert PEM")?;
	let private_key = parse_key(server_key_pem).context("parsing server key PEM")?;

	let mut roots = RootCertStore::empty();
	for cert in parse_certs(ca_pem_for_client_verification).context("parsing client-auth CA PEM")? {
		roots.add(cert).context("adding CA to client-verify root store")?;
	}
	let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
		.build()
		.context("building client verifier")?;

	let config = ServerConfig::builder()
		.with_client_cert_verifier(verifier)
		.with_single_cert(cert_chain, private_key)
		.context("building server config")?;
	Ok(config)
}

/// Build a client-side mTLS config that trusts a server cert chained back
/// to `ca_pem_for_server_verification` and presents `client_cert_pem`
/// + `client_key_pem` for client auth.
pub fn client_config(
	client_cert_pem: &str, client_key_pem: &str, ca_pem_for_server_verification: &str,
) -> Result<ClientConfig> {
	ensure_provider_installed();

	let cert_chain = parse_certs(client_cert_pem).context("parsing client cert PEM")?;
	let private_key = parse_key(client_key_pem).context("parsing client key PEM")?;

	let mut roots = RootCertStore::empty();
	for cert in parse_certs(ca_pem_for_server_verification).context("parsing server-auth CA PEM")? {
		roots.add(cert).context("adding CA to server-verify root store")?;
	}

	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_client_auth_cert(cert_chain, private_key)
		.context("building client config")?;
	Ok(config)
}

fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
	let mut reader = pem.as_bytes();
	let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
	let certs = certs.context("rustls-pemfile cert parsing failed")?;
	anyhow::ensure!(!certs.is_empty(), "no CERTIFICATE blocks found in PEM input");
	Ok(certs)
}

fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
	let mut reader = pem.as_bytes();
	let key = rustls_pemfile::private_key(&mut reader)
		.context("rustls-pemfile key parsing failed")?
		.context("no PRIVATE KEY block found in PEM input")?;
	Ok(key)
}
