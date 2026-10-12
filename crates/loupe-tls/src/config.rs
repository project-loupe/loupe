use std::io::Read;
use std::sync::Arc;

use anyhow::{Context, Result};
use loupe_provenance::Secret;
use rustls::pki_types::pem::{self, SectionKind};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{ClientConfig, InconsistentKeys, RootCertStore, ServerConfig};

use crate::provider::ring_provider;
use crate::secret::OwnedDer;

/// Build a server-side mTLS config that requires the client to present a
/// cert chained back to `ca_pem_for_client_verification`.
/// The first private key is used, and ALPN remains unset.
pub fn server_config(
	server_cert_pem: &str, server_key_pem: &str, ca_pem_for_client_verification: &str,
) -> Result<ServerConfig> {
	let cert_chain = parse_certs(server_cert_pem).context("parsing server cert PEM")?;
	let private_key = parse_key(server_key_pem).context("parsing server key PEM")?;
	let identity = load_identity(cert_chain, &private_key).context("building server identity")?;

	let mut roots = RootCertStore::empty();
	for cert in parse_certs(ca_pem_for_client_verification).context("parsing client-auth CA PEM")? {
		roots.add(cert).context("adding CA to client-verify root store")?;
	}
	let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), ring_provider())
		.build()
		.context("building client verifier")?;
	Ok(ServerConfig::builder_with_provider(ring_provider())
		.with_safe_default_protocol_versions()?
		.with_client_cert_verifier(verifier)
		.with_cert_resolver(Arc::new(identity)))
}

/// Build a client-side mTLS config that trusts only the supplied CA and presents
/// the supplied identity. The first private key is used, and ALPN remains unset.
pub fn client_config(
	client_cert_pem: &str, client_key_pem: &str, ca_pem_for_server_verification: &str,
) -> Result<ClientConfig> {
	let cert_chain = parse_certs(client_cert_pem).context("parsing client cert PEM")?;
	let private_key = parse_key(client_key_pem).context("parsing client key PEM")?;
	let identity = load_identity(cert_chain, &private_key).context("building client identity")?;

	let mut roots = RootCertStore::empty();
	for cert in parse_certs(ca_pem_for_server_verification).context("parsing server-auth CA PEM")? {
		roots.add(cert).context("adding CA to server-verify root store")?;
	}
	Ok(ClientConfig::builder_with_provider(ring_provider())
		.with_safe_default_protocol_versions()?
		.with_root_certificates(roots)
		.with_client_cert_resolver(Arc::new(identity)))
}

/// Build the concrete config accepted by reqwest's `use_preconfigured_tls`.
///
/// This preserves the workspace's reqwest identity grammar (last private key,
/// all certificates in order), additive webpki + supplied CA trust, TLS 1.2/1.3,
/// and HTTP/1.1 ALPN. Empty CA input is allowed. Reqwest's pinned feature set
/// excludes HTTP/2; enabling it requires updating this helper's ALPN policy.
/// Hostname and certificate verification, SNI and mandatory identity remain
/// enabled; safe rustls defaults keep early data and key logging disabled.
pub fn reqwest_client_config(
	client_cert_pem: &str, client_key_pem: &str, ca_pem: &str,
) -> Result<ClientConfig> {
	let identity = parse_reqwest_identity(client_cert_pem, client_key_pem)?;
	let mut config = ClientConfig::builder_with_provider(ring_provider())
		.with_safe_default_protocol_versions()?
		.with_root_certificates(reqwest_roots(ca_pem)?)
		.with_client_cert_resolver(Arc::new(identity));
	config.alpn_protocols = vec![b"http/1.1".to_vec()];
	Ok(config)
}

fn reqwest_roots(ca_pem: &str) -> Result<RootCertStore> {
	let mut roots = RootCertStore::empty();
	// Certificate::from_pem in reqwest accepts zero or more certificate blocks.
	for cert in scan_certs(ca_pem).map_err(|_| anyhow::anyhow!("invalid server-auth CA PEM"))? {
		roots.add(cert).context("adding CA to server-verify root store")?;
	}
	roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
	Ok(roots)
}

fn parse_reqwest_identity(cert: &str, key: &str) -> Result<SingleCertAndKey> {
	let newline = if cert.ends_with('\n') { b"".as_slice() } else { b"\n" };
	// Preserve reqwest Identity's logical input without a combined secret PEM
	// allocation. Dependency parser line/base64/error scratch remains outside
	// our guarantee; every returned private DER section is guarded immediately.
	let mut reader = cert.as_bytes().chain(newline).chain(key.as_bytes());
	let mut certs = Vec::new();
	let mut private_key = None;
	while let Some((kind, der)) =
		pem::from_buf(&mut reader).map_err(|_| anyhow::anyhow!("invalid client identity PEM"))?
	{
		match kind {
			SectionKind::Certificate => certs.push(CertificateDer::from(der)),
			SectionKind::PrivateKey => {
				private_key = Some(Secret::new(OwnedDer(PrivateKeyDer::Pkcs8(der.into()))));
			},
			SectionKind::RsaPrivateKey => {
				private_key = Some(Secret::new(OwnedDer(PrivateKeyDer::Pkcs1(der.into()))));
			},
			SectionKind::EcPrivateKey => {
				private_key = Some(Secret::new(OwnedDer(PrivateKeyDer::Sec1(der.into()))));
			},
			_ => anyhow::bail!("unsupported client identity PEM section"),
		}
	}
	let key = private_key.context("client identity requires a private key")?;
	anyhow::ensure!(!certs.is_empty(), "client identity requires a certificate");
	load_identity(certs, &key)
}

fn load_identity(
	certs: Vec<CertificateDer<'static>>, key: &Secret<OwnedDer>,
) -> Result<SingleCertAndKey> {
	// Borrow DER for ring's import, then drop its guard normally on every path.
	// The resulting opaque signer is shared by rustls; its internal allocations
	// cannot honestly be covered by a Loupe Zeroise adapter.
	let signer = rustls::crypto::ring::sign::any_supported_type(&key.expose().0)
		.map_err(|_| anyhow::anyhow!("invalid private signing key"))?;
	let identity = CertifiedKey::new(certs, signer);
	// Match CertifiedKey::from_der exactly; new() alone omits this check.
	match identity.keys_match() {
		Ok(()) | Err(rustls::Error::InconsistentKeys(InconsistentKeys::Unknown)) => {
			Ok(SingleCertAndKey::from(identity))
		},
		Err(_) => anyhow::bail!("certificate and private key do not match"),
	}
}

fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
	let certs = scan_certs(pem)?;
	anyhow::ensure!(!certs.is_empty(), "no CERTIFICATE blocks found in PEM input");
	Ok(certs)
}

fn scan_certs(input: &str) -> Result<Vec<CertificateDer<'static>>> {
	let mut reader = input.as_bytes();
	let mut certs = Vec::new();
	while let Some((kind, der)) =
		pem::from_buf(&mut reader).map_err(|_| anyhow::anyhow!("invalid certificate PEM"))?
	{
		// Certificate/CA bundles ignore non-certificate sections.
		// Completed private sections are controllable DER, even when unused:
		// guard/drop them immediately rather than leaving cleanup to a filter.
		// Dependency decoder scratch and partial-error buffers remain opaque.
		match kind {
			SectionKind::Certificate => certs.push(CertificateDer::from(der)),
			SectionKind::PrivateKey => {
				drop(Secret::new(OwnedDer(PrivateKeyDer::Pkcs8(der.into()))));
			},
			SectionKind::RsaPrivateKey => {
				drop(Secret::new(OwnedDer(PrivateKeyDer::Pkcs1(der.into()))));
			},
			SectionKind::EcPrivateKey => {
				drop(Secret::new(OwnedDer(PrivateKeyDer::Sec1(der.into()))));
			},
			_ => {},
		}
	}
	Ok(certs)
}

fn parse_key(pem: &str) -> Result<Secret<OwnedDer>> {
	let mut reader = pem.as_bytes();
	let key = rustls_pemfile::private_key(&mut reader)
		.map_err(|_| anyhow::anyhow!("invalid private key PEM"))?
		.context("no PRIVATE KEY block found in PEM input")?;
	Ok(Secret::new(OwnedDer(key)))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::secret::DER_CLEANUPS;
	use crate::Ca;

	fn ignored_private_der_cleanup_counts(reqwest: bool, later_error: bool) -> [usize; 3] {
		let ca = Ca::new("throwaway-mixed-der-ca").unwrap();
		let suffix = if later_error { "-----BEGIN PRIVATE KEY malformed\n" } else { "" };
		[
			include_str!("../tests/fixtures/throwaway-rsa-pkcs1.pem"),
			include_str!("../tests/fixtures/throwaway-rsa-pkcs8.pem"),
			include_str!("../tests/fixtures/throwaway-ec-sec1.pem"),
		]
		.map(|key| {
			let mixed = format!("{}{key}{suffix}", ca.cert_pem());
			let before = DER_CLEANUPS.get();
			let accepted =
				if reqwest { reqwest_roots(&mixed).is_ok() } else { parse_certs(&mixed).is_ok() };
			assert_eq!(accepted, !later_error, "mixed bundle admission must not change");
			DER_CLEANUPS.get() - before
		})
	}

	#[test]
	fn tls_r1_certificate_scan_cleans_all_ignored_private_der_kinds() {
		assert_eq!(ignored_private_der_cleanup_counts(false, false), [1, 1, 1]);
	}

	#[test]
	fn tls_r1_certificate_scan_cleans_ignored_der_before_later_error() {
		assert_eq!(ignored_private_der_cleanup_counts(false, true), [1, 1, 1]);
	}

	#[test]
	fn tls_r1_reqwest_roots_clean_all_ignored_private_der_kinds() {
		assert_eq!(ignored_private_der_cleanup_counts(true, false), [1, 1, 1]);
	}

	#[test]
	fn tls_r1_reqwest_roots_clean_ignored_der_before_later_error() {
		assert_eq!(ignored_private_der_cleanup_counts(true, true), [1, 1, 1]);
	}

	#[test]
	fn mixed_certificate_scans_preserve_order_and_ignored_sections() {
		let first = Ca::new("throwaway-mixed-first-ca").unwrap();
		let second = Ca::new("throwaway-mixed-second-ca").unwrap();
		let expected = parse_certs(&format!("{}{}", first.cert_pem(), second.cert_pem())).unwrap();
		let private = include_str!("../tests/fixtures/throwaway-rsa-pkcs1.pem");
		let public = "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n";
		let unknown = "-----BEGIN UNKNOWN-----\nAQID\n-----END UNKNOWN-----\n";
		for extra in [private, public, unknown] {
			for mixed in [
				format!("{extra}{}{}", first.cert_pem(), second.cert_pem()),
				format!("{}{extra}{}", first.cert_pem(), second.cert_pem()),
				format!("{}{}{extra}", first.cert_pem(), second.cert_pem()),
			] {
				let legacy = rustls_pemfile::certs(&mut mixed.as_bytes())
					.collect::<std::result::Result<Vec<_>, _>>()
					.unwrap();
				assert_eq!(legacy, expected);
				assert_eq!(parse_certs(&mixed).unwrap(), expected);
				let mut expected_roots = RootCertStore::empty();
				for cert in &expected {
					expected_roots.add(cert.clone()).unwrap();
				}
				expected_roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
				assert_eq!(reqwest_roots(&mixed).unwrap().roots, expected_roots.roots);
			}
		}
		for without_certificate in ["", private, public, unknown] {
			assert!(parse_certs(without_certificate).is_err());
			assert_eq!(
				reqwest_roots(without_certificate).unwrap().roots,
				webpki_roots::TLS_SERVER_ROOTS
			);
		}
	}

	#[test]
	fn guarded_der_is_borrowed_and_cleaned_after_success_and_errors() {
		let ca = Ca::new("throwaway-guard-ca").unwrap();
		let leaf = ca.mint_client("matching").unwrap();
		let other = ca.mint_client("other").unwrap();
		for (pem, expected) in [(leaf.key_pem.expose(), true), (other.key_pem.expose(), false)] {
			let key = parse_key(pem).unwrap();
			let before = DER_CLEANUPS.get();
			assert_eq!(load_identity(parse_certs(&leaf.cert_pem).unwrap(), &key).is_ok(), expected);
			assert!(!key.expose().0.secret_der().is_empty(), "signer only borrowed the owner");
			assert_eq!(DER_CLEANUPS.get(), before, "guard survives the borrowing call");
			drop(key);
			assert_eq!(DER_CLEANUPS.get(), before + 1, "success and mismatch both run cleanup");
		}
		let malformed =
			parse_key("-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n").unwrap();
		let before = DER_CLEANUPS.get();
		assert!(load_identity(parse_certs(&leaf.cert_pem).unwrap(), &malformed).is_err());
		drop(malformed);
		assert_eq!(DER_CLEANUPS.get(), before + 1, "malformed DER still has an owner");
	}

	#[test]
	fn superseded_and_error_path_identity_keys_are_cleaned() {
		let ca = Ca::new("throwaway-last-key-ca").unwrap();
		let leaf = ca.mint_client("matching").unwrap();
		let other = ca.mint_client("other").unwrap();
		for (suffix, expected, count) in [
			("", true, 2),
			("-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n", false, 2),
			("-----BEGIN PRIVATE KEY malformed\n", false, 2),
		] {
			let pem = format!("{}{}{suffix}", other.key_pem.expose(), leaf.key_pem.expose());
			let before = DER_CLEANUPS.get();
			assert_eq!(parse_reqwest_identity(&leaf.cert_pem, &pem).is_ok(), expected);
			assert_eq!(DER_CLEANUPS.get(), before + count);
		}
	}

	#[test]
	fn reqwest_roots_exactly_add_supplied_roots_to_compiled_roots() {
		let first = Ca::new("throwaway-first-root").unwrap();
		let second = Ca::new("throwaway-second-root").unwrap();
		let ca_pem = format!("{}{}", first.cert_pem(), second.cert_pem());
		let mut expected = RootCertStore::empty();
		for cert in parse_certs(&ca_pem).unwrap() {
			expected.add(cert).unwrap();
		}
		expected.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
		assert_eq!(reqwest_roots(&ca_pem).unwrap().roots, expected.roots);
		assert_eq!(reqwest_roots("").unwrap().roots, webpki_roots::TLS_SERVER_ROOTS);
		let leaf = first.mint_client("client").unwrap();
		let private =
			client_config(&leaf.cert_pem, leaf.key_pem.expose(), first.cert_pem()).unwrap();
		assert!(private.alpn_protocols.is_empty());
		assert!(client_config(&leaf.cert_pem, leaf.key_pem.expose(), "").is_err());
		let shared = reqwest_client_config(&leaf.cert_pem, leaf.key_pem.expose(), &ca_pem).unwrap();
		assert_eq!(shared.alpn_protocols, [b"http/1.1"]);
		assert!(shared.enable_sni);
		assert!(!shared.enable_early_data);
		assert!(!shared.key_log.will_log("CLIENT_RANDOM"));
	}
}
