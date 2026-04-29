use anyhow::{Context, Result};
use rcgen::{
	BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};

/// PEM-encoded cert + key. The key is plaintext PEM; callers are
/// responsible for keeping it safe (envelope-encrypted in the `secrets`
/// table on the server side, on-disk under restrictive perms on the
/// worker side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertBundle {
	pub cert_pem: String,
	pub key_pem: String,
}

/// In-memory certificate authority used to mint client and server certs.
///
/// `Ca::new` generates a fresh self-signed CA. `Ca::from_pem` rebuilds
/// one from previously persisted PEM (the server reloads its CA from the
/// envelope-encrypted `secrets` row on startup).
pub struct Ca {
	cert: rcgen::Certificate,
	key: KeyPair,
	cert_pem: String,
	key_pem: String,
}

impl Ca {
	pub fn new(common_name: &str) -> Result<Self> {
		let key = KeyPair::generate().context("generating CA key pair")?;
		let mut params = CertificateParams::default();
		params.distinguished_name = {
			let mut dn = DistinguishedName::new();
			dn.push(DnType::CommonName, common_name);
			dn.push(DnType::OrganizationName, "loupe");
			dn
		};
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
		params.key_usages = vec![
			KeyUsagePurpose::KeyCertSign,
			KeyUsagePurpose::CrlSign,
			KeyUsagePurpose::DigitalSignature,
		];
		let cert = params.self_signed(&key).context("self-signing CA cert")?;
		let cert_pem = cert.pem();
		let key_pem = key.serialize_pem();
		Ok(Self { cert, key, cert_pem, key_pem })
	}

	pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
		let key = KeyPair::from_pem(key_pem).context("parsing CA key PEM")?;
		let params =
			CertificateParams::from_ca_cert_pem(cert_pem).context("parsing CA cert PEM")?;
		let cert = params.self_signed(&key).context("re-binding CA cert to key pair")?;
		Ok(Self { cert_pem: cert_pem.to_owned(), key_pem: key_pem.to_owned(), cert, key })
	}

	pub fn cert_pem(&self) -> &str {
		&self.cert_pem
	}

	pub fn key_pem(&self) -> &str {
		&self.key_pem
	}

	/// Mint a client cert. The cert's CN is `name`; subject-alt-names are
	/// not set because we identify clients by certificate fingerprint, not
	/// by hostname.
	pub fn mint_client(&self, name: &str) -> Result<CertBundle> {
		self.mint(name, &[], false)
	}

	/// Mint a server cert. `hostnames` populates SubjectAltName so clients
	/// can verify the server identity; pass at least one entry.
	pub fn mint_server(&self, common_name: &str, hostnames: &[String]) -> Result<CertBundle> {
		anyhow::ensure!(!hostnames.is_empty(), "mint_server requires at least one hostname");
		self.mint(common_name, hostnames, true)
	}

	fn mint(&self, common_name: &str, hostnames: &[String], is_server: bool) -> Result<CertBundle> {
		let key = KeyPair::generate().context("generating leaf key pair")?;
		let mut params = CertificateParams::new(hostnames.to_vec()).context("new leaf params")?;
		params.distinguished_name = {
			let mut dn = DistinguishedName::new();
			dn.push(DnType::CommonName, common_name);
			dn.push(DnType::OrganizationName, "loupe");
			dn
		};
		params.is_ca = IsCa::NoCa;
		params.key_usages =
			vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
		params.extended_key_usages = if is_server {
			vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth]
		} else {
			vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth]
		};
		let cert = params.signed_by(&key, &self.cert, &self.key).context("signing leaf cert")?;
		Ok(CertBundle { cert_pem: cert.pem(), key_pem: key.serialize_pem() })
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn round_trips_through_pem() {
		let ca = Ca::new("loupe-test-ca").unwrap();
		let cert_pem = ca.cert_pem().to_owned();
		let key_pem = ca.key_pem().to_owned();
		let reloaded = Ca::from_pem(&cert_pem, &key_pem).unwrap();
		assert_eq!(reloaded.cert_pem(), cert_pem);
	}

	#[test]
	fn mints_client_and_server_certs() {
		let ca = Ca::new("loupe-test-ca").unwrap();
		let client = ca.mint_client("worker-1").unwrap();
		assert!(client.cert_pem.contains("BEGIN CERTIFICATE"));
		assert!(client.key_pem.contains("PRIVATE KEY"));

		let server = ca.mint_server("loupe-server", &["localhost".into()]).unwrap();
		assert!(server.cert_pem.contains("BEGIN CERTIFICATE"));
	}

	#[test]
	fn server_mint_requires_hostname() {
		let ca = Ca::new("loupe-test-ca").unwrap();
		assert!(ca.mint_server("loupe-server", &[]).is_err());
	}
}
