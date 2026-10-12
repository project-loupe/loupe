//! Command-line / environment configuration.
//!
//! The upstream connection arguments mirror `loupectl` exactly — same
//! flag names, same env vars, same three sources per input — so an
//! environment that already works for `loupectl` works here unchanged.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser};
mod input;
#[cfg(fuzzing)]
pub(crate) use input::{fuzz_parse, fuzz_selected};

/// Default listen port. Deliberately not adjacent to the server's 8443:
/// this is a different kind of endpoint and should not look like one.
pub const DEFAULT_PORT: u16 = 8455;

#[derive(Debug, Parser)]
#[command(
	name = "loupe-web",
	about = "Local operator dashboard for loupe-server.",
	long_about = "Serves a browser dashboard over the same admin RPCs loupectl uses.\n\n\
	              Binds loopback only and holds the admin certificate itself, so the \
	              browser needs no client certificate. Access is gated by a capability \
	              token printed at startup."
)]
pub struct Cli {
	/// Address to listen on. Must be a loopback address.
	#[arg(long, env = "LOUPE_WEB_BIND", default_value_t = default_bind())]
	pub bind: SocketAddr,

	/// Seconds between automatic refreshes of the visible view.
	#[arg(long, env = "LOUPE_WEB_POLL_SECONDS", default_value_t = 5)]
	pub poll_seconds: u32,

	#[command(flatten)]
	pub conn: ConnArgs,
}

fn default_bind() -> SocketAddr {
	SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT))
}

/// Upstream connection arguments. Each of CA cert / admin cert / admin key
/// is resolvable from a raw PEM env var, a base64 PEM env var, or a file
/// path, in that precedence order — identical to `loupectl`.
#[derive(Debug, Args)]
pub struct ConnArgs {
	#[arg(long, env = "LOUPE_SERVER_URL", value_parser = input::UrlParser)]
	pub server_url: Option<reqwest::Url>,

	#[arg(long, env = "LOUPE_CA_CERT", value_parser = input::PathParser)]
	pub ca_cert: Option<PathBuf>,
	#[arg(long, env = "LOUPE_CA_CERT_PEM", hide_env_values = true, value_parser = input::PemParser)]
	pub ca_cert_pem: Option<loupe_tls::PemInput>,
	#[arg(long, env = "LOUPE_CA_CERT_PEM_B64", hide_env_values = true, value_parser = input::PemParser)]
	pub ca_cert_pem_b64: Option<loupe_tls::PemInput>,

	#[arg(long, env = "LOUPE_ADMIN_CERT", value_parser = input::PathParser)]
	pub admin_cert: Option<PathBuf>,
	#[arg(long, env = "LOUPE_ADMIN_CERT_PEM", hide_env_values = true, value_parser = input::PemParser)]
	pub admin_cert_pem: Option<loupe_tls::PemInput>,
	#[arg(long, env = "LOUPE_ADMIN_CERT_PEM_B64", hide_env_values = true, value_parser = input::PemParser)]
	pub admin_cert_pem_b64: Option<loupe_tls::PemInput>,

	#[arg(long, env = "LOUPE_ADMIN_KEY", value_parser = input::PathParser)]
	pub admin_key: Option<PathBuf>,
	#[arg(long, env = "LOUPE_ADMIN_KEY_PEM", hide_env_values = true, value_parser = input::PemParser)]
	pub admin_key_pem: Option<loupe_tls::PemInput>,
	#[arg(long, env = "LOUPE_ADMIN_KEY_PEM_B64", hide_env_values = true, value_parser = input::PemParser)]
	pub admin_key_pem_b64: Option<loupe_tls::PemInput>,
}

/// Reject any non-loopback bind address.
///
/// This process holds the admin certificate, and its own listener has no
/// transport authentication at all. Binding it to a routable address would
/// hand loupe admin rights to anyone who can reach the port, which is a
/// different security model than the one the operator signed up for. It is
/// a hard error rather than a warning for that reason.
pub fn ensure_loopback(bind: SocketAddr) -> Result<()> {
	let is_loopback = match bind.ip() {
		IpAddr::V4(ip) => ip.is_loopback(),
		IpAddr::V6(ip) => ip.is_loopback(),
	};
	anyhow::ensure!(
		is_loopback,
		"refusing to bind {bind}: loupe-web holds the admin certificate and its own \
		 listener is unauthenticated, so it must stay on loopback. Use 127.0.0.1 or [::1]."
	);
	Ok(())
}

impl ConnArgs {
	/// Resolve the upstream base URL.
	pub fn server_url(&self) -> Result<reqwest::Url> {
		self.server_url
			.clone()
			.context("server URL missing — set LOUPE_SERVER_URL or pass --server-url")
	}

	/// Read the CA cert PEM.
	pub fn ca_pem(&self) -> Result<loupe_provenance::Secret<String>> {
		pem_from_env_or_file(
			"CA cert",
			&self.ca_cert_pem,
			&self.ca_cert_pem_b64,
			self.ca_cert.as_ref(),
			"CA cert missing — set LOUPE_CA_CERT_PEM, LOUPE_CA_CERT_PEM_B64, or LOUPE_CA_CERT",
		)
	}

	/// Read the admin client cert PEM.
	pub fn admin_cert_pem(&self) -> Result<loupe_provenance::Secret<String>> {
		pem_from_env_or_file(
			"admin cert",
			&self.admin_cert_pem,
			&self.admin_cert_pem_b64,
			self.admin_cert.as_ref(),
			"admin cert missing — set LOUPE_ADMIN_CERT_PEM, LOUPE_ADMIN_CERT_PEM_B64, \
			 or LOUPE_ADMIN_CERT",
		)
	}

	/// Read the admin client key PEM.
	pub fn admin_key_pem(&self) -> Result<loupe_provenance::Secret<String>> {
		pem_from_env_or_file(
			"admin key",
			&self.admin_key_pem,
			&self.admin_key_pem_b64,
			self.admin_key.as_ref(),
			"admin key missing — set LOUPE_ADMIN_KEY_PEM, LOUPE_ADMIN_KEY_PEM_B64, \
			 or LOUPE_ADMIN_KEY",
		)
	}
}

fn pem_from_env_or_file(
	_label: &str, pem: &Option<loupe_tls::PemInput>, pem_b64: &Option<loupe_tls::PemInput>,
	path: Option<&PathBuf>, missing: &'static str,
) -> Result<loupe_provenance::Secret<String>> {
	input::selected(pem, pem_b64, path, missing)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn loopback_addresses_are_accepted() {
		for addr in ["127.0.0.1:8455", "127.0.0.2:8455", "[::1]:8455"] {
			let addr: SocketAddr = addr.parse().unwrap();
			assert!(ensure_loopback(addr).is_ok(), "{addr} is loopback and should be accepted");
		}
	}

	#[test]
	fn routable_addresses_are_refused() {
		// 0.0.0.0 is the dangerous one: it looks like "just the default"
		// but exposes the admin credential to the whole network.
		for addr in ["0.0.0.0:8455", "192.168.1.10:8455", "[::]:8455", "[2001:db8::1]:8455"] {
			let parsed: SocketAddr = addr.parse().unwrap();
			let err = ensure_loopback(parsed).expect_err("{addr} must be refused");
			let msg = err.to_string();
			assert!(msg.contains("refusing to bind"), "unhelpful error for {addr}: {msg}");
			assert!(msg.contains("loopback"), "error should say why for {addr}: {msg}");
		}
	}

	#[test]
	fn raw_pem_env_wins_over_base64_and_path() {
		let args = ConnArgs {
			server_url: None,
			ca_cert: Some(PathBuf::from("/nonexistent")),
			ca_cert_pem: Some("RAW".into()),
			ca_cert_pem_b64: Some("QkFTRTY0".into()),
			admin_cert: None,
			admin_cert_pem: None,
			admin_cert_pem_b64: None,
			admin_key: None,
			admin_key_pem: None,
			admin_key_pem_b64: None,
		};
		assert_eq!(args.ca_pem().unwrap().expose(), "RAW");
	}

	#[test]
	fn base64_pem_is_decoded_when_raw_is_absent() {
		let args = ConnArgs {
			server_url: None,
			ca_cert: None,
			ca_cert_pem: None,
			ca_cert_pem_b64: Some("QkFTRTY0".into()),
			admin_cert: None,
			admin_cert_pem: None,
			admin_cert_pem_b64: None,
			admin_key: None,
			admin_key_pem: None,
			admin_key_pem_b64: None,
		};
		assert_eq!(args.ca_pem().unwrap().expose(), "BASE64");
	}

	#[test]
	fn a_missing_source_names_every_env_var() {
		let args = ConnArgs {
			server_url: None,
			ca_cert: None,
			ca_cert_pem: None,
			ca_cert_pem_b64: None,
			admin_cert: None,
			admin_cert_pem: None,
			admin_cert_pem_b64: None,
			admin_key: None,
			admin_key_pem: None,
			admin_key_pem_b64: None,
		};
		let msg = args.ca_pem().unwrap_err().to_string();
		for expected in ["LOUPE_CA_CERT_PEM", "LOUPE_CA_CERT_PEM_B64", "LOUPE_CA_CERT"] {
			assert!(msg.contains(expected), "{expected} missing from: {msg}");
		}
	}

	#[test]
	fn default_bind_is_loopback() {
		assert!(ensure_loopback(default_bind()).is_ok());
	}
}

#[cfg(test)]
mod tls_consumer_tests {
	use base64::Engine as _;

	use super::*;

	#[test]
	fn tls_consumer_web_options_debug_redacts_raw_and_encoded_tls_inputs() {
		let sentinel = "FAKE_WEB_TLS_OPTION";
		let encoded = base64::engine::general_purpose::STANDARD.encode(sentinel);
		let mut leaks = Vec::new();
		for flag in [
			"--ca-cert-pem",
			"--admin-cert-pem",
			"--admin-key-pem",
			"--ca-cert-pem-b64",
			"--admin-cert-pem-b64",
			"--admin-key-pem-b64",
		] {
			let value = if flag.ends_with("-b64") { &encoded } else { sentinel };
			let cli = Cli::try_parse_from(["loupe-web", flag, value]).unwrap();
			if [format!("{cli:?}"), format!("{cli:#?}")].iter().any(|text| text.contains(value)) {
				leaks.push(flag);
			}
		}
		assert!(leaks.is_empty(), "web option Debug disclosed inputs at {leaks:?}");
	}

	#[test]
	fn tls_consumer_web_loaded_pem_is_redacted() {
		let cli = Cli::try_parse_from([
			"loupe-web",
			"--ca-cert-pem",
			"FAKE_MIXED_WEB_CA",
			"--admin-cert-pem",
			"FAKE_MIXED_WEB_CERT",
			"--admin-key-pem",
			"FAKE_WEB_KEY",
		])
		.unwrap();
		for value in [
			cli.conn.ca_pem().unwrap(),
			cli.conn.admin_cert_pem().unwrap(),
			cli.conn.admin_key_pem().unwrap(),
		] {
			for rendered in [
				format!("{value:?}"),
				format!("{value:#?}"),
				format!("{value}"),
				format!("{value:#}"),
			] {
				assert_eq!(rendered, "[redacted]", "loaded TLS owner must redact every formatter");
			}
		}
	}

	#[test]
	fn tls_consumer_web_invalid_utf8_error_does_not_retain_private_bytes() {
		let bytes = b"FAKE_INVALID_WEB_TLS\xff";
		let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
		let cli = Cli::try_parse_from(["loupe-web", "--admin-key-pem-b64", &encoded]).unwrap();
		let error = cli.conn.admin_key_pem().unwrap_err();
		let rendered: String = format!("{error:#?}").split_whitespace().collect();
		let reflected: String = format!("bytes:{bytes:?}").split_whitespace().collect();
		assert!(!rendered.contains(&reflected), "invalid UTF-8 error retained private input bytes");
	}

	#[test]
	fn web_tls_loader_preserves_precedence_empty_fallback_and_errors() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("tls-input");
		std::fs::write(&path, "FILE_TLS").unwrap();
		let encoded = base64::engine::general_purpose::STANDARD.encode("B64_TLS");
		assert_eq!(
			pem_from_env_or_file(
				"key",
				&Some("RAW_TLS".into()),
				&Some("invalid%%%".into()),
				Some(&path),
				"missing"
			)
			.unwrap()
			.expose(),
			"RAW_TLS"
		);
		assert_eq!(
			pem_from_env_or_file(
				"key",
				&Some(String::new().into()),
				&Some(format!(" \n{encoded}\n ").into()),
				Some(&path),
				"missing"
			)
			.unwrap()
			.expose(),
			"B64_TLS"
		);
		assert_eq!(
			pem_from_env_or_file(
				"key",
				&Some(String::new().into()),
				&Some(String::new().into()),
				Some(&path),
				"missing"
			)
			.unwrap()
			.expose(),
			"FILE_TLS"
		);
		assert!(pem_from_env_or_file(
			"key",
			&None,
			&Some("invalid%%%".into()),
			Some(&path),
			"missing"
		)
		.is_err());
		std::fs::write(&path, b"invalid\xff").unwrap();
		assert!(pem_from_env_or_file("key", &None, &None, Some(&path), "missing").is_err());
		assert!(pem_from_env_or_file("key", &None, &None, None, "missing").is_err());
	}
}
