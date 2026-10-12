//! Command-line / environment configuration.
//!
//! The upstream connection arguments mirror `loupectl` exactly — same
//! flag names, same env vars, same three sources per input — so an
//! environment that already works for `loupectl` works here unchanged.

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result};
use clap::{Args, Parser};
mod input;
#[cfg(fuzzing)]
pub(crate) use input::{fuzz_parse, fuzz_selected};
pub use input::{ConfigPath, ConfigPem, ConfigTlsPem, ConfigUrl};

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
	pub server_url: Option<ConfigUrl>,

	#[arg(long, env = "LOUPE_CA_CERT", value_parser = input::PathParser)]
	pub ca_cert: Option<ConfigPath>,
	#[arg(long, env = "LOUPE_CA_CERT_PEM", hide_env_values = true, value_parser = input::PemParser)]
	pub ca_cert_pem: Option<ConfigPem>,
	#[arg(long, env = "LOUPE_CA_CERT_PEM_B64", hide_env_values = true, value_parser = input::PemParser)]
	pub ca_cert_pem_b64: Option<ConfigPem>,

	#[arg(long, env = "LOUPE_ADMIN_CERT", value_parser = input::PathParser)]
	pub admin_cert: Option<ConfigPath>,
	#[arg(long, env = "LOUPE_ADMIN_CERT_PEM", hide_env_values = true, value_parser = input::PemParser)]
	pub admin_cert_pem: Option<ConfigPem>,
	#[arg(long, env = "LOUPE_ADMIN_CERT_PEM_B64", hide_env_values = true, value_parser = input::PemParser)]
	pub admin_cert_pem_b64: Option<ConfigPem>,

	#[arg(long, env = "LOUPE_ADMIN_KEY", value_parser = input::PathParser)]
	pub admin_key: Option<ConfigPath>,
	#[arg(long, env = "LOUPE_ADMIN_KEY_PEM", hide_env_values = true, value_parser = input::PemParser)]
	pub admin_key_pem: Option<ConfigPem>,
	#[arg(long, env = "LOUPE_ADMIN_KEY_PEM_B64", hide_env_values = true, value_parser = input::PemParser)]
	pub admin_key_pem_b64: Option<ConfigPem>,
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
	pub(crate) fn tls_client(&self) -> Result<reqwest::Client> {
		input::tls_client(self.ca_pem()?, self.admin_cert_pem()?, self.admin_key_pem()?)
	}
	/// Resolve the upstream base URL.
	pub fn server_url(&self) -> Result<ConfigUrl> {
		self.server_url
			.clone()
			.context("server URL missing — set LOUPE_SERVER_URL or pass --server-url")
	}

	/// Read the CA cert PEM.
	pub fn ca_pem(&self) -> Result<ConfigTlsPem> {
		pem_from_env_or_file(
			"CA cert",
			&self.ca_cert_pem,
			&self.ca_cert_pem_b64,
			self.ca_cert.as_ref(),
			"CA cert missing — set LOUPE_CA_CERT_PEM, LOUPE_CA_CERT_PEM_B64, or LOUPE_CA_CERT",
		)
	}

	/// Read the admin client cert PEM.
	pub fn admin_cert_pem(&self) -> Result<ConfigTlsPem> {
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
	pub fn admin_key_pem(&self) -> Result<ConfigTlsPem> {
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
	_label: &str, pem: &Option<ConfigPem>, pem_b64: &Option<ConfigPem>, path: Option<&ConfigPath>,
	missing: &'static str,
) -> Result<ConfigTlsPem> {
	input::selected(pem, pem_b64, path, missing)
}

#[cfg(test)]
fn test_pem(value: &str) -> ConfigPem {
	use clap::builder::TypedValueParser;
	input::PemParser
		.parse_ref(&clap::Command::new("fixture"), None, std::ffi::OsStr::new(value))
		.unwrap()
}

#[cfg(test)]
fn test_path(value: &std::path::Path) -> ConfigPath {
	use clap::builder::TypedValueParser;
	input::PathParser.parse_ref(&clap::Command::new("fixture"), None, value.as_os_str()).unwrap()
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
			ca_cert: Some(test_path(std::path::Path::new("/nonexistent"))),
			ca_cert_pem: Some(test_pem("RAW")),
			ca_cert_pem_b64: Some(test_pem("QkFTRTY0")),
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
			ca_cert_pem_b64: Some(test_pem("QkFTRTY0")),
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
		use clap::builder::TypedValueParser;
		let selected_path = input::PathParser
			.parse_ref(&clap::Command::new("fixture"), None, path.as_os_str())
			.unwrap();
		let encoded = base64::engine::general_purpose::STANDARD.encode("B64_TLS");
		assert_eq!(
			pem_from_env_or_file(
				"key",
				&Some(test_pem("RAW_TLS")),
				&Some(test_pem("invalid%%%")),
				Some(&selected_path),
				"missing"
			)
			.unwrap()
			.expose(),
			"RAW_TLS"
		);
		assert_eq!(
			pem_from_env_or_file(
				"key",
				&Some(test_pem("")),
				&Some(test_pem(&format!(" \n{encoded}\n "))),
				Some(&selected_path),
				"missing"
			)
			.unwrap()
			.expose(),
			"B64_TLS"
		);
		assert_eq!(
			pem_from_env_or_file(
				"key",
				&Some(test_pem("")),
				&Some(test_pem("")),
				Some(&selected_path),
				"missing"
			)
			.unwrap()
			.expose(),
			"FILE_TLS"
		);
		assert!(pem_from_env_or_file(
			"key",
			&None,
			&Some(test_pem("invalid%%%")),
			Some(&selected_path),
			"missing"
		)
		.is_err());
		std::fs::write(&path, b"invalid\xff").unwrap();
		assert!(pem_from_env_or_file("key", &None, &None, Some(&selected_path), "missing").is_err());
		assert!(pem_from_env_or_file("key", &None, &None, None, "missing").is_err());
	}
}

#[cfg(test)]
mod actual_ingress_tests {
	use super::*;
	#[test]
	fn supplied_values_keep_defaults_zero_poll_and_native_paths() {
		use std::os::unix::ffi::OsStringExt;
		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join(std::ffi::OsString::from_vec(b"native-\xff".to_vec()));
		std::fs::write(&path, "FILE_TLS").unwrap();
		let cli = Cli::try_parse_from([
			std::ffi::OsStr::new("loupe-web"),
			std::ffi::OsStr::new("--ca-cert"),
			path.as_os_str(),
			std::ffi::OsStr::new("--poll-seconds"),
			std::ffi::OsStr::new("0"),
			std::ffi::OsStr::new("--server-url"),
			std::ffi::OsStr::new("http://localhost:8443/path"),
		])
		.unwrap();
		assert_eq!(cli.bind, "127.0.0.1:8455".parse().unwrap());
		assert_eq!(cli.poll_seconds, 0);
		assert_eq!(cli.conn.ca_cert.as_ref().map(ConfigPath::fixture_path), Some(path.as_path()));
		assert_eq!(cli.conn.ca_pem().unwrap().expose(), "FILE_TLS");
		assert_eq!(cli.conn.server_url().unwrap().fixture_str(), "http://localhost:8443/path");
	}
	#[test]
	fn actual_clap_child_environment_precedence() {
		const CHILD: &str = "LOUPE_WEB_INGRESS_TEST_CHILD";
		if std::env::var_os(CHILD).is_some() {
			let cli = Cli::try_parse_from([
				"loupe-web",
				"--server-url",
				"http://flag.invalid/",
				"--ca-cert-pem",
				"FLAG_RAW",
				"--poll-seconds",
				"0",
			])
			.unwrap();
			assert_eq!(cli.conn.server_url().unwrap().fixture_str(), "http://flag.invalid/");
			assert_eq!(cli.conn.ca_pem().unwrap().expose(), "FLAG_RAW");
			assert_eq!(cli.conn.admin_cert_pem().unwrap().expose(), "ENV_CERT");
			assert_eq!(cli.poll_seconds, 0);
			return;
		}
		let output = std::process::Command::new(std::env::current_exe().unwrap())
			.env_clear()
			.env(CHILD, "1")
			.env("LOUPE_SERVER_URL", "http://env.invalid/")
			.env("LOUPE_CA_CERT_PEM", "ENV_RAW")
			.env("LOUPE_ADMIN_CERT_PEM", "ENV_CERT")
			.env("LOUPE_WEB_POLL_SECONDS", "17")
			.args([
				"--exact",
				"config::actual_ingress_tests::actual_clap_child_environment_precedence",
				"--nocapture",
			])
			.output()
			.unwrap();
		assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
	}
}
