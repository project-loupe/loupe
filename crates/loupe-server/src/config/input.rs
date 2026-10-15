//! Fixed Config owners at native argument, file, and TLS boundaries.
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::builder::TypedValueParser;
use loupe_provenance::{Config, Ingress, Mark, Secret, Untrusted, Unvalidated, Validate};

/// Native host path captured by the actual process/configuration owner.
#[derive(Clone)]
pub struct ConfiguredPath(pub(super) PathBuf);
impl ConfiguredPath {
	pub fn as_path(&self) -> &Path {
		&self.0
	}
	pub(crate) fn join(&self, name: &'static str) -> Self {
		Self(self.0.join(name))
	}
	pub(super) fn from_file(_: &Mark<'_, Config>, base: &Path, path: PathBuf) -> Self {
		Self(if path.is_absolute() { path } else { base.join(path) })
	}
}
#[derive(Clone)]
pub struct ConfiguredHostname(String);
impl std::fmt::Debug for ConfiguredPath {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("ConfiguredPath<Config>([redacted])")
	}
}
/// Original raw/base64 argument; cloning shares the guarded original owner.
#[derive(Clone)]
pub struct ConfiguredPemArgument(loupe_tls::PemInput);
/// Selected original or decoded PEM retains Config through its TLS operation.
pub struct ConfiguredPem(pub(super) Secret<String>);
macro_rules! redacted {
	($($ty:ty),+) => { $(impl std::fmt::Debug for $ty {
		fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("[redacted]") }
	})+ };
}
redacted!(ConfiguredPemArgument, ConfiguredPem, ConfiguredHostname);
impl std::fmt::Display for ConfiguredPem {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("[redacted]")
	}
}
struct HostPath;
impl Validate<&OsStr, Config> for HostPath {
	type Output = ConfiguredPath;
	type Error = std::convert::Infallible;
	fn validate<'v>(
		self, input: Unvalidated<'v, &OsStr>, _: Mark<'v, Config>,
	) -> Result<Self::Output, Self::Error> {
		Ok(ConfiguredPath(PathBuf::from(input.get())))
	}
}
struct PemArgument;
impl Validate<&OsStr, Config> for PemArgument {
	type Output = ConfiguredPemArgument;
	type Error = &'static str;
	fn validate<'v>(
		self, input: Unvalidated<'v, &OsStr>, _: Mark<'v, Config>,
	) -> Result<Self::Output, Self::Error> {
		Ok(ConfiguredPemArgument(loupe_tls::PemInput::from(
			input.get().to_str().ok_or("PEM input is not UTF-8")?,
		)))
	}
}
struct Hostname;
impl Validate<&OsStr, Config> for Hostname {
	type Output = ConfiguredHostname;
	type Error = &'static str;
	fn validate<'v>(
		self, input: Unvalidated<'v, &OsStr>, _: Mark<'v, Config>,
	) -> Result<Self::Output, Self::Error> {
		Ok(ConfiguredHostname(input.get().to_str().ok_or("hostname is not UTF-8")?.to_owned()))
	}
}
macro_rules! parser {
	($name:ident, $value:ty, $decoder:ident) => {
		#[derive(Clone)]
		pub struct $name;
		impl TypedValueParser for $name {
			type Value = $value;
			#[allow(unsafe_code)]
			fn parse_ref(
				&self, _: &clap::Command, _: Option<&clap::Arg>, value: &OsStr,
			) -> Result<Self::Value, clap::Error> {
				// SAFETY: actual native CLI/environment value, captured before interpretation.
				let token = unsafe { Ingress::<Config>::new() };
				Untrusted::new(value, token).validate($decoder).map_err(|error| {
					clap::Error::raw(
						clap::error::ErrorKind::ValueValidation,
						format_args!("{error}"),
					)
				})
			}
		}
	};
}
parser!(PathParser, ConfiguredPath, HostPath);
parser!(PemParser, ConfiguredPemArgument, PemArgument);
parser!(HostnameParser, ConfiguredHostname, Hostname);
impl ConfiguredHostname {
	pub(crate) fn mint_server(ca: &loupe_tls::Ca, names: &[Self]) -> Result<loupe_tls::CertBundle> {
		// This owned dependency input is made only at the actual TLS mint operation.
		ca.mint_server("loupe-server", &names.iter().map(|name| name.0.clone()).collect::<Vec<_>>())
			.context("minting server cert")
	}
}

struct FilePem;
impl Validate<&str, Config> for FilePem {
	type Output = ();
	type Error = std::convert::Infallible;
	fn validate<'v>(
		self, _: Unvalidated<'v, &str>, _: Mark<'v, Config>,
	) -> Result<(), Self::Error> {
		Ok(())
	}
}
impl ConfiguredPath {
	/// This actual read captures file contents separately from the path owner.
	#[allow(unsafe_code)]
	pub fn read_tls_pem(&self) -> Result<ConfiguredPem> {
		let pem = loupe_tls::read_pem_file(&self.0)
			.with_context(|| format!("reading PEM at {}", self.0.display()))?;
		// SAFETY: the exact guarded UTF-8 payload of this actual file read.
		let token = unsafe { Ingress::<Config>::new() };
		let Ok(()) = Untrusted::new(pem.expose().as_str(), token).validate(FilePem);
		Ok(ConfiguredPem(pem))
	}
}
impl ConfiguredPem {
	/// Borrow both Config owners only at the concrete CA import operation.
	pub fn import_ca(&self, key: &Self) -> Result<loupe_tls::Ca> {
		loupe_tls::Ca::from_pem(self.0.expose(), key.0.expose()).context("rebuilding CA from PEM")
	}
}
/// Preserve raw > base64 > file precedence and empty-argument fallback.
pub fn select_tls_pem(
	label: &str, raw: Option<ConfiguredPemArgument>, base64: Option<ConfiguredPemArgument>,
	path: Option<ConfiguredPath>, missing: &'static str,
) -> Result<ConfiguredPem> {
	if let Some(raw) = raw.filter(|p| !p.0.expose().is_empty()) {
		tracing::info!(%label, "loupe-server: TLS PEM loaded from environment");
		return Ok(ConfiguredPem(raw.0.into_pem()));
	}
	if let Some(base64) = base64.filter(|p| !p.0.expose().is_empty()) {
		tracing::info!(%label, "loupe-server: TLS PEM loaded from base64 environment");
		let pem = loupe_tls::decode_pem_base64(base64.0.expose().trim())
			.with_context(|| format!("decoding base64 {label} PEM"))?;
		return Ok(ConfiguredPem(pem));
	}
	path.context(missing)?.read_tls_pem().with_context(|| format!("reading {label}"))
}

#[cfg(test)]
mod tests {
	use base64::Engine as _;
	use clap::Parser;

	use super::*;

	#[derive(Parser)]
	struct PemArgs {
		#[arg(long, value_parser = PemParser)]
		pem: ConfiguredPemArgument,
	}
	fn pem(value: impl AsRef<str>) -> ConfiguredPemArgument {
		PemArgs::try_parse_from(["fixture", &format!("--pem={}", value.as_ref())]).unwrap().pem
	}
	#[derive(Parser)]
	struct PathArgs {
		#[arg(long, value_parser = PathParser)]
		path: ConfiguredPath,
	}
	fn path(value: &Path) -> ConfiguredPath {
		PathArgs::try_parse_from([OsStr::new("fixture"), OsStr::new("--path"), value.as_os_str()])
			.unwrap()
			.path
	}

	#[test]
	fn config_raw_pem_egress_moves_original_guarded_allocation() {
		let pem = pem("FAKE_CONFIG_RAW_PEM");
		let address = pem.0.expose().as_ptr();
		let output = select_tls_pem("key", Some(pem), None, None, "missing").unwrap();
		assert_eq!(output.0.expose().as_ptr(), address);
		assert_eq!(output.0.expose(), "FAKE_CONFIG_RAW_PEM");
		assert_eq!(format!("{output:?}"), "[redacted]");
	}

	#[test]
	fn tls_consumer_server_loaded_pem_is_redacted() {
		let loaded =
			select_tls_pem("key", Some(pem("FAKE_LOADED_SERVER_TLS")), None, None, "missing")
				.unwrap();
		for rendered in [
			format!("{loaded:?}"),
			format!("{loaded:#?}"),
			format!("{loaded}"),
			format!("{loaded:#}"),
		] {
			assert_eq!(rendered, "[redacted]", "loaded TLS owner must redact every formatter");
		}
	}

	#[test]
	fn tls_consumer_server_invalid_utf8_error_does_not_retain_private_bytes() {
		let bytes = b"FAKE_INVALID_SERVER_TLS\xff";
		let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
		let error =
			select_tls_pem("server key", None, Some(pem(&encoded)), None, "missing").unwrap_err();
		let rendered: String = format!("{error:#?}").split_whitespace().collect();
		let reflected: String = format!("bytes:{bytes:?}").split_whitespace().collect();
		assert!(!rendered.contains(&reflected), "invalid UTF-8 error retained private input bytes");
	}

	#[test]
	fn server_tls_loader_preserves_precedence_empty_fallback_and_errors() {
		let dir = tempfile::tempdir().unwrap();
		let raw_path = dir.path().join("tls-input");
		let path = path(&raw_path);
		std::fs::write(path.as_path(), "FILE_TLS").unwrap();
		let encoded = base64::engine::general_purpose::STANDARD.encode("B64_TLS");
		assert_eq!(
			select_tls_pem(
				"key",
				Some(pem("RAW_TLS")),
				Some(pem("invalid%%%")),
				Some(path.clone()),
				"missing"
			)
			.unwrap()
			.0
			.expose(),
			"RAW_TLS"
		);
		assert_eq!(
			select_tls_pem(
				"key",
				Some(pem("")),
				Some(pem(format!(" \n{encoded}\n "))),
				Some(path.clone()),
				"missing"
			)
			.unwrap()
			.0
			.expose(),
			"B64_TLS"
		);
		assert_eq!(
			select_tls_pem("key", Some(pem("")), Some(pem("")), Some(path.clone()), "missing")
				.unwrap()
				.0
				.expose(),
			"FILE_TLS"
		);
		assert!(select_tls_pem(
			"key",
			None,
			Some(pem("invalid%%%")),
			Some(path.clone()),
			"missing"
		)
		.is_err());
		std::fs::write(path.as_path(), b"invalid\xff").unwrap();
		assert!(select_tls_pem("key", None, None, Some(path), "missing").is_err());
		assert!(select_tls_pem("key", None, None, None, "missing").is_err());
	}
}
