//! Actual native Config admission and closed HTTP, file and TLS sinks.
use std::ffi::OsStr;
use std::marker::PhantomData;
use std::path::PathBuf;

use clap::builder::TypedValueParser;
use loupe_provenance::{Config, Ingress, Mark, Secret, Untrusted, Unvalidated, Validate};
use loupe_tls::PemInput;

#[derive(Debug)]
pub(super) enum Failure {
	Url,
	NativeUtf8,
	Base64,
	File,
}
impl std::fmt::Display for Failure {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			Self::Url => "invalid server URL",
			Self::NativeUtf8 => "configuration value is not UTF-8",
			Self::Base64 => "invalid base64 PEM input",
			Self::File => "reading PEM input failed",
		})
	}
}
impl std::error::Error for Failure {}
fn clap_error(error: Failure) -> clap::Error {
	clap::Error::raw(clap::error::ErrorKind::ValueValidation, error)
}

/// URL admitted from actual native configuration; only the admin HTTP and
/// startup diagnostic sinks can borrow its value.
/// ```compile_fail,E0599
/// fn raw(url: loupe_web::config::ConfigUrl) { let _ = url.as_str(); }
/// ```
#[derive(Clone)]
pub struct ConfigUrl(reqwest::Url, PhantomData<Config>);
/// Native host path. It cannot be confused with a repository path.
/// ```compile_fail,E0277
/// fn raw() { let _: loupe_web::config::ConfigPath = "/tmp/key".into(); }
/// ```
#[derive(Clone)]
pub struct ConfigPath(PathBuf, PhantomData<Config>);
/// Original native PEM/base64 input, retained in guarded Secret storage.
/// ```compile_fail,E0277
/// fn raw() { let _: loupe_web::config::ConfigPem = "raw PEM".into(); }
/// ```
#[derive(Clone)]
pub struct ConfigPem(PemInput, PhantomData<Config>);
/// Selected PEM remains Config and Secret through the TLS constructor.
/// ```compile_fail,E0599
/// fn raw(pem: loupe_web::config::ConfigTlsPem) { let _ = pem.expose(); }
/// ```
pub struct ConfigTlsPem(Secret<String>, PhantomData<Config>);
macro_rules! redacted {
    ($($ty:ty),+) => { $(impl std::fmt::Debug for $ty {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("[redacted]") }
    })+ };
}
redacted!(ConfigUrl, ConfigPath, ConfigPem, ConfigTlsPem);
impl std::fmt::Display for ConfigTlsPem {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("[redacted]")
	}
}
impl ConfigUrl {
	#[cfg(test)]
	pub(super) fn fixture_str(&self) -> &str {
		self.0.as_str()
	}
	pub(crate) fn admin_request(
		&self, http: &reqwest::Client, method: reqwest::Method, path: &str,
	) -> Result<reqwest::RequestBuilder, crate::ingress::server::Failure> {
		let url = self.0.join(path).map_err(|_| crate::ingress::server::Failure::Url)?;
		Ok(http.request(method, url))
	}
	pub(crate) fn report_startup(
		&self, health: crate::client::UpstreamResult<crate::client::HealthResponse>,
	) -> anyhow::Result<()> {
		match health {
			Ok(health) => {
				tracing::info!(server = %self.0, ?health, "upstream reachable");
				Ok(())
			},
			Err(error) => Err(anyhow::anyhow!("cannot reach loupe-server at {}: {error}", self.0)),
		}
	}
}
struct WebServerUrlDecoder;
impl Validate<&OsStr, Config> for WebServerUrlDecoder {
	type Output = ConfigUrl;
	type Error = Failure;
	fn validate<'v>(
		self, raw: Unvalidated<'v, &OsStr>, _: Mark<'v, Config>,
	) -> Result<Self::Output, Failure> {
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::ConfigUrl);
		let url = reqwest::Url::parse(raw.get().to_str().ok_or(Failure::NativeUtf8)?)
			.map_err(|_| Failure::Url)?;
		#[cfg(fuzzing)]
		observe(crate::fuzz_support::Entry::ConfigUrl, url.as_str().as_bytes(), None);
		Ok(ConfigUrl(url, PhantomData))
	}
}
struct WebHostPathDecoder;
impl Validate<&OsStr, Config> for WebHostPathDecoder {
	type Output = ConfigPath;
	type Error = Failure;
	fn validate<'v>(
		self, raw: Unvalidated<'v, &OsStr>, _: Mark<'v, Config>,
	) -> Result<Self::Output, Failure> {
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::ConfigPath);
		let path = PathBuf::from(raw.get());
		#[cfg(fuzzing)]
		observe(crate::fuzz_support::Entry::ConfigPath, path.as_os_str().as_encoded_bytes(), None);
		Ok(ConfigPath(path, PhantomData))
	}
}
struct WebPemInputDecoder;
impl Validate<&OsStr, Config> for WebPemInputDecoder {
	type Output = ConfigPem;
	type Error = Failure;
	fn validate<'v>(
		self, raw: Unvalidated<'v, &OsStr>, _: Mark<'v, Config>,
	) -> Result<Self::Output, Failure> {
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::ConfigPem);
		let pem = PemInput::from(raw.get().to_str().ok_or(Failure::NativeUtf8)?);
		#[cfg(fuzzing)]
		observe(
			crate::fuzz_support::Entry::ConfigPem,
			pem.expose().as_bytes(),
			Some(format!("{pem:?}")),
		);
		Ok(ConfigPem(pem, PhantomData))
	}
}
macro_rules! parser {
	($name:ident, $value:ty, $decoder:ident) => {
		#[derive(Clone)]
		pub(super) struct $name;
		impl TypedValueParser for $name {
			type Value = $value;
			#[allow(unsafe_code)]
			fn parse_ref(
				&self, _: &clap::Command, _: Option<&clap::Arg>, value: &OsStr,
			) -> Result<Self::Value, clap::Error> {
				// SAFETY: actual native argument/environment observation before interpretation.
				let token = unsafe { Ingress::<Config>::new() };
				Untrusted::new(value, token).validate($decoder).map_err(clap_error)
			}
		}
	};
}
parser!(UrlParser, ConfigUrl, WebServerUrlDecoder);
parser!(PathParser, ConfigPath, WebHostPathDecoder);
parser!(PemParser, ConfigPem, WebPemInputDecoder);
struct WebFilePemDecoder;
impl Validate<&str, Config> for WebFilePemDecoder {
	type Output = ();
	type Error = std::convert::Infallible;
	fn validate<'v>(
		self, _: Unvalidated<'v, &str>, _: Mark<'v, Config>,
	) -> Result<Self::Output, Self::Error> {
		// The guarded shared reader checks UTF-8; the final TLS sink checks PEM grammar.
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::ConfigFile);
		Ok(())
	}
}
impl ConfigPath {
	#[cfg(test)]
	pub(super) fn fixture_path(&self) -> &std::path::Path {
		&self.0
	}
	#[allow(unsafe_code)]
	fn read_tls_pem(&self) -> Result<ConfigTlsPem, Failure> {
		let pem = loupe_tls::read_pem_file(&self.0).map_err(|_| Failure::File)?;
		// SAFETY: actual guarded file contents, before TLS/PEM interpretation.
		let token = unsafe { Ingress::<Config>::new() };
		Untrusted::new(pem.expose().as_str(), token)
			.validate(WebFilePemDecoder)
			.unwrap_or_else(|never| match never {});
		Ok(ConfigTlsPem(pem, PhantomData))
	}
}
impl ConfigTlsPem {
	#[cfg(test)]
	pub(super) fn expose(&self) -> &str {
		self.0.expose()
	}
	fn observe(&self) {
		#[cfg(fuzzing)]
		observe(
			crate::fuzz_support::Entry::ConfigSelected,
			self.0.expose().as_bytes(),
			Some(format!("{self:?}")),
		);
	}
}
pub(super) fn tls_client(
	ca: ConfigTlsPem, cert: ConfigTlsPem, key: ConfigTlsPem,
) -> anyhow::Result<reqwest::Client> {
	use anyhow::Context;
	let tls = loupe_tls::reqwest_client_config(cert.0.expose(), key.0.expose(), ca.0.expose())?;
	reqwest::Client::builder().use_preconfigured_tls(tls).build().context("building reqwest client")
}
pub(super) fn selected(
	pem: &Option<ConfigPem>, pem_b64: &Option<ConfigPem>, path: Option<&ConfigPath>,
	missing: &'static str,
) -> anyhow::Result<ConfigTlsPem> {
	let selected = if let Some(pem) = pem.as_ref().filter(|p| !p.0.expose().is_empty()) {
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::ConfigRaw);
		ConfigTlsPem(pem.0.clone().into_pem(), PhantomData)
	} else if let Some(pem) = pem_b64.as_ref().filter(|p| !p.0.expose().is_empty()) {
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::ConfigBase64);
		ConfigTlsPem(
			loupe_tls::decode_pem_base64(pem.0.expose().trim()).map_err(|_| Failure::Base64)?,
			PhantomData,
		)
	} else {
		path.ok_or_else(|| anyhow::anyhow!(missing))?.read_tls_pem()?
	};
	selected.observe();
	Ok(selected)
}
#[cfg(fuzzing)]
fn observe(owner: crate::fuzz_support::Entry, bytes: &[u8], debug: Option<String>) {
	crate::fuzz_support::record(crate::fuzz_support::Observation::ConfigValue {
		owner,
		bytes: bytes.to_vec(),
		pointer: bytes.as_ptr() as usize,
		debug,
	});
}
#[cfg(fuzzing)]
pub(crate) fn fuzz_parse(
	parser: crate::fuzz_support::ConfigParser, value: &OsStr,
) -> Result<Vec<u8>, String> {
	let command = clap::Command::new("web-native-fixture");
	match parser {
		crate::fuzz_support::ConfigParser::Url => {
			UrlParser.parse_ref(&command, None, value).map(|url| url.0.as_str().as_bytes().to_vec())
		},
		crate::fuzz_support::ConfigParser::Path => PathParser
			.parse_ref(&command, None, value)
			.map(|path| path.0.as_os_str().as_encoded_bytes().to_vec()),
		crate::fuzz_support::ConfigParser::Pem => {
			PemParser.parse_ref(&command, None, value).map(|pem| pem.0.expose().as_bytes().to_vec())
		},
	}
	.map_err(|error| error.to_string())
}
#[cfg(fuzzing)]
pub(crate) fn fuzz_selected(
	raw: Option<&str>, base64: Option<&str>, path: Option<&std::path::Path>,
) -> Result<Vec<u8>, String> {
	let command = clap::Command::new("web-selected-fixture");
	let raw = raw
		.map(|s| PemParser.parse_ref(&command, None, OsStr::new(s)))
		.transpose()
		.map_err(|e| e.to_string())?;
	let base64 = base64
		.map(|s| PemParser.parse_ref(&command, None, OsStr::new(s)))
		.transpose()
		.map_err(|e| e.to_string())?;
	let path = path
		.map(|p| PathParser.parse_ref(&command, None, p.as_os_str()))
		.transpose()
		.map_err(|e| e.to_string())?;
	selected(&raw, &base64, path.as_ref(), "missing fixture PEM source")
		.map(|pem| {
			assert_eq!(format!("{pem:?}"), "[redacted]");
			assert_eq!(format!("{pem}"), "[redacted]");
			observe(
				crate::fuzz_support::Entry::ConfigSelected,
				pem.0.expose().as_bytes(),
				Some(format!("{pem:?}")),
			);
			pem.0.expose().as_bytes().to_vec()
		})
		.map_err(|error| {
			let display = error.to_string();
			for cause in error.chain() {
				assert_eq!(cause.to_string(), display, "selected Config error retained a source");
			}
			display
		})
}
