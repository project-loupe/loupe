//! Concrete Config ingress at Clap/native-file/selected-PEM boundaries.
//! Private legacy projections are removed at M; native paths are never RepoPath.
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
struct ConfigUrl(reqwest::Url, PhantomData<Config>);
impl ConfigUrl {
	fn into_url_legacy(self) -> reqwest::Url {
		#[cfg(fuzzing)]
		observe(crate::fuzz_support::Entry::ConfigUrl, self.0.as_str().as_bytes(), None);
		self.0
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
		let url = raw.get().to_str().ok_or(Failure::NativeUtf8)?;
		reqwest::Url::parse(url).map(|url| ConfigUrl(url, PhantomData)).map_err(|_| Failure::Url)
	}
}
#[derive(Clone)]
pub(super) struct UrlParser;
impl TypedValueParser for UrlParser {
	type Value = reqwest::Url;
	#[allow(unsafe_code)]
	fn parse_ref(
		&self, _: &clap::Command, _: Option<&clap::Arg>, value: &OsStr,
	) -> Result<Self::Value, clap::Error> {
		// SAFETY: actual native URL argument or environment value, before URL decoding.
		let token = unsafe { Ingress::<Config>::new() };
		Untrusted::new(value, token)
			.validate(WebServerUrlDecoder)
			.map(ConfigUrl::into_url_legacy)
			.map_err(clap_error)
	}
}
struct ConfigPath(PathBuf, PhantomData<Config>);
impl ConfigPath {
	fn into_path_legacy(self) -> PathBuf {
		#[cfg(fuzzing)]
		observe(
			crate::fuzz_support::Entry::ConfigPath,
			self.0.as_os_str().as_encoded_bytes(),
			None,
		);
		self.0
	}
}
struct WebHostPathDecoder;
impl Validate<&OsStr, Config> for WebHostPathDecoder {
	type Output = ConfigPath;
	type Error = std::convert::Infallible;
	fn validate<'v>(
		self, raw: Unvalidated<'v, &OsStr>, _: Mark<'v, Config>,
	) -> Result<Self::Output, Self::Error> {
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::ConfigPath);
		Ok(ConfigPath(PathBuf::from(raw.get()), PhantomData))
	}
}
#[derive(Clone)]
pub(super) struct PathParser;
impl TypedValueParser for PathParser {
	type Value = PathBuf;
	#[allow(unsafe_code)]
	fn parse_ref(
		&self, _: &clap::Command, _: Option<&clap::Arg>, value: &OsStr,
	) -> Result<Self::Value, clap::Error> {
		// SAFETY: actual native path argument or environment value, before file use.
		let token = unsafe { Ingress::<Config>::new() };
		let path = Untrusted::new(value, token)
			.validate(WebHostPathDecoder)
			.unwrap_or_else(|never| match never {});
		Ok(path.into_path_legacy())
	}
}
struct ConfigPem(PemInput, PhantomData<Config>);
impl ConfigPem {
	fn into_input_legacy(self) -> PemInput {
		#[cfg(fuzzing)]
		observe(
			crate::fuzz_support::Entry::ConfigPem,
			self.0.expose().as_bytes(),
			Some(format!("{:?}", self.0)),
		);
		self.0
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
		let text = raw.get().to_str().ok_or(Failure::NativeUtf8)?;
		Ok(ConfigPem(PemInput::from(text), PhantomData))
	}
}
#[derive(Clone)]
pub(super) struct PemParser;
impl TypedValueParser for PemParser {
	type Value = PemInput;
	#[allow(unsafe_code)]
	fn parse_ref(
		&self, _: &clap::Command, _: Option<&clap::Arg>, value: &OsStr,
	) -> Result<Self::Value, clap::Error> {
		// SAFETY: actual native PEM/base64 argument or environment value, before decoding.
		let token = unsafe { Ingress::<Config>::new() };
		Untrusted::new(value, token)
			.validate(WebPemInputDecoder)
			.map(ConfigPem::into_input_legacy)
			.map_err(clap_error)
	}
}
struct ConfigTlsPem(Secret<String>, PhantomData<Config>);
impl ConfigTlsPem {
	fn move_legacy(self) -> Secret<String> {
		#[cfg(fuzzing)]
		observe(
			crate::fuzz_support::Entry::ConfigSelected,
			self.0.expose().as_bytes(),
			Some(format!("{:?}", self.0)),
		);
		self.0
	}
}
struct WebBase64PemDecoder;
impl Validate<&str, Config> for WebBase64PemDecoder {
	type Output = ConfigTlsPem;
	type Error = Failure;
	fn validate<'v>(
		self, raw: Unvalidated<'v, &str>, _: Mark<'v, Config>,
	) -> Result<Self::Output, Failure> {
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::ConfigBase64);
		loupe_tls::decode_pem_base64(raw.get().trim())
			.map(|pem| ConfigTlsPem(pem, PhantomData))
			.map_err(|_| Failure::Base64)
	}
}
struct WebRawPemDecoder;
impl Validate<&PemInput, Config> for WebRawPemDecoder {
	type Output = ConfigTlsPem;
	type Error = std::convert::Infallible;
	fn validate<'v>(
		self, raw: Unvalidated<'v, &PemInput>, _: Mark<'v, Config>,
	) -> Result<Self::Output, Self::Error> {
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::ConfigRaw);
		Ok(ConfigTlsPem((*raw.get()).clone().into_pem(), PhantomData))
	}
}
struct WebTlsPemEgress;
impl Validate<&str, Config> for WebTlsPemEgress {
	type Output = ();
	type Error = std::convert::Infallible;
	fn validate<'v>(
		self, _: Unvalidated<'v, &str>, _: Mark<'v, Config>,
	) -> Result<(), Self::Error> {
		// TLS performs PEM grammar admission; web adds no text cap or normalization.
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::ConfigFile);
		Ok(())
	}
}
impl WebTlsPemEgress {
	fn move_legacy(pem: Secret<String>, token: Ingress<Config>) -> Secret<String> {
		Untrusted::new(pem.expose().as_str(), token)
			.validate(Self)
			.unwrap_or_else(|never| match never {});
		#[cfg(fuzzing)]
		observe(
			crate::fuzz_support::Entry::ConfigSelected,
			pem.expose().as_bytes(),
			Some(format!("{pem:?}")),
		);
		pem
	}
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
			UrlParser.parse_ref(&command, None, value).map(|url| url.as_str().as_bytes().to_vec())
		},
		crate::fuzz_support::ConfigParser::Path => PathParser
			.parse_ref(&command, None, value)
			.map(|path| path.as_os_str().as_encoded_bytes().to_vec()),
		crate::fuzz_support::ConfigParser::Pem => {
			PemParser.parse_ref(&command, None, value).map(|pem| pem.expose().as_bytes().to_vec())
		},
	}
	.map_err(|error| error.to_string())
}
#[cfg(fuzzing)]
pub(crate) fn fuzz_selected(
	raw: Option<&str>, base64: Option<&str>, path: Option<&std::path::Path>,
) -> Result<Vec<u8>, String> {
	let path = path.map(std::path::Path::to_path_buf);
	selected(
		&raw.map(PemInput::from),
		&base64.map(PemInput::from),
		path.as_ref(),
		"missing fixture PEM source",
	)
	.map(|pem| {
		assert_eq!(format!("{pem:?}"), "[redacted]");
		assert_eq!(format!("{pem}"), "[redacted]");
		observe(
			crate::fuzz_support::Entry::ConfigSelected,
			pem.expose().as_bytes(),
			Some(format!("{pem:?}")),
		);
		pem.expose().as_bytes().to_vec()
	})
	.map_err(|error| {
		let display = error.to_string();
		for cause in error.chain() {
			assert_eq!(cause.to_string(), display, "selected Config error retained a source");
		}
		display
	})
}
/// Existing public ConnArgs fields are temporary I exits. Selection is a real
/// Config read too, including direct programmatic ConnArgs construction.
#[allow(unsafe_code)]
pub(super) fn selected(
	pem: &Option<PemInput>, pem_b64: &Option<PemInput>, path: Option<&PathBuf>,
	missing: &'static str,
) -> anyhow::Result<Secret<String>> {
	// SAFETY: this is the actual selected configuration read; interpretation
	// stays under fixed Config validators, never a caller-selected source.
	let token = unsafe { Ingress::<Config>::new() };
	if let Some(pem) = pem.as_ref().filter(|p| !p.expose().is_empty()) {
		return Ok(Untrusted::new(pem, token)
			.validate(WebRawPemDecoder)
			.unwrap_or_else(|never| match never {})
			.move_legacy());
	}
	if let Some(pem) = pem_b64.as_ref().filter(|p| !p.expose().is_empty()) {
		return Ok(Untrusted::new(pem.expose(), token)
			.validate(WebBase64PemDecoder)?
			.move_legacy());
	}
	let path = path.ok_or_else(|| anyhow::anyhow!(missing))?;
	// The shared guarded reader owns I/O and its existing UTF-8 check. Capture
	// its original text before any application TLS/PEM interpretation.
	let pem = loupe_tls::read_pem_file(path).map_err(|_| Failure::File)?;
	Ok(WebTlsPemEgress::move_legacy(pem, token))
}
