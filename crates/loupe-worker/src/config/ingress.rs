//! Original Config file bytes, parsed in one fixed mark scope. Scalar defaults
//! and final effective-config validation remain in the existing owner.

use std::path::PathBuf;

use loupe_core::source_migration::text::BoundedText;
use loupe_core::text::{Normalization, TextPolicy, Whitespace};
use loupe_provenance::{Config, Mark, Unvalidated, Validate};

struct WorkerFileText;
impl TextPolicy for WorkerFileText {
	const FIELD: &'static str = "worker_config";
	const MAX_BYTES: usize = loupe_core::text::policy::LEGACY_TEXT_MAX_BYTES;
	const MAX_CHARS: usize = loupe_core::text::policy::LEGACY_TEXT_MAX_BYTES;
	const MULTILINE: bool = false;
	const ALLOW_EMPTY: bool = true;
	const NORMALIZATION: Normalization = Normalization::Exact;
	const WHITESPACE: Whitespace = Whitespace::Significant;
}
type FileText = BoundedText<WorkerFileText, Config>;
struct NativeConfiguredPath {
	path: PathBuf,
	source: std::marker::PhantomData<Config>,
}
impl NativeConfiguredPath {
	fn new(_: &Mark<'_, Config>, path: PathBuf) -> Self {
		Self { path, source: std::marker::PhantomData }
	}
	fn into_legacy_native(self) -> PathBuf {
		self.path
	}
}

pub(super) struct DecodedWorkerFileConfig {
	scalars: super::FileConfig,
	server_url: Option<FileText>,
	allowlist: Option<Vec<FileText>>,
	log_level: Option<FileText>,
	claude_model: Option<FileText>,
	claude_effort: Option<FileText>,
	codex_model: Option<FileText>,
	codex_effort: Option<FileText>,
	bkb_api_url: Option<FileText>,
	ca_cert: Option<NativeConfiguredPath>,
	cert: Option<NativeConfiguredPath>,
	key: Option<NativeConfiguredPath>,
	cache_dir: Option<NativeConfiguredPath>,
}
pub(super) struct WorkerFileConfigDecoder;
/// Parser failures deliberately retain no TOML error object: it owns the
/// source document and interpolates arbitrary keys/values in Display/Debug.
#[derive(Debug, thiserror::Error)]
#[error("worker_config: {reason} at bytes {start}..{end}")]
struct ConfigSyntaxError {
	reason: &'static str,
	start: usize,
	end: usize,
}
impl From<toml::de::Error> for ConfigSyntaxError {
	fn from(error: toml::de::Error) -> Self {
		let reason =
			["unknown field", "unknown variant", "invalid type", "invalid value", "missing field"]
				.into_iter()
				.find(|prefix| error.message().starts_with(prefix))
				.unwrap_or("invalid TOML");
		let span = error.span().unwrap_or(0..0);
		Self { reason, start: span.start, end: span.end }
	}
}
impl Validate<&[u8], Config> for WorkerFileConfigDecoder {
	type Output = DecodedWorkerFileConfig;
	type Error = anyhow::Error;
	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, mark: Mark<'view, Config>,
	) -> anyhow::Result<Self::Output> {
		let text = std::str::from_utf8(u.get())?;
		let mut cfg: super::FileConfig = toml::from_str(text).map_err(ConfigSyntaxError::from)?;
		macro_rules! text {
			($field:expr) => {
				$field.take().map(|v| FileText::new(&mark, &v)).transpose()?
			};
		}
		macro_rules! path {
			($field:expr) => {
				$field.take().map(|v| NativeConfiguredPath::new(&mark, v))
			};
		}
		Ok(DecodedWorkerFileConfig {
			server_url: text!(cfg.server.url),
			allowlist: cfg
				.sandbox
				.allowlist
				.take()
				.map(|values| {
					values
						.into_iter()
						.map(|v| FileText::new(&mark, &v))
						.collect::<Result<Vec<_>, _>>()
				})
				.transpose()?,
			log_level: text!(cfg.logging.level),
			claude_model: text!(cfg.agents.claude.model),
			claude_effort: text!(cfg.agents.claude.effort),
			codex_model: text!(cfg.agents.codex.model),
			codex_effort: text!(cfg.agents.codex.effort),
			bkb_api_url: text!(cfg.bkb.api_url),
			ca_cert: path!(cfg.tls.ca_cert),
			cert: path!(cfg.tls.cert),
			key: path!(cfg.tls.key),
			cache_dir: path!(cfg.cache.dir),
			scalars: cfg,
		})
	}
}
impl DecodedWorkerFileConfig {
	/// Temporary concrete legacy exit. No already-decoded string is re-minted;
	/// M removes this projection when WorkerConfig itself retains sources.
	pub(super) fn into_legacy(self) -> super::FileConfig {
		let mut cfg = self.scalars;
		cfg.server.url = self.server_url.map(|v| v.expose().to_owned());
		cfg.sandbox.allowlist =
			self.allowlist.map(|v| v.into_iter().map(|s| s.expose().to_owned()).collect());
		cfg.logging.level = self.log_level.map(|v| v.expose().to_owned());
		cfg.agents.claude.model = self.claude_model.map(|v| v.expose().to_owned());
		cfg.agents.claude.effort = self.claude_effort.map(|v| v.expose().to_owned());
		cfg.agents.codex.model = self.codex_model.map(|v| v.expose().to_owned());
		cfg.agents.codex.effort = self.codex_effort.map(|v| v.expose().to_owned());
		cfg.bkb.api_url = self.bkb_api_url.map(|v| v.expose().to_owned());
		cfg.tls.ca_cert = self.ca_cert.map(NativeConfiguredPath::into_legacy_native);
		cfg.tls.cert = self.cert.map(NativeConfiguredPath::into_legacy_native);
		cfg.tls.key = self.key.map(NativeConfiguredPath::into_legacy_native);
		cfg.cache.dir = self.cache_dir.map(NativeConfiguredPath::into_legacy_native);
		cfg
	}
}
