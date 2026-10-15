//! Original Config file bytes, parsed in one fixed mark scope. Scalar defaults
//! and final effective-config validation belong to WorkerConfig.

use loupe_provenance::{Config, Mark, Unvalidated, Validate};

use super::value::{ConfiguredPath, ConfiguredText};

// debug-ok: Private decoder result; text/path fields are redacted and scalars have had their raw fields taken.
#[derive(Debug)]
pub(super) struct DecodedWorkerFileConfig {
	#[cfg(fuzzing)]
	pub(super) original_debug: String,
	pub(super) scalars: super::FileConfig,
	pub(super) server_url: Option<ConfiguredText>,
	pub(super) allowlist: Option<Vec<ConfiguredText>>,
	pub(super) log_level: Option<ConfiguredText>,
	pub(super) claude_model: Option<ConfiguredText>,
	pub(super) claude_effort: Option<ConfiguredText>,
	pub(super) codex_model: Option<ConfiguredText>,
	pub(super) codex_effort: Option<ConfiguredText>,
	pub(super) bkb_api_url: Option<ConfiguredText>,
	pub(super) ca_cert: Option<ConfiguredPath>,
	pub(super) cert: Option<ConfiguredPath>,
	pub(super) key: Option<ConfiguredPath>,
	pub(super) cache_dir: Option<ConfiguredPath>,
}
pub(super) struct WorkerFileConfigDecoder;
/// Parser failures deliberately retain no TOML error object: it owns the
/// source document and interpolates arbitrary keys/values in Display/Debug.
// debug-ok: Only a closed parser category and numeric byte offsets; never the TOML document.
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
		#[cfg(fuzzing)]
		let original_debug = format!("{cfg:?}");
		macro_rules! text {
			($field:expr) => {
				$field.take().map(|v| ConfiguredText::file(&mark, &v)).transpose()?
			};
		}
		macro_rules! path {
			($field:expr) => {
				$field.take().map(|v| ConfiguredPath::admitted(&mark, v))
			};
		}
		Ok(DecodedWorkerFileConfig {
			#[cfg(fuzzing)]
			original_debug,
			server_url: text!(cfg.server.url),
			allowlist: cfg
				.sandbox
				.allowlist
				.take()
				.map(|values| {
					values
						.into_iter()
						.map(|v| ConfiguredText::file(&mark, &v))
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
