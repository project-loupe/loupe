//! The Clap value-parser boundary receives original argv/environment OsStr
//! values before their text, URL or native-path interpretation.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use clap::builder::{TypedValueParser, ValueParserFactory};
use loupe_core::source_migration::text::BoundedText;
use loupe_core::text::{Normalization, TextPolicy, Whitespace};
use loupe_provenance::{Config, Ingress, Mark, Untrusted, Unvalidated, Validate};

#[derive(Debug, Clone)]
pub(super) struct WorkerArgument;
impl TextPolicy for WorkerArgument {
	const FIELD: &'static str = "worker_argument";
	const MAX_BYTES: usize = loupe_core::text::policy::LEGACY_TEXT_MAX_BYTES;
	const MAX_CHARS: usize = loupe_core::text::policy::LEGACY_TEXT_MAX_BYTES;
	const MULTILINE: bool = false;
	const ALLOW_EMPTY: bool = true;
	const NORMALIZATION: Normalization = Normalization::Exact;
	const WHITESPACE: Whitespace = Whitespace::Significant;
}
#[derive(Debug, Clone)]
pub(super) struct ConfiguredText(BoundedText<WorkerArgument, Config>);
impl ConfiguredText {
	pub(super) fn legacy_override(&self) -> String {
		self.0.expose().to_owned()
	}
}
#[derive(Debug, Clone)]
pub(super) struct ConfiguredUrl {
	text: BoundedText<WorkerArgument, Config>,
	url: reqwest::Url,
}
impl ConfiguredUrl {
	pub(super) fn legacy_override(&self) -> reqwest::Url {
		let _ = &self.text;
		self.url.clone()
	}
}
#[derive(Debug, Clone)]
pub(super) struct ConfiguredPath {
	native: PathBuf,
	source: std::marker::PhantomData<Config>,
}
impl ConfiguredPath {
	pub(super) fn as_path(&self) -> &Path {
		&self.native
	}
	pub(super) fn legacy_override(&self) -> PathBuf {
		self.native.clone()
	}
}

#[allow(unsafe_code)]
fn original_argument(value: &OsStr) -> Untrusted<&OsStr, Config> {
	// SAFETY: called only by this module's concrete Clap value parsers, on
	// the original argv/environment value before any value interpretation.
	Untrusted::new(value, unsafe { Ingress::<Config>::new() })
}
struct WorkerTextArgument;
impl Validate<&OsStr, Config> for WorkerTextArgument {
	type Output = ConfiguredText;
	type Error = anyhow::Error;
	fn validate<'view>(
		self, u: Unvalidated<'view, &OsStr>, mark: Mark<'view, Config>,
	) -> anyhow::Result<Self::Output> {
		let text =
			u.get().to_str().ok_or_else(|| anyhow::anyhow!("worker argument is not UTF-8"))?;
		Ok(ConfiguredText(BoundedText::new(&mark, text)?))
	}
}
struct WorkerUrlArgument;
impl Validate<&OsStr, Config> for WorkerUrlArgument {
	type Output = ConfiguredUrl;
	type Error = anyhow::Error;
	fn validate<'view>(
		self, u: Unvalidated<'view, &OsStr>, mark: Mark<'view, Config>,
	) -> anyhow::Result<Self::Output> {
		let text = u.get().to_str().ok_or_else(|| anyhow::anyhow!("worker URL is not UTF-8"))?;
		let text = BoundedText::new(&mark, text)?;
		let url = reqwest::Url::parse(text.expose())?;
		Ok(ConfiguredUrl { text, url })
	}
}
struct WorkerNativePathArgument;
impl Validate<&OsStr, Config> for WorkerNativePathArgument {
	type Output = ConfiguredPath;
	type Error = std::convert::Infallible;
	fn validate<'view>(
		self, u: Unvalidated<'view, &OsStr>, _: Mark<'view, Config>,
	) -> Result<Self::Output, Self::Error> {
		Ok(ConfiguredPath { native: PathBuf::from(u.get()), source: std::marker::PhantomData })
	}
}
macro_rules! parser {
	($name:ident, $output:ty, $validator:expr) => {
		#[derive(Clone)]
		pub(super) struct $name;
		impl TypedValueParser for $name {
			type Value = $output;
			fn parse_ref(
				&self, command: &clap::Command, _: Option<&clap::Arg>, value: &OsStr,
			) -> Result<Self::Value, clap::Error> {
				original_argument(value).validate($validator).map_err(|error| {
					clap::Error::raw(clap::error::ErrorKind::ValueValidation, format!("{error}"))
						.with_cmd(command)
				})
			}
		}
		impl ValueParserFactory for $output {
			type Parser = $name;
			fn value_parser() -> Self::Parser {
				$name
			}
		}
	};
}
parser!(ConfiguredTextParser, ConfiguredText, WorkerTextArgument);
parser!(ConfiguredUrlParser, ConfiguredUrl, WorkerUrlArgument);
parser!(ConfiguredPathParser, ConfiguredPath, WorkerNativePathArgument);

/// The temporary, named Config-to-legacy override exit. All textual/path
/// inputs were admitted by their actual Clap owner; this never mints a token.
pub(super) struct WorkerOverridesDecoder;
impl WorkerOverridesDecoder {
	pub(super) fn into_legacy(
		args: &super::RunArgs,
	) -> loupe_worker::config::WorkerConfigOverrides {
		loupe_worker::config::WorkerConfigOverrides {
			server_url: args.server_url.as_ref().map(ConfiguredUrl::legacy_override),
			ca_cert: args.ca_cert.as_ref().map(ConfiguredPath::legacy_override),
			cert: args.cert.as_ref().map(ConfiguredPath::legacy_override),
			key: args.key.as_ref().map(ConfiguredPath::legacy_override),
			cache_dir: args.cache_dir.as_ref().map(ConfiguredPath::legacy_override),
			max_cache_gb: args.max_cache_gb,
			max_workdir_gb: args.max_workdir_gb,
			disable_sandbox: args.disable_sandbox,
			sandbox_network: args.sandbox_network,
			sandbox_allowlist: args
				.sandbox_allowlist
				.as_ref()
				.map(|v| v.iter().map(ConfiguredText::legacy_override).collect()),
			log_level: args.log_level.as_ref().map(ConfiguredText::legacy_override),
			log_json: args.log_json,
			log_agent_output: args.log_agent_output,
			scan_agent: args.scan_agent,
			verify_agent: args.verify_agent,
			claude_model: args.claude_model.as_ref().map(ConfiguredText::legacy_override),
			claude_effort: args.claude_effort.as_ref().map(ConfiguredText::legacy_override),
			codex_model: args.codex_model.as_ref().map(ConfiguredText::legacy_override),
			codex_effort: args.codex_effort.as_ref().map(ConfiguredText::legacy_override),
			max_concurrent_files: args.max_concurrent_files,
			max_file_bytes: args.max_file_bytes,
			per_request_timeout_seconds: args.per_request_timeout_seconds,
			bkb_api_url: args.bkb_api_url.as_ref().map(ConfiguredText::legacy_override),
			broker_request_ceiling: args.broker_request_ceiling,
			broker_output_ceiling_bytes: args.broker_output_ceiling_bytes,
			broker_token_ceiling: args.broker_token_ceiling,
		}
	}
}
