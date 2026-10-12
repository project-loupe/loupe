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
