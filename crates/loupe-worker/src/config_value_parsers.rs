//! The Clap value-parser boundary receives original argv/environment OsStr
//! values before their text, URL or native-path interpretation.

use std::ffi::OsStr;
use std::path::PathBuf;

use clap::builder::{TypedValueParser, ValueParserFactory};
use loupe_core::text::BoundedText;
use loupe_provenance::{Config, Ingress, Mark, Untrusted, Unvalidated, Validate};

pub use crate::config::value::{ConfiguredPath, ConfiguredText, ConfiguredUrl};

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
		Ok(ConfiguredText::Argument(BoundedText::new(&mark, text)?))
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
		ConfiguredUrl::parse(ConfiguredText::Argument(BoundedText::new(&mark, text)?))
	}
}
struct WorkerNativePathArgument;
impl Validate<&OsStr, Config> for WorkerNativePathArgument {
	type Output = ConfiguredPath;
	type Error = std::convert::Infallible;
	fn validate<'view>(
		self, u: Unvalidated<'view, &OsStr>, mark: Mark<'view, Config>,
	) -> Result<Self::Output, Self::Error> {
		Ok(ConfiguredPath::admitted(&mark, PathBuf::from(u.get())))
	}
}
macro_rules! parser {
	($name:ident, $output:ty, $validator:expr) => {
		#[derive(Clone)]
		pub struct $name;
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
