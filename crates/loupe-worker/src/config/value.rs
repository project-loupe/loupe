//! Config-owned values retained across file/argument precedence and defaults.
use std::path::{Path, PathBuf};

use loupe_core::text::{BoundedText, Normalization, TextPolicy, Whitespace};
use loupe_provenance::{Config, Mark};

macro_rules! policy {
	($name:ident, $field:literal) => {
		pub struct $name;
		impl TextPolicy for $name {
			const FIELD: &'static str = $field;
			const MAX_BYTES: usize = loupe_core::text::policy::LEGACY_TEXT_MAX_BYTES;
			const MAX_CHARS: usize = loupe_core::text::policy::LEGACY_TEXT_MAX_BYTES;
			const MULTILINE: bool = false;
			const ALLOW_EMPTY: bool = true;
			const NORMALIZATION: Normalization = Normalization::Exact;
			const WHITESPACE: Whitespace = Whitespace::Significant;
		}
	};
}
policy!(WorkerArgument, "worker_argument");
policy!(WorkerFileText, "worker_config");

// debug-ok: Dynamic Config text uses redacted BoundedText; Builtin contains only host static literals.
#[derive(Clone, Debug)]
pub enum ConfiguredText {
	Builtin(&'static str),
	Argument(BoundedText<WorkerArgument, Config>),
	File(BoundedText<WorkerFileText, Config>),
}
impl ConfiguredText {
	/// Borrow at an explicit config validation, log, or process-argument sink.
	pub fn for_operation(&self) -> &str {
		match self {
			Self::Builtin(v) => v,
			Self::Argument(v) => v.expose(),
			Self::File(v) => v.expose(),
		}
	}
	pub(crate) fn file(mark: &Mark<'_, Config>, value: &str) -> anyhow::Result<Self> {
		Ok(Self::File(BoundedText::new(mark, value)?))
	}
}

#[derive(Clone)]
pub struct ConfiguredUrl {
	text: ConfiguredText,
	url: reqwest::Url,
}
impl std::fmt::Debug for ConfiguredUrl {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("ConfiguredUrl<Config>([redacted])")
	}
}
impl ConfiguredUrl {
	pub(crate) fn parse(text: ConfiguredText) -> anyhow::Result<Self> {
		let url = reqwest::Url::parse(text.for_operation())?;
		Ok(Self { text, url })
	}
	pub fn for_http(&self) -> &reqwest::Url {
		let _ = &self.text;
		&self.url
	}
}

#[derive(Clone)]
enum NativePathValue {
	Builtin(&'static str),
	Configured(PathBuf, std::marker::PhantomData<Config>),
}
#[derive(Clone)]
pub struct ConfiguredPath(NativePathValue);
impl std::fmt::Debug for ConfiguredPath {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("ConfiguredPath<Config>([redacted])")
	}
}
impl ConfiguredPath {
	pub const fn builtin(value: &'static str) -> Self {
		Self(NativePathValue::Builtin(value))
	}
	pub(crate) fn admitted(_: &Mark<'_, Config>, value: PathBuf) -> Self {
		Self(NativePathValue::Configured(value, std::marker::PhantomData))
	}
	pub fn for_filesystem(&self) -> &Path {
		match &self.0 {
			NativePathValue::Builtin(v) => Path::new(v),
			NativePathValue::Configured(v, _) => v,
		}
	}
	pub(super) fn resolve(mut self, base: &Path) -> Self {
		if let NativePathValue::Configured(path, _) = &mut self.0
			&& !path.is_absolute()
		{
			*path = base.join(&path);
		}
		self
	}
}
