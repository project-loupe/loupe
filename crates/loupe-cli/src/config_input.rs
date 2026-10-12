//! Config enters at Clap's actual argv/environment value callbacks. The
//! concrete *_legacy parsers end in the old argument shapes until atomic M.
use std::ffi::OsStr;
use std::fmt;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;

use clap::builder::TypedValueParser;
use clap::parser::ValueSource;
use loupe_core::source_migration::text::BoundedText;
use loupe_core::text::{policy, Normalization, TextPolicy, Whitespace};
use loupe_provenance::{Config, Ingress, Mark, Secret, Untrusted, Unvalidated, Validate};

// This is only called by the concrete Clap value parsers below, before any
// domain interpretation. Tests pass synthetic argv through the same callbacks.
#[allow(unsafe_code)]
fn argument(value: &OsStr) -> Untrusted<&OsStr, Config> {
	// SAFETY: this borrowed native value is supplied by Clap's argv/env reader.
	Untrusted::new(value, unsafe { Ingress::new() })
}
fn invalid() -> clap::Error {
	clap::Error::raw(
		clap::error::ErrorKind::ValueValidation,
		"configuration value violates field policy",
	)
}

macro_rules! local_policy {
	($name:ident, $field:literal, $multi:literal) => {
		pub(super) struct $name;
		impl TextPolicy for $name {
			const FIELD: &'static str = $field;
			const MAX_BYTES: usize = policy::LEGACY_TEXT_MAX_BYTES;
			const MAX_CHARS: usize = policy::LEGACY_TEXT_MAX_BYTES;
			const MULTILINE: bool = $multi;
			const ALLOW_EMPTY: bool = true;
			const NORMALIZATION: Normalization = Normalization::Exact;
			const WHITESPACE: Whitespace = Whitespace::Significant;
			const ALLOW_CR: bool = $multi;
		}
	};
}
local_policy!(SearchQuery, "search_query", true);
local_policy!(CertificateName, "certificate_name", false);

macro_rules! text_parser {
	($parser:ident, $validator:ident, $policy:ty) => {
		struct $validator;
		impl Validate<&OsStr, Config> for $validator {
			type Output = BoundedText<$policy, Config>;
			type Error = clap::Error;
			fn validate<'v>(
				self, u: Unvalidated<'v, &OsStr>, mark: Mark<'v, Config>,
			) -> Result<Self::Output, Self::Error> {
				let text = u.get().to_str().ok_or_else(invalid)?;
				BoundedText::new(&mark, text).map_err(|_| invalid())
			}
		}
		#[derive(Clone)]
		pub(super) struct $parser;
		impl TypedValueParser for $parser {
			type Value = String;
			fn parse_ref(
				&self, _: &clap::Command, _: Option<&clap::Arg>, value: &OsStr,
			) -> Result<String, clap::Error> {
				// Explicit temporary Config-text legacy exit; M removes it.
				Ok(argument(value).validate($validator)?.expose().to_owned())
			}
		}
	};
}
text_parser!(CloneUrlLegacy, CloneUrl, policy::CloneUrl);
text_parser!(BranchLegacy, Branch, policy::GitBranch);
text_parser!(OwnerLegacy, Owner, policy::RepoOwner);
text_parser!(RepoLegacy, Repo, policy::RepoName);
text_parser!(WorkerNameLegacy, WorkerName, policy::WorkerName);
text_parser!(SearchLegacy, Search, SearchQuery);
text_parser!(HostnameLegacy, Hostname, CertificateName);

#[derive(Clone)]
pub(super) struct CommonNameLegacy;
impl TypedValueParser for CommonNameLegacy {
	type Value = String;
	fn parse_ref(
		&self, c: &clap::Command, a: Option<&clap::Arg>, value: &OsStr,
	) -> Result<String, clap::Error> {
		HostnameLegacy.parse_ref(c, a, value)
	}
	fn parse_ref_(
		&self, c: &clap::Command, a: Option<&clap::Arg>, value: &OsStr, source: ValueSource,
	) -> Result<String, clap::Error> {
		if source == ValueSource::DefaultValue {
			Ok("loupe-server".to_owned())
		} else {
			self.parse_ref(c, a, value)
		}
	}
}

struct ConfiguredPath(PathBuf, PhantomData<Config>);
struct PathInput;
impl Validate<&OsStr, Config> for PathInput {
	type Output = ConfiguredPath;
	type Error = clap::Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &OsStr>, _: Mark<'v, Config>,
	) -> Result<Self::Output, Self::Error> {
		Ok(ConfiguredPath(PathBuf::from(u.get()), PhantomData))
	}
}
#[derive(Clone)]
pub(super) struct PathLegacy;
impl TypedValueParser for PathLegacy {
	type Value = PathBuf;
	fn parse_ref(
		&self, _: &clap::Command, _: Option<&clap::Arg>, value: &OsStr,
	) -> Result<PathBuf, clap::Error> {
		Ok(argument(value).validate(PathInput)?.0)
	}
}

struct ConfiguredUrl(reqwest::Url, PhantomData<Config>);
struct UrlInput;
impl Validate<&OsStr, Config> for UrlInput {
	type Output = ConfiguredUrl;
	type Error = clap::Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &OsStr>, _: Mark<'v, Config>,
	) -> Result<Self::Output, Self::Error> {
		let raw = u.get().to_str().ok_or_else(invalid)?;
		Ok(ConfiguredUrl(reqwest::Url::parse(raw).map_err(|_| invalid())?, PhantomData))
	}
}
#[derive(Clone)]
pub(super) struct UrlLegacy;
impl TypedValueParser for UrlLegacy {
	type Value = reqwest::Url;
	fn parse_ref(
		&self, _: &clap::Command, _: Option<&clap::Arg>, value: &OsStr,
	) -> Result<reqwest::Url, clap::Error> {
		Ok(argument(value).validate(UrlInput)?.0)
	}
}

struct ConfiguredPem(loupe_tls::PemInput, PhantomData<Config>);
struct PemArgument;
impl Validate<&OsStr, Config> for PemArgument {
	type Output = ConfiguredPem;
	type Error = clap::Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &OsStr>, _: Mark<'v, Config>,
	) -> Result<Self::Output, Self::Error> {
		let raw = u.get().to_str().ok_or_else(invalid)?;
		Ok(ConfiguredPem(raw.into(), PhantomData))
	}
}
#[derive(Clone)]
pub(super) struct PemLegacy;
impl TypedValueParser for PemLegacy {
	type Value = loupe_tls::PemInput;
	fn parse_ref(
		&self, _: &clap::Command, _: Option<&clap::Arg>, value: &OsStr,
	) -> Result<Self::Value, clap::Error> {
		Ok(argument(value).validate(PemArgument)?.0)
	}
}

/// Clap clones handles; each handle shares one guarded Config credential.
pub(super) struct PatInput(Arc<Secret<String>>, PhantomData<Config>);
impl Clone for PatInput {
	fn clone(&self) -> Self {
		Self(Arc::clone(&self.0), PhantomData)
	}
}
impl fmt::Debug for PatInput {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("[redacted]")
	}
}
impl fmt::Display for PatInput {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("[redacted]")
	}
}
impl PatInput {
	pub(super) fn into_pat(self) -> Secret<String> {
		Arc::try_unwrap(self.0).unwrap_or_else(|shared| Secret::new(shared.expose().to_owned()))
	}
	#[cfg(test)]
	pub(super) fn expose(&self) -> &str {
		self.0.expose()
	}
}
struct PatArgument;
impl Validate<&OsStr, Config> for PatArgument {
	type Output = PatInput;
	type Error = clap::Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &OsStr>, _: Mark<'v, Config>,
	) -> Result<Self::Output, Self::Error> {
		let raw = u.get().to_str().ok_or_else(invalid)?;
		Ok(PatInput(Arc::new(Secret::new(raw.to_owned())), PhantomData))
	}
}
#[derive(Clone)]
pub(super) struct Pat;
impl TypedValueParser for Pat {
	type Value = PatInput;
	fn parse_ref(
		&self, _: &clap::Command, _: Option<&clap::Arg>, value: &OsStr,
	) -> Result<Self::Value, clap::Error> {
		argument(value).validate(PatArgument)
	}
}

struct PemRead;
impl Validate<&str, Config> for PemRead {
	type Output = ();
	type Error = std::convert::Infallible;
	fn validate<'v>(
		self, _: Unvalidated<'v, &str>, _: Mark<'v, Config>,
	) -> Result<(), Self::Error> {
		// The existing guarded TLS reader already enforces UTF-8. PEM syntax
		// and trust remain with the existing operation-specific constructors.
		Ok(())
	}
}
#[allow(unsafe_code)]
pub(super) fn read_pem(path: &std::path::Path) -> anyhow::Result<Secret<String>> {
	let owner = loupe_tls::read_pem_file(path)?;
	// SAFETY: exact still-live text returned by this actual Config PEM file read.
	Untrusted::new(owner.expose().as_str(), unsafe { Ingress::new() }).validate(PemRead)?;
	Ok(owner)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn pat_handles_share_guard_and_unique_export_moves_the_allocation() {
		let cmd = clap::Command::new("test");
		let long = format!("{}\n\t\\\"é", "sentinel".repeat(128));
		let input = Pat.parse_ref(&cmd, None, OsStr::new(&long)).unwrap();
		let ptr = input.expose().as_ptr();
		let second = input.clone();
		assert_eq!(ptr, second.expose().as_ptr());
		assert_eq!(format!("{input:?}"), "[redacted]");
		assert_eq!(format!("{input:#?}"), "[redacted]");
		assert_eq!(format!("{input}"), "[redacted]");
		drop(input);
		assert_eq!(second.expose(), long);
		let third = second.clone();
		let exported = third.into_pat();
		assert_eq!(exported.expose(), &long);
		assert_ne!(exported.expose().as_ptr(), ptr, "shared export owns its separate guarded copy");
		let moved = second.into_pat();
		assert_eq!(moved.expose().as_ptr(), ptr);
		assert_eq!(moved.expose(), &long);
	}

	#[cfg(unix)]
	#[test]
	fn native_paths_preserve_distinct_non_utf8_bytes_and_text_errors_are_fixed() {
		use std::os::unix::ffi::{OsStrExt, OsStringExt};
		let command = clap::Command::new("test");
		for raw in [b"relative/\xff".as_slice(), b"relative/\xfe"] {
			let path = PathLegacy.parse_ref(&command, None, OsStr::from_bytes(raw)).unwrap();
			assert_eq!(path.into_os_string().into_vec(), raw);
			let error = Pat.parse_ref(&command, None, OsStr::from_bytes(raw)).unwrap_err();
			assert!(!format!("{error:?}").contains("relative"));
			assert!(error.to_string().contains("configuration value violates field policy"));
		}
	}

	#[test]
	fn exact_query_and_certificate_policies_retain_empty_spacing_and_boundaries() {
		let command = clap::Command::new("test");
		for value in ["", " NFD-e\u{301} *markup* ", "\r\n\tquery\n\n\n"] {
			assert_eq!(SearchLegacy.parse_ref(&command, None, OsStr::new(value)).unwrap(), value);
		}
		for value in ["", " space é *markup* "] {
			assert_eq!(HostnameLegacy.parse_ref(&command, None, OsStr::new(value)).unwrap(), value);
		}
		let exact = "x".repeat(policy::LEGACY_TEXT_MAX_BYTES);
		assert_eq!(SearchLegacy.parse_ref(&command, None, OsStr::new(&exact)).unwrap(), exact);
		assert!(SearchLegacy.parse_ref(&command, None, OsStr::new(&(exact + "x"))).is_err());
		assert_eq!(
			CommonNameLegacy
				.parse_ref_(&command, None, OsStr::new("loupe-server"), ValueSource::DefaultValue)
				.unwrap(),
			"loupe-server"
		);
	}
}
