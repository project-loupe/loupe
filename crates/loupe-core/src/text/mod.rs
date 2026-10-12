//! Validated, field-bound untrusted text. Use `expose()` only at deliberate
//! rendering or persistence boundaries; `Debug` never contains the payload.
//!
//! ```compile_fail
//! use loupe_core::text::{BoundedText, policy::{Title, Objective}};
//! fn title(_: BoundedText<Title>) {}
//! title(BoundedText::<Objective>::new("not a title").unwrap());
//! ```

pub(crate) mod checked;
pub(crate) mod json;
pub(crate) mod json_string;
pub mod policy;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

pub use json::BoundedJson;
pub use json_string::decode_json_string_bounded;
use serde::{Deserialize, Serialize};
use unicode_general_category::{get_general_category, GeneralCategory as G};
use unicode_normalization::UnicodeNormalization;

/// Whether field validation normalizes prose or retains admitted UTF-8 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Normalization {
	Semantic,
	Exact,
}

/// Whether boundary whitespace and repeated blank lines are meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Whitespace {
	Prose,
	Significant,
}

pub trait TextPolicy {
	const FIELD: &'static str;
	const MAX_CHARS: usize;
	const MAX_BYTES: usize;
	const MULTILINE: bool;
	const ALLOW_EMPTY: bool = false;
	const NORMALIZATION: Normalization = Normalization::Semantic;
	const WHITESPACE: Whitespace = Whitespace::Prose;
	const ALLOW_CR: bool = false;
}
pub trait IdentPolicy {
	const FIELD: &'static str;
	const MAX_LEN: usize;
	fn accepts(s: &str) -> bool;
}
pub trait AnchorPolicy: TextPolicy {}
pub trait JsonPolicy {
	const FIELD: &'static str;
	const MAX_BYTES: usize;
	const MAX_DEPTH: usize;
	const MAX_NODES: usize;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
	Character,
	Chars,
	Bytes,
	Whitespace,
	Empty,
	Identifier,
	IdentityLocation,
	IdentityHash,
	IdentityTransientId,
	Path,
	JsonSyntax,
	JsonDepth,
	JsonNodes,
	JsonDuplicateKey,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Error {
	pub field: &'static str,
	pub rule: Rule,
	pub code_point: Option<u32>,
}
impl Error {
	pub fn new(field: &'static str, rule: Rule) -> Self {
		Self { field, rule, code_point: None }
	}
}
impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}: {:?}", self.field, self.rule)?;
		if let Some(point) = self.code_point {
			write!(f, " (U+{point:04X})")?;
		}
		Ok(())
	}
}
impl std::error::Error for Error {}
impl fmt::Debug for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}

fn characters(
	field: &'static str, text: &str, multiline: bool, allow_cr: bool,
) -> Result<(), Error> {
	for c in text.chars() {
		if multiline && (matches!(c, '\n' | '\t') || (allow_cr && c == '\r')) {
			continue;
		}
		let cp = c as u32;
		if rejects_code_point(cp) {
			return Err(Error { field, rule: Rule::Character, code_point: Some(cp) });
		}
	}
	Ok(())
}

/// The character policy, independent of UTF-8 decoding and multiline exceptions.
pub(crate) fn rejects_code_point(cp: u32) -> bool {
	let Some(c) = char::from_u32(cp) else { return true };
	matches!(
		get_general_category(c),
		G::Control
			| G::Format
			| G::Unassigned
			| G::PrivateUse
			| G::LineSeparator
			| G::ParagraphSeparator
	) || (0xfdd0..=0xfdef).contains(&cp)
		|| cp & 0xffff >= 0xfffe
}

/// Count UTF-8 leading bytes; callers supply the bytes of a valid `str`.
/// Preserve the character-limit error before the byte-limit error.
pub(crate) fn count_within(text: &[u8], max_chars: usize, max_bytes: usize) -> Result<(), Rule> {
	if text.iter().filter(|byte| **byte & 0xc0 != 0x80).count() > max_chars {
		return Err(Rule::Chars);
	}
	if text.len() > max_bytes {
		return Err(Rule::Bytes);
	}
	Ok(())
}

fn limits<P: TextPolicy>(text: &str) -> Result<(), Error> {
	count_within(text.as_bytes(), P::MAX_CHARS, P::MAX_BYTES)
		.map_err(|rule| Error::new(P::FIELD, rule))
}

pub(crate) fn normalized(raw: &str) -> String {
	raw.replace("\r\n", "\n").replace('\r', "\n").nfc().collect()
}

#[derive(Clone, PartialEq, Eq)]
pub struct BoundedText<P: TextPolicy>(String, PhantomData<P>);
#[derive(Clone, PartialEq, Eq)]
pub struct Identifier<P: IdentPolicy>(String, PhantomData<P>);
#[derive(Clone, PartialEq, Eq)]
pub struct Anchor<P: AnchorPolicy>(String, PhantomData<P>);
#[derive(Clone, PartialEq, Eq)]
pub struct RepoPath(String);

/// Reject oversized prose before allocating, with a conservative margin for
/// CRLF folding and NFC contraction. The exact normalized caps follow below.
/// This is not valid for anchors: whitespace collapse can shrink them without
/// a bound on the ratio between raw and normalized lengths.
fn oversized(field: &'static str, raw: &str, max_bytes: usize) -> Result<(), Error> {
	if raw.len() > max_bytes.saturating_mul(4) {
		return Err(Error::new(field, Rule::Bytes));
	}
	Ok(())
}

impl<P: TextPolicy> BoundedText<P> {
	pub fn new(raw: &str) -> Result<Self, Error> {
		checked::text::<P>(raw).map(|text| Self(text, PhantomData))
	}
}
impl<P: IdentPolicy> Identifier<P> {
	pub fn new(raw: &str) -> Result<Self, Error> {
		checked::identifier::<P>(raw).map(|text| Self(text, PhantomData))
	}
}
impl<P: AnchorPolicy> Anchor<P> {
	pub fn new(raw: &str) -> Result<Self, Error> {
		checked::anchor::<P>(raw).map(|text| Self(text, PhantomData))
	}
}
impl RepoPath {
	pub fn new(raw: &str) -> Result<Self, Error> {
		checked::path(raw).map(Self)
	}
	pub fn expose(&self) -> &str {
		&self.0
	}
}

/// Path structure after the constructor's character and byte-limit checks.
pub(crate) fn is_repo_path(raw: &[u8]) -> bool {
	!raw.contains(&b'\\')
		&& !raw.contains(&0)
		&& !raw.split(|byte| *byte == b'/').any(|part| matches!(part, b"" | b"." | b".."))
}

macro_rules! text_impls {
	($ty:ident, $policy:ident) => {
		impl<P: $policy> $ty<P> {
			pub fn expose(&self) -> &str {
				&self.0
			}
		}
		impl<P: $policy> fmt::Debug for $ty<P> {
			fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				write!(f, "{}<{}>(len={})", stringify!($ty), P::FIELD, self.0.len())
			}
		}
		impl<P: $policy> FromStr for $ty<P> {
			type Err = Error;
			fn from_str(raw: &str) -> Result<Self, Error> {
				Self::new(raw)
			}
		}
		impl<P: $policy> TryFrom<String> for $ty<P> {
			type Error = Error;
			fn try_from(raw: String) -> Result<Self, Error> {
				Self::new(&raw)
			}
		}
		impl<P: $policy> Serialize for $ty<P> {
			fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
				s.serialize_str(&self.0)
			}
		}
		impl<'de, P: $policy> Deserialize<'de> for $ty<P> {
			fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
				Self::new(&String::deserialize(d)?).map_err(serde::de::Error::custom)
			}
		}
	};
}
text_impls!(BoundedText, TextPolicy);
text_impls!(Identifier, IdentPolicy);
text_impls!(Anchor, AnchorPolicy);

impl fmt::Debug for RepoPath {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "RepoPath(len={})", self.0.len())
	}
}
impl FromStr for RepoPath {
	type Err = Error;
	fn from_str(raw: &str) -> Result<Self, Error> {
		Self::new(raw)
	}
}
impl TryFrom<String> for RepoPath {
	type Error = Error;
	fn try_from(raw: String) -> Result<Self, Error> {
		Self::new(&raw)
	}
}
impl Serialize for RepoPath {
	fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		s.serialize_str(&self.0)
	}
}
impl<'de> Deserialize<'de> for RepoPath {
	fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		Self::new(&String::deserialize(d)?).map_err(serde::de::Error::custom)
	}
}

/// Structured storage reference; protocol adapters may accept path#symbol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
	pub path: RepoPath,
	pub symbol: Option<BoundedText<policy::Symbol>>,
}

#[cfg(test)]
mod json_string_tests;
#[cfg(test)]
mod tests;
