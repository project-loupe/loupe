//! Validated, field-bound untrusted text. Use `expose()` only at deliberate
//! rendering or persistence boundaries; `Debug` never contains the payload.
//!
//! ```compile_fail
//! use loupe_core::text::{BoundedText, policy::{Title, Objective}};
//! fn title(_: BoundedText<Title>) {}
//! title(BoundedText::<Objective>::new("not a title").unwrap());
//! ```

mod json;
pub mod policy;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::LazyLock;

pub use json::BoundedJson;
use regex::Regex;
use serde::{Deserialize, Serialize};
use unicode_general_category::{get_general_category, GeneralCategory as G};
use unicode_normalization::UnicodeNormalization;

pub trait TextPolicy {
	const FIELD: &'static str;
	const MAX_CHARS: usize;
	const MAX_BYTES: usize;
	const MULTILINE: bool;
	const ALLOW_EMPTY: bool = false;
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

fn characters(field: &'static str, text: &str, multiline: bool) -> Result<(), Error> {
	for c in text.chars() {
		if multiline && matches!(c, '\n' | '\t') {
			continue;
		}
		let cp = c as u32;
		if matches!(
			get_general_category(c),
			G::Control
				| G::Format | G::Unassigned
				| G::PrivateUse
				| G::LineSeparator
				| G::ParagraphSeparator
		) || (0xfdd0..=0xfdef).contains(&cp)
			|| cp & 0xffff >= 0xfffe
		{
			return Err(Error { field, rule: Rule::Character, code_point: Some(cp) });
		}
	}
	Ok(())
}

fn limits<P: TextPolicy>(text: &str) -> Result<(), Error> {
	if text.chars().count() > P::MAX_CHARS {
		return Err(Error::new(P::FIELD, Rule::Chars));
	}
	if text.len() > P::MAX_BYTES {
		return Err(Error::new(P::FIELD, Rule::Bytes));
	}
	Ok(())
}

fn normalized(raw: &str) -> String {
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
		oversized(P::FIELD, raw, P::MAX_BYTES)?;
		let text = normalized(raw);
		if text.is_empty() && !P::ALLOW_EMPTY {
			return Err(Error::new(P::FIELD, Rule::Empty));
		}
		characters(P::FIELD, &text, P::MULTILINE)?;
		limits::<P>(&text)?;
		if text.trim() != text || text.contains("\n\n\n") {
			return Err(Error::new(P::FIELD, Rule::Whitespace));
		}
		Ok(Self(text, PhantomData))
	}
}
impl<P: IdentPolicy> Identifier<P> {
	pub fn new(raw: &str) -> Result<Self, Error> {
		// Identifiers are never normalized, so the exact cap can go first.
		if raw.len() > P::MAX_LEN {
			return Err(Error::new(P::FIELD, Rule::Bytes));
		}
		characters(P::FIELD, raw, false)?;
		if !P::accepts(raw) {
			return Err(Error::new(P::FIELD, Rule::Identifier));
		}
		if raw.trim() != raw || raw.contains("  ") {
			return Err(Error::new(P::FIELD, Rule::Whitespace));
		}
		Ok(Self(raw.to_owned(), PhantomData))
	}
}
impl<P: AnchorPolicy> Anchor<P> {
	pub fn new(raw: &str) -> Result<Self, Error> {
		let text = normalized(raw);
		characters(P::FIELD, &text, false)?;
		let text = text.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ");
		// Case mapping can introduce combining sequences; retain NFC at rest.
		let text: String = text.nfc().collect();
		if text.is_empty() {
			return Err(Error::new(P::FIELD, Rule::Empty));
		}
		limits::<P>(&text)?;
		static TRANSIENT_ID: LazyLock<Regex> = LazyLock::new(|| {
			Regex::new(r"(?-u:\b(job|campaign|generation|unit|lead|finding|line)[ #_-]?[0-9]+\b)")
				.unwrap()
		});
		for word in text.split_whitespace() {
			let location = word.rsplit_once(':').is_some_and(|(name, number)| {
				!name.is_empty() && !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit())
			});
			if location {
				return Err(Error::new(P::FIELD, Rule::IdentityLocation));
			}
		}
		if TRANSIENT_ID.is_match(&text) {
			return Err(Error::new(P::FIELD, Rule::IdentityTransientId));
		}
		if text.split_whitespace().any(|word| {
			(7..=64).contains(&word.len())
				&& word.bytes().all(|b| b.is_ascii_hexdigit())
				&& word.bytes().any(|b| b.is_ascii_digit())
		}) {
			return Err(Error::new(P::FIELD, Rule::IdentityHash));
		}
		Ok(Self(text, PhantomData))
	}
}
impl RepoPath {
	pub fn new(raw: &str) -> Result<Self, Error> {
		characters("path", raw, false)?;
		if raw.len() > 512 {
			return Err(Error::new("path", Rule::Bytes));
		}
		if raw.contains('\\') || raw.split('/').any(|part| matches!(part, "" | "." | "..")) {
			return Err(Error::new("path", Rule::Path));
		}
		Ok(Self(raw.to_owned()))
	}
	pub fn expose(&self) -> &str {
		&self.0
	}
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
mod tests;
