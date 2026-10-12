//! Validated, field-bound untrusted text. Use `expose()` only at deliberate
//! rendering or persistence boundaries; `Debug` never contains the payload.
//!
//! ```compile_fail
//! use loupe_core::text::{BoundedText, policy::{Title, Objective}};
//! use loupe_provenance::Agent;
//! fn title(_: BoundedText<Title, Agent>) {}
//! fn wrong(value: BoundedText<Objective, Agent>) { title(value); }
//! ```

pub(crate) mod checked;
#[cfg(doctest)]
mod contract;
pub(crate) mod json;
pub(crate) mod json_string;
pub mod policy;
mod values;
use std::fmt;

pub use json_string::decode_json_string_bounded;
use unicode_general_category::{get_general_category, GeneralCategory as G};
use unicode_normalization::UnicodeNormalization;
pub use values::{Anchor, BoundedJson, BoundedText, Identifier, RepoPath, SourceRef};

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

/// Path structure after the constructor's character and byte-limit checks.
pub(crate) fn is_repo_path(raw: &[u8]) -> bool {
	!raw.contains(&b'\\')
		&& !raw.contains(&0)
		&& !raw.split(|byte| *byte == b'/').any(|part| matches!(part, b"" | b"." | b".."))
}

#[cfg(test)]
mod json_string_tests;
#[cfg(test)]
mod tests;
/// Fuzz-only observation of Payload's actual embedded serde visitor. This
/// deliberately omits the outer raw-document cap and creates no labelled owner.
#[cfg(fuzzing)]
pub fn fuzz_payload_visitor(raw: &str) -> Option<(String, [u8; 32])> {
	json::payload_visitor_observation(raw)
}
