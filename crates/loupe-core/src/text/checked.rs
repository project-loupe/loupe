//! Shared source-independent policy mechanics. Only wrappers attach a source.

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::Regex;
use unicode_normalization::UnicodeNormalization;

use super::{
	characters, is_repo_path, limits, normalized, oversized, AnchorPolicy, Error, IdentPolicy,
	Normalization, Rule, TextPolicy, Whitespace,
};

pub(crate) fn text<P: TextPolicy>(raw: &str) -> Result<String, Error> {
	let text = match P::NORMALIZATION {
		Normalization::Semantic => {
			oversized(P::FIELD, raw, P::MAX_BYTES)?;
			Cow::Owned(normalized(raw))
		},
		Normalization::Exact => {
			// Exact decoded bounds precede allocation of the owned output.
			if raw.len() > P::MAX_BYTES {
				return Err(Error::new(P::FIELD, Rule::Bytes));
			}
			Cow::Borrowed(raw)
		},
	};
	if text.is_empty() && !P::ALLOW_EMPTY {
		return Err(Error::new(P::FIELD, Rule::Empty));
	}
	characters(P::FIELD, &text, P::MULTILINE, P::ALLOW_CR)?;
	limits::<P>(&text)?;
	if P::WHITESPACE == Whitespace::Prose && (text.trim() != text || text.contains("\n\n\n")) {
		return Err(Error::new(P::FIELD, Rule::Whitespace));
	}
	Ok(text.into_owned())
}

pub(crate) fn check_identifier<P: IdentPolicy>(raw: &str) -> Result<(), Error> {
	if raw.len() > P::MAX_LEN {
		return Err(Error::new(P::FIELD, Rule::Bytes));
	}
	characters(P::FIELD, raw, false, false)?;
	if !P::accepts(raw) {
		return Err(Error::new(P::FIELD, Rule::Identifier));
	}
	if raw.trim() != raw || raw.contains("  ") {
		return Err(Error::new(P::FIELD, Rule::Whitespace));
	}
	Ok(())
}

pub(crate) fn identifier<P: IdentPolicy>(raw: &str) -> Result<String, Error> {
	check_identifier::<P>(raw)?;
	Ok(raw.to_owned())
}

pub(crate) fn anchor<P: AnchorPolicy>(raw: &str) -> Result<String, Error> {
	let text = normalized(raw);
	characters(P::FIELD, &text, false, false)?;
	let text = text.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ");
	// Case mapping can introduce combining sequences; retain NFC at rest.
	let text: String = text.nfc().collect();
	if text.is_empty() {
		return Err(Error::new(P::FIELD, Rule::Empty));
	}
	limits::<P>(&text)?;
	#[expect(
		clippy::unwrap_used,
		reason = "the checked-in literal regex has no runtime input and is exercised by anchor tests"
	)]
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
	Ok(text)
}

pub(crate) fn path(raw: &str) -> Result<String, Error> {
	characters("path", raw, false, false)?;
	if raw.len() > 512 {
		return Err(Error::new("path", Rule::Bytes));
	}
	if !is_repo_path(raw.as_bytes()) {
		return Err(Error::new("path", Rule::Path));
	}
	Ok(raw.to_owned())
}
