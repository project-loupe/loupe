//! Source-neutral original-token JSON string support for protocol and storage.
use std::borrow::Cow;
use std::str::Chars;

use super::{Error, Rule};

pub(crate) struct Size {
	pub(crate) bytes: usize,
	pub(crate) chars: usize,
	escaped: bool,
}

// No owned output, scratch String, or serde string visitor exists in this pass.
pub(crate) fn preflight(
	raw: &str, field: &'static str, max_bytes: usize, max_chars: usize,
) -> Result<Size, Error> {
	let contents = contents(raw).ok_or_else(|| Error::new(field, Rule::JsonSyntax))?;
	let mut size = Size { bytes: 0, chars: 0, escaped: contents.contains('\\') };
	for ch in DecodedChars(contents.chars()) {
		let ch = ch.ok_or_else(|| Error::new(field, Rule::JsonSyntax))?;
		size.bytes = size
			.bytes
			.checked_add(ch.len_utf8())
			.filter(|n| *n <= max_bytes)
			.ok_or_else(|| Error::new(field, Rule::Bytes))?;
		size.chars = size
			.chars
			.checked_add(1)
			.filter(|n| *n <= max_chars)
			.ok_or_else(|| Error::new(field, Rule::Chars))?;
	}
	Ok(size)
}

/// Decode one exact JSON string token with bounded decoded UTF-8 bytes/scalars.
///
/// A complete allocation-free syntax/counting pass precedes any output
/// allocation. Unescaped contents borrow the token; escaped contents allocate
/// only their checked decoded size. The token must include both quotes, with
/// no surrounding whitespace. Invalid escapes and unpaired surrogates fail.
///
/// These are decoded limits, independent of the encoded token's length. The
/// owner must bound its original body/column before locating tokens. Any
/// semantic policy's raw 4× margin, normalization, control rejection, source
/// attribution, and marked construction remain the named owner's decisions.
///
/// Errors contain only the static field, JsonSyntax/Bytes/Chars rule, and no
/// content. Per decoded scalar, checked byte accumulation precedes the scalar
/// count; exceeding a cap may reject before a malformed later suffix is read.
pub fn decode_json_string_bounded<'a>(
	raw: &'a str, field: &'static str, max_decoded_bytes: usize, max_decoded_chars: usize,
) -> Result<Cow<'a, str>, Error> {
	let size = preflight(raw, field, max_decoded_bytes, max_decoded_chars)?;
	let contents = contents(raw).ok_or_else(|| Error::new(field, Rule::JsonSyntax))?;
	if !size.escaped {
		return Ok(Cow::Borrowed(contents));
	}
	// This is the only decoded output allocation, after the complete preflight.
	let mut decoded = String::with_capacity(size.bytes);
	for ch in DecodedChars(contents.chars()) {
		decoded.push(ch.ok_or_else(|| Error::new(field, Rule::JsonSyntax))?);
	}
	Ok(Cow::Owned(decoded))
}

fn contents(raw: &str) -> Option<&str> {
	raw.strip_prefix('"')?.strip_suffix('"')
}

struct DecodedChars<'a>(Chars<'a>);
impl DecodedChars<'_> {
	fn hex_quad(&mut self) -> Option<u32> {
		let mut value = 0_u32;
		for _ in 0..4 {
			value = value.checked_mul(16)?.checked_add(self.0.next()?.to_digit(16)?)?;
		}
		Some(value)
	}
	fn escaped(&mut self) -> Option<char> {
		Some(match self.0.next()? {
			'"' => '"',
			'\\' => '\\',
			'/' => '/',
			'b' => '\u{8}',
			'f' => '\u{c}',
			'n' => '\n',
			'r' => '\r',
			't' => '\t',
			'u' => {
				let first = self.hex_quad()?;
				let scalar = if (0xd800..=0xdbff).contains(&first) {
					if self.0.next()? != '\\' || self.0.next()? != 'u' {
						return None;
					}
					let second = self.hex_quad()?;
					if !(0xdc00..=0xdfff).contains(&second) {
						return None;
					}
					(first - 0xd800) * 0x400 + (second - 0xdc00) + 0x10000
				} else {
					first
				};
				char::from_u32(scalar)?
			},
			_ => return None,
		})
	}
}
impl Iterator for DecodedChars<'_> {
	type Item = Option<char>;
	fn next(&mut self) -> Option<Self::Item> {
		let ch = self.0.next()?;
		Some(match ch {
			'\\' => self.escaped(),
			'"' | '\u{0}'..='\u{1f}' => None,
			ch => Some(ch),
		})
	}
}
