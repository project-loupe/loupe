//! Exact Agent fence claims checked against one open, streamed Repo file.
//! The source buffer and Unicode state are fixed-size. Search state is bounded
//! by the already admitted description; no source file or source line is copied.
use std::io::Read;

use loupe_core::security_event::CitationFailure;
use loupe_core::text::policy::FindingDescription;
use loupe_core::text::{BoundedText, RepoPath};
use loupe_provenance::{Agent, Mark, Repo, Unvalidated, Validate};

use super::repo_ingress::ComputedFingerprint;

mod fingerprint;
#[cfg(fuzzing)]
pub mod fuzzing;

// debug-ok: closed categories without source text, paths or I/O error chains.
#[derive(Debug, thiserror::Error)]
pub(super) enum CitationError {
	#[error("citation_missing_file")]
	Missing,
	#[error("citation_not_regular_file")]
	NotRegular,
	#[error("citation_range_invalid")]
	Range,
	#[error("citation_quote_mismatch")]
	Quote,
	#[error("citation_io_failed")]
	Io,
	#[error("citation_source_not_utf8")]
	Utf8,
	#[error("citation_task_failed")]
	Task,
	#[error("citation_cancelled")]
	Cancelled,
}
impl CitationError {
	pub(super) fn reason(&self) -> Option<CitationFailure> {
		match self {
			Self::Missing => Some(CitationFailure::MissingFile),
			Self::NotRegular => Some(CitationFailure::NotRegular),
			Self::Range => Some(CitationFailure::RangeInvalid),
			Self::Quote => Some(CitationFailure::QuoteMismatch),
			Self::Io | Self::Utf8 | Self::Task | Self::Cancelled => None,
		}
	}
}

pub(super) struct CitationClaim {
	pub(super) file: RepoPath<Agent>,
	pub(super) description: BoundedText<FindingDescription, Agent>,
	pub(super) start: u32,
	pub(super) end: u32,
	pub(super) cancel: tokio_util::sync::CancellationToken,
}
impl Validate<std::fs::File, Repo> for CitationClaim {
	type Output = ComputedFingerprint;
	type Error = CitationError;
	fn validate<'view>(
		self, u: Unvalidated<'view, std::fs::File>, _: Mark<'view, Repo>,
	) -> Result<Self::Output, Self::Error> {
		check_cancellation(Some(&self.cancel))?;
		if !u.get().metadata().map_err(|_| CitationError::Io)?.is_file() {
			return Err(CitationError::NotRegular);
		}
		let fingerprint = check_source(
			u.get(),
			self.file.expose(),
			self.start,
			self.end,
			self.description.expose().as_bytes(),
			&self.cancel,
		)?;
		Ok(ComputedFingerprint::from_stream(fingerprint))
	}
}

fn check_source(
	source: impl Read, file: &str, start: u32, end: u32, description: &[u8],
	cancel: &tokio_util::sync::CancellationToken,
) -> Result<blake3::Hash, CitationError> {
	check_cancellation(Some(cancel))?;
	let quotes = fences(description)?;
	let (lines, fingerprint, matches) = scan(source, file, start, end, &quotes, Some(cancel))?;
	if start == 0 || start > end || u64::from(end) > lines {
		return Err(CitationError::Range);
	}
	if matches.iter().any(Option::is_none) {
		return Err(CitationError::Quote);
	}
	Ok(fingerprint)
}

#[cfg(any(test, fuzzing))]
pub(super) struct FingerprintSource<'a> {
	pub(super) file: &'a str,
	pub(super) start: u32,
	pub(super) end: u32,
}
#[cfg(any(test, fuzzing))]
impl Validate<std::fs::File, Repo> for FingerprintSource<'_> {
	type Output = ComputedFingerprint;
	type Error = CitationError;
	fn validate<'view>(
		self, u: Unvalidated<'view, std::fs::File>, _: Mark<'view, Repo>,
	) -> Result<Self::Output, Self::Error> {
		let (_, hash, _) = scan(u.get(), self.file, self.start, self.end, &[], None)?;
		Ok(ComputedFingerprint::from_stream(hash))
	}
}

fn line_body(mut line: &[u8]) -> &[u8] {
	if let Some(body) = line.strip_suffix(b"\n") {
		line = body.strip_suffix(b"\r").unwrap_or(body);
	}
	line
}
fn delimiter(line: &[u8]) -> Option<(u8, usize, &[u8])> {
	let line = line_body(line);
	let spaces = line.iter().take_while(|b| **b == b' ').count();
	if spaces > 3 {
		return None;
	}
	let rest = line.get(spaces..)?;
	let kind = *rest.first()?;
	if !matches!(kind, b'`' | b'~') {
		return None;
	}
	let length = rest.iter().take_while(|b| **b == kind).count();
	(length >= 3).then(|| (kind, length, rest.get(length..).unwrap_or_default()))
}
fn fences(description: &[u8]) -> Result<Vec<&[u8]>, CitationError> {
	let mut open = None;
	let mut offset = 0;
	let mut quotes = Vec::new();
	for line in description.split_inclusive(|b| *b == b'\n') {
		if let Some((kind, length, start)) = open {
			if let Some((close, close_length, tail)) = delimiter(line)
				&& close == kind
				&& close_length >= length
				&& tail.iter().all(|b| matches!(*b, b' ' | b'\t'))
			{
				let payload = description.get(start..offset).ok_or(CitationError::Quote)?;
				let payload = if let Some(body) = payload.strip_suffix(b"\n") {
					body.strip_suffix(b"\r").unwrap_or(body)
				} else {
					payload
				};
				if payload.is_empty() {
					return Err(CitationError::Quote);
				}
				quotes.push(payload);
				open = None;
			}
		} else if let Some((kind, length, _)) = delimiter(line) {
			open = Some((kind, length, offset + line.len()));
		}
		offset += line.len();
	}
	if open.is_some() {
		return Err(CitationError::Quote);
	}
	Ok(quotes)
}

struct Search<'a> {
	quote: &'a [u8],
	prefix: Vec<usize>,
	matched: usize,
	found: Option<std::ops::Range<u64>>,
}
impl<'a> Search<'a> {
	fn new(quote: &'a [u8]) -> Self {
		let mut prefix = vec![0; quote.len()];
		let mut matched = 0;
		for at in 1..quote.len() {
			while matched > 0 && quote.get(at) != quote.get(matched) {
				matched = prefix[matched - 1];
			}
			if quote.get(at) == quote.get(matched) {
				matched += 1;
			}
			prefix[at] = matched;
		}
		Self { quote, prefix, matched: 0, found: None }
	}
	fn push(&mut self, byte: u8, offset: u64) {
		if self.found.is_some() {
			return;
		}
		while self.matched > 0 && self.quote.get(self.matched) != Some(&byte) {
			self.matched = self.prefix[self.matched - 1];
		}
		if self.quote.get(self.matched) == Some(&byte) {
			self.matched += 1;
		}
		if self.matched == self.quote.len() {
			self.found = Some(offset + 1 - self.quote.len() as u64..offset + 1);
		}
	}
}

type ScanOutput = (u64, blake3::Hash, Vec<Option<std::ops::Range<u64>>>);

fn check_cancellation(
	cancel: Option<&tokio_util::sync::CancellationToken>,
) -> Result<(), CitationError> {
	if cancel.is_some_and(tokio_util::sync::CancellationToken::is_cancelled) {
		Err(CitationError::Cancelled)
	} else {
		Ok(())
	}
}

fn scan(
	mut source: impl Read, file: &str, start: u32, end: u32, quotes: &[&[u8]],
	cancel: Option<&tokio_util::sync::CancellationToken>,
) -> Result<ScanOutput, CitationError> {
	check_cancellation(cancel)?;
	let mut search: Vec<_> = quotes.iter().map(|quote| Search::new(quote)).collect();
	let mut hash = fingerprint::Fingerprint::new(file);
	let from = u64::from(start.saturating_sub(super::FINGERPRINT_CONTEXT_LINES).max(1));
	let through = u64::from(end.saturating_add(super::FINGERPRINT_CONTEXT_LINES));
	let mut buffer = [0u8; 8192];
	let mut scalar = [0u8; 4];
	let mut scalar_len = 0;
	let mut scalar_width = 0;
	let mut line = 1u64;
	let mut offset = 0u64;
	let mut final_lf = false;
	loop {
		check_cancellation(cancel)?;
		let count = source.read(&mut buffer).map_err(|_| CitationError::Io)?;
		check_cancellation(cancel)?;
		if count == 0 {
			break;
		}
		for byte in buffer.iter().take(count).copied() {
			// Bound work between cancellation checks even with many fence claims.
			if offset.is_multiple_of(256) {
				check_cancellation(cancel)?;
			}
			if line >= u64::from(start) && line <= u64::from(end) {
				for quote in &mut search {
					quote.push(byte, offset);
				}
			}
			let ch = if scalar_len == 0 && byte.is_ascii() {
				Some(char::from(byte))
			} else {
				if scalar_len == 0 {
					scalar_width = match byte {
						0xc2..=0xdf => 2,
						0xe0..=0xef => 3,
						0xf0..=0xf4 => 4,
						_ => return Err(CitationError::Utf8),
					};
				}
				let slot = scalar.get_mut(scalar_len).ok_or(CitationError::Utf8)?;
				*slot = byte;
				scalar_len += 1;
				if scalar_len == scalar_width {
					let bytes = scalar.get(..scalar_len).ok_or(CitationError::Utf8)?;
					let ch =
						std::str::from_utf8(bytes).map_err(|_| CitationError::Utf8)?.chars().next();
					scalar_len = 0;
					ch
				} else {
					None
				}
			};
			if let Some(ch) = ch
				&& line >= from
				&& line <= through
			{
				hash.push(ch);
			}
			final_lf = byte == b'\n';
			if final_lf {
				line = line.checked_add(1).ok_or(CitationError::Io)?;
			}
			offset = offset.checked_add(1).ok_or(CitationError::Io)?;
		}
	}
	check_cancellation(cancel)?;
	if scalar_len != 0 {
		return Err(CitationError::Utf8);
	}
	let lines = if final_lf { line - 1 } else { line }.max(1);
	Ok((lines, hash.finish(), search.into_iter().map(|quote| quote.found).collect()))
}

#[cfg(test)]
mod tests;
