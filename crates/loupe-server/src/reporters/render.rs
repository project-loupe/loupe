//! Bounded literal report sinks. Only typed data and closed layout operations
//! enter this module; exposed wire text leaves through destination serializers.
//!
//! Typed data is accepted without granting access to the destination bytes:
//! ```
//! use loupe_core::text::policy::FindingDescription;
//! use loupe_core::text::{BoundedText, RepoPath};
//! use loupe_provenance::Agent;
//! use loupe_server::reporters::render::{ReportBuilder, ReportError};
//! #[rustfmt::skip]
//! fn render(
//!     value: &BoundedText<FindingDescription, Agent>, path: &RepoPath<Agent>,
//! ) -> Result<(), ReportError> {
//!     let mut out = ReportBuilder::github();
//!     out.heading("Description")?;
//!     out.prose(value)?;
//!     out.path(path, Some(1), Some(2))?;
//!     let _ = out.render()?;
//!     Ok(())
//! }
//! ```
//! ```compile_fail,E0308
//! use loupe_server::reporters::render::ReportBuilder;
//! let _ = ReportBuilder::github().field("description", "raw text");
//! ```
//! ```compile_fail,E0308
//! use loupe_server::reporters::render::ReportBuilder;
//! let _ = ReportBuilder::github().prose("raw text");
//! ```
//! ```compile_fail,E0308
//! use loupe_server::reporters::render::ReportBuilder;
//! let _ = ReportBuilder::github().path("src/file.rs", None, None);
//! ```
//! ```compile_fail
//! use loupe_server::reporters::render::ReportBuilder;
//! fn dynamic(text: &str) { let _ = ReportBuilder::github().heading(text); }
//! ```
//! ```compile_fail,E0308
//! use loupe_server::reporters::render::ReportBuilder;
//! use loupe_provenance::Secret;
//! let _ = ReportBuilder::github().field("secret", &Secret::new(String::new()));
//! ```
//! ```compile_fail,E0277
//! use loupe_server::reporters::render::ReportBody;
//! let _: ReportBody = serde_json::from_str("\"raw\"").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_server::reporters::render::IssueTitle;
//! let _: IssueTitle = serde_json::from_str("\"raw\"").unwrap();
//! ```
//! ```compile_fail,E0624
//! use loupe_server::reporters::render::ReportBuilder;
//! let _ = ReportBuilder::plain_text(usize::MAX);
//! ```
use std::fmt;

use loupe_core::report_limits::GITHUB_ISSUE_BODY_MAX_CHARS as GITHUB_SCALARS;
use loupe_core::text::policy::{FindingTitle, PatchUnified, RevisionText};
use loupe_core::text::{BoundedText, RepoPath, TextPolicy};
use loupe_core::{Finding, Severity};
use loupe_provenance::{Agent, Db, Source};
use serde::Serialize;

const GITHUB_BYTES: usize = 262_144;

// debug-ok: closed destination size-limit variants contain no report content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReportError {
	#[error("GitHub issue body exceeds 65536 characters or 262144 bytes including framing; shorten the report and retry")]
	GithubLimit,
	#[error("email message exceeds its byte budget")]
	MailLimit,
}

/// Fully admitted body. Construction and wire borrowing belong to reporters.
pub struct ReportBody(String);
/// Compact issue title, built without allocating the full input.
pub struct IssueTitle(String);

macro_rules! output {
	($name:ident) => {
		impl fmt::Debug for $name {
			fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.write_str(concat!(stringify!($name), "([redacted])"))
			}
		}
		impl Serialize for $name {
			fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
				serializer.serialize_str(&self.0)
			}
		}
	};
}
output!(ReportBody);
output!(IssueTitle);

impl ReportBody {
	#[cfg(test)]
	pub(super) fn as_str(&self) -> &str {
		&self.0
	}

	pub(super) fn into_string(self) -> String {
		self.0
	}
}

/// A borrowed Agent finding and its separately sourced stored metadata.
#[derive(Clone, Copy)]
pub(crate) struct ReportView<'a> {
	pub(super) id: i64,
	pub(super) finding: &'a Finding<Agent>,
	pub(super) reviewed_revision: Option<&'a BoundedText<RevisionText, Db>>,
	pub(super) patch: Option<&'a BoundedText<PatchUnified, Agent>>,
	pub(super) phase_review: bool,
}

impl<'a> ReportView<'a> {
	pub(crate) fn selected(finding: &'a loupe_storage::reports::ReportFinding) -> Self {
		Self {
			phase_review: finding.is_phase_review(),
			..Self::new(finding.id(), finding.finding(), finding.reviewed_revision())
		}
	}
	pub(crate) fn new(
		id: i64, finding: &'a Finding<Agent>,
		reviewed_revision: Option<&'a BoundedText<RevisionText, Db>>,
	) -> Self {
		Self {
			id,
			finding,
			reviewed_revision,
			patch: finding.patch_unified.as_ref(),
			phase_review: false,
		}
	}
	pub(crate) fn with_patch(mut self, patch: &'a BoundedText<PatchUnified, Agent>) -> Self {
		self.patch = Some(patch);
		self
	}
}

impl IssueTitle {
	#[cfg(any(test, fuzzing))]
	pub(super) fn as_str(&self) -> &str {
		&self.0
	}

	pub(super) fn from_finding(value: &BoundedText<FindingTitle, Agent>) -> Self {
		let mut out = String::new();
		let mut count = 0;
		'words: for word in value.expose().split_whitespace() {
			if count != 0 {
				out.push(' ');
				count += 1;
			}
			for ch in word.chars() {
				if count == 101 {
					break 'words;
				}
				out.push(ch);
				count += 1;
			}
			if count > 100 {
				break;
			}
		}
		if count == 0 {
			out.push_str("Untitled finding");
		}
		if count > 100 {
			let end = out.char_indices().nth(97).map(|(index, _)| index).unwrap_or(out.len());
			out.truncate(end);
			while out.ends_with(char::is_whitespace) {
				out.pop();
			}
			out.push_str("...");
		}
		Self(out)
	}
}

#[derive(Clone, Copy)]
struct Measure {
	bytes: usize,
	scalars: usize,
}
impl Measure {
	fn text(text: &str) -> Self {
		Self { bytes: text.len(), scalars: text.chars().count() }
	}
	fn ascii(count: usize) -> Self {
		Self { bytes: count, scalars: count }
	}
	fn add(self, other: Self) -> Option<Self> {
		Some(Self {
			bytes: self.bytes.checked_add(other.bytes)?,
			scalars: self.scalars.checked_add(other.scalars)?,
		})
	}
}

/// There is no raw-string data append or caller-selected destination budget.
pub struct ReportBuilder {
	out: Option<String>,
	used: Measure,
	bytes: usize,
	scalars: usize,
	markdown: bool,
	failed: Option<ReportError>,
}

impl ReportBuilder {
	pub fn github() -> Self {
		Self::github_mode(true)
	}
	pub(super) fn github_sizing() -> Self {
		Self::github_mode(false)
	}
	fn github_mode(render: bool) -> Self {
		Self {
			out: render.then(String::new),
			used: Measure::ascii(0),
			bytes: GITHUB_BYTES,
			scalars: GITHUB_SCALARS,
			markdown: true,
			failed: None,
		}
	}
	pub(super) fn plain_text(remaining: usize) -> Self {
		Self {
			out: Some(String::new()),
			used: Measure::ascii(0),
			bytes: remaining,
			scalars: usize::MAX,
			markdown: false,
			failed: None,
		}
	}
	fn error(&self) -> ReportError {
		if self.markdown {
			ReportError::GithubLimit
		} else {
			ReportError::MailLimit
		}
	}
	fn account(&mut self, added: Option<Measure>) -> Result<(), ReportError> {
		if let Some(error) = self.failed {
			return Err(error);
		}
		let total = added.and_then(|added| self.used.add(added));
		let Some(total) =
			total.filter(|total| total.bytes <= self.bytes && total.scalars <= self.scalars)
		else {
			let error = self.error();
			self.failed = Some(error);
			return Err(error);
		};
		if let Some(out) = &mut self.out {
			out.reserve(total.bytes - self.used.bytes);
		}
		self.used = total;
		Ok(())
	}
	pub(super) fn literal(&mut self, text: &'static str) -> Result<(), ReportError> {
		self.account(Some(Measure::text(text)))?;
		if let Some(out) = &mut self.out {
			out.push_str(text);
		}
		Ok(())
	}
	pub fn heading(&mut self, heading: &'static str) -> Result<(), ReportError> {
		let prefix = if self.markdown { "## " } else { "" };
		self.account(
			Measure::text(prefix)
				.add(Measure::text(heading))
				.and_then(|n| n.add(Measure::ascii(2))),
		)?;
		if let Some(out) = &mut self.out {
			out.push_str(prefix);
			out.push_str(heading);
			out.push_str("\n\n");
		}
		Ok(())
	}
	/// Write one measured sequence of pieces. The walk runs twice so nothing is
	/// allocated for a body that its destination budget would reject.
	fn emit(&mut self, walk: impl Fn(&mut dyn FnMut(&str))) -> Result<(), ReportError> {
		let mut measure = Some(Measure::ascii(0));
		walk(&mut |piece| {
			measure = measure.and_then(|total| total.add(Measure::text(piece)));
		});
		self.account(measure)?;
		if let Some(out) = &mut self.out {
			walk(&mut |piece| out.push_str(piece));
		}
		Ok(())
	}
	/// A labelled metadata line. In Markdown the whole value is inline code,
	/// which GitHub's post-parse reference and mention linking leaves alone.
	pub fn field<P: TextPolicy, S: Source>(
		&mut self, label: &'static str, value: &BoundedText<P, S>,
	) -> Result<(), ReportError> {
		let value = value.expose();
		if !self.markdown {
			return self.plain_field(label, value);
		}
		self.emit(|sink| {
			sink("**");
			sink(label);
			sink(":** ");
			let mut first = true;
			for line in lines(value).filter(|line| !line.is_empty()) {
				if !first {
					sink(" ");
				}
				first = false;
				code_span(line, sink);
			}
			sink("  \n");
		})
	}
	/// A labelled single-line value read as prose rather than as an identifier.
	pub fn prose_field<P: TextPolicy, S: Source>(
		&mut self, label: &'static str, value: &BoundedText<P, S>,
	) -> Result<(), ReportError> {
		let value = value.expose();
		if !self.markdown {
			return self.plain_field(label, value);
		}
		self.emit(|sink| {
			sink("**");
			sink(label);
			sink(":** ");
			let mut first = true;
			for line in lines(value) {
				if !first && !line.trim().is_empty() {
					sink(" ");
				}
				first &= line.trim().is_empty();
				inline_prose(line, sink);
			}
			sink("  \n");
		})
	}
	/// Agent text as readable paragraphs: only allowlisted words stay
	/// plain. Plain-text destinations indent it instead.
	pub fn prose<P: TextPolicy, S: Source>(
		&mut self, value: &BoundedText<P, S>,
	) -> Result<(), ReportError> {
		let value = value.expose();
		if !self.markdown {
			return self.plain_field("description", value);
		}
		self.emit(|sink| block_prose(value, sink))
	}
	/// A diff in a fence longer than every backtick run it contains.
	pub(super) fn diff<P: TextPolicy, S: Source>(
		&mut self, label: &'static str, value: &BoundedText<P, S>,
	) -> Result<(), ReportError> {
		let value = value.expose();
		if !self.markdown {
			return self.plain_field(label, value);
		}
		let width = fence_width(value).ok_or_else(|| self.error())?;
		self.emit(|sink| {
			fence(width, sink);
			sink("diff\n");
			sink(value);
			sink("\n");
			fence(width, sink);
			sink("\n\n");
		})
	}
	fn plain_field(&mut self, label: &'static str, value: &str) -> Result<(), ReportError> {
		let width = fence_width(value).ok_or_else(|| self.error())?;
		self.emit(|sink| {
			sink("- ");
			sink(label);
			sink(":\n");
			fence(width, sink);
			sink("\n");
			sink(value);
			sink("\n");
			fence(width, sink);
			sink("\n\n");
		})
	}
	pub fn path<S: Source>(
		&mut self, path: &RepoPath<S>, start: Option<u32>, end: Option<u32>,
	) -> Result<(), ReportError> {
		let suffix = match (start, end) {
			(Some(start), Some(end)) if end != start => format!(":{start}-{end}"),
			(Some(start), _) => format!(":{start}"),
			_ => String::new(),
		};
		let located = format!("{}{suffix}", path.expose());
		if !self.markdown {
			let width = fence_width(&located).ok_or_else(|| self.error())?;
			return self.emit(|sink| {
				sink("- file:\n");
				fence(width, sink);
				sink("\n");
				sink(&located);
				sink("\n");
				fence(width, sink);
				sink("\n\n");
			});
		}
		self.emit(|sink| {
			sink("**Location:** ");
			code_span(&located, sink);
			sink("  \n");
		})
	}
	pub(super) fn finding_id(&mut self, id: i64) -> Result<(), ReportError> {
		let value = loupe_core::format_finding_id(id);
		let prefix = if self.markdown { "## Finding " } else { "Finding " };
		self.account(
			Measure::text(prefix).add(Measure::text(&value)).and_then(|n| n.add(Measure::ascii(2))),
		)?;
		if let Some(out) = &mut self.out {
			out.push_str(prefix);
			out.push_str(&value);
			out.push_str("\n\n");
		}
		Ok(())
	}
	pub(super) fn severity(&mut self, severity: Severity) -> Result<(), ReportError> {
		self.literal(if self.markdown { "**Severity:** " } else { "- severity: " })?;
		self.literal(severity.as_str())?;
		if self.markdown {
			self.literal("  ")?;
		}
		self.literal("\n")
	}
	pub(super) fn count(&mut self, count: usize) -> Result<(), ReportError> {
		let value = count.to_string();
		self.account(Measure::ascii(12).add(Measure::text(&value)))?;
		if let Some(out) = &mut self.out {
			out.push_str("Findings: ");
			out.push_str(&value);
			out.push_str("\n\n");
		}
		Ok(())
	}
	pub fn render(self) -> Result<ReportBody, ReportError> {
		if let Some(error) = self.failed {
			return Err(error);
		}
		Ok(ReportBody(self.out.unwrap_or_default()))
	}
}

fn fence_width(value: &str) -> Option<usize> {
	let mut longest = 0usize;
	let mut run = 0usize;
	for byte in value.bytes() {
		if byte == b'`' {
			run = run.checked_add(1)?;
			longest = longest.max(run);
		} else {
			run = 0;
		}
	}
	Some(longest.checked_add(1)?.max(3))
}

fn fence(width: usize, sink: &mut dyn FnMut(&str)) {
	for _ in 0..width {
		sink("`");
	}
}

/// Agent line endings, including bare carriage returns, which CommonMark and
/// mail clients both treat as line breaks.
fn lines(value: &str) -> impl Iterator<Item = &str> {
	value.split("\r\n").flat_map(|part| part.split(['\n', '\r']))
}

/// Inline code that cannot end early and keeps its exact edge characters.
fn code_span(value: &str, sink: &mut dyn FnMut(&str)) {
	let longest = value.split(|ch| ch != '`').map(str::len).max().unwrap_or(0);
	let edge_tick = value.starts_with('`') || value.ends_with('`');
	let edge_spaces =
		value.starts_with(' ') && value.ends_with(' ') && value.bytes().any(|b| b != b' ');
	let padding = if edge_tick || edge_spaces { " " } else { "" };
	fence(longest + 1, sink);
	sink(padding);
	sink(value);
	sink(padding);
	fence(longest + 1, sink);
}

const LEADING_PUNCTUATION: [char; 6] = ['(', '"', '\'', '“', '‘', '¡'];
const TRAILING_PUNCTUATION: [char; 11] = [',', '.', ';', ':', '!', '?', ')', '"', '\'', '”', '’'];

/// The fail-closed allowlist for text outside code: letters with light
/// punctuation. Anything else may be a mention, reference, commit, autolink,
/// emoji or Markdown, whichever forms GitHub supports today, so it stays code.
fn is_plain_word(word: &str) -> bool {
	if matches!(word, "—" | "–") {
		return true;
	}
	let core = word.trim_start_matches(LEADING_PUNCTUATION).trim_end_matches(TRAILING_PUNCTUATION);
	// GitHub links a commit prefix bounded by any non-alphanumeric, so a hex
	// run joined to other letters by `-` or an apostrophe still counts.
	let looks_like_commit = core
		.split(|ch: char| !ch.is_ascii_alphanumeric())
		.any(|run| run.len() >= 7 && run.bytes().all(|b| b.is_ascii_hexdigit()));
	if core.is_empty() || looks_like_commit {
		return false;
	}
	let mut previous_letter = false;
	for ch in core.chars() {
		if ch.is_alphabetic() {
			previous_letter = true;
		} else if matches!(ch, '-' | '\'' | '’') && previous_letter {
			previous_letter = false;
		} else {
			return false;
		}
	}
	previous_letter
}

/// An agent-written code span at the start of `text`, with trailing punctuation.
/// Returns its contents, that punctuation and the remaining text.
fn agent_span(text: &str) -> Option<(&str, &str, &str)> {
	let width = text.bytes().take_while(|b| *b == b'`').count();
	let body = text.get(width..)?;
	let mut cursor = 0;
	while let Some(next) = body.get(cursor..)?.find('`') {
		let start = cursor + next;
		let tail = body.get(start..)?;
		let run = tail.bytes().take_while(|b| *b == b'`').count();
		if run == width {
			let inner = body.get(..start)?;
			let after = tail.get(run..)?;
			let word_end = after.find(char::is_whitespace).unwrap_or(after.len());
			let (punctuation, rest) = after.split_at(word_end);
			if inner.trim().is_empty()
				|| !punctuation.chars().all(|ch| TRAILING_PUNCTUATION.contains(&ch))
			{
				return None;
			}
			let inner = match inner.strip_prefix(' ').and_then(|s| s.strip_suffix(' ')) {
				Some(stripped) if !stripped.is_empty() => stripped,
				_ => inner,
			};
			return Some((inner, punctuation, rest));
		}
		cursor = start + run;
	}
	None
}

/// One line of words. Whitespace splitting happens first, so every token is
/// decided alone and no token can combine with a neighbour into markup.
fn inline_prose(line: &str, sink: &mut dyn FnMut(&str)) {
	let mut rest = line.trim();
	let mut first = true;
	while !rest.is_empty() {
		if !first {
			sink(" ");
		}
		first = false;
		if let Some((inner, punctuation, after)) =
			rest.starts_with('`').then(|| agent_span(rest)).flatten()
		{
			code_span(inner, sink);
			sink(punctuation);
			rest = after.trim_start();
			continue;
		}
		let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
		let (word, after) = rest.split_at(end);
		if is_plain_word(word) {
			sink(word);
		} else {
			code_span(word, sink);
		}
		rest = after.trim_start();
	}
}

/// The fence an agent line opens: at most three spaces, then at least three
/// of one marker, as in CommonMark.
fn agent_fence(line: &str) -> Option<(char, usize)> {
	let trimmed = line.trim_start_matches(' ');
	if line.len() - trimmed.len() > 3 {
		return None;
	}
	let marker = trimmed.chars().next().filter(|ch| matches!(ch, '`' | '~'))?;
	let width = trimmed.chars().take_while(|ch| *ch == marker).count();
	let info = trimmed.trim_start_matches(marker);
	(width >= 3 && (marker == '~' || !info.contains('`'))).then_some((marker, width))
}

fn closes_fence(line: &str, marker: char, width: usize) -> bool {
	let trimmed = line.trim();
	line.len() - line.trim_start_matches(' ').len() <= 3
		&& trimmed.chars().count() >= width
		&& trimmed.chars().all(|ch| ch == marker)
}

fn is_indented(line: &str) -> bool {
	line.starts_with("    ") || line.starts_with('\t')
}

fn literal_block(block: &[&str], sink: &mut dyn FnMut(&str)) {
	let longest =
		block.iter().flat_map(|line| line.split(|ch| ch != '`')).map(str::len).max().unwrap_or(0);
	let width = (longest + 1).max(3);
	fence(width, sink);
	sink("\n");
	for line in block {
		sink(line);
		sink("\n");
	}
	fence(width, sink);
}

/// Paragraphs of [`inline_prose`], with bullets as plain characters so agent
/// text adds no list structure. Fenced and indented snippets, where whitespace
/// carries meaning, become literal blocks with their own adaptive fences.
fn block_prose(value: &str, sink: &mut dyn FnMut(&str)) {
	let all: Vec<&str> = lines(value).collect();
	let mut index = 0;
	let mut wrote = false;
	let mut in_paragraph = false;
	while let Some(&line) = all.get(index) {
		if line.trim().is_empty() {
			in_paragraph = false;
			index += 1;
			continue;
		}
		let opened = agent_fence(line);
		let snippet = if let Some((marker, width)) = opened {
			let body = all.get(index + 1..).unwrap_or_default();
			let end = body
				.iter()
				.position(|line| closes_fence(line, marker, width))
				.unwrap_or(body.len());
			index = index.saturating_add(end).saturating_add(2);
			Some(body.get(..end).unwrap_or_default())
		} else if is_indented(line) {
			let start = index;
			let mut end = index;
			while let Some(&next) = all.get(index) {
				if is_indented(next) {
					end = index + 1;
				} else if !next.trim().is_empty() {
					break;
				}
				index += 1;
			}
			Some(all.get(start..end).unwrap_or_default())
		} else {
			None
		};
		if wrote && !(in_paragraph && snippet.is_none()) {
			sink("\n\n");
		} else if wrote {
			sink("\n");
		}
		wrote = true;
		if let Some(block) = snippet {
			in_paragraph = false;
			literal_block(block, sink);
			continue;
		}
		in_paragraph = true;
		index += 1;
		let trimmed = line.trim();
		match trimmed.strip_prefix(['-', '*', '+']).filter(|rest| rest.starts_with(' ')) {
			Some(item) => {
				sink("• ");
				inline_prose(item, sink);
			},
			None => inline_prose(trimmed, sink),
		}
	}
	if wrote {
		sink("\n\n");
	}
}

#[cfg(test)]
mod tests {
	use loupe_core::text::policy::FindingDescription;

	use super::super::fixtures::text;
	use super::*;

	#[test]
	fn admission_counts_unicode_and_framing_before_allocating_output() {
		let mut empty = ReportBuilder::github();
		empty.field("description", &text::<FindingDescription>("💣")).unwrap();
		let overhead = empty.render().unwrap().as_str().chars().count() - 1;
		let exact = text::<FindingDescription>(&"💣".repeat(GITHUB_SCALARS - overhead));
		let mut out = ReportBuilder::github();
		out.field("description", &exact).unwrap();
		let body = out.render().unwrap();
		assert_eq!(body.as_str().chars().count(), GITHUB_SCALARS);
		assert!(body.as_str().len() <= GITHUB_BYTES);
		let too_long = text::<FindingDescription>(&"💣".repeat(GITHUB_SCALARS - overhead + 1));
		let mut rejected = ReportBuilder::github();
		assert!(rejected.field("description", &too_long).is_err());
		assert_eq!(
			rejected.out.as_ref().unwrap().capacity(),
			0,
			"admission precedes output reservation"
		);
		assert!(rejected.render().is_err());
	}

	#[test]
	fn adaptive_delimiters_count_twice_and_failure_never_exposes_a_partial_body() {
		let ticks = text::<FindingDescription>(&"`".repeat(30_000));
		let mut rejected = ReportBuilder::github();
		assert!(
			rejected.field("description", &ticks).is_err(),
			"two fences exceed the final scalar budget even though the payload alone fits"
		);
		assert_eq!(rejected.out.as_ref().unwrap().capacity(), 0);
		assert!(rejected.heading("later").is_err());
		assert!(rejected.render().is_err());
		let mut partially_written = ReportBuilder::github();
		partially_written.heading("valid prefix").unwrap();
		assert!(partially_written.field("description", &ticks).is_err());
		assert!(partially_written.render().is_err());
	}
}
