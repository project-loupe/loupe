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
//!     out.field("description", value)?;
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
}

impl<'a> ReportView<'a> {
	pub(crate) fn selected(finding: &'a loupe_storage::reports::ReportFinding) -> Self {
		Self::new(finding.id(), finding.finding(), finding.reviewed_revision())
	}
	pub(crate) fn new(
		id: i64, finding: &'a Finding<Agent>,
		reviewed_revision: Option<&'a BoundedText<RevisionText, Db>>,
	) -> Self {
		Self { id, finding, reviewed_revision, patch: finding.patch_unified.as_ref() }
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
	pub fn field<P: TextPolicy, S: Source>(
		&mut self, label: &'static str, value: &BoundedText<P, S>,
	) -> Result<(), ReportError> {
		self.block(label, value.expose(), "", "")
	}
	pub(super) fn diff<P: TextPolicy, S: Source>(
		&mut self, label: &'static str, value: &BoundedText<P, S>,
	) -> Result<(), ReportError> {
		self.block(label, value.expose(), "", "diff")
	}
	fn block(
		&mut self, label: &'static str, value: &str, suffix: &str, language: &'static str,
	) -> Result<(), ReportError> {
		let width = fence_width(value).ok_or_else(|| self.error())?;
		let framing =
			width.checked_mul(2).and_then(|n| n.checked_add(8)).ok_or_else(|| self.error())?;
		self.account(
			Measure::text(label)
				.add(Measure::text(value))
				.and_then(|n| n.add(Measure::text(suffix)))
				.and_then(|n| n.add(Measure::text(language)))
				.and_then(|n| n.add(Measure::ascii(framing))),
		)?;
		if let Some(out) = &mut self.out {
			out.push_str("- ");
			out.push_str(label);
			out.push_str(":\n");
			out.extend(std::iter::repeat_n('`', width));
			out.push_str(language);
			out.push('\n');
			out.push_str(value);
			out.push_str(suffix);
			out.push('\n');
			out.extend(std::iter::repeat_n('`', width));
			out.push_str("\n\n");
		}
		Ok(())
	}
	pub fn path<S: Source>(
		&mut self, path: &RepoPath<S>, start: Option<u32>, end: Option<u32>,
	) -> Result<(), ReportError> {
		let suffix = match (start, end) {
			(Some(start), Some(end)) if self.markdown && end != start => format!(":{start}-{end}"),
			(Some(start), _) => format!(":{start}"),
			_ => String::new(),
		};
		let value = path.expose();
		if !self.markdown {
			return self.block("file", value, &suffix, "");
		}
		let width = fence_width(value).ok_or_else(|| self.error())?;
		let edge_tick = value.starts_with('`') || (suffix.is_empty() && value.ends_with('`'));
		let edge_spaces = suffix.is_empty()
			&& value.starts_with(' ')
			&& value.ends_with(' ')
			&& value.bytes().any(|b| b != b' ');
		let padding = edge_tick || edge_spaces;
		let framing = width
			.checked_mul(2)
			.and_then(|n| n.checked_add(13 + usize::from(padding) * 2))
			.ok_or_else(|| self.error())?;
		self.account(
			Measure::text(value)
				.add(Measure::text(&suffix))
				.and_then(|n| n.add(Measure::ascii(framing))),
		)?;
		if let Some(out) = &mut self.out {
			out.push_str("- location: ");
			out.extend(std::iter::repeat_n('`', width));
			if padding {
				out.push(' ');
			}
			out.push_str(value);
			out.push_str(&suffix);
			if padding {
				out.push(' ');
			}
			out.extend(std::iter::repeat_n('`', width));
			out.push('\n');
		}
		Ok(())
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
		self.literal("- severity: ")?;
		self.literal(severity.as_str())?;
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

#[cfg(test)]
mod tests {
	use loupe_core::text::policy::FindingDescription;

	use super::super::fixtures::text;
	use super::*;

	#[test]
	fn admission_counts_unicode_and_framing_before_allocating_output() {
		let mut empty = ReportBuilder::github();
		empty.field("description", &text::<FindingDescription>("")).unwrap();
		let overhead = empty.render().unwrap().as_str().chars().count();
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
