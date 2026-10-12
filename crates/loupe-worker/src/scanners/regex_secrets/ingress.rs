//! Actual repository file bytes and observed native path stay in one Repo
//! mark scope through matching and source-bearing finding construction.
use std::path::PathBuf;

use loupe_core::source_migration::text::{BoundedText, RepoPath};
use loupe_core::source_migration::Finding;
use loupe_core::Severity;
use loupe_provenance::{Mark, Repo, Unvalidated, Validate};

pub(super) struct RepoFileInput {
	pub(super) bytes: Vec<u8>,
	pub(super) relative_path: PathBuf,
}
pub(super) struct RegexSecretFindings<'a> {
	pub(super) regex: &'a regex::Regex,
}
pub(super) enum FileFindings {
	UnrepresentablePath,
	Findings(Vec<RepoFinding>),
}
pub(super) struct RepoFinding(Finding<Repo>);
impl Validate<RepoFileInput, Repo> for RegexSecretFindings<'_> {
	type Output = FileFindings;
	type Error = loupe_core::text::Error;
	fn validate<'view>(
		self, u: Unvalidated<'view, RepoFileInput>, mark: Mark<'view, Repo>,
	) -> Result<Self::Output, Self::Error> {
		let input = u.get();
		let Some(relative) = input.relative_path.to_str() else {
			return Ok(FileFindings::UnrepresentablePath);
		};
		let Ok(path) = RepoPath::new(&mark, relative) else {
			return Ok(FileFindings::UnrepresentablePath);
		};
		if input.bytes.iter().take(8192).any(|b| *b == 0) {
			return Ok(FileFindings::Findings(Vec::new()));
		}
		let Ok(text) = std::str::from_utf8(&input.bytes) else {
			return Ok(FileFindings::Findings(Vec::new()));
		};
		let mut findings = Vec::new();
		for found in self.regex.find_iter(text) {
			let line_start = 1 + text[..found.start()].matches('\n').count() as u32;
			// Stable across line shifts and revisions; preserve legacy framing.
			let fingerprint =
				crate::fingerprint::compute(super::SCANNER_ID, path.expose(), found.as_str());
			let description=format!("Found a string matching the AWS access key id pattern (`AKIA…`) at {relative}:{line_start}. \
				Treat as a potential secret leak — confirm against the AWS account before reporting.");
			findings.push(RepoFinding(Finding {
				scanner_id: BoundedText::new(&mark, super::SCANNER_ID)?,
				severity: Severity::High,
				title: BoundedText::new(&mark, "Possible AWS access key id")?,
				description: BoundedText::new(&mark, &description)?,
				file_path: Some(path.clone()),
				line_start: Some(line_start),
				line_end: Some(line_start),
				cwe: Some(BoundedText::new(&mark, "CWE-798")?),
				patch_unified: None,
				poc_unified: None,
				fingerprint: BoundedText::new(&mark, &fingerprint)?,
			}));
		}
		Ok(FileFindings::Findings(findings))
	}
}
impl RepoFinding {
	/// Temporary concrete Scanner::scan exit. M changes the trait to Repo
	/// findings; no Agent mark is introduced by this projection.
	pub(super) fn into_legacy(self) -> loupe_core::Finding {
		let f = self.0;
		loupe_core::Finding {
			scanner_id: f.scanner_id.expose().to_owned(),
			severity: f.severity,
			title: f.title.expose().to_owned(),
			description: f.description.expose().to_owned(),
			file_path: f.file_path.map(|v| v.expose().to_owned()),
			line_start: f.line_start,
			line_end: f.line_end,
			cwe: f.cwe.map(|v| v.expose().to_owned()),
			patch_unified: None,
			poc_unified: None,
			fingerprint: f.fingerprint.expose().to_owned(),
		}
	}
}
