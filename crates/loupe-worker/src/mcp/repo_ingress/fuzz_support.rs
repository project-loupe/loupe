//! Concrete synthetic Repo operation results, before their real interpretation.
use loupe_provenance::{Ingress, Untrusted};

use super::*;

pub enum RepoCase<'a> {
	Canonical { root: &'a Path, native: PathBuf },
	LocalFile(&'a [u8]),
	Fingerprint { bytes: &'a [u8], file: &'a str, start: u32, end: u32 },
	GitOutput(std::process::Output),
}
// debug-ok: Cfg-only synthetic observation; raw values support independent source and compatibility assertions.
#[derive(Debug, PartialEq, Eq)]
pub enum RepoObservation {
	Membership { native: PathBuf, relative: Option<String> },
	Lines(u64),
	Fingerprint(String),
	Applies,
	Rejects(String),
	Outside,
	InvalidUtf8,
}

#[allow(unsafe_code)]
pub fn observe_repo(case: RepoCase<'_>) -> RepoObservation {
	match case {
		RepoCase::Canonical { root, native } => {
			// SAFETY: original cfg-only native canonical-path operation fixture.
			let original = Untrusted::new(native, unsafe { Ingress::<Repo>::new() });
			match original.validate(SubmittedPathMembership { workdir: root }) {
				Ok(value) => RepoObservation::Membership {
					native: value._native,
					relative: value._relative.map(|path| path.expose().to_owned()),
				},
				Err(_) => RepoObservation::Outside,
			}
		},
		RepoCase::LocalFile(bytes) => {
			// SAFETY: original cfg-only Repo file read bytes.
			let original = Untrusted::new(bytes, unsafe { Ingress::<Repo>::new() });
			match original.validate(LocalFindingSource) {
				Ok(lines) => RepoObservation::Lines(lines),
				Err(_) => RepoObservation::InvalidUtf8,
			}
		},
		RepoCase::Fingerprint { bytes, file, start, end } => {
			// SAFETY: original cfg-only Repo window-source file bytes.
			let original = Untrusted::new(bytes, unsafe { Ingress::<Repo>::new() });
			match original.validate(FingerprintWindow { file, line_start: start, line_end: end }) {
				Ok(hash) => RepoObservation::Fingerprint(hash.for_submission().to_owned()),
				Err(_) => RepoObservation::InvalidUtf8,
			}
		},
		RepoCase::GitOutput(output) => {
			// SAFETY: original cfg-only Git command Output fixture before diagnostic decoding.
			let original = Untrusted::new(output, unsafe { Ingress::<Repo>::new() });
			match original.validate(RepoDiffCheckDecoder).unwrap().into_outcome() {
				super::super::DiffCheck::Applies => RepoObservation::Applies,
				super::super::DiffCheck::Rejects { stderr } => {
					RepoObservation::Rejects(stderr.for_tool_response().to_owned())
				},
			}
		},
	}
}
