//! Concrete Repo observations used alongside separately admitted Agent claims.
//! No repository bytes are carried or re-labelled as Agent.
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use loupe_core::text::RepoPath;
use loupe_provenance::{Mark, Repo, Unvalidated, Validate};
#[cfg(fuzzing)]
pub(super) mod fuzz_support;

pub(super) struct SubmittedPathMembership<'a> {
	pub(super) workdir: &'a Path,
}
pub(super) struct ObservedSubmittedPath {
	_native: PathBuf,
	_relative: Option<RepoPath<Repo>>,
	source: PhantomData<Repo>,
}
impl Validate<PathBuf, Repo> for SubmittedPathMembership<'_> {
	type Output = ObservedSubmittedPath;
	type Error = OutsideWorkdir;
	fn validate<'view>(
		self, u: Unvalidated<'view, PathBuf>, mark: Mark<'view, Repo>,
	) -> Result<Self::Output, Self::Error> {
		let relative = u.get().strip_prefix(self.workdir).map_err(|_| OutsideWorkdir)?;
		// Native names can be unrepresentable as RepoPath. Membership remains
		// a native-path operation; no lossy alias is granted a Repo mark.
		let typed = relative.to_str().and_then(|v| RepoPath::new(&mark, v).ok());
		Ok(ObservedSubmittedPath {
			_native: u.get().clone(),
			_relative: typed,
			source: PhantomData,
		})
	}
}
// debug-ok: Fieldless fixed error with no rejected input retained.
#[derive(Debug, thiserror::Error)]
#[error("`file` resolves outside the workdir")]
pub(super) struct OutsideWorkdir;

#[cfg(fuzzing)]
pub(super) struct LocalFindingSource;
#[cfg(fuzzing)]
impl Validate<&[u8], Repo> for LocalFindingSource {
	type Output = u64;
	type Error = std::str::Utf8Error;
	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, _: Mark<'view, Repo>,
	) -> Result<u64, Self::Error> {
		Ok(std::str::from_utf8(u.get())?.lines().count().max(1) as u64)
	}
}
#[cfg(fuzzing)]
pub(super) struct FingerprintWindow<'a> {
	pub(super) file: &'a str,
	pub(super) line_start: u32,
	pub(super) line_end: u32,
}
/// Host-computed digest; its narrow output is not invented Agent text.
pub(super) struct ComputedFingerprint(String);
impl std::fmt::Debug for ComputedFingerprint {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("ComputedFingerprint([redacted])")
	}
}
impl ComputedFingerprint {
	pub(super) fn from_stream(hash: blake3::Hash) -> Self {
		Self(hash.to_hex().to_string())
	}
	pub(super) fn for_submission(&self) -> &str {
		&self.0
	}
	pub(super) fn line_range(file: &str, line_start: u32, line_end: u32) -> Self {
		Self(crate::fingerprint::compute(
			super::SCANNER_ID,
			file,
			&format!("L{line_start}-L{line_end}"),
		))
	}
}
impl serde::Serialize for ComputedFingerprint {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		serializer.serialize_str(&self.0)
	}
}
#[cfg(fuzzing)]
impl Validate<&[u8], Repo> for FingerprintWindow<'_> {
	type Output = ComputedFingerprint;
	type Error = std::str::Utf8Error;
	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, _: Mark<'view, Repo>,
	) -> Result<Self::Output, Self::Error> {
		let source = std::str::from_utf8(u.get())?;
		let window = crate::fingerprint::extract_window(
			source,
			self.line_start,
			self.line_end,
			super::FINGERPRINT_CONTEXT_LINES,
		);
		Ok(ComputedFingerprint(crate::fingerprint::compute(super::SCANNER_ID, self.file, &window)))
	}
}

pub(super) struct RepoDiffCheckDecoder;
pub(super) struct RepoDiffCheck {
	status: std::process::ExitStatus,
	diagnostic: String,
	source: PhantomData<Repo>,
}
impl std::fmt::Debug for RepoDiffCheck {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("RepoDiffCheck<Repo>([redacted])")
	}
}
impl Validate<std::process::Output, Repo> for RepoDiffCheckDecoder {
	type Output = RepoDiffCheck;
	type Error = std::convert::Infallible;
	fn validate<'view>(
		self, u: Unvalidated<'view, std::process::Output>, _: Mark<'view, Repo>,
	) -> Result<Self::Output, Self::Error> {
		let output = u.get();
		let mut stderr = if output.status.success() {
			String::new()
		} else {
			String::from_utf8_lossy(&output.stderr).into_owned()
		};
		const MAX_STDERR: usize = 4096;
		if stderr.len() > MAX_STDERR {
			let mut end = MAX_STDERR;
			while !stderr.is_char_boundary(end) {
				end -= 1;
			}
			stderr.truncate(end);
			stderr.push_str("\n…(truncated)");
		}
		if !output.status.success() && stderr.trim().is_empty() {
			stderr = format!("git apply exited {}", output.status);
		}
		Ok(RepoDiffCheck { status: output.status, diagnostic: stderr, source: PhantomData })
	}
}
impl RepoDiffCheck {
	/// Existing finite sender-facing Git diagnostic egress. This preserves
	/// rendered UTF-8 truncation; wait_with_output collection remains unbounded.
	pub(super) fn into_outcome(self) -> super::DiffCheck {
		if self.status.success() {
			super::DiffCheck::Applies
		} else {
			super::DiffCheck::Rejects { stderr: self }
		}
	}
	pub(super) fn for_tool_response(&self) -> &str {
		&self.diagnostic
	}
}
