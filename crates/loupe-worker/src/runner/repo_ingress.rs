//! Original libgit2 observations are Repo, before hex/path formatting.
use loupe_core::text::{BoundedText, RepoPath};
use loupe_provenance::{Mark, Repo, Unvalidated, Validate};

use crate::ingress_text::{DecodeError, RevisionText};
#[cfg(fuzzing)]
pub mod fuzz_support;

pub(super) struct CheckedOutRevision(BoundedText<RevisionText, Repo>);
pub(super) struct CheckedOutRevisionDecoder;
impl Validate<&[u8], Repo> for CheckedOutRevisionDecoder {
	type Output = CheckedOutRevision;
	type Error = DecodeError;
	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, mark: Mark<'view, Repo>,
	) -> Result<Self::Output, Self::Error> {
		let oid = git2::Oid::from_bytes(u.get())
			.map_err(|_| DecodeError::Data("invalid repository object id"))?;
		Ok(CheckedOutRevision(BoundedText::new(&mark, &oid.to_string())?))
	}
}
impl CheckedOutRevision {
	pub(super) fn into_revision(self) -> BoundedText<RevisionText, Repo> {
		self.0
	}
}

pub(super) struct GitlinkName<'a> {
	pub(super) root: &'a [u8],
	pub(super) name: &'a [u8],
}
pub(super) enum RepositoryGitlinkPath {
	Relative(RepoPath<Repo>),
	UnrepresentableNative { bytes: Vec<u8>, source: std::marker::PhantomData<Repo> },
}
pub(super) struct RepositoryGitlinkPathDecoder;
impl Validate<GitlinkName<'_>, Repo> for RepositoryGitlinkPathDecoder {
	type Output = RepositoryGitlinkPath;
	type Error = std::convert::Infallible;
	fn validate<'view>(
		self, u: Unvalidated<'view, GitlinkName<'_>>, mark: Mark<'view, Repo>,
	) -> Result<Self::Output, Self::Error> {
		let name = u.get();
		let mut bytes = Vec::with_capacity(name.root.len() + name.name.len());
		bytes.extend_from_slice(name.root);
		bytes.extend_from_slice(name.name);
		let typed =
			std::str::from_utf8(&bytes).ok().and_then(|text| RepoPath::new(&mark, text).ok());
		Ok(match typed {
			Some(path) => RepositoryGitlinkPath::Relative(path),
			None => RepositoryGitlinkPath::UnrepresentableNative {
				bytes,
				source: std::marker::PhantomData,
			},
		})
	}
}
impl RepositoryGitlinkPath {
	pub(super) fn byte_count(&self) -> usize {
		match self {
			Self::Relative(path) => path.expose().len(),
			Self::UnrepresentableNative { bytes, .. } => bytes.len(),
		}
	}
	#[cfg(test)]
	pub(super) fn fixture_text(&self) -> std::borrow::Cow<'_, str> {
		match self {
			Self::Relative(path) => std::borrow::Cow::Borrowed(path.expose()),
			Self::UnrepresentableNative { bytes, .. } => String::from_utf8_lossy(bytes),
		}
	}
}
