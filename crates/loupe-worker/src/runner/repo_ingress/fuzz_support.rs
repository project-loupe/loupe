//! Original binary Git OID and raw tree-prefix/name fixture observations.
use loupe_provenance::{Ingress, Untrusted};

use super::*;

#[allow(unsafe_code)]
pub fn revision(original: &[u8]) -> Result<String, String> {
	// SAFETY: original cfg-only binary repository OID fixture, before hex formatting.
	let original = Untrusted::new(original, unsafe { Ingress::<Repo>::new() });
	original
		.validate(CheckedOutRevisionDecoder)
		.map(|v| v.into_revision().expose().to_owned())
		.map_err(|e| e.to_string())
}
// debug-ok: Cfg-only synthetic observation; raw values support independent source and compatibility assertions.
#[derive(Debug, PartialEq, Eq)]
pub enum Gitlink {
	Relative(String),
	Unrepresentable(Vec<u8>),
}
#[allow(unsafe_code)]
pub fn gitlink(root: &[u8], name: &[u8]) -> Gitlink {
	// SAFETY: original cfg-only libgit2 raw prefix/name observations, before concatenation.
	let original = Untrusted::new(GitlinkName { root, name }, unsafe { Ingress::<Repo>::new() });
	match original.validate(RepositoryGitlinkPathDecoder).unwrap() {
		RepositoryGitlinkPath::Relative(path) => Gitlink::Relative(path.expose().to_owned()),
		RepositoryGitlinkPath::UnrepresentableNative { bytes, .. } => {
			Gitlink::Unrepresentable(bytes)
		},
	}
}
