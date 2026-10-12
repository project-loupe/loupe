//! Closed host decisions with separately retained Server revision evidence.
//! Host-generated reasons are serialized here and never minted as Agent text.
use loupe_core::text::BoundedText;
use loupe_provenance::Server;

use crate::ingress_text::RevisionText;

#[derive(Clone, Debug)]
pub struct ReviewedRevision(BoundedText<RevisionText, Server>);
impl ReviewedRevision {
	pub(crate) fn admitted(value: BoundedText<RevisionText, Server>) -> Self {
		Self(value)
	}
	pub(crate) fn text(&self) -> &str {
		self.0.expose()
	}
	pub(crate) fn into_revision(self) -> BoundedText<RevisionText, Server> {
		self.0
	}
}
#[derive(Clone)]
pub(crate) enum ReviewedRevisionFact {
	MissingReviewedRevision,
	Available(ReviewedRevision),
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum CheckoutFailure {
	#[error("creating temp worktree dir")]
	CreateWorktree,
	#[error("opening bare repository")]
	OpenRepository,
	#[error("locating branch reference")]
	LocateBranch,
	#[error("locating HEAD reference")]
	LocateHead,
	#[error("resolving ref to commit")]
	ResolveReference,
	#[error("parsing reviewed revision")]
	ParseRevision,
	#[error("locating reviewed revision")]
	LocateRevision,
	#[error("resolving reviewed revision to commit")]
	ResolveRevision,
	#[error("resolving commit tree")]
	ResolveTree,
	#[error("attaching temporary worktree to bare repo")]
	AttachWorktree,
	#[error("checking out tree into worktree dir")]
	CheckoutTree,
	#[error("checkout task failed")]
	Task,
}

pub enum HostVerifyReason {
	ScannerDoesNotVerify,
	MissingReviewedRevision,
	ReviewedRevisionUnavailable { revision: ReviewedRevision, failure: CheckoutFailure },
}
impl HostVerifyReason {
	pub(crate) fn into_submission(self) -> HostSubmission {
		HostSubmission(self)
	}
}

/// Only this closed host decision can construct the mixed-source wire owner.
pub(crate) struct HostSubmission(HostVerifyReason);
impl serde::Serialize for HostSubmission {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		use serde::ser::SerializeStruct;
		let mut wire = serializer.serialize_struct("VerdictSubmission", 2)?;
		wire.serialize_field("protocol_version", &loupe_proto::PROTOCOL_VERSION)?;
		wire.serialize_field("verdict", &HostVerdict(&self.0))?;
		wire.end()
	}
}
struct HostVerdict<'a>(&'a HostVerifyReason);
impl serde::Serialize for HostVerdict<'_> {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		use serde::ser::SerializeStruct;
		let terminal = !matches!(self.0, HostVerifyReason::ScannerDoesNotVerify);
		let mut wire = serializer.serialize_struct("Verdict", if terminal { 3 } else { 2 })?;
		wire.serialize_field("outcome", "inconclusive")?;
		wire.serialize_field("reason", &HostReason(self.0))?;
		if terminal {
			wire.serialize_field("terminal", &true)?;
		}
		wire.end()
	}
}
struct HostReason<'a>(&'a HostVerifyReason);
impl std::fmt::Display for HostReason<'_> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self.0 {
			HostVerifyReason::ScannerDoesNotVerify => f.write_str("scanner does not verify"),
			HostVerifyReason::MissingReviewedRevision => f.write_str("original reviewed revision is unavailable: verify lease did not carry the original reviewed revision"),
			HostVerifyReason::ReviewedRevisionUnavailable { revision, failure } => {
				let sha = revision.text();
				write!(f, "original reviewed revision {sha} is unavailable after refreshing and re-cloning the repository: {failure}")?;
				if matches!(failure, CheckoutFailure::ParseRevision | CheckoutFailure::LocateRevision) {
					write!(f, " {sha}")?;
				}
				Ok(())
			},
		}
	}
}
impl serde::Serialize for HostReason<'_> {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		serializer.collect_str(self)
	}
}
