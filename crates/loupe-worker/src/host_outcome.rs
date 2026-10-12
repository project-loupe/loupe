//! Closed host decisions with separately retained Server revision evidence.
//! Host-generated reasons are serialized here and never minted as Agent text.
use loupe_core::source_migration::text::BoundedText;
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
	/// Named mixed-source submission egress. The temporary legacy DTO adapter
	/// disappears at M; the closed reason and Server input survive that join.
	pub(crate) fn into_legacy_submission(self) -> loupe_proto::VerdictSubmission {
		let (reason,terminal)=match self {
			Self::ScannerDoesNotVerify=>("scanner does not verify".to_owned(),false),
			Self::MissingReviewedRevision=>("original reviewed revision is unavailable: verify lease did not carry the original reviewed revision".to_owned(),true),
			Self::ReviewedRevisionUnavailable{revision,failure}=>{
				let sha=revision.text();
				let detail=match failure {
					CheckoutFailure::ParseRevision|CheckoutFailure::LocateRevision=>format!("{failure} {sha}"),
					_=>failure.to_string(),
				};
				(format!("original reviewed revision {sha} is unavailable after refreshing and re-cloning the repository: {detail}"),true)
			}
		};
		loupe_proto::VerdictSubmission {
			protocol_version: loupe_proto::PROTOCOL_VERSION,
			verdict: loupe_core::Verdict::Inconclusive { reason, terminal },
		}
	}
}
