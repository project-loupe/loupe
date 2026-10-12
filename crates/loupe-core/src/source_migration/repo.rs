use loupe_provenance::Source;
use serde::Serialize;

use super::text::BoundedText;
use crate::text::policy::{
	CloneUrl, GitBranch, MailAddress, MailSubjectPrefix, RepoHost, RepoName, RepoOwner,
};

/// Exact repository settings from the named configuration or wire boundary.
/// The Git sink separately validates destination and credential authority.
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct RepoSpec<S: Source> {
	pub host: BoundedText<RepoHost, S>,
	pub owner: BoundedText<RepoOwner, S>,
	pub repo: BoundedText<RepoName, S>,
	pub clone_url: BoundedText<CloneUrl, S>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub branch: Option<BoundedText<GitBranch, S>>,
}
record_impls!(RepoSpec { host, owner, repo, clone_url, branch });

/// Source-retaining report settings. Text validation alone does not authorize
/// a destination or admit these strings as email headers.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", bound(serialize = ""))]
pub enum ReportingDestination<S: Source> {
	GithubIssue {
		target_owner: BoundedText<RepoOwner, S>,
		target_repo: BoundedText<RepoName, S>,
		#[serde(skip_serializing_if = "Option::is_none")]
		pat_secret_id: Option<i64>,
	},
	Email {
		to: Vec<BoundedText<MailAddress, S>>,
		#[serde(skip_serializing_if = "Option::is_none")]
		from: Option<BoundedText<MailAddress, S>>,
		#[serde(skip_serializing_if = "Option::is_none")]
		subject_prefix: Option<BoundedText<MailSubjectPrefix, S>>,
	},
	Manual,
}
impl<S: Source> Clone for ReportingDestination<S> {
	fn clone(&self) -> Self {
		match self {
			Self::GithubIssue { target_owner, target_repo, pat_secret_id } => Self::GithubIssue {
				target_owner: target_owner.clone(),
				target_repo: target_repo.clone(),
				pat_secret_id: *pat_secret_id,
			},
			Self::Email { to, from, subject_prefix } => Self::Email {
				to: to.clone(),
				from: from.clone(),
				subject_prefix: subject_prefix.clone(),
			},
			Self::Manual => Self::Manual,
		}
	}
}
impl<S: Source> PartialEq for ReportingDestination<S> {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			(
				Self::GithubIssue { target_owner: a, target_repo: b, pat_secret_id: c },
				Self::GithubIssue { target_owner: x, target_repo: y, pat_secret_id: z },
			) => a == x && b == y && c == z,
			(
				Self::Email { to: a, from: b, subject_prefix: c },
				Self::Email { to: x, from: y, subject_prefix: z },
			) => a == x && b == y && c == z,
			(Self::Manual, Self::Manual) => true,
			_ => false,
		}
	}
}
impl<S: Source> Eq for ReportingDestination<S> {}
impl<S: Source> std::fmt::Debug for ReportingDestination<S> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "ReportingDestination<{}>([redacted])", S::NAME)
	}
}
