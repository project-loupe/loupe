use serde::{Deserialize, Serialize};

/// Where a worker can find a repository to scan.
///
/// `clone_url` is what the worker passes to `git clone` — typically an
/// `https://` URL. The host/owner/repo triple is duplicated so the server
/// can index without re-parsing every URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoSpec {
	pub host: String,
	pub owner: String,
	pub repo: String,
	pub clone_url: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub branch: Option<String>,
}

/// How a confirmed finding should be reported.
///
/// Tagged so future variants (`GithubPr`, ...) can be added without an
/// `unknown variant` error breaking older clients — readers that don't
/// know a variant should mark the destination invalid rather than
/// crash. See `loupe-storage::repos` for that handling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReportingDestination {
	/// Open an issue on the target repo, either with a stored GitHub PAT
	/// or through the server-wide GitHub App.
	GithubIssue {
		target_owner: String,
		target_repo: String,
		/// Foreign key into `loupe-storage`'s `secrets` table — the PAT
		/// itself never travels in serialized `RepoSpec`/`ReportingDestination`
		/// payloads. `None` means the server files issues as its GitHub
		/// App instead.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pat_secret_id: Option<i64>,
	},
	/// Send an email to one or more recipients via the server's
	/// configured `sendmail` binary.
	Email {
		to: Vec<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		from: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		subject_prefix: Option<String>,
	},
	/// No automatic reporter is configured. Confirmed findings remain
	/// `confirmed` until an operator either handles them out-of-band or
	/// configures a reporter and retries delivery.
	Manual,
}
