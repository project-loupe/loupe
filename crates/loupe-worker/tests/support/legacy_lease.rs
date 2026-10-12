//! Independent serde oracle for lease wire compatibility. Field order, types,
//! defaults and serde attributes define the comparison contract; keep them
//! independent of production decoding. This creates no labelled production values.
use loupe_core::Severity;
use loupe_proto::JobCapability;
use loupe_provenance::Secret;
use serde::{Deserialize, Serialize};
/// Response body. Either a job is handed out (`Lease(LeaseEnvelope)`) or
/// the queue is empty / no job matches the worker's capabilities (`Empty`).
/// We carry the variant inside the body rather than relying on HTTP status
/// codes because intermediaries strip / mangle them often enough.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LeaseResponse {
	Lease(Box<LeaseEnvelope>),
	Empty { protocol_version: u16 },
}

/// The contents of an active lease — what the worker needs to run the job.
///
/// `payload` discriminates between scan and verify so that, for verify
/// jobs, the target finding travels alongside the repo spec without
/// inflating every scan-job response with optional finding fields.
#[derive(Debug, Serialize, Deserialize)]
pub struct LeaseEnvelope {
	pub protocol_version: u16,
	pub job_id: i64,
	pub job_capability: JobCapability,
	/// Server-side numeric id for the registered repo. Workers
	/// forward this through `ScanContext`/`VerifyContext` so LLM
	/// backends can scope MCP tool calls
	/// (e.g. `query_prior_findings`) to the repo currently under
	/// scan without piecing it together from `(host, owner, repo)`.
	pub repo_id: i64,
	pub repo: RepoSpec,
	pub head_branch: Option<String>,
	/// Lease expiry as epoch seconds. Worker must heartbeat or complete
	/// before this point or the server reaper will reclaim the job.
	pub lease_expires_at: i64,
	pub scanner_config: serde_json::Value,
	#[serde(default, skip_serializing_if = "Option::is_none", with = "optional")]
	pub github_pat: Option<Secret<String>>,
	pub payload: LeasePayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LeasePayload {
	Scan {
		#[serde(default, skip_serializing_if = "Option::is_none")]
		since_sha: Option<String>,
	},
	Verify {
		finding_id: i64,
		finding: Box<Finding>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		reviewed_sha: Option<String>,
	},
}

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

/// A single security finding produced by a `Scanner` and ferried back to
/// the server. The wire format intentionally mirrors the `findings` table
/// columns one-for-one so the worker can construct one without consulting
/// the storage layer.
///
/// `fingerprint` is the server-side dedup key. Scanners treat it as
/// opaque; the built-in implementations currently hash scanner id,
/// file path, and a normalized source window.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
	pub scanner_id: String,
	pub severity: Severity,
	pub title: String,
	pub description: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub file_path: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub line_start: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub line_end: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cwe: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub patch_unified: Option<String>,
	/// Unified diff that adds a regression test demonstrating the
	/// vulnerability — fails on HEAD, passes after a fix is applied.
	/// Distinct from `patch_unified` which carries a candidate *fix*.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub poc_unified: Option<String>,
	pub fingerprint: String,
}

// Findings contain repository and agent text, including paths that can embed
// secrets. Diagnostics expose only severity and source line numbers; serde
// remains the explicit transport for the complete finding.
impl std::fmt::Debug for Finding {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Finding")
			.field("severity", &self.severity)
			.field("line_start", &self.line_start)
			.field("line_end", &self.line_end)
			.finish_non_exhaustive()
	}
}

mod optional {
	use serde::{Deserializer, Serializer};

	use super::*;
	pub fn serialize<S: Serializer>(
		value: &Option<Secret<String>>, serializer: S,
	) -> Result<S::Ok, S::Error> {
		value.as_ref().map(Secret::expose).serialize(serializer)
	}
	pub fn deserialize<'de, D: Deserializer<'de>>(
		deserializer: D,
	) -> Result<Option<Secret<String>>, D::Error> {
		Option::<String>::deserialize(deserializer).map(|value| value.map(Secret::new))
	}
}
