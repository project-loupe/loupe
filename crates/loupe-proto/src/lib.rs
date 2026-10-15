// Keep production safety lints separate from test-only assertions.
#![cfg_attr(
	not(test),
	deny(
		clippy::unwrap_used,
		clippy::expect_used,
		clippy::string_slice,
		clippy::mem_forget,
		clippy::dbg_macro,
		clippy::todo,
		clippy::unimplemented,
		clippy::disallowed_methods
	)
)]
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]
//! Wire-format DTOs for loupe.
//!
//! Every DTO request and response carries a `protocol_version: u16` so
//! a mismatched server/worker pair fails loudly at the application
//! layer rather than silently mis-parsing. The URL prefix (`/v1`) and
//! the `X-Loupe-Protocol` request/response header cover routes whose
//! request body is empty or query-string only.

#[macro_use]
mod record;
mod credential_wire;
mod findings_admin;
mod job_io;
mod lease;
mod registry;
mod scan;
mod secret_serde;
mod version;

#[cfg(test)]
#[path = "../tests/support/fixtures.rs"]
mod test_support;

pub use credential_wire::server_certificate_json_pretty;
pub use findings_admin::{
	FindingDetail, FindingSummary, ListFindingsResponse, RetryVerifyRequest, RetryVerifyResponse,
};
pub use job_io::{
	validate_llm_finding, validate_llm_finding_submission, CompleteOutcome, CompleteRequest,
	FindingsBatch, HeartbeatRequest, HeartbeatResponse, LlmFindingSubmission, LlmFindingValidation,
	VerdictSubmission,
};
pub use lease::{JobCapability, LeaseEnvelope, LeasePayload, LeaseRequest, LeaseResponse};
pub use loupe_core::ScannerDocument;
pub use registry::{
	GithubAppResponse, GithubAppSummary, GithubReportingAuth, ListReposResponse,
	RegisterRepoRequest, RegisterRepoResponse, RegisterWorkerRequest, RegisterWorkerResponse,
	RepoSummary, ReportingSetup, ReportingSummary, RotateRepoPatRequest, SetGithubAppRequest,
	SetRepoGithubReportingRequest, UpdateRepoRequest,
};
pub use scan::{JobInfo, ScanRequest, ScanResponse};
pub use version::{check_protocol_version, ProtocolMismatch, PROTOCOL_VERSION};

/// HTTP header that carries the Loupe wire-protocol version independently
/// of any DTO field. Workers send it on every request; the server sets it
/// on every response.
pub const PROTOCOL_VERSION_HEADER: &str = "X-Loupe-Protocol";
/// Per-lease bearer capability. Worker mTLS identifies the trusted
/// supervisor; this header binds a request to one exact active job.
pub const JOB_CAPABILITY_HEADER: &str = "X-Loupe-Job-Capability";
/// Length of a capability token: 32 random bytes in unpadded base64url.
/// The server filters on it before hashing, so it has to travel with
/// the header rather than being restated as a literal at that check.
pub const JOB_CAPABILITY_TOKEN_CHARS: usize = 43;

/// Scanner id the LLM discovery agent submits under. The worker tags
/// its findings with it and the server both stamps it on strict
/// submissions and refuses it on the batch endpoint, so the two must
/// agree; a silent drift would reopen the batch path to LLM findings.
pub const LLM_CODE_REVIEW_SCANNER_ID: &str = "llm-code-review";

/// Observe the actual strict-submission lexical path predicate. The normal
/// validator reaches it only after its source-retaining RepoPath admission.
#[cfg(fuzzing)]
pub fn fuzz_llm_path_is_normalized(raw: &str) -> bool {
	job_io::llm_path_is_normalized(raw)
}

#[cfg(kani)]
#[path = "../kani/mod.rs"]
mod kani;
