//! Wire-format DTOs for loupe.
//!
//! Every DTO request and response carries a `protocol_version: u16` so
//! a mismatched server/worker pair fails loudly at the application
//! layer rather than silently mis-parsing. The URL prefix (`/v1`) and
//! the `X-Loupe-Protocol` request/response header cover routes whose
//! request body is empty or query-string only.

mod findings_admin;
mod job_io;
mod lease;
mod registry;
mod scan;
mod version;

pub use findings_admin::{
	FindingDetail, FindingSummary, ListFindingsResponse, RetryVerifyRequest, RetryVerifyResponse,
};
pub use job_io::{
	validate_llm_finding_submission, CompleteOutcome, CompleteRequest, FindingsBatch,
	HeartbeatRequest, HeartbeatResponse, LlmFindingSubmission, VerdictSubmission,
};
pub use lease::{JobCapability, LeaseEnvelope, LeasePayload, LeaseRequest, LeaseResponse};
pub use registry::{
	ListReposResponse, RegisterRepoRequest, RegisterRepoResponse, RegisterWorkerRequest,
	RegisterWorkerResponse, RepoSummary, ReportingSetup, ReportingSummary, RotateRepoPatRequest,
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
