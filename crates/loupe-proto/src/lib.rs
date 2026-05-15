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

pub use findings_admin::{FindingDetail, FindingSummary, ListFindingsResponse};
pub use job_io::{
	CompleteOutcome, CompleteRequest, FindingsBatch, HeartbeatRequest, HeartbeatResponse,
	VerdictSubmission,
};
pub use lease::{LeaseEnvelope, LeasePayload, LeaseRequest, LeaseResponse};
pub use registry::{
	ListReposResponse, RegisterRepoRequest, RegisterRepoResponse, RegisterWorkerRequest,
	RegisterWorkerResponse, RepoSummary, ReportingSetup, RotateRepoPatRequest,
	SetRepoGithubReportingRequest, UpdateRepoRequest,
};
pub use scan::{JobInfo, ScanRequest, ScanResponse};
pub use version::{check_protocol_version, ProtocolMismatch, PROTOCOL_VERSION};

/// HTTP header that carries the Loupe wire-protocol version independently
/// of any DTO field. Workers send it on every request; the server sets it
/// on every response.
pub const PROTOCOL_VERSION_HEADER: &str = "X-Loupe-Protocol";
