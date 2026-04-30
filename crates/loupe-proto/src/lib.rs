//! Wire-format DTOs for loupe.
//!
//! Every request and response carries a `protocol_version: u16` so a
//! mismatched server/worker pair fails loudly at the application layer
//! rather than silently mis-parsing. The URL prefix (`/v1`) and the
//! `X-Loupe-Protocol` response header are the other two layers — see the
//! plan for the full versioning strategy.

mod findings_admin;
mod job_io;
mod lease;
mod registry;
mod scan;
mod version;

pub use findings_admin::{
	FindingDetail, FindingSummary, KnownFingerprintsRequest, KnownFingerprintsResponse,
	ListFindingsResponse,
};
pub use job_io::{
	CompleteOutcome, CompleteRequest, FindingsBatch, HeartbeatResponse, VerdictSubmission,
};
pub use lease::{LeaseEnvelope, LeasePayload, LeaseRequest, LeaseResponse};
pub use registry::{
	ListReposResponse, RegisterRepoRequest, RegisterRepoResponse, RegisterWorkerRequest,
	RegisterWorkerResponse, RepoSummary, ReportingSetup, UpdateRepoRequest,
};
pub use scan::{JobInfo, ScanRequest, ScanResponse};
pub use version::{check_protocol_version, ProtocolMismatch, PROTOCOL_VERSION};

/// HTTP header that carries the server's protocol version on every response,
/// independently of any DTO field. Set by the server, logged by clients.
pub const PROTOCOL_VERSION_HEADER: &str = "X-Loupe-Protocol";
