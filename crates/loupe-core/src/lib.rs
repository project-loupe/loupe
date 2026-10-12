#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]
//! Shared domain types for loupe.
//!
//! These types are the lingua franca between `loupe-server`, `loupe-worker`,
//! and `loupe-cli`. They deliberately know nothing about storage layout or
//! wire framing — those concerns live in `loupe-storage` and `loupe-proto`.

#[macro_use]
mod record;
mod pending_follow_up;
mod scanner;
pub use pending_follow_up::{FollowUpTrigger, PendingFollowUp, ReviewIntent};
pub use scanner::ScannerDocument;
pub mod canonical;
/// Immutable recipe/behavior contract recorded on review generations and jobs.
pub const WORKFLOW_CONTRACT_VERSION: i64 = 2;
mod error;
mod finding;
mod finding_state;
mod job;
mod repo;
pub mod report_limits;
pub mod security_event;
mod severity;
mod state_machine;
#[cfg(test)]
mod test_support;
pub mod text;
mod verdict;

pub use error::{Error, Result};
pub use finding::{format_finding_id, Finding};
pub use finding_state::FindingState;
pub use job::{JobKind, JobState};
pub use repo::{RepoSpec, ReportingDestination};
pub use severity::Severity;
pub use state_machine::{
	initial_finding_state, initial_job_state, roll_up_verdicts, FindingTransition, JobTransition,
	StateTransitionError, VerdictRollup,
};
pub use verdict::{Verdict, VerdictPatch};

#[cfg(kani)]
#[path = "../kani/mod.rs"]
mod kani;
