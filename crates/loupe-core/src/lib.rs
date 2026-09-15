//! Shared domain types for loupe.
//!
//! These types are the lingua franca between `loupe-server`, `loupe-worker`,
//! and `loupe-cli`. They deliberately know nothing about storage layout or
//! wire framing — those concerns live in `loupe-storage` and `loupe-proto`.

pub mod canonical;
mod error;
mod finding;
mod finding_state;
mod job;
mod repo;
mod severity;
mod state_machine;
pub mod text;
mod verdict;

pub use error::{Error, Result};
pub use finding::Finding;
pub use finding_state::FindingState;
pub use job::{JobKind, JobState};
pub use repo::{RepoSpec, ReportingDestination};
pub use severity::Severity;
pub use state_machine::{
	initial_finding_state, initial_job_state, roll_up_verdicts, FindingTransition, JobTransition,
	StateTransitionError, VerdictRollup,
};
pub use verdict::{Verdict, VerdictPatch};
