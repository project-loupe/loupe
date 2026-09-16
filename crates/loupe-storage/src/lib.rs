//! SQLite storage layer for loupe.
//!
//! The schema is defined as an ordered list of migrations in `migrations`.
//! `Db::open` runs any unapplied migrations inside a transaction and
//! advances `schema_meta.version`. Tests are encouraged to use
//! `Db::open_in_memory` so the migration code path is exercised on every
//! run.

pub mod campaigns;
pub mod checkpoints;
mod db;
pub mod finding_details;
pub mod findings;
pub mod generations;
pub mod identity;
pub mod inventory;
pub mod jobs;
pub mod lead_observations;
pub mod leads;
pub mod migrations;
pub mod ownership;
pub mod proofs;
pub mod repos;
mod review;
pub mod review_unit_results;
pub mod review_units;
pub mod scheduler;
pub mod secrets;
pub mod source_refs;
pub mod terminal_receipt;
pub mod transaction;
pub mod workers;

#[cfg(test)]
mod proof_tests;
#[cfg(test)]
mod replay_tests;
#[cfg(test)]
mod review_tests;
#[cfg(test)]
mod scope_tests;

pub use db::{Db, Error, Result};
pub use loupe_core::canonical;
pub use review::{Conflict, Entity, Ownership};
