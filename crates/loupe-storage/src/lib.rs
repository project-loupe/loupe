#![deny(unsafe_code)]
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

//! SQLite storage layer for loupe.
//!
//! The schema is defined as an ordered list of migrations in `migrations`.
//! `Db::open` runs any unapplied migrations inside a transaction and
//! advances `schema_meta.version`. Tests are encouraged to use
//! `Db::open_in_memory` so the migration code path is exercised on every
//! run.

pub mod campaign_workflow;
pub mod campaigns;
pub mod checkpoints;
mod db;
pub mod finding_details;
pub mod findings;
pub mod generations;
pub mod github_app;
pub mod identity;
mod ingress;
pub mod inventory;
pub mod jobs;
pub mod lead_observations;
pub mod leads;
pub mod maintenance;
pub mod migrations;
mod ownership;
pub mod proofs;
pub mod recovery;
pub mod registry;
mod report_identity;
pub mod reports;
pub mod repos;
mod review;
pub mod review_unit_results;
pub mod review_units;
pub mod scheduler;
pub mod scope;
#[cfg(any(test, fuzzing))]
pub mod scope_sequence_fuzz;
pub mod secrets;
pub mod source_refs;
pub mod terminal_receipt;
pub(crate) mod transaction;
pub mod workers;

#[cfg(test)]
extern crate self as loupe_storage;

#[cfg(test)]
#[path = "sql_tests/support/db.rs"]
mod sql_fixture;

#[cfg(test)]
#[path = "sql_tests/source_migration_baseline.rs"]
mod source_migration_baseline_tests;
#[cfg(test)]
#[path = "sql_tests/source_migration.rs"]
mod source_migration_tests;
#[cfg(test)]
#[path = "sql_tests/sql_ingress.rs"]
mod sql_ingress_tests;

#[cfg(test)]
mod proof_tests;
#[cfg(test)]
mod replay_tests;
#[cfg(test)]
mod review_tests;
#[cfg(test)]
mod scope_tests;
#[cfg(test)]
mod server_campaign_support;
#[cfg(test)]
mod server_campaign_tests;
#[cfg(test)]
mod server_fixture_tests;
#[cfg(test)]
mod server_lifecycle_tests;
#[cfg(test)]
mod test_support;

pub use db::{Db, Error, Result};
pub use loupe_core::canonical;
pub use review::{Conflict, Entity, Ownership};

#[cfg(test)]
mod scope_agreement_tests;

#[cfg(kani)]
#[path = "../kani/mod.rs"]
mod kani;
