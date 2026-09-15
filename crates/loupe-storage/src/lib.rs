//! SQLite storage layer for loupe.
//!
//! The schema is defined as an ordered list of migrations in `migrations`.
//! `Db::open` runs any unapplied migrations inside a transaction and
//! advances `schema_meta.version`. Tests are encouraged to use
//! `Db::open_in_memory` so the migration code path is exercised on every
//! run.

pub mod campaigns;
mod db;
pub mod findings;
pub mod generations;
pub mod identity;
pub mod inventory;
pub mod jobs;
pub mod migrations;
pub mod ownership;
pub mod repos;
mod review;
pub mod secrets;
pub mod transaction;
pub mod workers;

#[cfg(test)]
mod review_tests;

pub use db::{Db, Error, Result};
pub use loupe_core::canonical;
pub use review::{Conflict, Entity, Ownership};
