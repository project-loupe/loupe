// Tests may unwrap fixture setup errors; production code must handle them.
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
#![deny(unsafe_code)]
//! `loupe-worker` library surface.

#[cfg(test)]
mod test_env;
#[cfg(test)]
mod test_support;

pub mod canary;
pub mod client;
pub mod config;
pub mod config_value_parsers;
pub mod fingerprint;
mod git_credentials;
pub mod host_outcome;
mod ingress_text;
mod limits;
pub mod llm;
pub mod mcp;
pub mod repo_cache;
pub mod runner;
pub mod sandbox;
mod sandbox_network;
pub mod scanner;
pub mod scanners;
pub(crate) mod source_discovery;

pub use client::ServerClient;
#[doc(hidden)]
pub use git_credentials::run_git_credential_helper;
pub use repo_cache::{RepoCache, RepoKey};
pub use runner::Runner;
pub use scanner::{ScanContext, Scanner, VerifyContext, VerifyOutcome};

#[cfg(any(kani, test))]
#[path = "../kani/mod.rs"]
mod kani;
