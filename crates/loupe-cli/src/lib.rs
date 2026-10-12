#![cfg_attr(not(any(test, fuzzing)), forbid(unsafe_code))]
#![cfg_attr(any(test, fuzzing), deny(unsafe_code))]
//! Rendering shared by the operator CLI and its security harnesses.
//!
//! Normal builds expose no response decoder or fixture mint:
//! ```compile_fail,E0432
//! use loupe_cli::fuzz_support::observe_response;
//! ```

#[cfg(fuzzing)]
mod config_input;
#[cfg(fuzzing)]
pub mod fuzz_support;
#[cfg(any(test, fuzzing))]
#[cfg_attr(test, allow(dead_code))] // Test render inputs use the actual fixed response owner.
mod ingress;
#[cfg(test)]
#[path = "../tests/support/legacy_responses.rs"]
mod legacy_responses;
pub mod render;
