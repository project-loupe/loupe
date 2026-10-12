#![cfg_attr(not(fuzzing), forbid(unsafe_code))]
#![cfg_attr(fuzzing, deny(unsafe_code))]
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
#[cfg(fuzzing)]
mod ingress;
pub mod render;
