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
//! Provenance labels: where a value came from, and whether it is a
//! secret, enforced by the type system.
//!
//! Two independent wrappers:
//!
//! - [`Untrusted<T, S>`] says "this value arrived from source `S` and has not
//!   been parsed". It cannot be read. The only way out is
//!   [`Untrusted::validate`], which runs a [`Validate`] impl (a parser) and
//!   returns that parser's typed output or its error. Every parser in the tree
//!   is a `Validate` impl, so forgetting to parse is a compile error, and `grep
//!   Unvalidated<` plus `grep map_ref(` finds every place bytes are looked at.
//!   An `Untrusted` can only be constructed with an [`Ingress`] token, so a
//!   wrapped value is born only where bytes enter the process. A
//!   [`ValidateCarrying`] impl may hand sub-slices on under another source with
//!   [`Unvalidated::carry`], for the sealed pairs in [`CarriedFrom`] only (the
//!   text fields of a worker's phase payload are agent text).
//! - [`Secret<T>`] says "do not print this and wipe it when done". `Debug` and
//!   `Display` print `[redacted]`; [`Secret::expose`] is the one accessor;
//!   `Drop` zeroises the bytes through volatile writes.
//!
//! `no_std` plus `alloc`, no dependencies. This crate never touches a
//! socket, file, clock or process. Nothing in it panics. Source labels
//! and their trust assumptions are defined in [`Source`]; the crate's
//! security contracts are documented in `PRACTICES.md`.
#![no_std]
// `unsafe_code` is denied by the workspace lints. One module,
// `volatile`, allows it for zeroising writes.
#![deny(missing_docs)]
// Not a parser crate, but it promises never to panic, so
// it opts into the parser lint block to hold that for every input size,
// not only the Kani bounds.
#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::panic)]
// The workspace rustfmt formats code inside doc comments with hard
// tabs (`hard_tabs` plus `format_code_in_doc_comments`); the lint and
// the formatter cannot both be satisfied, and the formatter is the
// project's choice.
#![allow(clippy::tabs_in_doc_comments)]

extern crate alloc;

mod secret;
mod source;
mod untrusted;
mod volatile;

#[cfg(test)]
mod tests;

#[cfg(doctest)]
mod compile_fail;

#[cfg(kani)]
#[path = "../kani/mod.rs"]
mod kani;

pub use secret::{Secret, Zeroise};
pub use source::{
	Agent, Browser, Config, Db, Operator, Provider, Repo, Reporter, Sandbox, Server, Source, Worker,
};
pub use untrusted::{
	CarriedFrom, Ingress, Mark, Unlabelled, Untrusted, Unvalidated, Validate, ValidateCarrying,
};
