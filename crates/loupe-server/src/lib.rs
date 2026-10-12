#![deny(unsafe_code)]
//! `loupe-server` library surface.
//!
//! Exposed for integration tests; the binary in `main.rs` is a thin
//! wrapper that loads config and spins up [`serve`].

pub mod auth;
pub mod background;
pub mod config;
#[cfg(fuzzing)]
pub mod fuzz_support;
mod ingress;
pub mod init;
pub mod job_capability;
pub mod reporters;
pub mod request_budget;
pub mod review;
pub mod router;
pub mod routes;
pub mod state;
pub mod tls;

pub use config::{Config, FileConfig};
pub use router::{router, serve, PeerCert, ServeHandle};
pub use state::AppState;

#[cfg(kani)]
#[path = "../kani/mod.rs"]
mod kani;
