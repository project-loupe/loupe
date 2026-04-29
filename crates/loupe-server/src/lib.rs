//! `loupe-server` library surface.
//!
//! Exposed for integration tests; the binary in `main.rs` is a thin
//! wrapper that loads config and spins up [`serve`].

pub mod config;
pub mod init;
pub mod router;
pub mod routes;
pub mod state;
pub mod tls;

pub use config::Config;
pub use router::{router, serve, ServeHandle};
pub use state::AppState;
