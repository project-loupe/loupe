//! Entry point for the loupe scan/verify worker.
//!
//! At this commit the binary is just a placeholder so the workspace
//! produces a buildable target — the lease/heartbeat/scan loop lands in
//! a follow-up commit.

fn main() {
	tracing_subscriber::fmt::init();
	tracing::info!("loupe-worker starting (placeholder; runner not yet implemented)");
}
