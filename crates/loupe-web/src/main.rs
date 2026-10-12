#![forbid(unsafe_code)]
//! Thin wrapper: parse args, init tracing, serve. The interesting parts
//! live in the library so integration tests can reach them.

use anyhow::{Context, Result};
use clap::Parser;
use loupe_web::{config, router, AdminClient, Cli, Token, WebState};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
	let cli = Cli::parse();
	init_tracing();

	// Checked before anything else: if the bind address is wrong, nothing
	// below should have happened at all.
	config::ensure_loopback(cli.bind)?;

	let base = cli.conn.server_url()?;
	let client = AdminClient::new(
		base.clone(),
		&cli.conn.ca_pem()?,
		&cli.conn.admin_cert_pem()?,
		&cli.conn.admin_key_pem()?,
	)?;

	// Fail fast on a broken upstream rather than serving a dashboard whose
	// every action errors. `/v1/health` needs no auth, so this checks
	// reachability and protocol agreement, not the admin cert.
	match client.health().await {
		Ok(health) => {
			tracing::info!(server = %base, ?health, "upstream reachable");
		},
		Err(e) => {
			return Err(anyhow::anyhow!("cannot reach loupe-server at {base}: {e}"));
		},
	}

	let token = Token::generate();
	let listener =
		TcpListener::bind(cli.bind).await.with_context(|| format!("binding {}", cli.bind))?;
	let local_addr = listener.local_addr().context("local_addr on bound listener")?;

	// The one and only time the token is printed. It is deliberately not
	// logged through `tracing`, so it cannot end up in a log file or a
	// journal that other users can read.
	println!("loupe-web listening on http://{local_addr}");
	println!();
	println!("    http://{local_addr}/#t={}", token.reveal());
	println!();
	println!("The token above gates access to this dashboard. Anyone who can");
	println!("reach it can act as loupe admin, so treat it like the admin key.");

	let state = WebState::new(client, token, local_addr, cli.poll_seconds);
	axum::serve(listener, router(state)).await.context("serving loupe-web")?;
	Ok(())
}

fn init_tracing() {
	let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
	tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).init();
}
