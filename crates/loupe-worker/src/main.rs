//! Entry point for the loupe scan/verify worker.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use loupe_worker::scanners::RegexSecretsScanner;
use loupe_worker::{RepoCache, Runner, Scanner, ServerClient};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(version, about = "loupe scan/verify worker")]
struct Args {
	/// Base URL of the loupe-server (e.g. https://loupe-server:8443).
	#[arg(long, env = "LOUPE_SERVER_URL")]
	server_url: reqwest::Url,
	/// Path to the CA cert (server-auth root).
	#[arg(long, env = "LOUPE_CA_CERT")]
	ca_cert: PathBuf,
	/// Path to this worker's client cert PEM.
	#[arg(long, env = "LOUPE_WORKER_CERT")]
	cert: PathBuf,
	/// Path to this worker's client private-key PEM.
	#[arg(long, env = "LOUPE_WORKER_KEY")]
	key: PathBuf,
	/// Where to keep cached bare clones.
	#[arg(long, env = "LOUPE_CACHE_DIR")]
	cache_dir: PathBuf,
	/// Maximum cache size in GB before LRU eviction kicks in.
	#[arg(long, default_value_t = 40)]
	max_cache_gb: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
	tracing_subscriber::fmt::init();
	let args = Args::parse();

	let ca_cert_pem = std::fs::read_to_string(&args.ca_cert)
		.with_context(|| format!("reading CA cert at {}", args.ca_cert.display()))?;
	let cert_pem = std::fs::read_to_string(&args.cert)
		.with_context(|| format!("reading worker cert at {}", args.cert.display()))?;
	let key_pem = std::fs::read_to_string(&args.key)
		.with_context(|| format!("reading worker key at {}", args.key.display()))?;

	let client = Arc::new(ServerClient::new(&ca_cert_pem, &cert_pem, &key_pem, args.server_url)?);
	let cache = Arc::new(RepoCache::new(args.cache_dir, args.max_cache_gb * 1_073_741_824)?);

	let scanners: Vec<Arc<dyn Scanner>> = vec![Arc::new(RegexSecretsScanner::new())];
	let runner = Runner::new(client, cache, scanners);

	let cancel = CancellationToken::new();
	let cancel_for_signal = cancel.clone();
	tokio::spawn(async move {
		let _ = tokio::signal::ctrl_c().await;
		tracing::info!("loupe-worker shutdown requested");
		cancel_for_signal.cancel();
	});

	tracing::info!("loupe-worker running");
	runner.run_forever(cancel).await?;
	Ok(())
}
