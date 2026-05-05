//! Entry point for the loupe scan/verify worker.
//!
//! Two modes via subcommands:
//!
//! - `run` (default when no subcommand is given): the long-running
//!   worker loop — leases jobs, runs scanners, submits findings.
//! - `mcp-serve`: a one-shot stdio MCP server, spawned as a child of
//!   `claude` for the duration of one discovery / validation call.
//!   Talks to the same `loupe-server` over the same mTLS cert; the
//!   only difference is the surface (JSON-RPC over stdio vs. the
//!   long-poll lease loop).

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use loupe_worker::llm::McpContext;
use loupe_worker::llm::{
	bkb_mcp_available, build_verifier_backend, claude_available, codex_available, ClaudeCliBackend,
};
use loupe_worker::scanners::{LlmCodeReviewScanner, LlmVerifierScanner, RegexSecretsScanner};
use loupe_worker::{mcp, sandbox, RepoCache, Runner, Scanner, ServerClient};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(version, about = "loupe scan/verify worker")]
struct Cli {
	#[command(subcommand)]
	cmd: Option<Cmd>,
	#[command(flatten)]
	run: RunArgs,
}

#[derive(Debug, Subcommand)]
enum Cmd {
	/// Run the long-running scan/verify worker loop. Default when no
	/// subcommand is given, so the existing
	/// `loupe-worker --server-url ... ...` invocation keeps working.
	Run(RunArgs),
	/// Serve the MCP protocol over stdio for one agent invocation.
	/// Spawned by `claude --mcp-config <file>` from inside the
	/// sandbox the runner sets up; reads JSON-RPC from stdin, writes
	/// to stdout, logs to stderr.
	McpServe(McpServeArgs),
}

#[derive(Debug, Parser)]
struct RunArgs {
	/// Base URL of the loupe-server (e.g. https://loupe-server:8443).
	#[arg(long, env = "LOUPE_SERVER_URL")]
	server_url: Option<reqwest::Url>,
	/// Path to the CA cert (server-auth root).
	#[arg(long, env = "LOUPE_CA_CERT")]
	ca_cert: Option<PathBuf>,
	/// Path to this worker's client cert PEM.
	#[arg(long, env = "LOUPE_WORKER_CERT")]
	cert: Option<PathBuf>,
	/// Path to this worker's client private-key PEM.
	#[arg(long, env = "LOUPE_WORKER_KEY")]
	key: Option<PathBuf>,
	/// Where to keep cached bare clones.
	#[arg(long, env = "LOUPE_CACHE_DIR")]
	cache_dir: Option<PathBuf>,
	/// Maximum cache size in GB before LRU eviction kicks in.
	#[arg(long, default_value_t = 40)]
	max_cache_gb: u64,
}

#[derive(Debug, Parser)]
struct McpServeArgs {
	/// Base URL of the loupe-server.
	#[arg(long, env = "LOUPE_SERVER_URL")]
	server_url: reqwest::Url,
	#[arg(long, env = "LOUPE_CA_CERT")]
	ca_cert: PathBuf,
	#[arg(long, env = "LOUPE_WORKER_CERT")]
	cert: PathBuf,
	#[arg(long, env = "LOUPE_WORKER_KEY")]
	key: PathBuf,
	/// Repo id the agent is currently scanning. Tool calls scope to
	/// this repo automatically — there's no cross-repo lookup at the
	/// agent surface.
	#[arg(long, env = "LOUPE_REPO_ID")]
	repo_id: i64,
	/// Job id the agent is currently working on. Required for the
	/// `submit_finding` tool — submissions POST to
	/// `/v1/jobs/{job_id}/findings`. When omitted (e.g. a future
	/// read-only MCP usage) the tool is not advertised.
	#[arg(long, env = "LOUPE_JOB_ID")]
	job_id: Option<i64>,
	/// Path to the worktree the agent is reasoning over. The MCP
	/// server reads source files from here to compute fingerprints
	/// for `submit_finding`. Inside the bwrap sandbox this is
	/// `/workdir`; bare runs use the host worktree path.
	#[arg(long, env = "LOUPE_WORKDIR")]
	workdir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
	init_tracing();
	let cli = Cli::parse();
	match cli.cmd {
		Some(Cmd::Run(args)) => run_worker(args).await,
		Some(Cmd::McpServe(args)) => run_mcp_serve(args).await,
		// Default subcommand for backwards compatibility with the
		// existing `loupe-worker --server-url ...` invocation pattern.
		None => run_worker(cli.run).await,
	}
}

async fn run_worker(args: RunArgs) -> Result<()> {
	let server_url = args.server_url.context("--server-url / LOUPE_SERVER_URL is required")?;
	let ca_cert = args.ca_cert.context("--ca-cert / LOUPE_CA_CERT is required")?;
	let cert = args.cert.context("--cert / LOUPE_WORKER_CERT is required")?;
	let key = args.key.context("--key / LOUPE_WORKER_KEY is required")?;
	let cache_dir = args.cache_dir.context("--cache-dir / LOUPE_CACHE_DIR is required")?;

	let ca_cert_pem = std::fs::read_to_string(&ca_cert)
		.with_context(|| format!("reading CA cert at {}", ca_cert.display()))?;
	let cert_pem = std::fs::read_to_string(&cert)
		.with_context(|| format!("reading worker cert at {}", cert.display()))?;
	let key_pem = std::fs::read_to_string(&key)
		.with_context(|| format!("reading worker key at {}", key.display()))?;

	let client =
		Arc::new(ServerClient::new(&ca_cert_pem, &cert_pem, &key_pem, server_url.clone())?);
	let cache = Arc::new(RepoCache::new(cache_dir, args.max_cache_gb * 1_073_741_824)?);

	let mut scanners: Vec<Arc<dyn Scanner>> = vec![Arc::new(RegexSecretsScanner::new())];

	// LLM scanners auto-wire based on which agent CLIs are on PATH:
	//
	// - `claude` present  → discovery scanner (only claude has the
	//                       MCP `--mcp-config` plumbing today, so it
	//                       owns submission via the loupe MCP server).
	// - `claude` or `codex` present → verifier scanner (codex
	//                       preferred — true cross-model second
	//                       opinion; claude fallback if it's the only
	//                       one installed).
	// - neither present   → hard-fatal at startup. A loupe-worker
	//                       with no agent CLI is "regex-only", which
	//                       isn't a deployment we want operators to
	//                       fall into by accident.
	let claude = claude_available();
	let codex = codex_available();
	if !claude && !codex {
		anyhow::bail!(
			"no LLM agent CLI found on PATH (looked for `claude` and `codex`). \
			 Install at least one before starting the worker — see the README \
			 prerequisites section."
		);
	}
	// bwrap is the security boundary for every agent subprocess; if
	// it's missing and LOUPE_DISABLE_SANDBOX isn't set, refuse to run.
	match sandbox::probe_at_startup() {
		Ok(true) => tracing::info!("bubblewrap available; LLM scanners sandboxed"),
		Ok(false) => {
			tracing::warn!("LOUPE_DISABLE_SANDBOX is set; LLM scanners running without isolation")
		},
		Err(e) => return Err(e.context("LLM scanner requires bubblewrap")),
	}

	// Optional bkb-mcp auto-attach. When the operator has installed
	// `bkb-mcp` (cargo install bkb-mcp), the discovery agent gets the
	// bkb tool surface alongside loupe's submit_finding for spec /
	// historical-context lookups on bitcoin-shaped projects. The
	// presence is a single PATH probe — no opt-in flag, no install at
	// runtime; absence is silent.
	let bkb_mcp_path = bkb_mcp_available();
	if let Some(path) = &bkb_mcp_path {
		tracing::info!(
			path = %path.display(),
			"bkb-mcp detected; attaching to discovery agent's MCP config"
		);
	} else {
		tracing::info!(
			"bkb-mcp not on PATH; discovery agent will run without Bitcoin-context tools \
			 (install via `cargo install bkb-mcp` to enable)"
		);
	}

	if claude {
		// Resolve the worker binary's host path so the sandbox can
		// bind-mount it for the MCP child to exec. `current_exe()`
		// returns the executable currently running; the agent's MCP
		// child will be `loupe-worker mcp-serve`, served by the same
		// binary.
		let worker_binary = std::env::current_exe()
			.context("resolving the loupe-worker binary path for MCP bind-mount")?;
		let mcp_ctx = McpContext {
			worker_binary,
			server_url: server_url.to_string(),
			ca_cert_path: ca_cert.clone(),
			client_cert_path: cert.clone(),
			client_key_path: key.clone(),
			bkb_mcp_path: bkb_mcp_path.clone(),
		};
		let backend = Arc::new(ClaudeCliBackend::new().with_mcp_context(mcp_ctx));
		scanners
			.push(Arc::new(LlmCodeReviewScanner::new(backend).with_bkb(bkb_mcp_path.is_some())));
		tracing::info!("LLM code-review scanner enabled (claude with MCP submit_finding)");
	} else {
		tracing::info!(
			"`claude` not on PATH; LLM code-review (discovery) scanner not registered \
			 — this worker advertises verify-only"
		);
	}

	// Verifier always wires up when *either* CLI is present. The
	// helper logs which backend it picked.
	let backend = build_verifier_backend();
	scanners.push(Arc::new(LlmVerifierScanner::new(backend)));
	tracing::info!("LLM verifier scanner enabled (verify:llm advertised)");

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

async fn run_mcp_serve(args: McpServeArgs) -> Result<()> {
	let ca_cert_pem = std::fs::read_to_string(&args.ca_cert)
		.with_context(|| format!("reading CA cert at {}", args.ca_cert.display()))?;
	let cert_pem = std::fs::read_to_string(&args.cert)
		.with_context(|| format!("reading worker cert at {}", args.cert.display()))?;
	let key_pem = std::fs::read_to_string(&args.key)
		.with_context(|| format!("reading worker key at {}", args.key.display()))?;

	let client = Arc::new(ServerClient::new(&ca_cert_pem, &cert_pem, &key_pem, args.server_url)?);
	tracing::info!(
		repo_id = args.repo_id,
		job_id = ?args.job_id,
		workdir = %args.workdir.display(),
		"loupe-mcp: starting stdio server",
	);
	mcp::run_stdio_server(client, args.repo_id, args.job_id, args.workdir).await
}

/// Initialise tracing. Defaults to the human-readable formatter; set
/// `LOUPE_LOG_JSON=1` to switch to structured JSON output. Filter level
/// is taken from `RUST_LOG`.
///
/// MCP-serve mode pipes its tracing to stderr explicitly: stdout is
/// reserved for the JSON-RPC stream, and the agent will choke on any
/// non-JSON noise mixed in. Worker mode uses the default writer
/// (also stderr by `tracing_subscriber` default), so the change is
/// invisible to the long-running worker but load-bearing for the MCP
/// child.
fn init_tracing() {
	let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
		.unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
	let json = std::env::var_os("LOUPE_LOG_JSON").map(|v| !v.is_empty()).unwrap_or(false);
	if json {
		tracing_subscriber::fmt()
			.json()
			.with_writer(std::io::stderr)
			.with_env_filter(env_filter)
			.init();
	} else {
		tracing_subscriber::fmt().with_writer(std::io::stderr).with_env_filter(env_filter).init();
	}
}
