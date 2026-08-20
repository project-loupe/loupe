//! Entry point for the loupe scan/verify worker.
//!
//! Worker and internal helper modes are selected via subcommands:
//!
//! - `run` (default when no subcommand is given): the long-running
//!   worker loop — leases jobs, runs scanners, submits findings.
//! - `mcp-proxy`: a credential-free stdio/Unix-socket bridge spawned
//!   inside an agent sandbox. The trusted MCP broker stays in the
//!   parent worker process.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use loupe_worker::config::{LoggingConfig, WorkerConfig, WorkerConfigOverrides};
use loupe_worker::llm::{
	bkb_mcp_available, build_scan_backend, build_verifier_backend, claude_auth_available,
	claude_available, codex_auth_available, codex_available, BackendRuntimeConfig, JobAgent,
	McpContext,
};
use loupe_worker::sandbox::SandboxNetworkMode;
use loupe_worker::scanners::{LlmCodeReviewScanner, LlmVerifierScanner, RegexSecretsScanner};
use loupe_worker::{sandbox, RepoCache, Runner, Scanner, ServerClient};
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
	Run(Box<RunArgs>),
	/// Bridge MCP stdio to one host-side Unix socket. This subcommand
	/// receives no server URL, mTLS credentials, job id, or capability.
	McpProxy(McpProxyArgs),
	/// Internal supervisor for one isolated sandbox network.
	#[command(hide = true)]
	SandboxExec(SandboxExecArgs),
}

#[derive(Debug, Parser)]
struct RunArgs {
	/// Path to worker config TOML. CLI/env values override file settings.
	#[arg(long, env = "LOUPE_WORKER_CONFIG")]
	config: Option<PathBuf>,
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
	/// CA cert PEM content. When set, this takes precedence over
	/// --ca-cert / LOUPE_CA_CERT.
	#[arg(long, env = "LOUPE_WORKER_CA_CERT_PEM", hide_env_values = true)]
	ca_cert_pem: Option<String>,
	#[arg(long, env = "LOUPE_WORKER_CA_CERT_PEM_B64", hide_env_values = true)]
	ca_cert_pem_b64: Option<String>,
	/// Worker client cert PEM content. When set, this takes precedence
	/// over --cert / LOUPE_WORKER_CERT.
	#[arg(long, env = "LOUPE_WORKER_CERT_PEM", hide_env_values = true)]
	cert_pem: Option<String>,
	#[arg(long, env = "LOUPE_WORKER_CERT_PEM_B64", hide_env_values = true)]
	cert_pem_b64: Option<String>,
	/// Worker client private-key PEM content. When set, this takes
	/// precedence over --key / LOUPE_WORKER_KEY.
	#[arg(long, env = "LOUPE_WORKER_KEY_PEM", hide_env_values = true)]
	key_pem: Option<String>,
	#[arg(long, env = "LOUPE_WORKER_KEY_PEM_B64", hide_env_values = true)]
	key_pem_b64: Option<String>,
	/// Where to keep cached bare clones.
	#[arg(long, env = "LOUPE_CACHE_DIR")]
	cache_dir: Option<PathBuf>,
	/// Maximum cache size in GB before LRU eviction kicks in.
	#[arg(long, env = "LOUPE_MAX_CACHE_GB")]
	max_cache_gb: Option<u64>,
	/// Maximum checked-out worktree size in GB before a job fails.
	#[arg(long, env = "LOUPE_MAX_WORKDIR_GB")]
	max_workdir_gb: Option<u64>,
	/// Legacy option. Enabling it is rejected; LLM workers require bubblewrap.
	#[arg(long, env = "LOUPE_DISABLE_SANDBOX", value_parser = clap::builder::BoolishValueParser::new())]
	disable_sandbox: Option<bool>,
	/// Agent sandbox network policy: public or allowlist.
	#[arg(long, env = "LOUPE_SANDBOX_NETWORK", value_enum)]
	sandbox_network: Option<SandboxNetworkMode>,
	/// Comma-separated hostnames or IPv4 addresses added in allowlist mode.
	#[arg(long, env = "LOUPE_SANDBOX_ALLOWLIST", value_delimiter = ',')]
	sandbox_allowlist: Option<Vec<String>>,
	/// Logging level: trace, debug, info, warn, or error.
	#[arg(long, env = "LOUPE_LOG_LEVEL")]
	log_level: Option<String>,
	/// Emit structured JSON logs.
	#[arg(long, env = "LOUPE_LOG_JSON", value_parser = clap::builder::BoolishValueParser::new())]
	log_json: Option<bool>,
	/// Dump full successful agent stdout/stderr at info level.
	#[arg(long, env = "LOUPE_LOG_AGENT_OUTPUT", value_parser = clap::builder::BoolishValueParser::new())]
	log_agent_output: Option<bool>,
	/// Agent backend for LLM scan jobs: auto, claude, or codex.
	#[arg(long, env = "LOUPE_SCAN_AGENT", value_enum)]
	scan_agent: Option<JobAgent>,
	/// Agent backend for LLM verify jobs: auto, claude, or codex.
	#[arg(long, env = "LOUPE_VERIFY_AGENT", value_enum)]
	verify_agent: Option<JobAgent>,
	/// Claude model for every Claude-backed invocation.
	#[arg(long, env = "LOUPE_CLAUDE_MODEL")]
	claude_model: Option<String>,
	/// Claude effort level: low, medium, high, xhigh, or max.
	#[arg(long, env = "LOUPE_CLAUDE_EFFORT")]
	claude_effort: Option<String>,
	/// Codex model for every Codex-backed invocation.
	#[arg(long, env = "LOUPE_CODEX_MODEL")]
	codex_model: Option<String>,
	/// Codex reasoning effort: none, low, medium, high, or xhigh.
	#[arg(long, env = "LOUPE_CODEX_EFFORT")]
	codex_effort: Option<String>,
	/// Fleet-wide default for concurrent per-file LLM sessions.
	#[arg(long, env = "LOUPE_MAX_CONCURRENT_FILES")]
	max_concurrent_files: Option<usize>,
	/// Fleet-wide default max source file size for LLM review.
	#[arg(long, env = "LOUPE_MAX_FILE_BYTES")]
	max_file_bytes: Option<u64>,
	/// Fleet-wide default per-agent request timeout.
	#[arg(long, env = "LOUPE_PER_REQUEST_TIMEOUT_SECONDS")]
	per_request_timeout_seconds: Option<u64>,
	/// BKB HTTP API URL for the optional bkb-mcp child.
	#[arg(long, env = "LOUPE_BKB_API_URL")]
	bkb_api_url: Option<String>,
}

#[derive(Debug, Parser)]
struct McpProxyArgs {
	#[arg(long)]
	socket: PathBuf,
}

#[derive(Debug, Parser)]
struct SandboxExecArgs {
	#[arg(long, value_enum)]
	network: SandboxNetworkMode,
	#[arg(long)]
	required_host: Vec<String>,
	#[arg(long)]
	allow_host: Vec<String>,
	#[arg(last = true, required = true, allow_hyphen_values = true)]
	command: Vec<OsString>,
}

#[tokio::main]
async fn main() -> Result<()> {
	let cli = Cli::parse();
	match cli.cmd {
		Some(Cmd::Run(args)) => {
			let cfg = load_worker_config(&args)?;
			init_tracing(&cfg.logging);
			run_worker(*args, cfg).await
		},
		Some(Cmd::McpProxy(args)) => {
			init_tracing_from_env();
			run_mcp_proxy(args).await
		},
		Some(Cmd::SandboxExec(args)) => {
			let status = sandbox::run_networked_sandbox(
				args.network,
				args.required_host,
				args.allow_host,
				args.command,
			)?;
			std::process::exit(status.code().unwrap_or(1));
		},
		// Default subcommand for backwards compatibility with the
		// existing `loupe-worker --server-url ...` invocation pattern.
		None => {
			let cfg = load_worker_config(&cli.run)?;
			init_tracing(&cfg.logging);
			run_worker(cli.run, cfg).await
		},
	}
}

async fn run_worker(args: RunArgs, cfg: WorkerConfig) -> Result<()> {
	let server_url = cfg
		.server_url
		.clone()
		.context("--server-url / LOUPE_SERVER_URL / [server].url in worker config is required")?;
	let cache_dir = cfg.cache.dir.clone();
	if cfg.runtime.disable_sandbox {
		std::env::set_var(sandbox::DISABLE_SANDBOX_ENV, "1");
	}
	let tls = read_worker_tls(
		args.ca_cert_pem,
		args.ca_cert_pem_b64,
		args.cert_pem,
		args.cert_pem_b64,
		args.key_pem,
		args.key_pem_b64,
		cfg.tls.ca_cert.clone(),
		cfg.tls.cert.clone(),
		cfg.tls.key.clone(),
	)?;

	let client = Arc::new(ServerClient::new(
		&tls.ca_cert_pem,
		&tls.cert_pem,
		&tls.key_pem,
		server_url.clone(),
	)?);
	let cache = Arc::new(RepoCache::new(cache_dir.clone(), cfg.cache.max_gb * 1_073_741_824)?);

	let mut scanners: Vec<Arc<dyn Scanner>> = vec![Arc::new(RegexSecretsScanner::new())];

	// LLM scanners wire through worker-local job-agent policy:
	//
	// - [agents].scan = "auto" preserves the historical discovery
	//   default: use claude when ready, otherwise advertise verify-only.
	// - [agents].verify = "auto" preserves the historical verifier
	//   default: prefer codex, falling back to claude.
	// - explicit claude/codex selections fail startup when unavailable.
	// - no authenticated CLI still hard-fatals at startup. Docker
	//   images can install both CLIs, but missing credentials should fail
	//   before a worker leases jobs.
	let claude_installed = claude_available();
	let codex_installed = codex_available();
	let claude_auth = claude_auth_available();
	let codex_auth = codex_auth_available();
	let claude = claude_installed && claude_auth;
	let codex = codex_installed && codex_auth;
	if !claude && !codex {
		anyhow::bail!(
			"no authenticated LLM agent CLI available \
			 (claude: installed={}, auth={}; codex: installed={}, auth={}). \
			 Install at least one CLI and provide an environment credential before starting the worker.",
			claude_installed,
			claude_auth,
			codex_installed,
			codex_auth,
		);
	}
	if claude_installed && !claude_auth {
		tracing::warn!(
			"`claude` is installed but no ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN was found"
		);
	}
	if codex_installed && !codex_auth {
		tracing::warn!("`codex` is installed but no CODEX_API_KEY or OPENAI_API_KEY was found");
	}
	// bwrap is the security boundary for every agent subprocess; a
	// missing binary or attempted bypass is a startup error.
	sandbox::probe_at_startup().context("LLM scanner requires bubblewrap")?;
	sandbox::smoketest(&cache_dir, cfg.sandbox.clone())
		.context("bubblewrap sandbox smoketest failed")?;
	tracing::info!(
		network = %cfg.sandbox.mode,
		allowlist_hosts = cfg.sandbox.allowlist.len(),
		"bubblewrap and isolated sandbox networking available"
	);

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

	// The agent gets only this binary's credential-free proxy mode and
	// a per-invocation Unix socket. The authenticated client remains in
	// the trusted parent process.
	let worker_binary = std::env::current_exe()
		.context("resolving the loupe-worker binary path for MCP bind-mount")?;
	let mcp_ctx = McpContext {
		worker_binary,
		client: client.clone(),
		bkb_mcp_path: bkb_mcp_path.clone(),
		bkb_api_url: cfg.bkb.api_url.clone(),
	};

	if let Some(backend) = build_scan_backend(
		Some(mcp_ctx.clone()),
		cfg.agents.scan,
		claude,
		codex,
		cfg.agents.codex.clone(),
		cfg.agents.claude.clone(),
		BackendRuntimeConfig {
			network: cfg.sandbox.clone(),
			log_agent_output: cfg.logging.agent_output,
		},
	)? {
		scanners.push(Arc::new(
			LlmCodeReviewScanner::new(backend)
				.with_config(cfg.scanner_defaults.clone())
				.with_bkb(bkb_mcp_path.is_some()),
		));
		tracing::info!("LLM code-review scanner enabled (scan:llm advertised, MCP-driven)");
	}

	// The helper logs which backend it picked. MCP context is required
	// for the verify-mode tool surface (`submit_verdict` /
	// `submit_patch` / `validate_patch`); without it, the agent has
	// no way to commit a verdict.
	let backend = build_verifier_backend(
		Some(mcp_ctx),
		cfg.agents.verify,
		claude,
		codex,
		cfg.agents.codex.clone(),
		cfg.agents.claude.clone(),
		BackendRuntimeConfig {
			network: cfg.sandbox.clone(),
			log_agent_output: cfg.logging.agent_output,
		},
	)?;
	scanners.push(Arc::new(LlmVerifierScanner::new(backend)));
	tracing::info!("LLM verifier scanner enabled (verify:llm advertised, MCP-driven)");

	let runner =
		Runner::new(client, cache, scanners).with_max_workdir_bytes(cfg.runtime.max_workdir_bytes);

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

async fn run_mcp_proxy(args: McpProxyArgs) -> Result<()> {
	use tokio::io::{AsyncWriteExt, BufReader};

	let stream = tokio::net::UnixStream::connect(&args.socket)
		.await
		.with_context(|| format!("connecting MCP broker socket at {}", args.socket.display()))?;
	let (socket_read, mut socket_write) = stream.into_split();
	let mut socket_read = BufReader::new(socket_read);
	let mut stdin = tokio::io::stdin();
	let mut stdout = tokio::io::stdout();
	let to_broker = async {
		tokio::io::copy(&mut stdin, &mut socket_write).await?;
		socket_write.shutdown().await
	};
	let from_broker = async {
		tokio::io::copy(&mut socket_read, &mut stdout).await?;
		stdout.flush().await
	};
	tokio::try_join!(to_broker, from_broker)?;
	Ok(())
}

fn load_worker_config(args: &RunArgs) -> Result<WorkerConfig> {
	WorkerConfig::load(
		args.config.as_deref(),
		WorkerConfigOverrides {
			server_url: args.server_url.clone(),
			ca_cert: args.ca_cert.clone(),
			cert: args.cert.clone(),
			key: args.key.clone(),
			cache_dir: args.cache_dir.clone(),
			max_cache_gb: args.max_cache_gb,
			max_workdir_gb: args.max_workdir_gb,
			disable_sandbox: args.disable_sandbox,
			sandbox_network: args.sandbox_network,
			sandbox_allowlist: args.sandbox_allowlist.clone(),
			log_level: args.log_level.clone(),
			log_json: args.log_json,
			log_agent_output: args.log_agent_output,
			scan_agent: args.scan_agent,
			verify_agent: args.verify_agent,
			claude_model: args.claude_model.clone(),
			claude_effort: args.claude_effort.clone(),
			codex_model: args.codex_model.clone(),
			codex_effort: args.codex_effort.clone(),
			max_concurrent_files: args.max_concurrent_files,
			max_file_bytes: args.max_file_bytes,
			per_request_timeout_seconds: args.per_request_timeout_seconds,
			bkb_api_url: args.bkb_api_url.clone(),
		},
	)
}

struct WorkerTls {
	ca_cert_pem: String,
	cert_pem: String,
	key_pem: String,
}

#[allow(clippy::too_many_arguments)]
fn read_worker_tls(
	ca_cert_pem: Option<String>, ca_cert_pem_b64: Option<String>, cert_pem: Option<String>,
	cert_pem_b64: Option<String>, key_pem: Option<String>, key_pem_b64: Option<String>,
	ca_cert: Option<PathBuf>, cert: Option<PathBuf>, key: Option<PathBuf>,
) -> Result<WorkerTls> {
	let env_pem_present = has_value(&ca_cert_pem)
		|| has_value(&ca_cert_pem_b64)
		|| has_value(&cert_pem)
		|| has_value(&cert_pem_b64)
		|| has_value(&key_pem)
		|| has_value(&key_pem_b64);
	if env_pem_present {
		return Ok(WorkerTls {
			ca_cert_pem: required_pem_env(
				ca_cert_pem,
				ca_cert_pem_b64,
				"LOUPE_WORKER_CA_CERT_PEM",
				"LOUPE_WORKER_CA_CERT_PEM_B64",
			)?,
			cert_pem: required_pem_env(
				cert_pem,
				cert_pem_b64,
				"LOUPE_WORKER_CERT_PEM",
				"LOUPE_WORKER_CERT_PEM_B64",
			)?,
			key_pem: required_pem_env(
				key_pem,
				key_pem_b64,
				"LOUPE_WORKER_KEY_PEM",
				"LOUPE_WORKER_KEY_PEM_B64",
			)?,
		});
	}

	let ca_cert = ca_cert
		.context("--ca-cert / LOUPE_CA_CERT is required unless LOUPE_WORKER_CA_CERT_PEM is set")?;
	let cert =
		cert.context("--cert / LOUPE_WORKER_CERT is required unless LOUPE_WORKER_CERT_PEM is set")?;
	let key =
		key.context("--key / LOUPE_WORKER_KEY is required unless LOUPE_WORKER_KEY_PEM is set")?;
	let ca_cert_pem = std::fs::read_to_string(&ca_cert)
		.with_context(|| format!("reading CA cert at {}", ca_cert.display()))?;
	let cert_pem = std::fs::read_to_string(&cert)
		.with_context(|| format!("reading worker cert at {}", cert.display()))?;
	let key_pem = std::fs::read_to_string(&key)
		.with_context(|| format!("reading worker key at {}", key.display()))?;
	Ok(WorkerTls { ca_cert_pem, cert_pem, key_pem })
}

fn has_value(value: &Option<String>) -> bool {
	value.as_deref().is_some_and(|s| !s.is_empty())
}

fn required_pem_env(
	value: Option<String>, value_b64: Option<String>, name: &'static str, b64_name: &'static str,
) -> Result<String> {
	if let Some(value) = value.filter(|s| !s.is_empty()) {
		return Ok(value);
	}
	if let Some(value_b64) = value_b64.filter(|s| !s.is_empty()) {
		return decode_pem_b64(b64_name, &value_b64);
	}
	anyhow::bail!("{name} or {b64_name} is required when any worker TLS PEM env var is set")
}

fn decode_pem_b64(label: &str, pem_b64: &str) -> Result<String> {
	use base64::Engine as _;
	let bytes = base64::engine::general_purpose::STANDARD
		.decode(pem_b64.trim())
		.with_context(|| format!("decoding {label}"))?;
	String::from_utf8(bytes).with_context(|| format!("{label} did not decode to valid UTF-8"))
}

/// Initialise tracing. Defaults to the human-readable formatter; set
/// `[logging].json = true` or `LOUPE_LOG_JSON=true` to switch to
/// structured JSON output. `RUST_LOG` remains the compatibility escape
/// hatch for module-level filters; otherwise `[logging].level` is used.
///
/// MCP-proxy mode pipes its tracing to stderr explicitly: stdout is
/// reserved for the JSON-RPC stream, and the agent will choke on any
/// non-JSON noise mixed in. Worker mode uses the default writer
/// (also stderr by `tracing_subscriber` default).
fn init_tracing(logging: &LoggingConfig) {
	let env_filter = tracing_subscriber::EnvFilter::try_from_env("RUST_LOG")
		.unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&logging.level));
	if logging.json {
		tracing_subscriber::fmt()
			.json()
			.with_writer(std::io::stderr)
			.with_env_filter(env_filter)
			.init();
	} else {
		tracing_subscriber::fmt().with_writer(std::io::stderr).with_env_filter(env_filter).init();
	}
}

fn init_tracing_from_env() {
	let logging = LoggingConfig {
		level: "info".to_owned(),
		json: bool_env("LOUPE_LOG_JSON").unwrap_or(false),
		agent_output: false,
	};
	init_tracing(&logging);
}

fn bool_env(name: &str) -> Option<bool> {
	let value = std::env::var_os(name)?;
	let value = value.to_string_lossy();
	if value.is_empty() {
		return Some(false);
	}
	match value.to_ascii_lowercase().as_str() {
		"1" | "true" | "yes" | "on" => Some(true),
		"0" | "false" | "no" | "off" => Some(false),
		_ => Some(true),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn b64(value: &str) -> String {
		use base64::Engine as _;
		base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
	}

	#[test]
	fn read_worker_tls_accepts_base64_env_values() {
		let ca = "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n";
		let cert = "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n";
		let key = "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n";

		let tls = read_worker_tls(
			None,
			Some(b64(ca)),
			None,
			Some(b64(cert)),
			None,
			Some(b64(key)),
			None,
			None,
			None,
		)
		.unwrap();

		assert_eq!(tls.ca_cert_pem, ca);
		assert_eq!(tls.cert_pem, cert);
		assert_eq!(tls.key_pem, key);
	}

	#[test]
	fn read_worker_tls_requires_complete_env_tuple() {
		let ca = "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n";

		let err =
			match read_worker_tls(None, Some(b64(ca)), None, None, None, None, None, None, None) {
				Ok(_) => panic!("partial env TLS should be rejected"),
				Err(e) => e,
			};

		assert!(err.to_string().contains("LOUPE_WORKER_CERT_PEM"));
	}

	#[test]
	fn cli_parses_sandbox_network_and_comma_separated_allowlist() {
		let cli = Cli::try_parse_from([
			"loupe-worker",
			"--sandbox-network",
			"allowlist",
			"--sandbox-allowlist",
			"example.com,203.0.113.9",
		])
		.unwrap();

		assert_eq!(cli.run.sandbox_network, Some(SandboxNetworkMode::Allowlist));
		assert_eq!(cli.run.sandbox_allowlist.unwrap(), ["example.com", "203.0.113.9"]);
	}
}
