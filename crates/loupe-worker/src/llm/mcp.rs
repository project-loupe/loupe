//! Shared MCP-attachment plumbing for both LLM backends.
//!
//! Both `claude` and `codex` need to advertise the same loupe MCP
//! server (and optionally bkb-mcp) to the agent at invocation time.
//! The sandbox-side paths are identical across backends — only the
//! mechanism for *telling the CLI to load the config* differs:
//!
//! - claude takes `--mcp-config <file>` pointing at a JSON file the
//!   per-call scratch dir holds.
//! - codex takes `-c mcp_servers.<name>.command="..."` repeated for
//!   each TOML key under `mcp_servers.<name>`; no scratch file.
//!
//! Each backend wraps the same args list (this module's
//! [`mcp_serve_args`]) into its CLI's preferred shape. The sandbox
//! bind-mounts and cert paths are identical, so [`bind_mcp_into_sandbox`]
//! does that work in one place.

use std::path::PathBuf;

use crate::sandbox::SandboxBuilder;

/// Fixed sandbox paths the MCP child resolves at runtime. Inside the
/// bwrap sandbox the agent only ever sees these, regardless of
/// where the host install actually lives — the bind mounts in
/// [`bind_mcp_into_sandbox`] keep the abstraction watertight.
pub const SANDBOX_LOUPE_BIN: &str = "/loupe/loupe-worker";
pub const SANDBOX_CA_CERT: &str = "/loupe/ca.pem";
pub const SANDBOX_CLIENT_CERT: &str = "/loupe/worker.pem";
pub const SANDBOX_CLIENT_KEY: &str = "/loupe/worker.key";
pub const SANDBOX_BKB_MCP_BIN: &str = "/loupe/bkb-mcp";

/// BKB HTTP API endpoint loupe always pins for the bkb-mcp child.
///
/// bkb-mcp's own compiled-in default (`http://127.0.0.1:3000`) is
/// handy for a developer running the BKB stack locally but useless
/// on a fresh worker host that has only `cargo install`'d the
/// client. Loupe overrides unconditionally so the bkb tools work
/// out of the box pointing at the public hosted instance, with
/// uniform behaviour across the worker fleet.
///
/// Operators with a self-hosted BKB instance: patch this constant
/// (recompile) — there's no env-var escape hatch on purpose, so
/// findings emitted by different workers can't disagree about
/// where their bkb context came from.
pub const BKB_API_URL: &str = "https://bitcoinknowledge.dev";

/// Everything the MCP child needs to talk back to loupe-server.
/// Built once at worker startup from the `loupe-worker run` CLI
/// flags and stashed on the backend; per-call data (the repo id /
/// job id) arrives through [`super::LlmRequest`].
#[derive(Debug, Clone)]
pub struct McpContext {
	/// Path to the loupe-worker binary on the host. Usually
	/// `std::env::current_exe()` for the worker itself, so the same
	/// binary serves both `run` and `mcp-serve` modes.
	pub worker_binary: PathBuf,
	/// loupe-server URL the MCP child will call back to.
	pub server_url: String,
	pub ca_cert_path: PathBuf,
	pub client_cert_path: PathBuf,
	pub client_key_path: PathBuf,
	/// Optional `bkb-mcp` binary path. When `Some`, the per-call MCP
	/// config gets a second server entry exposing bkb's spec /
	/// historical-context tools (`bkb_search`, `bkb_lookup_bip`, …)
	/// alongside loupe's `submit_finding`. None means "host doesn't
	/// have bkb-mcp installed; advertise loupe only."
	pub bkb_mcp_path: Option<PathBuf>,
}

/// Build the args list that gets appended to `loupe-worker
/// mcp-serve` for one MCP-attached agent invocation. Cert + binary
/// paths come from the sandbox fixed paths above; per-call data
/// (`repo_id`, `job_id`, `sandbox_workdir`) is wired by the caller.
///
/// `job_id` is optional — the MCP server hides `submit_finding` when
/// it isn't supplied (e.g. a future read-only diagnostic flow).
/// Both backends emit the same args list; only the wrapper around
/// it (a JSON file vs. `-c` overrides) differs.
pub fn mcp_serve_args(
	ctx: &McpContext, repo_id: i64, job_id: Option<i64>, sandbox_workdir: &str,
) -> Vec<String> {
	let mut args: Vec<String> = vec![
		"mcp-serve".into(),
		"--server-url".into(),
		ctx.server_url.clone(),
		"--ca-cert".into(),
		SANDBOX_CA_CERT.into(),
		"--cert".into(),
		SANDBOX_CLIENT_CERT.into(),
		"--key".into(),
		SANDBOX_CLIENT_KEY.into(),
		"--repo-id".into(),
		repo_id.to_string(),
		"--workdir".into(),
		sandbox_workdir.to_owned(),
	];
	if let Some(j) = job_id {
		args.push("--job-id".into());
		args.push(j.to_string());
	}
	args
}

/// Bind the worker binary, mTLS cert/key/CA, and (optionally) the
/// bkb-mcp binary into the sandbox at the fixed paths above. Idempotent
/// across both backends — same mounts, same paths.
pub fn bind_mcp_into_sandbox(sandbox: SandboxBuilder, ctx: &McpContext) -> SandboxBuilder {
	let mut sb = sandbox
		.bind_ro(ctx.worker_binary.clone(), SANDBOX_LOUPE_BIN)
		.bind_ro(ctx.ca_cert_path.clone(), SANDBOX_CA_CERT)
		.bind_ro(ctx.client_cert_path.clone(), SANDBOX_CLIENT_CERT)
		.bind_ro(ctx.client_key_path.clone(), SANDBOX_CLIENT_KEY);
	if let Some(bkb_path) = &ctx.bkb_mcp_path {
		sb = sb.bind_ro(bkb_path.clone(), SANDBOX_BKB_MCP_BIN);
	}
	sb
}
