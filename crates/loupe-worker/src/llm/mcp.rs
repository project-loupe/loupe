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

/// Default BKB HTTP API endpoint for the bkb-mcp child.
///
/// bkb-mcp's own compiled-in default (`http://127.0.0.1:3000`) is
/// handy for a developer running the BKB stack locally but useless
/// on a fresh worker host that has only `cargo install`'d the
/// client. Loupe overrides unconditionally so the bkb tools work
/// out of the box pointing at the public hosted instance, with
/// uniform behaviour across the worker fleet.
///
/// Operators with a self-hosted BKB instance can override this through
/// the worker config.
pub const DEFAULT_BKB_API_URL: &str = "https://bitcoinknowledge.dev";

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
	pub tls: McpTlsSource,
	/// Optional `bkb-mcp` binary path. When `Some`, the per-call MCP
	/// config gets a second server entry exposing bkb's spec /
	/// historical-context tools (`bkb_search`, `bkb_lookup_bip`, …)
	/// alongside loupe's `submit_finding`. None means "host doesn't
	/// have bkb-mcp installed; advertise loupe only."
	pub bkb_mcp_path: Option<PathBuf>,
	/// HTTP API endpoint for the optional bkb-mcp child.
	pub bkb_api_url: String,
}

#[derive(Debug, Clone)]
pub enum McpTlsSource {
	Paths { ca_cert_path: PathBuf, client_cert_path: PathBuf, client_key_path: PathBuf },
	Env,
}

/// Where the agent's MCP child looks for the worker binary, the mTLS
/// material, and bkb-mcp.
///
/// Under bubblewrap these are the fixed `/loupe/...` mount points that
/// [`bind_mcp_into_sandbox`] creates. With `LOUPE_DISABLE_SANDBOX` set
/// there are no mounts at all — the child sees the host filesystem —
/// so those same paths resolve to nothing and every agent session dies
/// before it starts. Resolve to the real host paths in that case.
pub struct McpPaths {
	pub loupe_bin: String,
	pub bkb_bin: String,
	pub ca_cert: String,
	pub client_cert: String,
	pub client_key: String,
}

impl McpPaths {
	pub fn resolve(ctx: &McpContext) -> Self {
		if !crate::sandbox::sandbox_disabled() {
			return Self {
				loupe_bin: SANDBOX_LOUPE_BIN.to_owned(),
				bkb_bin: SANDBOX_BKB_MCP_BIN.to_owned(),
				ca_cert: SANDBOX_CA_CERT.to_owned(),
				client_cert: SANDBOX_CLIENT_CERT.to_owned(),
				client_key: SANDBOX_CLIENT_KEY.to_owned(),
			};
		}
		let (ca_cert, client_cert, client_key) = match &ctx.tls {
			McpTlsSource::Paths { ca_cert_path, client_cert_path, client_key_path } => (
				ca_cert_path.to_string_lossy().into_owned(),
				client_cert_path.to_string_lossy().into_owned(),
				client_key_path.to_string_lossy().into_owned(),
			),
			// Env-sourced TLS: the child reads PEMs from the inherited
			// environment, so no paths are passed as args.
			McpTlsSource::Env => (String::new(), String::new(), String::new()),
		};
		Self {
			loupe_bin: ctx.worker_binary.to_string_lossy().into_owned(),
			bkb_bin: ctx
				.bkb_mcp_path
				.as_ref()
				.map(|p| p.to_string_lossy().into_owned())
				.unwrap_or_else(|| SANDBOX_BKB_MCP_BIN.to_owned()),
			ca_cert,
			client_cert,
			client_key,
		}
	}
}

/// Build the args list that gets appended to `loupe-worker
/// mcp-serve` for one MCP-attached agent invocation. Cert + binary
/// paths come from [`McpPaths`]; per-call data
/// (`repo_id`, `job_id`, `finding_id`, `sandbox_workdir`) is wired
/// by the caller.
///
/// `job_id` is optional — the MCP server hides `submit_finding` when
/// it isn't supplied (e.g. a future read-only diagnostic flow).
/// `finding_id`, when present, flips the MCP server into verify
/// mode: it advertises `submit_verdict` / `submit_patch` /
/// `validate_patch` instead of `submit_finding` / `validate_poc`.
/// Both backends emit the same args list; only the wrapper around
/// it (a JSON file vs. `-c` overrides) differs.
pub fn mcp_serve_args(
	ctx: &McpContext, repo_id: i64, job_id: Option<i64>, finding_id: Option<i64>,
	sandbox_workdir: &str,
) -> Vec<String> {
	let paths = McpPaths::resolve(ctx);
	let mut args: Vec<String> = vec![
		"mcp-serve".into(),
		"--server-url".into(),
		ctx.server_url.clone(),
		"--repo-id".into(),
		repo_id.to_string(),
		"--workdir".into(),
		sandbox_workdir.to_owned(),
	];
	if matches!(ctx.tls, McpTlsSource::Paths { .. }) {
		args.splice(
			3..3,
			[
				"--ca-cert".into(),
				paths.ca_cert.clone(),
				"--cert".into(),
				paths.client_cert.clone(),
				"--key".into(),
				paths.client_key.clone(),
			],
		);
	}
	if let Some(j) = job_id {
		args.push("--job-id".into());
		args.push(j.to_string());
	}
	if let Some(f) = finding_id {
		args.push("--finding-id".into());
		args.push(f.to_string());
	}
	args
}

/// Bind the worker binary, mTLS cert/key/CA, and (optionally) the
/// bkb-mcp binary into the sandbox at the fixed paths above. Idempotent
/// across both backends — same mounts, same paths.
pub fn bind_mcp_into_sandbox(sandbox: SandboxBuilder, ctx: &McpContext) -> SandboxBuilder {
	let mut sb = sandbox.bind_ro(ctx.worker_binary.clone(), SANDBOX_LOUPE_BIN);
	match &ctx.tls {
		McpTlsSource::Paths { ca_cert_path, client_cert_path, client_key_path } => {
			sb = sb
				.bind_ro(ca_cert_path.clone(), SANDBOX_CA_CERT)
				.bind_ro(client_cert_path.clone(), SANDBOX_CLIENT_CERT)
				.bind_ro(client_key_path.clone(), SANDBOX_CLIENT_KEY);
		},
		McpTlsSource::Env => {
			sb = sb
				.forward_env("LOUPE_WORKER_CA_CERT_PEM")
				.forward_env("LOUPE_WORKER_CA_CERT_PEM_B64")
				.forward_env("LOUPE_WORKER_CERT_PEM")
				.forward_env("LOUPE_WORKER_CERT_PEM_B64")
				.forward_env("LOUPE_WORKER_KEY_PEM");
			sb = sb.forward_env("LOUPE_WORKER_KEY_PEM_B64");
		},
	}
	if let Some(bkb_path) = &ctx.bkb_mcp_path {
		sb = sb.bind_ro(bkb_path.clone(), SANDBOX_BKB_MCP_BIN);
	}
	sb
}

#[cfg(test)]
mod tests {
	use std::path::PathBuf;
	use std::sync::Mutex;

	use super::*;
	use crate::sandbox::DISABLE_SANDBOX_ENV;

	static ENV_LOCK: Mutex<()> = Mutex::new(());

	fn ctx() -> McpContext {
		McpContext {
			worker_binary: PathBuf::from("/opt/loupe/bin/loupe-worker"),
			server_url: "https://loupe.example:8443".to_owned(),
			tls: McpTlsSource::Paths {
				ca_cert_path: PathBuf::from("/etc/loupe/ca.pem"),
				client_cert_path: PathBuf::from("/etc/loupe/worker.pem"),
				client_key_path: PathBuf::from("/etc/loupe/worker.key"),
			},
			bkb_mcp_path: Some(PathBuf::from("/home/op/.cargo/bin/bkb-mcp")),
			bkb_api_url: DEFAULT_BKB_API_URL.to_owned(),
		}
	}

	#[test]
	fn sandboxed_runs_use_the_fixed_mount_points() {
		let _guard = ENV_LOCK.lock().unwrap();
		std::env::remove_var(DISABLE_SANDBOX_ENV);

		let paths = McpPaths::resolve(&ctx());

		assert_eq!(paths.loupe_bin, SANDBOX_LOUPE_BIN);
		assert_eq!(paths.ca_cert, SANDBOX_CA_CERT);
		assert_eq!(paths.client_cert, SANDBOX_CLIENT_CERT);
		assert_eq!(paths.client_key, SANDBOX_CLIENT_KEY);
		assert_eq!(paths.bkb_bin, SANDBOX_BKB_MCP_BIN);
	}

	/// With the sandbox disabled there are no bind mounts, so the fixed
	/// `/loupe/...` paths point at nothing. Handing them to the agent
	/// makes every session die instantly with "MCP config file not
	/// found", which the scanner reports as a per-file session error —
	/// the job still completes and the repo looks clean.
	#[test]
	fn sandbox_disabled_runs_resolve_to_host_paths() {
		let _guard = ENV_LOCK.lock().unwrap();
		std::env::set_var(DISABLE_SANDBOX_ENV, "1");

		let paths = McpPaths::resolve(&ctx());

		assert_eq!(paths.loupe_bin, "/opt/loupe/bin/loupe-worker");
		assert_eq!(paths.ca_cert, "/etc/loupe/ca.pem");
		assert_eq!(paths.client_cert, "/etc/loupe/worker.pem");
		assert_eq!(paths.client_key, "/etc/loupe/worker.key");
		assert_eq!(paths.bkb_bin, "/home/op/.cargo/bin/bkb-mcp");
		assert!(
			!paths.loupe_bin.starts_with("/loupe/"),
			"a /loupe/ path outside the sandbox is a mount point that does not exist",
		);

		std::env::remove_var(DISABLE_SANDBOX_ENV);
	}

	#[test]
	fn env_sourced_tls_passes_no_cert_paths() {
		let _guard = ENV_LOCK.lock().unwrap();
		std::env::set_var(DISABLE_SANDBOX_ENV, "1");

		let mut c = ctx();
		c.tls = McpTlsSource::Env;
		let args = mcp_serve_args(&c, 7, Some(9), None, "/tmp/work");

		assert!(!args.iter().any(|a| a == "--ca-cert"), "args: {args:?}");
		assert!(args.windows(2).any(|w| w == ["--repo-id", "7"]), "args: {args:?}");

		std::env::remove_var(DISABLE_SANDBOX_ENV);
	}
}
