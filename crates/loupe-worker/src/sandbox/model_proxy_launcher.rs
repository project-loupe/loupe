//! Binary-only launch inside the sandbox. These original native command
//! operands never become host ConfigNonSecret or host mount authority.
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use loupe_worker::llm::model_proxy::ModelProxy;

#[derive(Parser)]
pub(super) struct Args {
	#[arg(long)]
	pub(super) socket: PathBuf,
	#[arg(long, default_value = "127.0.0.1:0")]
	pub(super) listen: SocketAddr,
	#[arg(long)]
	pub(super) port_file: PathBuf,
	#[arg(long, value_enum, default_value = "claude")]
	provider: Provider,
	#[arg(last = true, required = true, allow_hyphen_values = true)]
	pub(super) command: Vec<OsString>,
}
impl std::fmt::Debug for Args {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("ModelProxyArgs([redacted])")
	}
}

// debug-ok: fixed provider choices without command, credential or path data.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Provider {
	Claude,
	Codex,
}

const MODEL_BASE_URL_PLACEHOLDER: &str = "@LOUPE_MODEL_BASE_URL@";

pub(super) async fn run(args: Args) -> Result<std::process::ExitStatus> {
	// ModelProxy admits only a loopback listener; its Unix socket remains a
	// sandbox-local route to the already owned host broker.
	let proxy = ModelProxy::bind(args.socket, args.listen, &args.port_file).await?;
	let base_url = proxy.base_url();
	let mut relay = tokio::spawn(proxy.relay());
	let (program, command_args) = args.command.split_first().context("agent command required")?;
	#[allow(
		clippy::disallowed_methods,
		reason = "This binary-only sandbox launcher receives the configured agent program from its typed parent command."
	)]
	let mut child = tokio::process::Command::new(program);
	child.args(
		command_args.iter().cloned().map(|argument| replace_model_base_url(argument, &base_url)),
	);
	// The sandbox's runtime paths are the sole inherited environment. A fixed
	// gateway sentinel substitutes for the host's provider credential.
	child.env_clear();
	for name in ["PATH", "HOME", "TMPDIR"] {
		if let Some(value) = std::env::var_os(name) {
			child.env(name, value);
		}
	}
	match args.provider {
		Provider::Claude => {
			child.env("ANTHROPIC_AUTH_TOKEN", "loupe-brokered");
			child.env("ANTHROPIC_BASE_URL", base_url);
			child.env("DISABLE_AUTOUPDATER", "1");
			child.env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1");
			child.env("DISABLE_TELEMETRY", "1");
			child.env("DISABLE_ERROR_REPORTING", "1");
			child.env("DISABLE_BUG_COMMAND", "1");
		},
		Provider::Codex => {
			child.env("CODEX_API_KEY", "loupe-brokered");
		},
	}
	child.kill_on_drop(true);
	#[allow(
		clippy::disallowed_methods,
		reason = "The private launcher starts the selected sandbox agent with only fixed gateway credentials and inherited stdin."
	)]
	let mut child = child.spawn().context("spawning model-proxied agent command")?;

	tokio::select! {
		biased;
		status = child.wait() => {
			relay.abort();
			let _ = relay.await;
			status.context("waiting for model-proxied agent command")
		},
		result = &mut relay => {
			match result.context("model proxy relay task panicked")? {
				Ok(()) => child.wait().await.context("waiting for model-proxied agent command"),
				Err(error) => {
					let _ = child.kill().await;
					Err(error)
				},
			}
		},
	}
}

pub(super) fn replace_model_base_url(argument: OsString, base_url: &str) -> OsString {
	match argument.into_string() {
		Ok(argument) => OsString::from(argument.replace(MODEL_BASE_URL_PLACEHOLDER, base_url)),
		Err(argument) => argument,
	}
}
