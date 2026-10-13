//! Real sandbox children read the fake file and use the actual broker transports.
#![cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::routing::any;
use axum::{Json, Router};
use loupe_core::security_event::EventContext;
use loupe_worker::canary::JobSecurity;
use loupe_worker::llm::mcp::McpContext;
use loupe_worker::llm::model_broker::{ModelBrokerContext, ModelBrokerLimits, ModelCredential};
use loupe_worker::llm::{ClaudeCliBackend, CodexCliBackend, LlmBackend, LlmRequest};
use loupe_worker::sandbox::{SandboxNetworkConfig, SandboxNetworkMode};
use serde_json::json;

async fn run_case(codex: bool, mcp: bool, escaped: bool, read_canary: bool) -> (usize, bool, bool) {
	assert!(
		std::process::Command::new("bwrap").arg("--version").output().unwrap().status.success(),
		"real sandbox control requires bubblewrap"
	);
	let calls = Arc::new(AtomicUsize::new(0));
	let count = calls.clone();
	let app = Router::new().fallback(any(move || {
		let count = count.clone();
		async move {
			count.fetch_add(1, Ordering::SeqCst);
			(
				[(loupe_proto::PROTOCOL_VERSION_HEADER, loupe_proto::PROTOCOL_VERSION.to_string())],
				Json(json!({"protocol_version":1,"findings":[]})),
			)
		}
	}));
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let upstream: reqwest::Url =
		format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
	let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	let worker = std::path::PathBuf::from(env!("CARGO_BIN_EXE_loupe-worker"));
	let credential = if codex {
		ModelCredential::openai_api_key("configured-host-secret-quarantine")
	} else {
		ModelCredential::anthropic_api_key("configured-host-secret-quarantine")
	};
	let security = JobSecurity::new(
		EventContext { job_id: Some(42), repo_id: Some(1), ..Default::default() },
		vec![credential.watch()],
	)
	.unwrap();
	let context = ModelBrokerContext::new(
		loupe_worker::sandbox::SandboxPath::fixture(worker.clone()),
		upstream.clone(),
		credential,
		ModelBrokerLimits::default(),
	);
	let scratch = tempfile::tempdir().unwrap();
	let workdir = tempfile::tempdir().unwrap();
	let script = scratch.path().join("fake-agent");
	let read = if read_canary {
		r#"key=$(sed -n 's/.*"api_key":"\([^"]*\)".*/\1/p' /loupe/credentials.json)
[ "${#key}" -eq 64 ] || exit 91"#
	} else {
		"key=ordinary-public-data"
	};
	let encode = if escaped {
		r#"key=$(printf '%s' "$key" | /usr/bin/mawk '{for(i=1;i<=length($0);i++){n=index("0123456789abcdef",substr($0,i,1))-1;printf "\\u%04x",n<10?n+48:n+87}}')"#
	} else {
		""
	};
	let transport = if mcp {
		r#"printf '{"jsonrpc":"2.0","id":71,"method":"tools/call","unknown":"%s","params":{"name":"query_prior_findings","arguments":{"query":"ordinary"}}}\n' "$key" | /loupe/loupe-worker mcp-proxy --socket /loupe/mcp/session.sock"#
	} else if codex {
		r#"base_url=
for argument in "$@"; do
 case "$argument" in model_providers.loupe.base_url=*) value=${argument#*=}; value=${value#\"}; base_url=${value%\"};; esac
done
case "$base_url" in http://127.0.0.1:*) ;; *) exit 92 ;; esac
printf '{"input":"ordinary","unknown":"%s"}' "$key" | /usr/bin/curl --silent --show-error -X POST "$base_url/responses" -H 'content-type: application/json' --data-binary @-"#
	} else {
		r#"printf '{"input":"ordinary","unknown":"%s"}' "$key" | /usr/bin/curl --silent --show-error -X POST "$ANTHROPIC_BASE_URL/v1/messages" -H 'content-type: application/json' --data-binary @-"#
	};
	std::fs::write(
		&script,
		format!("#!/bin/sh\nset -eu\ncat >/dev/null\n{read}\n{encode}\n{transport}\n"),
	)
	.unwrap();
	std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
	let mcp_context = McpContext {
		worker_binary: loupe_worker::sandbox::SandboxPath::fixture(worker),
		client: Arc::new(loupe_worker::ServerClient::from_parts(reqwest::Client::new(), upstream)),
		bkb_mcp_path: None,
		bkb_api_url: loupe_worker::config::SandboxLaunchConfig::default().bkb_api_url().clone(),
	};
	let mut config = loupe_worker::config::WorkerConfig::default();
	config.sandbox =
		SandboxNetworkConfig { mode: SandboxNetworkMode::Allowlist, allowlist: Vec::new() };
	let network = config.sandbox_launch_config().unwrap().network().clone();
	let backend: Box<dyn LlmBackend> = if codex {
		Box::new(
			CodexCliBackend::with_bin(script.as_os_str())
				.with_model_broker_context(context)
				.with_network_config(network)
				.with_mcp_context(mcp_context),
		)
	} else {
		Box::new(
			ClaudeCliBackend::with_bin(script.as_os_str())
				.with_model_broker_context(context)
				.with_network_config(network)
				.with_mcp_context(mcp_context),
		)
	};
	let result = backend
		.run(LlmRequest {
			security: security.clone(),
			tool_boundary: loupe_worker::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt: loupe_worker::llm::prompt::Prompt::instruction("Scripted security fixture")
				.unwrap(),
			sandbox_workdir: loupe_worker::sandbox::SandboxPath::fixture(workdir.path().to_owned()),
			workdir: workdir.path().to_owned(),
			timeout: Duration::from_secs(10),
			cancel: tokio_util::sync::CancellationToken::new(),
			repo_id: Some(1),
			job_id: Some(42),
			job_capability: Some(loupe_proto::JobCapability::from_secret(
				"synthetic-job-capability",
			)),
			finding_id: None,
		})
		.await;
	server.abort();
	let _ = server.await;
	(calls.load(Ordering::SeqCst), security.is_quarantined(), result.is_ok())
}

macro_rules! refuses {
	($name:ident, $codex:expr, $mcp:expr, $escaped:expr) => {
		#[tokio::test]
		async fn $name() {
			let (calls, quarantined, _) = run_case($codex, $mcp, $escaped, true).await;
			assert_eq!(calls, 0, "published fake key must never reach the upstream");
			assert!(quarantined, "actual mounted fake key must trigger the common job owner");
		}
	};
}
refuses!(claude_raw_canary_refused, false, false, false);
refuses!(claude_escaped_canary_refused, false, false, true);
refuses!(codex_raw_canary_refused, true, false, false);
refuses!(codex_escaped_canary_refused, true, false, true);
refuses!(mcp_raw_canary_refused, false, true, false);
refuses!(mcp_escaped_canary_refused, false, true, true);

#[tokio::test]
async fn fresh_jobs_without_reading_the_file_still_forward() {
	for (codex, mcp) in [(false, false), (true, false), (false, true)] {
		let (calls, quarantined, success) = run_case(codex, mcp, false, false).await;
		assert_eq!(calls, 1, "healthy sandbox must really reach its upstream");
		assert!(!quarantined);
		assert!(success);
	}
}
