//! A fake agent in the real sandbox reaches the drilldown catalog over the
//! real MCP socket.
#![cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::routing::any;
use axum::Router;
use loupe_core::security_event::EventContext;
use loupe_worker::canary::JobSecurity;
use loupe_worker::llm::mcp::McpContext;
use loupe_worker::llm::model_broker::{ModelBrokerContext, ModelBrokerLimits, ModelCredential};
use loupe_worker::llm::{ClaudeCliBackend, LlmBackend, LlmRequest};
use loupe_worker::mcp::McpMode;
use loupe_worker::review::session::{DrilldownSession, PhaseSession};
use loupe_worker::sandbox::{SandboxNetworkConfig, SandboxNetworkMode};
use serde_json::json;
use tokio_util::sync::CancellationToken;

fn bwrap_available() -> bool {
	std::process::Command::new("bwrap")
		.arg("--version")
		.output()
		.is_ok_and(|output| output.status.success())
}

fn limits_body() -> String {
	json!({"protocol_version":3,"soft_deadline_at":100,"submit_by":100,"hard_deadline_at":200,
		"remaining_seconds":60,"new_units":{"limit":32,"remaining":29},
		"leads":{"limit":16,"remaining":15},"siblings":{"limit":4,"remaining":4},
		"candidate_queries":{"limit":8,"remaining":7},"campaign_jobs_limit":10,
		"campaign_jobs_admitted":2,"campaign_general_remaining":5,
		"campaign_urgent_remaining":1,"campaign_verification_remaining":2,
		"proof_capacity":"unavailable","artifact_capacity":"unavailable",
		"output_capacity":"unavailable","tokens":{"status":"none"}})
	.to_string()
}

#[tokio::test]
async fn a_sandboxed_agent_reads_its_job_limits_through_the_drilldown_catalog() {
	if !bwrap_available() {
		eprintln!("skipping: the real sandbox requires bubblewrap");
		return;
	}
	let seen = Arc::new(Mutex::new(Vec::new()));
	let record = seen.clone();
	let app = Router::new().fallback(any(move |uri: axum::http::Uri| {
		let record = record.clone();
		async move {
			record.lock().unwrap().push(uri.path().to_owned());
			(
				[
					(loupe_proto::PROTOCOL_VERSION_HEADER, "3"),
					(axum::http::header::CONTENT_TYPE.as_str(), "application/json"),
				],
				limits_body(),
			)
		}
	}));
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let upstream: reqwest::Url =
		format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
	let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

	let worker = std::path::PathBuf::from(env!("CARGO_BIN_EXE_loupe-worker"));
	let credential = ModelCredential::anthropic_api_key("configured-host-secret-drilldown");
	let security = JobSecurity::new(
		EventContext { job_id: Some(42), repo_id: Some(1), ..Default::default() },
		vec![credential.watch()],
	)
	.unwrap();
	let broker = ModelBrokerContext::new(
		loupe_worker::sandbox::SandboxPath::fixture(worker.clone()),
		upstream.clone(),
		credential,
		ModelBrokerLimits::default(),
	);
	let scratch = tempfile::tempdir().unwrap();
	let workdir = tempfile::tempdir().unwrap();
	let script = scratch.path().join("fake-agent");
	std::fs::write(
		&script,
		"#!/bin/sh\nset -eu\ncat >/dev/null\n\
		 printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"get_job_limits\",\"arguments\":{}}}\\n' \
		 | /loupe/loupe-worker mcp-proxy --socket /loupe/mcp/session.sock\n",
	)
	.unwrap();
	std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
	let mcp = McpContext {
		worker_binary: loupe_worker::sandbox::SandboxPath::fixture(worker),
		client: Arc::new(loupe_worker::ServerClient::from_parts(reqwest::Client::new(), upstream)),
		bkb_mcp_path: None,
		bkb_api_url: loupe_worker::config::SandboxLaunchConfig::default().bkb_api_url().clone(),
	};
	let mut config = loupe_worker::config::WorkerConfig::default();
	config.sandbox =
		SandboxNetworkConfig { mode: SandboxNetworkMode::Allowlist, allowlist: Vec::new() };
	let network = config.sandbox_launch_config().unwrap().network().clone();
	let backend = ClaudeCliBackend::with_bin(script.as_os_str())
		.with_model_broker_context(broker)
		.with_network_config(network)
		.with_mcp_context(mcp);

	let cancel = CancellationToken::new();
	let now = SystemTime::now();
	let capability = loupe_proto::JobCapability::from_secret("synthetic-drilldown-capability");
	let phase = PhaseSession::new(
		42,
		capability.clone(),
		now + Duration::from_secs(600),
		now + Duration::from_secs(1200),
		Arc::new(SystemTime::now),
		cancel.clone(),
	);
	let session = Arc::new(DrilldownSession::new(phase, 9, None));
	let result = backend
		.run(LlmRequest {
			security: security.clone(),
			tool_boundary: loupe_worker::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt: loupe_worker::llm::prompt::Prompt::instruction("Drilldown sandbox fixture")
				.unwrap(),
			sandbox_workdir: loupe_worker::sandbox::SandboxPath::fixture(workdir.path().to_owned()),
			workdir: workdir.path().to_owned(),
			timeout: Duration::from_secs(20),
			cancel,
			repo_id: Some(1),
			mcp_mode: McpMode::Drilldown,
			phase: Some(loupe_worker::mcp::PhaseTools::Drilldown(session.clone())),
			token_budget: None,
			job_capability: Some(capability),
		})
		.await;
	server.abort();
	let _ = server.await;
	assert!(!security.is_quarantined());
	assert_eq!(*seen.lock().unwrap(), ["/v1/jobs/42/limits"], "agent run: {:?}", result.err());
	assert!(
		session
			.status_line()
			.contains("sibling leads remaining: 4; candidate queries remaining: 7"),
		"the host session took the limits read: {}",
		session.status_line()
	);
}
