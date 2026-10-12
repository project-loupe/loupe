#![cfg(unix)]

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use loupe_worker::llm::mcp::McpContext;
use loupe_worker::llm::model_broker::{ModelBrokerContext, ModelBrokerLimits, ModelCredential};
use loupe_worker::llm::{ClaudeCliBackend, CodexCliBackend, LlmBackend, LlmRequest};
use loupe_worker::sandbox::{SandboxNetworkConfig, SandboxNetworkMode};
use loupe_worker::ServerClient;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct Captured {
	headers: HeaderMap,
	body: Vec<u8>,
}

fn bwrap_present() -> bool {
	std::process::Command::new("bwrap")
		.arg("--version")
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.status()
		.map(|status| status.success())
		.unwrap_or(false)
}

fn model_only_allowlist() -> SandboxNetworkConfig {
	SandboxNetworkConfig { mode: SandboxNetworkMode::Allowlist, allowlist: Vec::new() }
}

fn cli_from_env(name: &str) -> Option<PathBuf> {
	let Some(path) = std::env::var_os(name).map(PathBuf::from) else {
		eprintln!("skipping: {name} is not set");
		return None;
	};
	let output = std::process::Command::new(&path).arg("--version").output().unwrap();
	assert!(output.status.success(), "{name} --version failed: {}", output.status);
	let version = String::from_utf8_lossy(&output.stdout);
	assert!(!version.trim().is_empty(), "{name} --version returned an empty version");
	eprintln!("testing {name}: {}", version.trim());
	Some(path)
}

#[tokio::test]
async fn claude_reaches_fake_upstream_only_through_the_broker() {
	use std::os::unix::fs::PermissionsExt;

	if !bwrap_present() {
		eprintln!("skipping: bwrap missing");
		return;
	}
	let worker_binary = PathBuf::from(env!("CARGO_BIN_EXE_loupe-worker"));

	let captured = Arc::new(Mutex::new(Vec::<Captured>::new()));
	let app = Router::new()
		.route(
			"/v1/messages",
			post(
				|State(captured): State<Arc<Mutex<Vec<Captured>>>>, request: Request| async move {
					let headers = request.headers().clone();
					let body = to_bytes(request.into_body(), 1024 * 1024).await.unwrap().to_vec();
					captured.lock().await.push(Captured { headers, body });
					Response::new(Body::from("BROKERED"))
				},
			),
		)
		.with_state(captured.clone());
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let upstream: reqwest::Url =
		format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
	tokio::spawn(async move {
		axum::serve(listener, app).await.unwrap();
	});

	let scratch = tempfile::tempdir().unwrap();
	let workdir = tempfile::tempdir().unwrap();
	let fake_claude = scratch.path().join("fake-claude");
	std::fs::write(
		&fake_claude,
		"#!/bin/sh\n\
		if [ -n \"${ANTHROPIC_API_KEY-}\" ] || [ -n \"${CLAUDE_CODE_OAUTH_TOKEN-}\" ]; then\n\
		  echo credential-leaked >&2\n\
		  exit 90\n\
		fi\n\
		case \"$*\" in *host-anthropic-secret*) echo credential-argument-leaked >&2; exit 92 ;; esac\n\
		if [ \"${ANTHROPIC_AUTH_TOKEN-}\" != \"loupe-brokered\" ]; then\n\
		  echo missing-sentinel >&2\n\
		  exit 91\n\
		fi\n\
		exec /usr/bin/curl --silent --show-error --fail-with-body -X POST \"${ANTHROPIC_BASE_URL}/v1/messages\" -H 'content-type: application/json' -H 'authorization: Bearer loupe-brokered' --data '{\"model\":\"repo-controlled\",\"output_config\":{\"effort\":\"low\"},\"messages\":[],\"max_tokens\":8}'\n",
	)
	.unwrap();
	std::fs::set_permissions(&fake_claude, std::fs::Permissions::from_mode(0o755)).unwrap();

	let context = ModelBrokerContext::new(
		worker_binary,
		upstream,
		ModelCredential::anthropic_api_key("host-anthropic-secret"),
		ModelBrokerLimits::default(),
	);
	let backend = ClaudeCliBackend::with_bin(fake_claude.to_string_lossy())
		.with_network_config(model_only_allowlist())
		.with_model_broker_context(context);
	let response = backend
		.run(LlmRequest {
			tool_boundary: loupe_worker::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt: loupe_worker::llm::prompts::Prompt::instruction("ignored by fake CLI").unwrap(),
			workdir: workdir.path().to_path_buf(),
			timeout: Duration::from_secs(10),
			cancel: CancellationToken::new(),
			repo_id: None,
			job_id: None,
			job_capability: None,
			finding_id: None,
		})
		.await
		.expect("Claude must run through the real no-egress sandbox and model proxy");
	assert_eq!(response.text.for_log(), "BROKERED");

	let captured = captured.lock().await;
	assert_eq!(captured.len(), 1);
	assert_eq!(captured[0].headers.get("x-api-key").unwrap(), "host-anthropic-secret");
	assert!(!captured[0].headers.contains_key("authorization"));
	let body: serde_json::Value = serde_json::from_slice(&captured[0].body).unwrap();
	assert_eq!(body["model"], "claude-opus-4-7");
	assert_eq!(body["output_config"]["effort"], "max");
}

#[tokio::test]
async fn codex_reaches_fake_upstream_only_through_the_broker() {
	use std::os::unix::fs::PermissionsExt;

	if !bwrap_present() {
		eprintln!("skipping: bwrap missing");
		return;
	}
	let worker_binary = PathBuf::from(env!("CARGO_BIN_EXE_loupe-worker"));

	let captured = Arc::new(Mutex::new(Vec::<Captured>::new()));
	let app = Router::new()
		.route(
			"/v1/responses",
			post(
				|State(captured): State<Arc<Mutex<Vec<Captured>>>>, request: Request| async move {
					let headers = request.headers().clone();
					let body = to_bytes(request.into_body(), 1024 * 1024).await.unwrap().to_vec();
					captured.lock().await.push(Captured { headers, body });
					Response::new(Body::from("BROKERED-CODEX"))
				},
			),
		)
		.with_state(captured.clone());
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let upstream: reqwest::Url =
		format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
	tokio::spawn(async move {
		axum::serve(listener, app).await.unwrap();
	});

	let scratch = tempfile::tempdir().unwrap();
	let workdir = tempfile::tempdir().unwrap();
	std::fs::create_dir(workdir.path().join(".codex")).unwrap();
	std::fs::write(
		workdir.path().join(".codex/config.toml"),
		"model_provider = \"hostile\"\nmodel = \"repo-controlled\"\n",
	)
	.unwrap();
	let fake_codex = scratch.path().join("fake-codex");
	std::fs::write(
		&fake_codex,
		r#"#!/bin/sh
if [ -n "${OPENAI_API_KEY-}" ] || [ "${CODEX_API_KEY-}" != "loupe-brokered" ]; then
  echo credential-leaked >&2
  exit 90
fi
case "$*" in *host-openai-secret*) echo credential-argument-leaked >&2; exit 92 ;; esac
base_url=
for argument in "$@"; do
  case "$argument" in
    model_providers.loupe.base_url=*)
      value=${argument#*=}
      value=${value#\"}
      base_url=${value%\"}
      ;;
  esac
done
case "$base_url" in
  http://127.0.0.1:*) ;;
  *) echo missing-loopback-provider >&2; exit 91 ;;
esac
exec /usr/bin/curl --silent --show-error --fail-with-body -X POST "${base_url}/responses" -H 'content-type: application/json' -H 'authorization: Bearer loupe-brokered' --data '{"model":"repo-controlled","reasoning":{"effort":"low"},"input":"test"}'
"#,
	)
	.unwrap();
	std::fs::set_permissions(&fake_codex, std::fs::Permissions::from_mode(0o755)).unwrap();

	let context = ModelBrokerContext::new(
		worker_binary,
		upstream,
		ModelCredential::openai_api_key("host-openai-secret"),
		ModelBrokerLimits::default(),
	);
	let backend = CodexCliBackend::with_bin(fake_codex.to_string_lossy())
		.with_network_config(model_only_allowlist())
		.with_model_broker_context(context);
	let response = backend
		.run(LlmRequest {
			tool_boundary: loupe_worker::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt: loupe_worker::llm::prompts::Prompt::instruction("ignored by fake CLI").unwrap(),
			workdir: workdir.path().to_path_buf(),
			timeout: Duration::from_secs(10),
			cancel: CancellationToken::new(),
			repo_id: None,
			job_id: None,
			job_capability: None,
			finding_id: None,
		})
		.await
		.expect("Codex must run through the real no-egress sandbox and model proxy");
	assert_eq!(response.text.for_log(), "BROKERED-CODEX");

	let captured = captured.lock().await;
	assert_eq!(captured.len(), 1);
	assert_eq!(captured[0].headers.get("authorization").unwrap(), "Bearer host-openai-secret");
	let body: serde_json::Value = serde_json::from_slice(&captured[0].body).unwrap();
	assert_eq!(body["model"], "gpt-5.5");
	assert_eq!(body["reasoning"]["effort"], "xhigh");
}

#[tokio::test]
async fn selected_claude_cli_reaches_the_messages_contract() {
	let Some(claude) = cli_from_env("LOUPE_TEST_CLAUDE_BIN") else {
		return;
	};
	if !bwrap_present() {
		eprintln!("skipping: bwrap missing");
		return;
	}

	let captured = Arc::new(Mutex::new(Vec::<Captured>::new()));
	let app = Router::new()
		.route(
			"/v1/messages",
			post(
				|State(captured): State<Arc<Mutex<Vec<Captured>>>>, request: Request| async move {
					let headers = request.headers().clone();
					let body = to_bytes(request.into_body(), 1024 * 1024).await.unwrap().to_vec();
					captured.lock().await.push(Captured { headers, body });
					Response::new(Body::from("intentional protocol-gate stop"))
				},
			),
		)
		.with_state(captured.clone());
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let upstream: reqwest::Url =
		format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
	tokio::spawn(async move {
		axum::serve(listener, app).await.unwrap();
	});

	let context = ModelBrokerContext::new(
		PathBuf::from(env!("CARGO_BIN_EXE_loupe-worker")),
		upstream,
		ModelCredential::anthropic_api_key("host-anthropic-secret"),
		ModelBrokerLimits::default(),
	);
	let backend = ClaudeCliBackend::with_bin(claude.to_string_lossy())
		.with_network_config(model_only_allowlist())
		.with_model_broker_context(context);
	let workdir = tempfile::tempdir().unwrap();
	let cli_result = backend
		.run(LlmRequest {
			tool_boundary: loupe_worker::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt: loupe_worker::llm::prompts::Prompt::instruction(
				"Return OK and do nothing else.",
			)
			.unwrap(),
			workdir: workdir.path().to_path_buf(),
			timeout: Duration::from_secs(3),
			cancel: CancellationToken::new(),
			repo_id: None,
			job_id: None,
			job_capability: None,
			finding_id: None,
		})
		.await;

	let captured = captured.lock().await;
	assert!(
		!captured.is_empty(),
		"selected Claude CLI never reached POST /v1/messages: {cli_result:?}"
	);
	assert_eq!(captured[0].headers.get("x-api-key").unwrap(), "host-anthropic-secret");
	let body: serde_json::Value = serde_json::from_slice(&captured[0].body).unwrap();
	assert_eq!(body["model"], "claude-opus-4-7");
	assert_eq!(body["output_config"]["effort"], "max");
}

#[tokio::test]
async fn selected_codex_cli_reaches_the_responses_contract() {
	let Some(codex) = cli_from_env("LOUPE_TEST_CODEX_BIN") else {
		return;
	};
	if !bwrap_present() {
		eprintln!("skipping: bwrap missing");
		return;
	}

	let captured = Arc::new(Mutex::new(Vec::<Captured>::new()));
	let app = Router::new()
		.route(
			"/v1/responses",
			post(
				|State(captured): State<Arc<Mutex<Vec<Captured>>>>, request: Request| async move {
					let headers = request.headers().clone();
					let body = to_bytes(request.into_body(), 1024 * 1024).await.unwrap().to_vec();
					captured.lock().await.push(Captured { headers, body });
					Response::new(Body::from("intentional protocol-gate stop"))
				},
			),
		)
		.with_state(captured.clone());
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let upstream: reqwest::Url =
		format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
	tokio::spawn(async move {
		axum::serve(listener, app).await.unwrap();
	});

	let context = ModelBrokerContext::new(
		PathBuf::from(env!("CARGO_BIN_EXE_loupe-worker")),
		upstream,
		ModelCredential::openai_api_key("host-openai-secret"),
		ModelBrokerLimits::default(),
	);
	let backend = CodexCliBackend::with_bin(codex.to_string_lossy())
		.with_network_config(model_only_allowlist())
		.with_model_broker_context(context);
	let workdir = tempfile::tempdir().unwrap();
	let cli_result = backend
		.run(LlmRequest {
			tool_boundary: loupe_worker::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt: loupe_worker::llm::prompts::Prompt::instruction(
				"Return OK and do nothing else.",
			)
			.unwrap(),
			workdir: workdir.path().to_path_buf(),
			timeout: Duration::from_secs(3),
			cancel: CancellationToken::new(),
			repo_id: None,
			job_id: None,
			job_capability: None,
			finding_id: None,
		})
		.await;

	let captured = captured.lock().await;
	assert!(
		!captured.is_empty(),
		"selected Codex CLI never reached POST /v1/responses: {cli_result:?}"
	);
	assert_eq!(captured[0].headers.get("authorization").unwrap(), "Bearer host-openai-secret");
	let body: serde_json::Value = serde_json::from_slice(&captured[0].body).unwrap();
	assert_eq!(body["model"], "gpt-5.5");
	assert_eq!(body["reasoning"]["effort"], "xhigh");
}

#[tokio::test]
async fn selected_claude_cli_completes_a_local_response_with_the_exact_prompt() {
	let Some(claude) = cli_from_env("LOUPE_TEST_CLAUDE_BIN") else {
		return;
	};
	assert!(bwrap_present(), "the selected real CLI check requires Bubblewrap");
	let captured = Arc::new(Mutex::new(Vec::<Captured>::new()));
	let app = Router::new()
		.route(
			"/v1/messages",
			post(
				|State(captured): State<Arc<Mutex<Vec<Captured>>>>, request: Request| async move {
					let headers = request.headers().clone();
					let body = to_bytes(request.into_body(), 1024 * 1024).await.unwrap().to_vec();
					captured.lock().await.push(Captured { headers, body });
					let events = [
						json!({"type": "message_start", "message": {
							"id": "msg_loupe_fixture", "type": "message", "role": "assistant",
							"content": [], "model": "claude-opus-4-7", "stop_reason": null,
							"stop_sequence": null, "usage": {"input_tokens": 10, "output_tokens": 0}
						}}),
						json!({"type": "content_block_start", "index": 0,
					"content_block": {"type": "text", "text": ""}}),
						json!({"type": "content_block_delta", "index": 0,
					"delta": {"type": "text_delta", "text": "LOUPE_LOCAL_RESPONSE_OK"}}),
						json!({"type": "content_block_stop", "index": 0}),
						json!({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": null},
					"usage": {"output_tokens": 8}}),
						json!({"type": "message_stop"}),
					];
					let body = events
						.iter()
						.map(|event| {
							format!("event: {}\ndata: {event}\n\n", event["type"].as_str().unwrap())
						})
						.collect::<String>();
					Response::builder()
						.header("content-type", "text/event-stream")
						.body(Body::from(body))
						.unwrap()
				},
			),
		)
		.with_state(captured.clone());
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let upstream = format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
	let server = tokio::spawn(async move {
		axum::serve(listener, app).await.unwrap();
	});
	let context = ModelBrokerContext::new(
		PathBuf::from(env!("CARGO_BIN_EXE_loupe-worker")),
		upstream,
		ModelCredential::anthropic_api_key("host-anthropic-secret"),
		ModelBrokerLimits::default(),
	);
	let backend = ClaudeCliBackend::with_bin(claude.to_string_lossy())
		.with_network_config(model_only_allowlist())
		.with_model_broker_context(context);
	let workdir = tempfile::tempdir().unwrap();
	let prompt = loupe_worker::llm::prompts::Prompt::instruction(
		"Return LOUPE_LOCAL_RESPONSE_OK and do nothing else.",
	)
	.unwrap();
	let expected = prompt.expose().to_owned();
	let result = backend
		.run(LlmRequest {
			tool_boundary: loupe_worker::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt,
			workdir: workdir.path().to_owned(),
			timeout: Duration::from_secs(15),
			cancel: CancellationToken::new(),
			repo_id: None,
			job_id: None,
			job_capability: None,
			finding_id: None,
		})
		.await;
	server.abort();
	let response = result.expect("selected Claude CLI must complete the local response");
	assert_eq!(response.text.for_log().trim(), "LOUPE_LOCAL_RESPONSE_OK");
	let captured = captured.lock().await;
	assert_eq!(captured.len(), 1, "the local response must complete without retry");
	assert_eq!(captured[0].headers.get("x-api-key").unwrap(), "host-anthropic-secret");
	let body: Value = serde_json::from_slice(&captured[0].body).unwrap();
	assert_eq!(body["model"], "claude-opus-4-7");
	assert_eq!(body["output_config"]["effort"], "max");
	assert!(
		body["messages"].as_array().unwrap().iter().any(|message| {
			message["role"] == "user"
				&& message["content"].as_array().is_some_and(|content| {
					content.iter().any(|block| block["type"] == "text" && block["text"] == expected)
				})
		}),
		"rendered prompt must reach the upstream as an exact user text block"
	);
}

fn fixture_response(step: usize, item: Value) -> Response {
	let response = json!({
		"id": format!("resp_{step}"), "status": "completed", "output": [item.clone()],
		"usage": {"input_tokens": 10, "output_tokens": 10, "total_tokens": 20}
	});
	let events = [
		json!({"type": "response.created", "response": {"id": format!("resp_{step}")}}),
		json!({"type": "response.output_item.done", "output_index": 0, "item": item}),
		json!({"type": "response.completed", "response": response}),
	];
	let body = events
		.iter()
		.map(|event| format!("event: {}\ndata: {event}\n\n", event["type"].as_str().unwrap()))
		.collect::<String>();
	Response::builder().header("content-type", "text/event-stream").body(Body::from(body)).unwrap()
}

fn fixture_function(tools: &Value, suffix: &str, id: &str, arguments: Value) -> Value {
	for tool in tools.as_array().expect("Codex must advertise tools") {
		let functions = tool["tools"]
			.as_array()
			.map(Vec::as_slice)
			.unwrap_or_else(|| std::slice::from_ref(tool));
		for function in functions {
			let name = function["name"].as_str().unwrap_or_default();
			if name == suffix || name.ends_with(&format!("__{suffix}")) {
				let mut call = json!({"type": "function_call", "call_id": id, "name": name,
					"arguments": arguments.to_string()});
				if tool["type"] == "namespace" {
					call["namespace"] = tool["name"].clone();
				}
				return call;
			}
		}
	}
	panic!("Codex did not advertise {suffix}: {tools}");
}

fn fixture_tool_output(request: &Captured, id: &str) -> String {
	let body: Value = serde_json::from_slice(&request.body).unwrap();
	body["input"]
		.as_array()
		.unwrap()
		.iter()
		.find(|item| item["type"] == "function_call_output" && item["call_id"] == id)
		.unwrap_or_else(|| panic!("missing result for {id}: {body}"))["output"]
		.to_string()
}

const CODEX_PERMISSION_CHECK: &str = r#"set -eu
test "$(cat /workdir/input.txt)" = repo-readable
printf scratch > /tmp/policy-check
printf home > /home/scanner/policy-check
if (printf forbidden > /workdir/forbidden) 2>/dev/null; then exit 21; fi
test "$CODEX_API_KEY" = loupe-brokered
code=$(/usr/bin/curl --silent --max-time 3 --output /tmp/route-check --write-out '%{http_code}' "http://127.0.0.1:$(cat /tmp/loupe-model.port)/invalid")
test "$code" != 000
printf 'LOCAL_PERMISSIONS_OK\n'
"#;

/// Compatibility check with real Codex command execution and both Loupe brokers.
/// The scripted upstream keeps the check deterministic and uses no provider key.
#[tokio::test]
async fn selected_codex_cli_completes_commands_and_mcp_under_the_worker_policy() {
	let Some(codex) = cli_from_env("LOUPE_TEST_CODEX_BIN") else {
		return;
	};
	assert!(bwrap_present(), "the real CLI check requires Bubblewrap");
	let captured = Arc::new(Mutex::new(Vec::<Captured>::new()));
	let mcp_headers = Arc::new(Mutex::new(Vec::<HeaderMap>::new()));
	let query_headers = mcp_headers.clone();
	let app = Router::new()
		.route(
			"/v1/responses",
			post(
				|State(captured): State<Arc<Mutex<Vec<Captured>>>>, request: Request| async move {
					let headers = request.headers().clone();
					let body = to_bytes(request.into_body(), 1024 * 1024).await.unwrap().to_vec();
					let value: Value = serde_json::from_slice(&body).unwrap();
					let mut captured = captured.lock().await;
					let step = captured.len();
					captured.push(Captured { headers, body });
					let item = match step {
						0 => fixture_function(
							&value["tools"],
							"exec_command",
							"shell-check",
							json!({
								"cmd": CODEX_PERMISSION_CHECK,
								"yield_time_ms": 1000, "max_output_tokens": 2000
							}),
						),
						1 => json!({"type": "tool_search_call", "execution": "client",
					"call_id": "discover-mcp", "status": "completed",
					"arguments": {"query": "query_prior_findings", "limit": 8}}),
						2 => {
							let found = value["input"]
								.as_array()
								.unwrap()
								.iter()
								.find(|item| item["type"] == "tool_search_output")
								.expect("tool search result");
							fixture_function(
								&found["tools"],
								"query_prior_findings",
								"mcp-check",
								json!({"query": "policy-check", "limit": 1}),
							)
						},
						_ => json!({"type": "message", "role": "assistant", "content": [
							{"type": "output_text", "text": "PERMISSIONS_AND_MCP_OK"}
						]}),
					};
					fixture_response(step, item)
				},
			),
		)
		.route(
			"/v1/repos/7/findings/search",
			get(move |headers: HeaderMap| {
				let query_headers = query_headers.clone();
				async move {
					query_headers.lock().await.push(headers);
					Response::builder()
						.header("content-type", "application/json")
						.header(
							loupe_proto::PROTOCOL_VERSION_HEADER,
							loupe_proto::PROTOCOL_VERSION.to_string(),
						)
						.body(Body::from(
							json!({"protocol_version": loupe_proto::PROTOCOL_VERSION,
					"findings": []})
							.to_string(),
						))
						.unwrap()
				}
			}),
		)
		.with_state(captured.clone());
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let upstream: reqwest::Url =
		format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
	let server = tokio::spawn(async move {
		axum::serve(listener, app).await.unwrap();
	});
	let worker_binary = PathBuf::from(env!("CARGO_BIN_EXE_loupe-worker"));
	let model = ModelBrokerContext::new(
		worker_binary.clone(),
		upstream.clone(),
		ModelCredential::openai_api_key("host-openai-secret"),
		ModelBrokerLimits::default(),
	);
	let mcp = McpContext {
		worker_binary,
		client: Arc::new(ServerClient::from_parts(reqwest::Client::new(), upstream)),
		bkb_mcp_path: None,
		bkb_api_url: loupe_worker::config::ConfiguredText::Builtin("https://example.invalid"),
	};
	let workdir = tempfile::tempdir().unwrap();
	std::fs::write(workdir.path().join("input.txt"), "repo-readable").unwrap();
	std::fs::create_dir(workdir.path().join(".codex")).unwrap();
	std::fs::write(
		workdir.path().join(".codex/config.toml"),
		"model_provider = \"hostile\"\nsandbox_mode = \"danger-full-access\"\n",
	)
	.unwrap();
	let prompt = loupe_worker::llm::prompts::Prompt::instruction(
		"Run the permission check and query prior findings.",
	)
	.unwrap();
	let expected_prompt = prompt.expose().to_owned();
	let result = CodexCliBackend::with_bin(codex.to_string_lossy())
		.with_network_config(model_only_allowlist())
		.with_model_broker_context(model)
		.with_mcp_context(mcp)
		.run(LlmRequest {
			tool_boundary: loupe_worker::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt,
			workdir: workdir.path().to_path_buf(),
			timeout: Duration::from_secs(30),
			cancel: CancellationToken::new(),
			repo_id: Some(7),
			job_id: None,
			job_capability: Some(loupe_proto::JobCapability::from_secret("host-job-capability")),
			finding_id: None,
		})
		.await;
	server.abort();
	let response =
		result.expect("Codex must complete through both brokers with its command sandbox");
	assert_eq!(response.text.for_log().trim(), "PERMISSIONS_AND_MCP_OK");
	assert!(!workdir.path().join("forbidden").exists(), "repository writes must stay blocked");
	let captured = captured.lock().await;
	assert_eq!(captured.len(), 4);
	let first: Value = serde_json::from_slice(&captured[0].body).unwrap();
	assert!(
		first["input"].as_array().unwrap().iter().any(|item| {
			item["role"] == "user"
				&& item["content"].as_array().is_some_and(|content| {
					content
						.iter()
						.any(|part| part["type"] == "input_text" && part["text"] == expected_prompt)
				})
		}),
		"the real Codex CLI must forward exact stdin prompt bytes"
	);
	assert!(
		fixture_tool_output(&captured[1], "shell-check").contains("LOCAL_PERMISSIONS_OK"),
		"sandboxed command failed: {}",
		fixture_tool_output(&captured[1], "shell-check")
	);
	let result: Value =
		serde_json::from_str(&fixture_tool_output(&captured[3], "mcp-check")).unwrap();
	let text = result
		.as_array()
		.unwrap()
		.iter()
		.filter_map(|part| part["text"].as_str())
		.find(|text| text.starts_with("No prior findings match."))
		.expect("successful framed MCP output");
	let query = framed_tool_data(text, "query");
	assert_eq!(query, "policy-check");
	let findings: Value = serde_json::from_str(framed_tool_data(text, "findings")).unwrap();
	assert_eq!(findings, json!({"repo_id":7, "findings":[]}));
	for request in captured.iter() {
		assert_eq!(request.headers.get("authorization").unwrap(), "Bearer host-openai-secret");
		let body = String::from_utf8_lossy(&request.body);
		assert!(!body.contains("host-openai-secret") && !body.contains("host-job-capability"));
	}
	let mcp_headers = mcp_headers.lock().await;
	assert_eq!(mcp_headers.len(), 1);
	assert_eq!(
		mcp_headers[0].get(loupe_proto::JOB_CAPABILITY_HEADER).unwrap(),
		"host-job-capability"
	);
}

fn framed_tool_data<'a>(text: &'a str, field: &str) -> &'a str {
	let prefix = format!("<loupe-data field=\"{field}\" source=\"agent\" boundary=\"");
	let rest = text.split_once(&prefix).expect("source-labelled block").1;
	let (boundary, data) = rest.split_once("\">\n").expect("complete opening tag");
	assert_eq!(boundary.len(), 32);
	assert!(boundary.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
	let closing = format!("\n</loupe-data boundary=\"{boundary}\">\n");
	let data = data.split_once(&closing).expect("complete closing tag").0;
	assert!(!data.contains(boundary));
	data
}
