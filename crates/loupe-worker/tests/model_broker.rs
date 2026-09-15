#![cfg(unix)]

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use loupe_worker::llm::model_broker::{ModelBrokerContext, ModelBrokerLimits, ModelCredential};
use loupe_worker::llm::{ClaudeCliBackend, CodexCliBackend, LlmBackend, LlmRequest};
use loupe_worker::sandbox::{SandboxNetworkConfig, SandboxNetworkMode};
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
			prompt: "ignored by fake CLI".into(),
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
	assert_eq!(response.text, "BROKERED");

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
			prompt: "ignored by fake CLI".into(),
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
	assert_eq!(response.text, "BROKERED-CODEX");

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
			prompt: "Return OK and do nothing else.".into(),
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
			prompt: "Return OK and do nothing else.".into(),
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
