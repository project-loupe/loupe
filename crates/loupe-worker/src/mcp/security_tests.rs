use std::io::Write;
use std::sync::Mutex;

use super::*;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
	fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
		self.0.lock().unwrap().extend_from_slice(bytes);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

fn subscriber(capture: Capture) -> impl tracing::Subscriber + Send + Sync {
	tracing_subscriber::fmt()
		.with_max_level(tracing::Level::DEBUG)
		.without_time()
		.with_ansi(false)
		.with_writer(move || capture.clone())
		.finish()
}

fn context(workdir: &Path) -> McpSessionContext {
	McpSessionContext {
		tool_boundary: crate::llm::prompt::JobToolBoundary::new().unwrap(),
		client: Arc::new(ServerClient::from_parts(
			reqwest::Client::new(),
			"http://127.0.0.1:1/".parse().unwrap(),
		)),
		job_capability: JobCapability::from_secret("fixture-capability"),
		repo_id: 1,
		job_id: Some(1),
		finding_id: None,
		workdir: workdir.to_owned(),
	}
}

#[tokio::test]
async fn request_argument_bytes_never_reach_logs() {
	// Tracing caches callsite interest across threads; isolate capture from other tests.
	if !crate::test_env::in_env(
		"mcp::security_tests::request_argument_bytes_never_reach_logs",
		"log-capture",
		&[],
	) {
		return;
	}
	let capture = Capture::default();
	let _guard = tracing::subscriber::set_default(subscriber(capture.clone()));
	let workdir = tempfile::tempdir().unwrap();
	let marker = "private-argument-7f83b4d69a";
	let input = format!(
		"{}\n",
		json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"private":marker}})
	);
	let mut output = Vec::new();
	run_stream_server(context(workdir.path()), input.as_bytes(), &mut output).await.unwrap();
	let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
	assert!(!logs.contains(marker), "request argument leaked into MCP logs");
	assert!(
		logs.contains("received request"),
		"capture must observe the request log; logs={logs:?}; output={:?}",
		String::from_utf8_lossy(&output),
	);
}

#[tokio::test]
async fn unknown_method_bytes_never_reach_logs() {
	if !crate::test_env::in_env(
		"mcp::security_tests::unknown_method_bytes_never_reach_logs",
		"log-capture",
		&[],
	) {
		return;
	}
	let capture = Capture::default();
	let _guard = tracing::subscriber::set_default(subscriber(capture.clone()));
	let workdir = tempfile::tempdir().unwrap();
	let marker = "private-method-7f83b4d69a";
	let input = format!("{}\n", json!({"jsonrpc":"2.0","id":1,"method":marker}));
	let mut output = Vec::new();
	run_stream_server(context(workdir.path()), input.as_bytes(), &mut output).await.unwrap();
	let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
	assert!(!logs.contains(marker), "unknown method leaked into MCP logs");
	assert!(logs.contains("received request"), "capture must observe the request log: {logs:?}");
	assert!(String::from_utf8(output).unwrap().contains(marker), "sender keeps its protocol error");
}

#[tokio::test]
async fn rejected_arguments_never_reach_tool_failure_logs() {
	if !crate::test_env::in_env(
		"mcp::security_tests::rejected_arguments_never_reach_tool_failure_logs",
		"log-capture",
		&[],
	) {
		return;
	}
	let capture = Capture::default();
	let _guard = tracing::subscriber::set_default(subscriber(capture.clone()));
	let workdir = tempfile::tempdir().unwrap();
	let context = context(workdir.path());
	let session = Arc::new(Session {
		tool_boundary: crate::llm::prompt::JobToolBoundary::new().unwrap(),
		data_mode: crate::llm::prompt::DataMode::Delimited,
		client: context.client,
		job_capability: context.job_capability,
		repo_id: 1,
		job_id: Some(1),
		workdir: context.workdir,
		verify: Some(VerifySessionState { finding_id: 1, inner: tokio::sync::Mutex::default() }),
	});
	let marker = "private-verdict-7f83b4d69a";
	let request = Request {
		jsonrpc: "2.0".into(),
		id: Some(json!(1)),
		method: "tools/call".into(),
		params: Some(
			json!({"name":"submit_verdict","arguments":{"verdict":marker,"notes":"note"}}),
		),
	};
	let response = handle_request(&session, &request, json!(1)).await;
	assert_eq!(response.result.as_ref().unwrap()["isError"], true);
	let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
	assert!(!logs.contains(marker), "rejected argument leaked into tool-failure log");
	assert!(logs.contains("tool call failed"), "capture must observe tool failure; logs={logs:?}");
}

#[tokio::test]
async fn reflected_response_bytes_never_reach_logs() {
	if !crate::test_env::in_env(
		"mcp::security_tests::reflected_response_bytes_never_reach_logs",
		"log-capture",
		&[],
	) {
		return;
	}
	let capture = Capture::default();
	let _guard = tracing::subscriber::set_default(subscriber(capture.clone()));
	let marker = "private-response-7f83b4d69a";
	let mut output = Vec::new();
	write_response(&mut output, &Response::err(json!(1), -32601, marker)).await.unwrap();
	let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
	assert!(!logs.contains(marker), "reflected response leaked into MCP logs");
	assert!(logs.contains("sending response"), "capture must observe the response log: {logs:?}");
	assert!(String::from_utf8(output).unwrap().contains(marker));
}

#[tokio::test]
async fn git_diagnostic_truncation_handles_multibyte_boundary() {
	let workdir = tempfile::tempdir().unwrap();
	let stderr_path = workdir.path().join("stderr");
	std::fs::write(&stderr_path, format!("{}€tail", "x".repeat(4095))).unwrap();
	let mut command = tokio::process::Command::new("/bin/sh");
	command
		.args(["-c", "cat >/dev/null; cat \"$1\" >&2; exit 1", "stub-git"])
		.arg(stderr_path)
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let result = check_diff_applies_with_command(command, "diff").await.unwrap();
	let DiffCheck::Rejects { stderr } = result else { panic!("expected rejected diff") };
	assert_eq!(stderr.for_tool_response(), format!("{}\n…(truncated)", "x".repeat(4095)));
}
