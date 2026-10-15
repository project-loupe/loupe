//! The raw denied-tool suffix must not escape into host diagnostic sinks.

use std::io::Write;

use super::*;

const DENIED_TOOL: &str = "web_fetch_private-sentinel";

#[derive(Clone, Default)]
struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);

impl Write for LogCapture {
	fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
		self.0.lock().unwrap().extend_from_slice(bytes);
		Ok(bytes.len())
	}

	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

async fn captured_tool_denial(test_name: &str, json_logs: bool) -> Option<String> {
	// A process-wide subscriber reaches the broker's spawned Tokio tasks.
	// Isolating the process also avoids tracing's shared callsite cache.
	if !crate::test_env::in_env(test_name, "model-tool-log-capture", &[]) {
		return None;
	}
	let capture = LogCapture::default();
	let writer = capture.clone();
	let subscriber = tracing_subscriber::fmt()
		.with_max_level(tracing::Level::DEBUG)
		.without_time()
		.with_ansi(false)
		.with_writer(move || writer.clone());
	if json_logs {
		tracing::subscriber::set_global_default(subscriber.json().finish()).unwrap();
	} else {
		tracing::subscriber::set_global_default(subscriber.finish()).unwrap();
	}

	const CREDENTIAL: &str = "host-private-credential-sentinel";
	const BODY_MARKER: &str = "request-private-body-sentinel";
	const CAPABILITY: &str = "capability-private-sentinel";
	let upstream = FakeUpstream::start("{}").await;
	let session = ModelBrokerSession::start(
		claude_backend(),
		upstream.url.clone(),
		ModelCredential::anthropic_api_key(CREDENTIAL),
		limits(),
	)
	.await
	.unwrap();
	let mut client = connect(&session).await;
	let denied = format!(
		r#"{{"model":"claude-test","output_config":{{"effort":"high"}},"input":"{BODY_MARKER}","tools":[{{"type":"{DENIED_TOOL}"}}]}}"#
	);
	let mut denied_request = request("/v1/messages", denied);
	denied_request.headers_mut().insert(
		loupe_proto::JOB_CAPABILITY_HEADER,
		axum::http::HeaderValue::from_static(CAPABILITY),
	);
	let response = client.send_request(denied_request).await.unwrap();
	assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
	let response_body = response.into_body().collect().await.unwrap().to_bytes();
	let response_json: serde_json::Value = serde_json::from_slice(&response_body).unwrap();
	assert_eq!(response_json["error"]["code"], "tool_policy_denied");
	assert!(upstream.captured().await.is_empty(), "denied request reached the provider");

	let allowed = format!(
		r#" {{ "model":"claude-test", "output_config":{{"effort":"high"}}, "input":"{BODY_MARKER}", "tools":[{{"type":"web_search_20250305","name":"search"}}] }} "#
	);
	let response = client
		.send_request(request("/v1/messages", Bytes::copy_from_slice(allowed.as_bytes())))
		.await
		.unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	response.into_body().collect().await.unwrap();
	let captured = upstream.captured().await;
	assert_eq!(captured.len(), 1, "only the allowed tool request may reach the provider");
	assert_eq!(captured[0].body.as_ref(), allowed.as_bytes());
	assert_eq!(captured[0].headers["x-api-key"], CREDENTIAL);
	session.finish().await.unwrap();

	let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
	assert!(
		logs.contains("model broker denied a provider-side fetch tool"),
		"capture must observe the real denial warning: {logs}"
	);
	for marker in [CREDENTIAL, BODY_MARKER, CAPABILITY] {
		assert!(
			!logs.contains(marker),
			"model logs disclosed unrelated transported content: {logs}"
		);
	}
	eprintln!("positive controls passed: 422/tool_policy_denied, zero denied forwards, one byte-identical allowed forward, and observed denial warning");
	Some(logs)
}

#[tokio::test]
async fn denied_tool_suffix_preserves_policy_and_allowed_forwarding() {
	let _ = captured_tool_denial(
		"llm::model_broker::tests::security_log_tests::denied_tool_suffix_preserves_policy_and_allowed_forwarding",
		false,
	)
	.await;
}

#[tokio::test]
async fn denied_tool_suffix_never_reaches_text_logs() {
	if let Some(logs) = captured_tool_denial(
		"llm::model_broker::tests::security_log_tests::denied_tool_suffix_never_reaches_text_logs",
		false,
	)
	.await
	{
		assert!(!logs.contains(DENIED_TOOL), "denied tool suffix leaked into text logs: {logs}");
	}
}

#[tokio::test]
async fn denied_tool_suffix_never_reaches_json_logs() {
	if let Some(logs) = captured_tool_denial(
		"llm::model_broker::tests::security_log_tests::denied_tool_suffix_never_reaches_json_logs",
		true,
	)
	.await
	{
		assert!(!logs.contains(DENIED_TOOL), "denied tool suffix leaked into JSON logs: {logs}");
	}
}
