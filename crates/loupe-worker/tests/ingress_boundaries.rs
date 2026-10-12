//! Real transport controls for worker source admission and record framing.

use std::path::Path;
use std::sync::Arc;

use loupe_proto::{JobCapability, PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use loupe_worker::mcp::{run_stream_server, McpSessionContext};
use loupe_worker::ServerClient;
use serde_json::{json, Value};

const RECORD_BYTES: usize = 16 * 1024 * 1024;

#[test]
fn worker_file_admission_errors_discard_source_document() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("worker.toml");
	for document in [
		"[logging]\nprivate_config_sentinel = true\n",
		"[agents]\nscan = 'private_config_sentinel'\n",
		"[agents.codex]\nmodel = 'private_config_sentinel\n",
	] {
		std::fs::write(&path, document).unwrap();
		let error = loupe_worker::config::FileConfig::load(&path).unwrap_err();
		assert!(
			!format!("{error:#}").contains("private_config_sentinel"),
			"Config admission error retained source text"
		);
		assert!(
			!format!("{error:?}").contains("private_config_sentinel"),
			"Config admission error debug retained source text"
		);
		assert!(
			format!("{error:#}").contains("bytes "),
			"Config admission error lost its byte span"
		);
	}
	std::fs::write(&path, "[agents.codex]\nmodel = 'private_config_sentinel'\n").unwrap();
	assert_eq!(
		loupe_worker::config::FileConfig::load(&path).unwrap().agents.codex.model.as_deref(),
		Some("private_config_sentinel")
	);
}

#[tokio::test]
async fn mcp_admission_errors_discard_invalid_choice_text() {
	for (name, arguments) in [
		("submit_finding", json!({"severity":"private_argument_sentinel"})),
		("submit_verdict", json!({"verdict":"private_argument_sentinel","notes":"notes"})),
	] {
		let record = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":name,"arguments":arguments}})).unwrap();
		let mut output = Vec::new();
		run_stream_server(context(), record.as_slice(), &mut output).await.unwrap();
		let reply: Value = serde_json::from_slice(&output).unwrap();
		assert_eq!(reply["result"]["isError"], true);
		assert!(
			!String::from_utf8(output).unwrap().contains("private_argument_sentinel"),
			"MCP admission error retained invalid choice text"
		);
	}
}

#[tokio::test]
async fn mcp_protocol_name_echo_remains_sender_facing() {
	for (method, params, expected) in [
		("private_method_sentinel", json!({}), "method not found: private_method_sentinel"),
		(
			"tools/call",
			json!({"name":"private_tool_sentinel"}),
			"unknown tool: private_tool_sentinel",
		),
	] {
		let record =
			serde_json::to_vec(&json!({"jsonrpc":"2.0","id":5,"method":method,"params":params}))
				.unwrap();
		let mut output = Vec::new();
		run_stream_server(context(), record.as_slice(), &mut output).await.unwrap();
		assert!(String::from_utf8(output).unwrap().contains(expected));
	}
}

#[test]
fn worker_file_config_rejects_new_text_control_policy() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("worker.toml");
	std::fs::write(&path, "[agents.codex]\nmodel = \"model\\u0001\"\n").unwrap();
	let result = loupe_worker::config::WorkerConfig::load(Some(&path), Default::default());
	assert!(result.is_err(), "worker TOML model control bytes were accepted");
}

#[test]
fn worker_file_config_rejects_new_text_cap() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("worker.toml");
	std::fs::write(
		&path,
		format!("[agents.codex]\nmodel = '{}'\n", "a".repeat(2 * 1024 * 1024 + 1)),
	)
	.unwrap();
	let result = loupe_worker::config::WorkerConfig::load(Some(&path), Default::default());
	assert!(result.is_err(), "worker TOML model above 2 MiB was accepted");
}

fn context() -> McpSessionContext {
	McpSessionContext {
		client: Arc::new(ServerClient::from_parts(
			reqwest::Client::new(),
			"http://127.0.0.1:1/".parse().unwrap(),
		)),
		job_capability: JobCapability::from_secret("fixture-capability"),
		repo_id: 1,
		job_id: Some(1),
		finding_id: None,
		workdir: Path::new("/").to_owned(),
	}
}

#[tokio::test]
async fn mcp_rejects_oversized_blank_record() {
	let mut input = vec![b' '; RECORD_BYTES + 1];
	input.push(b'\n');
	let mut output = Vec::new();
	let result = run_stream_server(context(), input.as_slice(), &mut output).await;
	assert!(result.is_err(), "oversized blank MCP record was accepted");
	assert!(output.is_empty(), "framing failure must not invent a protocol reply");
}

#[tokio::test]
async fn mcp_exact_record_cap_preserves_lf_crlf_and_eof() {
	let request = br#"{"jsonrpc":"unchecked","id":17,"method":"ping"}"#;
	for delimiter in [b"\n".as_slice(), b"\r\n", b""] {
		let mut input = request.to_vec();
		input.resize(RECORD_BYTES, b' ');
		input.extend_from_slice(delimiter);
		let mut output = Vec::new();
		run_stream_server(context(), input.as_slice(), &mut output).await.unwrap();
		let reply: Value = serde_json::from_slice(&output).unwrap();
		assert_eq!(reply, json!({"jsonrpc":"2.0","id":17,"result":{}}));
	}
}

#[tokio::test]
async fn mcp_lone_cr_at_eof_counts_toward_record_cap() {
	let mut input = vec![b' '; RECORD_BYTES];
	input.push(b'\r');
	let result = run_stream_server(context(), input.as_slice(), &mut Vec::new()).await;
	assert!(result.is_err(), "over-budget EOF record hid its last CR as a delimiter");
}

#[tokio::test]
async fn mcp_verdict_rejects_control_before_lock_and_flush() {
	let (client, task) = response(json!({})).await;
	let mut context = context();
	context.client = Arc::new(client);
	context.finding_id = Some(1);
	let record = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"submit_verdict","arguments":{"verdict":"confirmed","notes":"private\u0001note"}}}"#;
	let mut output = Vec::new();
	let result = run_stream_server(context, record.as_slice(), &mut output).await;
	task.abort();
	let reply: Value = serde_json::from_slice(&output).unwrap();
	assert_eq!(reply["result"]["isError"], true, "MCP accepted prohibited verdict notes");
	assert!(result.is_err(), "invalid verdict unexpectedly locked and flushed");
}

#[tokio::test]
async fn mcp_query_rejects_new_text_cap_before_http() {
	let (client, task) = response(json!({"protocol_version":PROTOCOL_VERSION,"findings":[]})).await;
	let mut context = context();
	context.client = Arc::new(client);
	let record = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_prior_findings","arguments":{"query":"a".repeat(2*1024*1024+1)}}})).unwrap();
	let mut output = Vec::new();
	run_stream_server(context, record.as_slice(), &mut output).await.unwrap();
	task.abort();
	let reply: Value = serde_json::from_slice(&output).unwrap();
	assert_eq!(reply["result"]["isError"], true, "MCP accepted query above 2 MiB");
	assert!(
		reply["result"]["content"][0]["text"] == "Error: query: Bytes",
		"query cap must reject at MCP admission, before an HTTP failure"
	);
}

#[tokio::test]
async fn mcp_over_limit_escaped_field_stops_before_params_content_pass() {
	// RawValue locates this token without decoding it. The field preflight must
	// reject before the legacy Value/content pass can allocate the escaped text
	// or reach the later numeric overflow. The whole record remains under16MiB.
	let notes = "\\u0061".repeat(2 * 1024 * 1024 + 1);
	let record = format!(
		r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"submit_verdict","arguments":{{"verdict":"confirmed","notes":"{notes}","later":1e400}}}}}}"#
	);
	assert!(record.len() < RECORD_BYTES);
	let mut output = Vec::new();
	run_stream_server(context(), record.as_bytes(), &mut output).await.unwrap();
	let reply: Value = serde_json::from_slice(&output).unwrap();
	assert!(
		reply["error"].is_null(),
		"rejected field reached the later params compatibility traversal"
	);
	assert_eq!(reply["id"], 7);
	assert_eq!(reply["result"]["isError"], true);
	assert_eq!(reply["result"]["content"][0]["text"], "Error: verdict_notes: Bytes");
}

#[tokio::test]
async fn mcp_field_rejection_keeps_original_id_depth() {
	#[derive(serde::Deserialize)]
	#[allow(dead_code)]
	struct LegacyRequest {
		jsonrpc: String,
		id: Option<Value>,
		method: String,
		params: Option<Value>,
	}
	#[derive(serde::Deserialize)]
	struct Reply<'a> {
		#[serde(borrow)]
		id: &'a serde_json::value::RawValue,
		#[serde(borrow)]
		error: Option<&'a serde_json::value::RawValue>,
	}
	for depth in 123..130 {
		for notes in ["safe", "bad\\u0001"] {
			let id = format!("{}7{}", "[".repeat(depth), "]".repeat(depth));
			let record = format!(
				r#"{{"jsonrpc":"unchecked","id":{id},"method":"tools/call","params":{{"name":"submit_verdict","arguments":{{"verdict":"confirmed","notes":"{notes}"}}}}}}"#
			);
			let expected = serde_json::from_str::<LegacyRequest>(&record);
			let mut output = Vec::new();
			run_stream_server(context(), record.as_bytes(), &mut output).await.unwrap();
			let reply: Reply<'_> = serde_json::from_slice(&output).unwrap();
			assert_eq!(reply.error.is_none(), expected.is_ok(), "id depth {depth}, notes {notes}");
			assert_eq!(reply.id.get(), if expected.is_ok() { &id } else { "null" });
		}
	}
}

#[tokio::test]
async fn mcp_unused_tool_fields_keep_legacy_params_syntax() {
	for (method, id) in [
		("ping", "1"),
		("initialize", "1"),
		("tools/list", "1"),
		("unknown", "1"),
		("tools/call", "null"),
	] {
		let record = format!(
			r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{{"name":"submit_verdict","arguments":{{"verdict":"confirmed","notes":"bad\u0001","later":1e400}}}}}}"#
		);
		let mut output = Vec::new();
		run_stream_server(context(), record.as_bytes(), &mut output).await.unwrap();
		assert!(!output.is_empty(), "malformed notification params lost their parse error");
		let reply: Value = serde_json::from_slice(&output).unwrap();
		assert_eq!(
			reply["error"]["code"], -32700,
			"unused tool fields changed {method} params syntax"
		);
		assert!(reply["id"].is_null());
	}
}

async fn response(body: Value) -> (ServerClient, tokio::task::JoinHandle<()>) {
	response_encoded(serde_json::to_string(&body).unwrap()).await
}

async fn response_encoded(body: String) -> (ServerClient, tokio::task::JoinHandle<()>) {
	let app = axum::Router::new().fallback(move || async move {
		([(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string())], body)
	});
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let url = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
	let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	(ServerClient::from_parts(reqwest::Client::new(), url), task)
}

fn finding(description: &str) -> Value {
	json!({
		"protocol_version":PROTOCOL_VERSION,"id":1,"repo_id":2,"job_id":3,
		"scanner_id":"scanner","severity":"high","title":" title ",
		"description":description,"fingerprint":"legacy-fingerprint",
		"state":"validating","verification_required":true,"created_at":42,
		"file_path":"src/cafe\u{301}.rs","poc_unified":"\r\n\t patch \n",
		"approved_by_cn":" Audit Name ","rejected_by_cn":null
	})
}

#[tokio::test]
async fn client_rejects_prohibited_finding_content() {
	let (client, task) = response(finding("private\u{1}text")).await;
	let result = client.get_finding(1, &JobCapability::from_secret("test")).await;
	task.abort();
	assert!(result.is_err(), "server finding control bytes were accepted");
}

#[tokio::test]
async fn client_rejects_finding_field_over_two_mib() {
	let (client, task) = response(finding(&"a".repeat(2 * 1024 * 1024 + 1))).await;
	let result = client.get_finding(1, &JobCapability::from_secret("test")).await;
	task.abort();
	assert!(result.is_err(), "finding field above 2 MiB was accepted");
}

#[tokio::test]
async fn client_rejects_finding_path_over_512_bytes() {
	let mut body = finding("description");
	body["file_path"] = json!("a".repeat(513));
	let (client, task) = response(body).await;
	let result = client.get_finding(1, &JobCapability::from_secret("test")).await;
	task.abort();
	assert!(result.is_err(), "finding path above 512 bytes was accepted");
}

#[tokio::test]
async fn client_preserves_exact_finding_and_audit_fields() {
	let description = " cafe\u{301}\r\n\t body \n\n\n";
	let (client, task) = response(finding(description)).await;
	let result = client.get_finding(1, &JobCapability::from_secret("test")).await.unwrap();
	task.abort();
	assert_eq!(result.description, description);
	assert_eq!(result.title, " title ");
	assert_eq!(result.file_path.as_deref(), Some("src/cafe\u{301}.rs"));
	assert_eq!(result.poc_unified.as_deref(), Some("\r\n\t patch \n"));
	assert_eq!(result.approved_by_cn.as_deref(), Some(" Audit Name "));
}

fn lease(config: Value) -> Value {
	json!({
		"kind":"lease","protocol_version":PROTOCOL_VERSION,"job_id":1,
		"job_capability":"lease-capability","repo_id":2,"lease_expires_at":42,
		"repo":{"host":"local","owner":"owner","repo":"repo","clone_url":"file:///tmp/repo"},
		"head_branch":null,"scanner_config":config,"payload":{"kind":"scan"}
	})
}

#[tokio::test]
async fn reviewed_revision_keeps_nonempty_exact_text_and_bounds_missing_fact() {
	for (revision, admitted) in [
		(" base ".to_owned(), true),
		("bad\trevision".to_owned(), false),
		(" ".repeat(2 * 1024 * 1024 + 1), false),
	] {
		let mut body = lease(Value::Null);
		body["payload"] = json!({"kind":"verify","finding_id":1,"finding":finding("description"),"reviewed_sha":revision});
		let (client, task) = response(body).await;
		let result = client.lease(Vec::new(), 0).await;
		task.abort();
		assert_eq!(result.is_ok(), admitted, "reviewed revision admission changed");
		if admitted {
			let loupe_proto::LeaseResponse::Lease(env) = result.unwrap() else { panic!("lease") };
			let loupe_proto::LeasePayload::Verify { reviewed_sha, .. } = env.payload else {
				panic!("verify")
			};
			assert_eq!(reviewed_sha.as_deref(), Some(revision.as_str()));
		}
	}
}

#[tokio::test]
async fn lease_rejects_newly_invalid_scanner_text() {
	let (client, task) = response(lease(json!({"include_extensions":["rs\u{1}"]}))).await;
	let result = client.lease(Vec::new(), 0).await;
	task.abort();
	assert!(result.is_err(), "scanner control bytes passed lease admission");
}

#[tokio::test]
async fn lease_keeps_old_ignored_scanner_shapes_and_unknown_values() {
	for config in [
		json!({"include_extensions":[7]}),
		json!({"include_extensions":["c"],"max_file_bytes":false}),
		json!([1, 4096, 1, ["c"], []]),
		json!({"include_extensions":[" c ","C", ""],"future":"\u{1}"}),
	] {
		let (client, task) = response(lease(config.clone())).await;
		let result = client.lease(Vec::new(), 0).await.unwrap();
		task.abort();
		let loupe_proto::LeaseResponse::Lease(result) = result else { panic!("lease") };
		assert_eq!(result.scanner_config, config);
	}
}

#[tokio::test]
async fn client_exact_field_and_path_caps_are_admitted() {
	let description = "a".repeat(2 * 1024 * 1024);
	let path = "a".repeat(512);
	let mut body = finding(&description);
	body["file_path"] = json!(path);
	let (client, task) = response(body).await;
	let result = client.get_finding(1, &JobCapability::from_secret("test")).await.unwrap();
	task.abort();
	assert_eq!(result.description, description);
	assert_eq!(result.file_path.as_deref(), Some(path.as_str()));
}

#[tokio::test]
async fn lease_selected_scanner_tokens_preserve_last_wins() {
	for config in [
		r#"{"include_extensions":["bad\u0001"],"include_extensions":[" c ","C",""]}"#,
		r#"{"include_extensions":false,"include_extensions":["c"]}"#,
		r#"{"include_extensions":["c"],"include_extensions":false}"#,
		r#"{"include_extensions":false,"include_\u0065xtensions":["c"]}"#,
		r#"{"max_file_bytes":false,"include_extensions":["c"]}"#,
	] {
		let raw = serde_json::to_string(&lease(Value::Null))
			.unwrap()
			.replace("\"scanner_config\":null", &format!("\"scanner_config\":{config}"));
		let (client, task) = response_encoded(raw.clone()).await;
		let result = client.lease(Vec::new(), 0).await.unwrap();
		task.abort();
		let expected: loupe_proto::LeaseResponse = serde_json::from_str(&raw).unwrap();
		let loupe_proto::LeaseResponse::Lease(expected) = expected else { panic!("lease") };
		let loupe_proto::LeaseResponse::Lease(result) = result else { panic!("lease") };
		assert_eq!(result.scanner_config, expected.scanner_config);
	}
}

#[tokio::test]
async fn lease_parser_matches_legacy_shapes_tags_and_depth() {
	let object = serde_json::to_string(&lease(Value::Null)).unwrap();
	let version = PROTOCOL_VERSION;
	let mut cases = vec![
		object.clone(),
		format!(r#"{{"kind":"empty","protocol_version":{version}}}"#),
		format!(r#"["empty",{version}]"#),
		format!(
			r#"["lease",{version},1,"cap",2,["local","owner","repo","file:///tmp/repo",null],null,42,null,null,["scan",null]]"#
		),
		object.replace(r#""payload":{"kind":"scan"}"#, r#""payload":["scan",null]"#),
		object.replace(r#""kind":"lease""#, r#""kind":1e400"#),
		object.replace(r#""kind":"lease""#, r#""kind":{"lease":null}"#),
		object.replace(r#""kind":"lease""#, r#""kind":"lease","kind":"empty""#),
		object.replace(r#""scanner_config":null"#, r#""scanner_config":{"future":1e400}"#),
		object.replace(r#""scanner_config":null"#, r#""scanner_config":{"future":"\ud800"}"#),
	];
	for depth in 122..132 {
		let nested = format!("{}null{}", "[".repeat(depth), "]".repeat(depth));
		cases.push(object.replace(
			r#""scanner_config":null"#,
			&format!(r#""scanner_config":{{"future":{nested}}}"#),
		));
	}
	for raw in cases {
		let expected = serde_json::from_str::<loupe_proto::LeaseResponse>(&raw);
		let (client, task) = response_encoded(raw.clone()).await;
		let result = client.lease(Vec::new(), 0).await;
		task.abort();
		assert_eq!(
			result.is_ok(),
			expected.is_ok(),
			"lease admission differs for {raw}: {result:?}; legacy {expected:?}"
		);
		if let (Ok(result), Ok(expected)) = (result, expected) {
			assert_eq!(
				serde_json::to_value(result).unwrap(),
				serde_json::to_value(expected).unwrap(),
				"lease value changed for {raw}"
			);
		}
	}
}
