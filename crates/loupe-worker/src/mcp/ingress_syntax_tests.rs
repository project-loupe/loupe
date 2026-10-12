//! Actual stream transport controls for syntax versus new field-policy failures.
use super::*;

fn context(workdir: &Path) -> McpSessionContext {
	McpSessionContext {
		client: Arc::new(ServerClient::from_parts(
			reqwest::Client::new(),
			"http://127.0.0.1:1/".parse().unwrap(),
		)),
		job_capability: JobCapability::from_secret("syntax-fixture-capability"),
		repo_id: 1,
		job_id: Some(1),
		finding_id: None,
		workdir: workdir.to_owned(),
	}
}

async fn stream_output(record: String) -> Vec<u8> {
	let workdir = tempfile::tempdir().unwrap();
	let mut output = Vec::new();
	run_stream_server(context(workdir.path()), record.as_bytes(), &mut output).await.unwrap();
	output
}

async fn response(record: String) -> Value {
	serde_json::from_slice(&stream_output(record).await).unwrap()
}

fn verdict(notes_token: &str) -> String {
	format!(
		r#"{{"jsonrpc":"2.0","id":73,"method":"tools/call","params":{{"name":"submit_verdict","arguments":{{"verdict":"confirmed","notes":{notes_token}}}}}}}
"#
	)
}

fn assert_parse_error(reply: &Value) {
	assert_eq!(
		reply["error"]["code"], -32700,
		"JSON syntax must retain JSON-RPC parse error; reply={reply}"
	);
	assert!(reply["id"].is_null(), "syntax failure must discard request id");
	assert!(reply.get("result").is_none(), "syntax failure cannot be a tool result");
}

#[tokio::test]
async fn selected_lone_high_surrogate_is_null_id_parse_error() {
	assert_parse_error(&response(verdict(r#""\uD800""#)).await);
}

#[tokio::test]
async fn selected_lone_low_surrogate_is_null_id_parse_error() {
	assert_parse_error(&response(verdict(r#""\uDC00""#)).await);
}

#[tokio::test]
async fn selected_non_low_surrogate_pair_is_null_id_parse_error() {
	assert_parse_error(&response(verdict(r#""\uD800\u0041""#)).await);
}

#[tokio::test]
async fn selected_path_syntax_uses_null_id_parse_error() {
	for token in [r#""\uD800""#, r#""\uDC00""#, r#""\uD800\u0041""#] {
		let record = format!(
			r#"{{"jsonrpc":"2.0","id":73,"method":"tools/call","params":{{"name":"submit_finding","arguments":{{"severity":"high","title":"safe","file":{token},"line_start":1,"line_end":1,"description":"safe","poc_unified":""}}}}}}"#
		);
		assert_parse_error(&response(record).await);
	}
}

#[tokio::test]
async fn selected_reference_syntax_uses_null_id_parse_error() {
	for token in [r#""\uD800""#, r#""\uDC00""#, r#""\uD800\u0041""#] {
		let record = format!(
			r#"{{"jsonrpc":"2.0","id":73,"method":"tools/call","params":{{"name":"get_finding_by_id","arguments":{{"id":{token}}}}}}}"#
		);
		assert_parse_error(&response(record).await);
	}
}

#[tokio::test]
async fn valid_surrogate_pair_reaches_ordinary_tool_handler() {
	let reply = response(verdict(r#""\uD83D\uDE00""#)).await;
	assert_eq!(reply["id"], 73);
	assert!(reply.get("error").is_none());
	assert_eq!(reply["result"]["isError"], true);
	assert!(
		reply["result"]["content"][0]["text"]
			.as_str()
			.unwrap()
			.contains("server is in discovery mode"),
		"valid pair must reach the real tool handler; reply={reply}"
	);
}

#[tokio::test]
async fn selected_control_is_id_preserving_tool_error() {
	let reply = response(verdict(r#""\u0001""#)).await;
	assert_eq!(reply["id"], 73);
	assert!(reply.get("error").is_none());
	assert_eq!(reply["result"]["isError"], true);
	assert!(
		!reply["result"]["content"][0]["text"]
			.as_str()
			.unwrap()
			.contains("server is in discovery mode"),
		"new field policy rejection must precede tool dispatch"
	);
}

#[tokio::test]
async fn selected_overcap_escaped_text_is_id_preserving_tool_error() {
	let token = format!("\"{}\"", "\\u0020".repeat(2 * 1024 * 1024 + 1));
	let record = verdict(&token);
	assert!(record.len() < 16 * 1024 * 1024);
	let reply = response(record).await;
	assert_eq!(reply["id"], 73);
	assert!(reply.get("error").is_none());
	assert_eq!(reply["result"]["isError"], true);
	assert!(
		!reply["result"]["content"][0]["text"]
			.as_str()
			.unwrap()
			.contains("server is in discovery mode"),
		"new cap rejection must precede tool dispatch"
	);
}

#[tokio::test]
async fn unused_lone_surrogate_is_null_id_parse_error() {
	let reply = response(
		concat!(
			r#"{"jsonrpc":"2.0","id":73,"method":"initialize","params":{"unused":"\uD800"}}"#,
			"\n"
		)
		.to_owned(),
	)
	.await;
	assert_eq!(reply["error"]["code"], -32700);
	assert!(reply["id"].is_null());
	assert!(reply.get("result").is_none());
}

#[tokio::test]
async fn admitted_notes_reach_verdict_http_unchanged() {
	for (token, expected) in [
		(r#""\uD83D\uDE00""#, "😀"),
		(r#"" ordinary cafe\u0301\r\n\t ""#, " ordinary cafe\u{301}\r\n\t "),
	] {
		let seen = Arc::new(std::sync::Mutex::new(None));
		let captured = seen.clone();
		let app =
			axum::Router::new().fallback(move |axum::Json(body): axum::Json<Value>| async move {
				*captured.lock().unwrap() = Some(body);
				(
					[(loupe_proto::PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string())],
					axum::Json(json!({})),
				)
			});
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let url = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
		let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
		let workdir = tempfile::tempdir().unwrap();
		let mut context = context(workdir.path());
		context.client = Arc::new(ServerClient::from_parts(reqwest::Client::new(), url));
		context.finding_id = Some(1);
		let record = verdict(token);
		let mut output = Vec::new();
		run_stream_server(context, record.as_bytes(), &mut output).await.unwrap();
		server.abort();
		let reply: Value = serde_json::from_slice(&output).unwrap();
		assert_eq!(reply["id"], 73);
		assert!(reply.get("error").is_none());
		assert!(reply["result"].get("isError").is_none());
		assert!(reply["result"]["content"][0]["text"]
			.as_str()
			.unwrap()
			.starts_with("Verdict locked: confirmed."));
		let captured = seen.lock().unwrap().take().expect("real verdict POST");
		assert_eq!(
			captured["verdict"]["notes"], expected,
			"admitted notes changed at HTTP submission"
		);
	}
}

#[tokio::test]
async fn malformed_tokens_keep_record_errors_in_all_protocol_contexts() {
	for token in [r#""\q""#, r#""\u12G4""#, r#""\uD800""#] {
		for (method, id) in [
			("tools/call", r#""id":73,"#),
			("ping", r#""id":73,"#),
			("initialize", r#""id":73,"#),
			("tools/call", ""),
		] {
			let record = format!(
				r#"{{"jsonrpc":"2.0",{id}"method":"{method}","params":{{"name":"submit_verdict","arguments":{{"verdict":"confirmed","notes":{token}}}}}}}"#
			);
			assert_parse_error(&response(record).await);
		}
		let unused = format!(
			r#"{{"jsonrpc":"2.0","id":73,"method":"tools/call","params":{{"name":"submit_verdict","arguments":{{"verdict":"confirmed","notes":"safe","unused":{token}}}}}}}"#
		);
		assert_parse_error(&response(unused).await);
	}
}

#[tokio::test]
async fn cap_rejection_precedes_late_unicode_syntax_and_overflow() {
	let notes = "\\u0061".repeat(2 * 1024 * 1024 + 1);
	let record = format!(
		r#"{{"jsonrpc":"2.0","id":73,"method":"tools/call","params":{{"name":"submit_verdict","arguments":{{"verdict":"confirmed","notes":"{notes}\uD800","later":1e400}}}}}}"#
	);
	assert!(record.len() < 16 * 1024 * 1024);
	let reply = response(record).await;
	assert_eq!(reply["id"], 73);
	assert!(
		reply.get("error").is_none(),
		"over-cap preflight must precede later malformed Unicode"
	);
	assert_eq!(reply["result"]["isError"], true);
	assert_eq!(reply["result"]["content"][0]["text"], "Error: verdict_notes: Bytes");
}

#[tokio::test]
async fn admitted_fields_keep_original_params_depth() {
	for depth in 120..130 {
		let nested = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
		let record = format!(
			r#"{{"jsonrpc":"2.0","id":73,"method":"tools/call","params":{{"name":"submit_verdict","arguments":{{"verdict":"confirmed","notes":"safe","unused":{nested}}}}}}}"#
		);
		let legacy = serde_json::from_str::<Request>(&record);
		let reply = response(record).await;
		assert_eq!(reply.get("error").is_none(), legacy.is_ok(), "original params depth {depth}");
		if legacy.is_ok() {
			assert_eq!(reply["id"], 73);
			assert!(reply["result"]["content"][0]["text"]
				.as_str()
				.unwrap()
				.contains("server is in discovery mode"));
		} else {
			assert_parse_error(&reply);
		}
	}
}

#[tokio::test]
async fn valid_unknown_fields_positional_params_and_notifications_stay_admitted() {
	for params in
		[r#"{"unused":"\uD83D\uDE00","nested":[1,null,true]}"#, r#"["\uD83D\uDE00",1,null]"#]
	{
		let record =
			format!(r#"{{"jsonrpc":"unchecked","id":73,"method":"ping","params":{params}}}"#);
		assert_eq!(response(record).await, json!({"jsonrpc":"2.0","id":73,"result":{}}));
	}
	let notification = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"submit_verdict","arguments":{"verdict":"confirmed","notes":"safe"}}}"#;
	assert!(stream_output(notification.to_owned()).await.is_empty());
}

#[tokio::test]
async fn syntax_errors_are_closed_while_unknown_tool_names_keep_sender_echo() {
	let marker = "private-syntax-marker-219da7";
	let record = verdict(&format!(r#""{marker}\uD800""#));
	let reply = response(record).await;
	assert_parse_error(&reply);
	assert!(!reply.to_string().contains(marker), "syntax response reflected source text");
	assert!(reply["error"]["message"]
		.as_str()
		.unwrap()
		.starts_with("parse error: invalid JSON syntax at line "));
	let record = format!(
		r#"{{"jsonrpc":"2.0","id":73,"method":"tools/call","params":{{"name":"{marker}","arguments":{{}}}}}}"#
	);
	let reply = response(record).await;
	assert_eq!(reply["id"], 73);
	assert_eq!(reply["result"]["content"][0]["text"], format!("Error: unknown tool: {marker}"));
}
