//! Exact source quotation controls through the actual MCP stream and POST owner.
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

#[tokio::test]
async fn citation_special_file_refusal_does_not_wait_for_a_fifo_writer() {
	let (workdir, submission) = super::tests::valid_local_submission();
	let path = workdir.path().join(submission.file_path.expose());
	std::fs::remove_file(&path).unwrap();
	rustix::fs::mkfifoat(rustix::fs::CWD, &path, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)
		.unwrap();
	let root = workdir.path().to_owned();
	let mut task = tokio::spawn(async move {
		validate_local_llm_submission(&root, &submission, Default::default()).await
	});
	let (refused_without_writer, result) =
		match tokio::time::timeout(std::time::Duration::from_millis(500), &mut task).await {
			Ok(result) => (true, result.unwrap()),
			Err(_) => {
				// Release a blocked open before asserting so a failure cannot hang the test.
				let writer =
					std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
				let result = task.await.unwrap();
				drop(writer);
				(false, result)
			},
		};
	assert!(
		refused_without_writer,
		"citation regular-file admission must not block opening a FIFO while waiting for a writer"
	);
	assert!(matches!(
		result.unwrap_err().downcast_ref::<citation::CitationError>(),
		Some(citation::CitationError::NotRegular)
	));
}

async fn quoted_submission(quote: &str) -> (usize, Value) {
	let calls = Arc::new(AtomicUsize::new(0));
	let seen = calls.clone();
	let app = axum::Router::new().route(
		"/v1/jobs/42/llm-findings",
		axum::routing::post(move || {
			let seen = seen.clone();
			async move {
				seen.fetch_add(1, Ordering::SeqCst);
				(
					[(
						loupe_proto::PROTOCOL_VERSION_HEADER,
						loupe_proto::PROTOCOL_VERSION.to_string(),
					)],
					axum::Json(json!({})),
				)
			}
		}),
	);
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let base = format!("http://{}", listener.local_addr().unwrap());
	let stub = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	let (workdir, submission) = super::tests::valid_local_submission();
	let mut args = serde_json::to_value(&submission).unwrap();
	args["protocol_version"] = json!(LOUPE_MCP_PROTOCOL_VERSION);
	args["file"] = json!(submission.file_path.expose());
	args["description"] = json!(format!("An attacker reaches this operation and terminates the service.\n```rust\n{quote}\n```\nThe supplied PoC demonstrates this impact."));
	let input = format!(
		"{}\n",
		json!({"jsonrpc":"2.0","id":71,"method":"tools/call",
		"params":{"name":"submit_finding","arguments":args}})
	);
	let mut output = Vec::new();
	run_stream_server(
		McpSessionContext {
			security: crate::canary::JobSecurity::new(Default::default(), Vec::new()).unwrap(),
			tool_boundary: crate::llm::prompt::JobToolBoundary::new().unwrap(),
			client: Arc::new(ServerClient::from_parts(
				reqwest::Client::new(),
				base.parse().unwrap(),
			)),
			job_capability: JobCapability::from_secret("citation-test-capability"),
			repo_id: 1,
			job_id: Some(42),
			finding_id: None,
			workdir: workdir.path().to_owned(),
		},
		input.as_bytes(),
		&mut output,
	)
	.await
	.unwrap();
	stub.abort();
	let _ = stub.await;
	(calls.load(Ordering::SeqCst), serde_json::from_slice(&output).unwrap())
}

#[tokio::test]
async fn s3_sandbox_invented_fenced_quote_never_reaches_the_server() {
	let (calls, response) =
		quoted_submission("fn fabricated_private_quote() { secret_operation(); }").await;
	assert_eq!(calls, 0, "invented fenced source must be refused before a finding POST");
	assert_eq!(response["id"], 71);
	assert_eq!(response["result"]["isError"], true);
}

#[tokio::test]
async fn s3_sandbox_exact_fenced_quote_keeps_the_existing_submission() {
	let (calls, response) = quoted_submission("fn vulnerable() {}").await;
	assert_eq!(calls, 1, "an exact in-range quote with applying PoC must reach the server");
	assert_eq!(response["id"], 71);
	assert!(response.get("error").is_none());
	assert!(response["result"].get("isError").is_none());
	assert!(response["result"]["content"][0]["text"]
		.as_str()
		.unwrap()
		.starts_with("Submitted. job=42 fingerprint="));
}

async fn local(source: &[u8], description: &str, start: u32, end: u32) -> Result<()> {
	let (workdir, submission) = super::tests::valid_local_submission();
	std::fs::write(workdir.path().join("src/lib.rs"), source).unwrap();
	let mut args = serde_json::to_value(submission).unwrap();
	args["protocol_version"] = json!(LOUPE_MCP_PROTOCOL_VERSION);
	args["file"] = json!("src/lib.rs");
	args["description"] = json!(format!("An attacker-controlled request reaches this operation without validation and terminates the service.\n{description}"));
	args["line_start"] = json!(start);
	args["line_end"] = json!(end);
	args["poc_unified"] = json!("--- /dev/null\n+++ b/citation_regression.rs\n@@ -0,0 +1 @@\n+#[test] fn demonstrates_failure() {}\n");
	let submission = build_finding_from_args(workdir.path(), &args).unwrap();
	assert!(
		matches!(
			check_diff_applies(workdir.path(), AgentDiff::Poc(&submission.poc_unified))
				.await
				.unwrap(),
			DiffCheck::Applies
		),
		"every citation fixture must have an independently applying PoC"
	);
	validate_local_llm_submission(workdir.path(), &submission, Default::default()).await.map(|_| ())
}

macro_rules! quote_refusal {
	($name:ident, $source:expr, $quote:expr, $start:expr, $end:expr) => {
		#[tokio::test]
		async fn $name() {
			let result = local($source, $quote, $start, $end).await;
			assert!(
				result.is_err(),
				"citation claim must be refused before its otherwise valid PoC"
			);
			assert_eq!(result.unwrap_err().to_string(), "citation_quote_mismatch");
		}
	};
}
quote_refusal!(
	quote_outside_selected_range_is_refused,
	b"fn vulnerable() {}\noutside-quote\n",
	"```\noutside-quote\n```",
	1,
	1
);
quote_refusal!(empty_claimed_fence_is_refused, b"fn vulnerable() {}\n", "```\n```", 1, 1);
quote_refusal!(
	unterminated_claimed_fence_is_refused,
	b"fn vulnerable() {}\n",
	"```\nfn vulnerable() {}",
	1,
	1
);
quote_refusal!(
	normalized_crlf_quote_is_refused,
	b"fn vulnerable() {}\na\r\nb\r\n",
	"```\na\nb\n```",
	2,
	3
);
quote_refusal!(
	normalized_nfd_quote_is_refused,
	"fn vulnerable() {}\ncafe\u{301}\n".as_bytes(),
	"```\ncafé\n```",
	2,
	2
);
quote_refusal!(
	short_closing_fence_is_not_a_close,
	b"fn vulnerable() {}\n",
	"````\nfn vulnerable() {}\n```",
	1,
	1
);

#[tokio::test]
async fn exact_fence_grammar_preserves_existing_positive_submissions() {
	for (source, quote, start, end) in [
		(b"fn vulnerable() {}\n".as_slice(), "   ~~~rust\nfn vulnerable() {}\n  ~~~~  \n", 1, 1),
		(b"fn vulnerable() {}\na\r\nb\r\n", "```\r\na\r\nb\r\n```\r\n", 2, 3),
		(
			"fn vulnerable() {}\ncafe\u{301}\n".as_bytes(),
			"```\ncafe\u{301}\n```\n~~~\nfn vulnerable() {}\n~~~\n",
			1,
			2,
		),
		(b"fn vulnerable() {}", "```\nfn vulnerable() {}\n```", 1, 1),
		(b"fn vulnerable() {}\n", "Ordinary prose has no source quote obligation.", 1, 1),
	] {
		local(source, quote, start, end).await.unwrap();
	}
}

#[tokio::test]
async fn existing_citation_path_failure_has_a_fixed_content_free_error() {
	let (workdir, submission) = super::tests::valid_local_submission();
	let mut args = serde_json::to_value(submission).unwrap();
	args["protocol_version"] = json!(LOUPE_MCP_PROTOCOL_VERSION);
	args["file"] = json!("private-path-sentinel.rs");
	let submission = build_finding_from_args(workdir.path(), &args).unwrap();
	let error = validate_local_llm_submission(workdir.path(), &submission, Default::default())
		.await
		.unwrap_err();
	assert!(
		!format!("{error:#}").contains("private-path-sentinel"),
		"path content must not reach the public failure chain"
	);
	assert_eq!(error.to_string(), "citation_missing_file");
}

#[test]
fn prechange_fingerprint_goldens_cover_unicode_and_window_boundaries() {
	let fixtures = [
		"  fn Vulnerable() {}\r\n\n  next   token\nend\n",
		"ΟΣ ΑΣ\nAΣ'\u{301}A AΣ'\u{301}.\nΣΣ Σ\n",
		"\n\tcafe\u{301}\u{a0}İ K 𐐀\n\u{345}Σ\u{345}A\nlast",
		"",
		"x",
		"\r\n",
		"\r",
	];
	let workdir = tempfile::tempdir().unwrap();
	for (index, source) in fixtures.iter().enumerate() {
		std::fs::write(workdir.path().join("source.rs"), source).unwrap();
		for (start, end) in [(1, 1), (2, 3), (1, 8), (99, 100)] {
			let actual = fingerprint_for(workdir.path(), "source.rs", start, end);
			let expected = crate::fingerprint::compute(
				SCANNER_ID,
				"source.rs",
				&crate::fingerprint::extract_window(source, start, end, FINGERPRINT_CONTEXT_LINES),
			);
			assert_eq!(actual.for_submission(), expected);
			eprintln!("fixture={index} range={start}:{end} hash={expected}");
		}
	}
}
