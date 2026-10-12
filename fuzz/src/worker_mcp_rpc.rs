//! Stateful real request-loop coverage with a recording HTTP server and a
//! constant git fixture. Input: mode byte, then up to 32 JSON-RPC lines.
//! Mode bit 0 enables verify, bit 1 rejects git checks, bit 2 supplies UTF-8
//! stderr crossing byte 4096. The worktree and process arguments are fixed.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::response::IntoResponse;
use loupe_proto::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use loupe_worker::mcp::fuzz_support::FuzzSession;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;
use tracing_subscriber::layer::{Context, SubscriberExt};

use crate::utils::input::ByteSource;
use crate::utils::test_logger;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<LogEvent>>>);

#[derive(Default)]
struct LogEvent {
	message: String,
	fields: BTreeMap<String, String>,
}

impl tracing::field::Visit for LogEvent {
	fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
		if field.name() == "message" {
			self.message = format!("{value:?}");
		} else {
			self.fields.insert(field.name().into(), format!("{value:?}"));
		}
	}
	fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
		if field.name() == "message" {
			self.message = value.into();
		} else {
			self.fields.insert(field.name().into(), value.into());
		}
	}
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
	fn on_event(&self, event: &tracing::Event<'_>, _context: Context<'_, S>) {
		if event.metadata().target().starts_with("loupe_worker::mcp") {
			let mut recorded = LogEvent::default();
			event.record(&mut recorded);
			self.0.lock().unwrap_or_else(|e| e.into_inner()).push(recorded);
		}
	}
}

#[derive(Deserialize)]
struct Request {
	#[allow(dead_code)]
	jsonrpc: String,
	#[allow(dead_code)]
	id: Option<Value>,
	method: String,
	params: Option<Value>,
}

pub fn do_test(data: &[u8]) {
	let mut source = ByteSource::new(data);
	let mode = source.u8().unwrap_or_default();
	let verify = mode & 1 != 0;
	let rejects = mode & 2 != 0;
	let raw = source.rest();
	let raw = &raw[..raw.len().min(64 * 1024)];
	let text = String::from_utf8_lossy(raw);
	let lines: Vec<_> = text.lines().take(32).collect();
	let script = format!("{}\n", lines.join("\n"));
	let capture = Capture::default();
	let subscriber = tracing_subscriber::registry().with(capture.clone());
	let _guard = tracing::subscriber::set_default(subscriber);
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap_or_else(|e| panic!("runtime: {e}"));
	runtime.block_on(async {
		// The same bytes also reach the actual CLI pipe collector. Mode
		// bit 3 streams one MiB of padding without allocating that input.
		let padding = if mode & 8 != 0 { 1024 * 1024 } else { 0 };
		let reader = tokio::io::repeat(b'x').take(padding as u64).chain(raw);
		let (kept, truncated) = loupe_worker::llm::fuzz_collect_cli_output(reader)
			.await
			.unwrap_or_else(|e| panic!("CLI collector: {e}"));
		assert!(kept.len() <= 1024 * 1024);
		assert!(kept.capacity() <= 1024 * 1024);
		assert_eq!(truncated, padding + raw.len() > 1024 * 1024);
		if padding == 0 {
			assert_eq!(kept, raw);
		} else {
			assert!(kept.ends_with(raw));
		}
		let workdir = tempfile::tempdir().unwrap_or_else(|e| panic!("worktree: {e}"));
		std::fs::create_dir(workdir.path().join("src"))
			.unwrap_or_else(|e| panic!("source dir: {e}"));
		let source_text = "fn source() {}\n// second\n// third\n";
		std::fs::write(workdir.path().join("src/lib.rs"), source_text)
			.unwrap_or_else(|e| panic!("source: {e}"));
		let git = workdir.path().join("fuzz-git");
		let git_script = if rejects {
			"#!/bin/sh\ncat >/dev/null\ncat git-stderr >&2\nexit 1\n"
		} else {
			"#!/bin/sh\ncat >/dev/null\nexit 0\n"
		};
		std::fs::write(&git, git_script).unwrap_or_else(|e| panic!("git fixture: {e}"));
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o700))
				.unwrap_or_else(|e| panic!("git executable: {e}"));
		}
		let stderr = if mode & 4 != 0 {
			format!("{}€tail", "x".repeat(4095))
		} else {
			"fixture rejected diff".into()
		};
		std::fs::write(workdir.path().join("git-stderr"), &stderr)
			.unwrap_or_else(|e| panic!("stderr: {e}"));
		// Model every regular file in the fixture from its known contents,
		// independently of the production path and submission validators.
		let fixture_files = BTreeMap::from([
			("src/lib.rs", source_text.lines().count()),
			("fuzz-git", git_script.lines().count()),
			("git-stderr", stderr.lines().count()),
		]);
		#[cfg(unix)]
		let (_outside, fixture_files) = {
			let outside = tempfile::tempdir().unwrap_or_else(|e| panic!("outside: {e}"));
			std::fs::write(outside.path().join("file"), "outside\n")
				.unwrap_or_else(|e| panic!("outside source: {e}"));
			std::os::unix::fs::symlink("lib.rs", workdir.path().join("src/inside.rs"))
				.unwrap_or_else(|e| panic!("inside symlink: {e}"));
			std::os::unix::fs::symlink(
				outside.path().join("file"),
				workdir.path().join("src/outside.rs"),
			)
			.unwrap_or_else(|e| panic!("outside symlink: {e}"));
			let mut files = fixture_files;
			files.insert("src/inside.rs", source_text.lines().count());
			(outside, files)
		};
		let calls = Arc::new(Mutex::new(Vec::<(String, Value)>::new()));
		let recorded = calls.clone();
		let router = axum::Router::new().fallback(move |request: axum::extract::Request| {
			let recorded = recorded.clone();
			async move {
				let path = request.uri().path().to_owned();
				let bytes = axum::body::to_bytes(request.into_body(), 512 * 1024)
					.await
					.unwrap_or_else(|e| panic!("stub body: {e}"));
				let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
				recorded.lock().unwrap_or_else(|e| e.into_inner()).push((path.clone(), body));
				let reply = if path.ends_with("/search") {
					json!({"protocol_version":PROTOCOL_VERSION,"findings":[]})
				} else {
					json!({"protocol_version":PROTOCOL_VERSION,"id":1,"repo_id":1,"job_id":1,
						"scanner_id":"scanner","severity":"high","title":"fixture finding",
						"description":"fixture description","fingerprint":"abc","state":"validating",
						"verification_required":true,"created_at":1})
				};
				([(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string())], axum::Json(reply))
					.into_response()
			}
		});
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
			.await
			.unwrap_or_else(|e| panic!("listener: {e}"));
		let address = listener.local_addr().unwrap_or_else(|e| panic!("address: {e}"));
		let server = tokio::spawn(async move { axum::serve(listener, router).await });
		let client = loupe_worker::ServerClient::from_parts(
			reqwest::Client::new(),
			format!("http://{address}").parse().unwrap_or_else(|e| panic!("URL: {e}")),
		);
		let session = FuzzSession::new(Arc::new(client), workdir.path().to_owned(), verify);
		let outcome =
			tokio::time::timeout(std::time::Duration::from_secs(5), session.run(script.as_bytes()))
				.await
				.unwrap_or_else(|e| panic!("session timeout: {e}"));
		server.abort();
		let output =
			String::from_utf8(outcome.reply).unwrap_or_else(|e| panic!("reply UTF-8: {e}"));
		let mut responses = output.lines();
		let mut verdict = None;
		let mut patch = false;
		for line in lines.iter().filter(|line| !line.trim().is_empty()) {
			let request = crate::worker_mcp_ingress::oracle::request(line);
			if request.as_ref().is_ok_and(|req| req.id.is_none()) {
				continue;
			}
			let reply: Value =
				serde_json::from_str(responses.next().unwrap_or_else(|| panic!("missing reply")))
					.unwrap_or_else(|e| panic!("reply JSON: {e}"));
			let Ok(request) = request else {
				assert_eq!(reply["id"], Value::Null);
				assert_eq!(reply["error"]["code"], -32700);
				continue;
			};
			assert_eq!(Some(&reply["id"]), request.id.as_ref());
			if request.method == "tools/call" && request.arguments.is_err() {
				assert_eq!(
					reply["result"]["isError"], true,
					"invalid original fields reached tool dispatch"
				);
				continue;
			}
			let request: Request = serde_json::from_str(line)
				.unwrap_or_else(|error| panic!("admitted original record: {error}"));
			match request.method.as_str() {
				"initialize" | "ping" | "notifications/initialized" => {
					assert!(reply.get("result").is_some())
				},
				"tools/list" => {
					let tools =
						reply["result"]["tools"].as_array().unwrap_or_else(|| panic!("catalogue"));
					let names: Vec<_> =
						tools.iter().filter_map(|tool| tool["name"].as_str()).collect();
					let expected = if verify {
						vec![
							"query_prior_findings",
							"get_finding_by_id",
							"submit_verdict",
							"submit_patch",
							"validate_patch",
						]
					} else {
						vec![
							"query_prior_findings",
							"get_finding_by_id",
							"submit_finding",
							"validate_poc",
						]
					};
					assert_eq!(names.len(), expected.len());
					assert!(expected.iter().all(|name| names.contains(name)));
				},
				"tools/call" => check_tool(
					&request.params.unwrap_or(Value::Null),
					&reply,
					verify,
					rejects,
					&fixture_files,
					&mut verdict,
					&mut patch,
				),
				_ => assert_eq!(reply["error"]["code"], -32601),
			}
		}
		assert!(responses.next().is_none());
		assert_eq!(outcome.verdict, verdict);
		assert_eq!(outcome.patch, patch);
		assert_eq!(outcome.completed, !verify || verdict.is_some());
		let recorded = calls.lock().unwrap_or_else(|e| e.into_inner());
		let verdict_posts = recorded.iter().filter(|(path, _)| path.ends_with("/verdict")).count();
		assert_eq!(verdict_posts, usize::from(verify && verdict.is_some()));
	});
	let captured = capture.0.lock().unwrap_or_else(|e| e.into_inner());
	let received =
		captured.iter().filter(|event| event.message == "loupe-mcp: received request").count();
	assert_eq!(received, lines.iter().filter(|line| !line.trim().is_empty()).count());
	// Independent of responses: every log event must match its exact static
	// schema. This also catches a leaked copy of text equal to static metadata.
	for event in captured.iter() {
		assert_log_schema(event);
		for line in &lines {
			if let Ok(value) = serde_json::from_str::<Value>(line) {
				for field in event.fields.values() {
					assert_no_strings_in_logs(&value, field.as_bytes());
				}
			}
		}
	}
}

fn assert_log_schema(event: &LogEvent) {
	let mut expected = match event.message.as_str() {
		"loupe-mcp: received request" => vec!["method", "line_bytes"],
		"loupe-mcp: sending response" => vec!["response_bytes"],
		"loupe-mcp: tool call failed" => vec!["tool"],
		"loupe-mcp: agent submitted a finding" => vec!["job_id", "repo_id"],
		"loupe-mcp: agent submitted verify verdict" => vec!["finding_id", "verdict"],
		"loupe-mcp: agent submitted verifier patch" => vec!["finding_id"],
		"loupe-mcp: flushing verify session verdict" => vec!["finding_id", "job_id"],
		"fingerprint: could not read worktree file; falling back to line-range-only window" => {
			vec!["error_kind"]
		},
		_ => panic!("unexpected MCP log message"),
	};
	expected.sort_unstable();
	assert_eq!(event.fields.keys().map(String::as_str).collect::<Vec<_>>(), expected);
	for (key, value) in &event.fields {
		match key.as_str() {
			"method" => assert!([
				"initialize",
				"tools/list",
				"tools/call",
				"notifications/initialized",
				"ping",
				"invalid",
				"unknown"
			]
			.contains(&value.as_str())),
			"tool" => assert!([
				"query_prior_findings",
				"get_finding_by_id",
				"submit_finding",
				"validate_poc",
				"submit_verdict",
				"submit_patch",
				"validate_patch",
				"unknown"
			]
			.contains(&value.as_str())),
			"verdict" => {
				assert!(["confirmed", "dismissed", "inconclusive"].contains(&value.as_str()))
			},
			"line_bytes" | "response_bytes" => assert!(value.parse::<usize>().is_ok()),
			"error_kind" => {
				assert!(!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_alphabetic()))
			},
			_ => assert_eq!(value, "1"),
		}
	}
}

fn check_tool(
	params: &Value, reply: &Value, verify: bool, rejects: bool,
	fixture_files: &BTreeMap<&str, usize>, verdict: &mut Option<&'static str>, patch: &mut bool,
) {
	let name = params["name"].as_str().unwrap_or("");
	let args = &params["arguments"];
	let failed = reply["result"]["isError"] == true;
	if !crate::worker_mcp_ingress::oracle::arguments_admitted(name, args) {
		assert!(failed);
		return;
	}
	let string = |key: &str| args[key].as_str();
	match name {
		"query_prior_findings" => assert_eq!(failed, string("query").is_none()),
		"get_finding_by_id" => {
			let value = &args["id"];
			let id = value.as_i64().filter(|id| *id > 0).or_else(|| {
				let text = value.as_str()?.strip_prefix("LUP-")?;
				if text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
					return None;
				}
				text.parse::<i64>().ok().filter(|id| *id > 0)
			});
			assert_eq!(failed, id.is_none());
		},
		"validate_poc" | "validate_patch" => {
			let field = if name == "validate_poc" { "poc_unified" } else { "patch_unified" };
			assert_eq!(failed, string(field).is_none());
			if !failed {
				let text = reply["result"]["content"][0]["text"].as_str().unwrap_or("");
				let value: Value =
					serde_json::from_str(text).unwrap_or_else(|e| panic!("diff result: {e}"));
				assert_eq!(value["applies"], !rejects);
			}
		},
		"submit_verdict" => {
			let kind = match string("verdict") {
				Some("confirmed") => Some("confirmed"),
				Some("dismissed") => Some("dismissed"),
				Some("inconclusive") => Some("inconclusive"),
				_ => None,
			};
			let accepted =
				verify && verdict.is_none() && kind.is_some() && string("notes").is_some();
			assert_eq!(failed, !accepted);
			if accepted {
				*verdict = kind;
			}
		},
		"submit_patch" => {
			let within_budget = string("patch_unified")
				.is_some_and(|text| text.chars().count() + "fixture description".len() <= 60_000);
			let accepted = verify
				&& *verdict == Some("confirmed")
				&& !*patch
				&& string("notes").is_some()
				&& within_budget
				&& !rejects;
			assert_eq!(failed, !accepted);
			if accepted {
				*patch = true;
			}
		},
		"submit_finding" => {
			assert_eq!(
				failed,
				!finding_admitted(args, rejects, fixture_files),
				"finding admission differs for file={} range={}..={}",
				args["file"],
				args["line_start"],
				args["line_end"]
			);
		},
		_ => assert!(failed),
	}
}

fn finding_admitted(args: &Value, rejects: bool, fixture_files: &BTreeMap<&str, usize>) -> bool {
	if rejects
		|| !matches!(
			args["severity"].as_str(),
			Some("info" | "low" | "medium" | "high" | "critical")
		) {
		return false;
	}
	let (Some(file), Some(title), Some(description), Some(poc)) = (
		args["file"].as_str(),
		args["title"].as_str(),
		args["description"].as_str(),
		args["poc_unified"].as_str(),
	) else {
		return false;
	};
	let (Some(start), Some(end)) = (args["line_start"].as_u64(), args["line_end"].as_u64()) else {
		return false;
	};
	let relative = file.strip_prefix("/workdir/").unwrap_or(file);
	let parts: Vec<_> =
		relative.split('/').filter(|part| !part.is_empty() && *part != ".").collect();
	if relative.starts_with('/') || parts.contains(&"..") {
		return false;
	}
	// Only known regular files and the internal symlink can be admitted.
	// Missing paths, directories and the external symlink are absent.
	let Some(&line_count) = fixture_files.get(parts.join("/").as_str()) else {
		return false;
	};
	if start == 0 || end < start || end > line_count as u64 {
		return false;
	}
	if !(8..=100).contains(&title.trim().chars().count())
		|| !(80..=16_384).contains(&description.trim().chars().count())
		|| description.chars().count() + poc.chars().count() > 60_000
		|| poc.len() > 256 * 1024
	{
		return false;
	}
	if let Some(cwe) = args["cwe"].as_str().filter(|text| !text.is_empty()) {
		let Some(digits) = cwe.strip_prefix("CWE-") else { return false };
		if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
			return false;
		}
	}
	// Headers must precede the first hunk; a later nonblank addition is
	// required. The fixed git command independently decides applicability.
	let lines: Vec<_> = poc.lines().collect();
	let Some(first_hunk) = lines.iter().position(|line| line.starts_with("@@ ")) else {
		return false;
	};
	lines[..first_hunk].iter().any(|line| line.starts_with("--- "))
		&& lines[..first_hunk].iter().any(|line| line.starts_with("+++ "))
		&& lines[first_hunk + 1..].iter().any(|line| {
			!line.starts_with("+++")
				&& line.strip_prefix('+').is_some_and(|addition| !addition.trim().is_empty())
		})
}

fn assert_no_strings_in_logs(value: &Value, logs: &[u8]) {
	match value {
		Value::String(text) if text.len() >= 40 => {
			for window in text.as_bytes().windows(40) {
				assert!(
					!logs.windows(40).any(|logged| logged == window),
					"sandbox text leaked to MCP logs"
				);
			}
		},
		Value::Array(values) => {
			for value in values {
				assert_no_strings_in_logs(value, logs);
			}
		},
		Value::Object(values) => {
			for value in values.values() {
				assert_no_strings_in_logs(value, logs);
			}
		},
		_ => {},
	}
}

pub fn worker_mcp_rpc_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes during the call.
#[allow(unsafe_code)] // C fuzz entry point.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_mcp_rpc_run(data: *const u8, datalen: usize) {
	// SAFETY: supplied by the caller as documented above.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	#[should_panic]
	fn log_oracle_rejects_payload_equal_to_a_static_message() {
		let event = LogEvent {
			message: "loupe-mcp: received request".into(),
			fields: BTreeMap::from([
				("method".into(), "unknown".into()),
				("line_bytes".into(), "100".into()),
				("request".into(), "loupe-mcp: received request".into()),
			]),
		};
		assert_log_schema(&event);
	}
}
