//! MCP server exposed to the agent (`claude` and friends) for the
//! duration of one scan session over one source file.
//!
//! Wire shape: JSON-RPC 2.0 over stdio. The agent is the JSON-RPC
//! client; this module is the server. We hand-roll the protocol to
//! avoid taking a third-party MCP dep — the surface we use is small
//! (`initialize`, `tools/list`, `tools/call`).
//!
//! Tools currently exposed:
//!
//! - `query_prior_findings(query, limit?)` — FTS5 keyword search
//!   over the repo's accumulated findings. Backed by
//!   `loupe-server`'s `GET /v1/repos/{repo_id}/findings/search`
//!   endpoint via the worker's mTLS client cert. The MCP server is
//!   spawned per `claude` invocation by the worker, with the
//!   `repo_id` baked in as a CLI arg, so the tool doesn't need to
//!   take it as a parameter.
//! - `get_finding_by_id(id)` — full detail view for one finding.
//!   Used after `query_prior_findings` returns a summary and the
//!   model wants to see the description / PoC of a hit before
//!   deciding whether the new finding is a duplicate.
//! - `submit_finding(severity, title, file, line_start, line_end,
//!   description, poc_unified, cwe?)` — the agent's only path for
//!   reporting a vulnerability. Computes the fingerprint server-
//!   side (reading the source window from `--workdir`) and POSTs
//!   to `/v1/jobs/{job_id}/findings`. Only registered when the
//!   worker passed `--job-id` at MCP-server start; without a job
//!   id, there's nowhere to attribute submissions to.
//! - `validate_poc(poc_unified)` — pre-flight check for the PoC
//!   diff the agent is about to attach to a `submit_finding` call.
//!   Runs `git apply --check` against the worktree (`--workdir`)
//!   without writing anything; returns `{applies, error?}`. Use it
//!   to catch path drift, fuzzy-context failures, and malformed
//!   diff hunks before submission so we don't store a finding whose
//!   "regression test" doesn't actually apply.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result};
use loupe_core::{Finding, Severity};
use loupe_proto::{FindingsBatch, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;

use crate::scanners::llm_code_review::SCANNER_ID;
use crate::ServerClient;

/// Identity emitted on `initialize`. The version is the loupe-worker
/// build's protocol intent, not a release version — bumping it is a
/// signal to the agent that the tool surface changed.
const SERVER_NAME: &str = "loupe-mcp";
const SERVER_VERSION: &str = "0.1.0";

/// How many lines of context to take on each side of the bug-line
/// range when computing the fingerprint window. Two lines is enough
/// to keep the hash stable across `cargo fmt`-style reflows while
/// staying narrow enough that touching the bug body shifts it.
const FINGERPRINT_CONTEXT_LINES: u32 = 2;

/// Pull a required string argument out of an MCP `tools/call` payload.
/// Compresses the `args.get(k).and_then(as_str).context(...)` triplet
/// repeated across every tool handler.
fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
	args.get(key)
		.and_then(|v| v.as_str())
		.with_context(|| format!("`{key}` argument is required and must be a string"))
}

/// Pull a required positive `u32` argument out of an MCP `tools/call`
/// payload. Saturates at `u32::MAX` so a model that emits an absurdly
/// large line number doesn't poison downstream arithmetic — line
/// counts are 1-indexed and capped well below 4 billion in any real
/// source file.
fn arg_u32(args: &Value, key: &str) -> Result<u32> {
	let v = args
		.get(key)
		.and_then(|v| v.as_u64())
		.with_context(|| format!("`{key}` argument is required and must be a positive integer"))?;
	Ok(v.min(u32::MAX as u64) as u32)
}

/// Format a finding's location as `path:line[-end]` for human display
/// in MCP tool text output. Used for both `query_prior_findings`
/// summaries (which lack `line_end`) and `get_finding_by_id` detail
/// views — `line_end` is only rendered when it strictly exceeds
/// `line_start` to keep "1:5-5" out of the output.
fn format_location(path: Option<&str>, line_start: Option<u32>, line_end: Option<u32>) -> String {
	match (path, line_start, line_end) {
		(Some(p), Some(s), Some(e)) if e > s => format!("{p}:{s}-{e}"),
		(Some(p), Some(s), _) => format!("{p}:{s}"),
		(Some(p), None, _) => p.to_owned(),
		_ => "(no location)".into(),
	}
}

/// Per-call session state that flows into every tool handler. Built
/// once at `run_stdio_server` start from CLI args; never mutated.
struct Session {
	client: Arc<ServerClient>,
	repo_id: i64,
	/// Job id the agent is reporting findings against. `None` means
	/// `submit_finding` is unavailable — the MCP server is in
	/// read-only mode (e.g. a future read-only diagnostic flow).
	job_id: Option<i64>,
	/// Worktree the agent is reasoning over. Used to read source
	/// files for fingerprint window extraction in `submit_finding`.
	/// Inside the bwrap sandbox this is `/workdir`; bare-mode
	/// (`LOUPE_DISABLE_SANDBOX`) runs use the host worktree path.
	workdir: PathBuf,
}

/// JSON-RPC 2.0 envelope shapes. Kept small — we don't need batch
/// requests, notifications-with-body, or any of the optional MCP
/// surface beyond the three methods above.
#[derive(Debug, Deserialize)]
struct Request {
	#[allow(dead_code)]
	jsonrpc: String,
	#[serde(default)]
	id: Option<Value>,
	method: String,
	#[serde(default)]
	params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct Response {
	jsonrpc: &'static str,
	id: Value,
	#[serde(skip_serializing_if = "Option::is_none")]
	result: Option<Value>,
	#[serde(skip_serializing_if = "Option::is_none")]
	error: Option<RpcError>,
}

impl Response {
	fn ok(id: Value, result: Value) -> Self {
		Self { jsonrpc: "2.0", id, result: Some(result), error: None }
	}

	fn err(id: Value, code: i64, message: impl Into<String>) -> Self {
		Self {
			jsonrpc: "2.0",
			id,
			result: None,
			error: Some(RpcError { code, message: message.into(), data: None }),
		}
	}
}

#[derive(Debug, Serialize)]
struct RpcError {
	code: i64,
	message: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	data: Option<Value>,
}

/// Run the MCP server against `client` until stdin closes.
///
/// `repo_id` scopes search/lookup tools to this repo. `job_id`, when
/// `Some`, enables `submit_finding` — submissions POST to
/// `/v1/jobs/{job_id}/findings`. `workdir` is the path the agent's
/// file references resolve against (`/workdir` inside bwrap, the
/// host worktree path in disable-sandbox mode).
pub async fn run_stdio_server(
	client: Arc<ServerClient>, repo_id: i64, job_id: Option<i64>, workdir: PathBuf,
) -> Result<()> {
	let session = Arc::new(Session { client, repo_id, job_id, workdir });
	let stdin = std::io::stdin();
	let mut stdout = std::io::stdout();

	for line in stdin.lock().lines() {
		let line = line?;
		if line.trim().is_empty() {
			continue;
		}
		tracing::debug!(request = %line, "loupe-mcp: received request");

		let request: Request = match serde_json::from_str(&line) {
			Ok(r) => r,
			Err(e) => {
				write_response(
					&mut stdout,
					&Response::err(Value::Null, -32700, format!("parse error: {e}")),
				)?;
				continue;
			},
		};

		// Notifications (no `id`) require no response per JSON-RPC.
		let Some(id) = request.id.clone() else { continue };

		let response = handle_request(&session, &request, id).await;
		write_response(&mut stdout, &response)?;
	}

	Ok(())
}

async fn handle_request(session: &Arc<Session>, req: &Request, id: Value) -> Response {
	match req.method.as_str() {
		"initialize" => Response::ok(
			id,
			json!({
				"protocolVersion": "2024-11-05",
				"capabilities": { "tools": { "listChanged": false } },
				"serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
			}),
		),
		"tools/list" => {
			Response::ok(id, json!({ "tools": tool_definitions(session.job_id.is_some()) }))
		},
		"tools/call" => handle_tool_call(session, req, id).await,
		// Common no-op MCP notifications/requests we just ack.
		"notifications/initialized" | "ping" => Response::ok(id, json!({})),
		other => Response::err(id, -32601, format!("method not found: {other}")),
	}
}

/// MCP tool catalogue. Each entry is the JSON Schema the agent uses
/// to decide when to call the tool and what shape arguments to send.
/// `submissions_enabled` gates `submit_finding` — without a job to
/// attribute submissions to (i.e. when the worker didn't pass
/// `--job-id`), the tool is hidden so the agent can't try to call it.
fn tool_definitions(submissions_enabled: bool) -> Value {
	let mut tools = vec![
		json!({
			"name": "query_prior_findings",
			"description":
				"Keyword search over prior security findings on the repo currently being scanned. \
				 Use this to check whether a vulnerability you're about to report has already been \
				 surfaced in an earlier scan — same bug, possibly different wording. Returns up to \
				 `limit` matches ranked by relevance, with the title, severity, file location, \
				 state (e.g. 'reported', 'awaiting_approval', 'dismissed'), and finding id of each. \
				 If a match looks like the same vulnerability you're investigating, do NOT submit \
				 a duplicate — the agent surface is meant to suppress repeats, not amplify them.",
			"inputSchema": {
				"type": "object",
				"required": ["query"],
				"properties": {
					"query": {
						"type": "string",
						"description":
							"Free-form keywords. The server splits on whitespace, drops 1-char \
							 tokens, and requires every term to appear (in title, description, or \
							 file_path). Quote nothing — operators are stripped.",
					},
					"limit": {
						"type": "integer",
						"description": "Max number of hits to return. Defaults to 20.",
						"minimum": 1,
						"maximum": 100,
					},
				},
			},
		}),
		json!({
			"name": "get_finding_by_id",
			"description":
				"Fetch the full detail view for one prior finding — description, PoC unified diff, \
				 patch (if any), CWE, file location, severity, state, audit trail. Use this after \
				 `query_prior_findings` returns a summary and you want to compare bodies before \
				 deciding whether the new finding you're about to report duplicates an existing one. \
				 The id is from a prior `query_prior_findings` hit.",
			"inputSchema": {
				"type": "object",
				"required": ["id"],
				"properties": {
					"id": {
						"type": "integer",
						"description": "The finding id, as returned in `query_prior_findings` hits.",
						"minimum": 1,
					},
				},
			},
		}),
	];
	if submissions_enabled {
		tools.push(json!({
			"name": "submit_finding",
			"description":
				"Report a confirmed vulnerability. This is the only path for emitting a finding \
				 from the agent — the worker does not parse findings out of your text response. \
				 Call this once per real, exploitable vulnerability you've found in the file you're \
				 reviewing, only after you've verified the bug is real and (where appropriate) \
				 cross-checked against `query_prior_findings` to avoid duplicating an existing \
				 report. The PoC must be a unified diff that adds a regression test demonstrating \
				 the bug — failing on HEAD, would pass once the bug is fixed. Submitting a finding \
				 you're not confident about is worse than not submitting one.",
			"inputSchema": {
				"type": "object",
				"required": [
					"severity", "title", "file", "line_start", "line_end",
					"description", "poc_unified",
				],
				"properties": {
					"severity": {
						"type": "string",
						"enum": ["info", "low", "medium", "high", "critical"],
						"description": "Impact level. `critical` for unauthenticated RCE / mass data \
							exposure; `high` for authenticated RCE / privilege escalation / serious \
							data leaks; `medium` for typical exploitable bugs; `low` for hardening \
							issues; `info` for advisory-only.",
					},
					"title": {
						"type": "string",
						"description":
							"Short imperative title (under ~80 chars). E.g. \
							 'Unchecked array index in request handler' — not a CVE-style ID.",
					},
					"file": {
						"type": "string",
						"description":
							"Path to the vulnerable file, relative to the worktree root. \
							 The same path you were asked to inspect in the prompt.",
					},
					"line_start": {
						"type": "integer",
						"description": "First line of the bug (1-indexed).",
						"minimum": 1,
					},
					"line_end": {
						"type": "integer",
						"description":
							"Last line of the bug (1-indexed, inclusive). Equal to line_start \
							 when the bug spans one line.",
						"minimum": 1,
					},
					"description": {
						"type": "string",
						"description":
							"Mechanism + impact + reproduction sketch. Aim for ~200 words. \
							 Mention any prior-finding ids you considered and ruled out.",
					},
					"poc_unified": {
						"type": "string",
						"description":
							"Unified diff that adds a regression test demonstrating the bug. \
							 The diff must apply against the worktree as it stands and the test \
							 must fail on HEAD; once the bug is fixed the test passes. Use the \
							 repo's existing test framework (`#[test]` for Rust, `pytest` for \
							 Python, etc.).",
					},
					"cwe": {
						"type": "string",
						"description":
							"Optional CWE-NNN string (e.g. 'CWE-129'). Omit if you're not sure.",
					},
				},
			},
		}));
	}
	// Always-on, read-only against the worktree. Useful even when
	// submission is disabled (e.g. the agent might validate a diff
	// for diagnostics) — and harmless to advertise either way since
	// `git apply --check` doesn't write.
	tools.push(json!({
		"name": "validate_poc",
		"description":
			"Pre-flight check for a PoC unified diff. Runs `git apply --check` against the \
			 worktree without writing anything; returns `applies: true` when the diff would \
			 cleanly apply, or `applies: false` with `error` carrying git's stderr (typically \
			 'corrupt patch', 'patch does not apply', fuzz/context warnings, or missing-file \
			 messages). Use this before calling `submit_finding` to catch path drift, fuzzy \
			 context, and malformed hunks — a finding whose PoC doesn't apply is a finding \
			 someone has to reproduce by hand.",
		"inputSchema": {
			"type": "object",
			"required": ["poc_unified"],
			"properties": {
				"poc_unified": {
					"type": "string",
					"description":
						"Unified diff to check, in `git diff` format with `a/`/`b/` prefixes. \
						 Same string you'd pass as `submit_finding`'s `poc_unified`.",
				},
			},
		},
	}));
	Value::Array(tools)
}

async fn handle_tool_call(session: &Arc<Session>, req: &Request, id: Value) -> Response {
	let params = req.params.as_ref();
	let tool_name = params.and_then(|p| p.get("name")).and_then(|n| n.as_str()).unwrap_or("");
	let arguments = params
		.and_then(|p| p.get("arguments"))
		.cloned()
		.unwrap_or_else(|| Value::Object(serde_json::Map::new()));

	let result: Result<String> = match tool_name {
		"query_prior_findings" => {
			tool_query_prior_findings(&session.client, session.repo_id, &arguments).await
		},
		"get_finding_by_id" => tool_get_finding_by_id(&session.client, &arguments).await,
		"submit_finding" => tool_submit_finding(session, &arguments).await,
		"validate_poc" => tool_validate_poc(&session.workdir, &arguments).await,
		other => Err(anyhow::anyhow!("unknown tool: {other}")),
	};

	match result {
		Ok(text) => Response::ok(id, json!({ "content": [{ "type": "text", "text": text }] })),
		Err(e) => {
			tracing::warn!(tool = tool_name, error = %e, "loupe-mcp: tool call failed");
			// MCP convention: tool errors flow through `result` with
			// `isError: true`, not the JSON-RPC `error` field (which
			// is reserved for protocol-level failures).
			Response::ok(
				id,
				json!({
					"content": [{ "type": "text", "text": format!("Error: {e}") }],
					"isError": true,
				}),
			)
		},
	}
}

async fn tool_get_finding_by_id(client: &Arc<ServerClient>, args: &Value) -> Result<String> {
	let id = args
		.get("id")
		.and_then(|v| v.as_i64())
		.context("`id` argument is required and must be an integer")?;
	let detail =
		client.get_finding(id).await.with_context(|| format!("calling /v1/findings/{id}"))?;
	let loc = format_location(detail.file_path.as_deref(), detail.line_start, detail.line_end);
	let mut out = String::with_capacity(detail.description.len() + 256);
	let _ = std::fmt::Write::write_fmt(
		&mut out,
		format_args!(
			"Finding #{} [{:?}] state={} {}\n{}\n",
			detail.id, detail.severity, detail.state, loc, detail.title,
		),
	);
	if let Some(cwe) = &detail.cwe {
		let _ = std::fmt::Write::write_fmt(&mut out, format_args!("CWE: {cwe}\n"));
	}
	out.push_str("\nDescription:\n");
	out.push_str(&detail.description);
	if let Some(poc) = &detail.poc_unified {
		out.push_str("\n\nProof of concept (unified diff):\n");
		out.push_str(poc);
	}
	if let Some(patch) = &detail.patch_unified {
		out.push_str("\n\nSuggested fix (unified diff):\n");
		out.push_str(patch);
	}
	Ok(out)
}

async fn tool_query_prior_findings(
	client: &Arc<ServerClient>, repo_id: i64, args: &Value,
) -> Result<String> {
	let query = arg_str(args, "query")?;
	let limit = args.get("limit").and_then(|v| v.as_i64()).unwrap_or(20).clamp(1, 100);

	let resp = client
		.search_findings(repo_id, query, limit)
		.await
		.context("calling /v1/repos/:id/findings/search")?;

	if resp.findings.is_empty() {
		return Ok(format!(
			"No prior findings on repo {repo_id} match `{query}`. Treat this as a novel finding."
		));
	}
	let mut out = String::with_capacity(512);
	out.push_str(&format!(
		"{} prior finding(s) on repo {repo_id} match `{query}`:\n\n",
		resp.findings.len()
	));
	for f in &resp.findings {
		// Search summaries don't include line_end; pass None so the
		// helper renders `path:line` instead of falling through.
		let loc = format_location(f.file_path.as_deref(), f.line_start, None);
		out.push_str(&format!(
			"- #{} [{:?}] state={} {} — {}\n",
			f.id, f.severity, f.state, loc, f.title,
		));
	}
	Ok(out)
}

/// Build a [`Finding`] from `submit_finding` arguments.
///
/// Pure function — extracted from `tool_submit_finding` so tests can
/// exercise the fingerprint / clamp / parse logic without standing
/// up an MCP server or a real HTTP backend.
pub(crate) fn build_finding_from_args(workdir: &Path, args: &Value) -> Result<Finding> {
	let severity_str = arg_str(args, "severity")?;
	let severity: Severity =
		severity_str.parse().with_context(|| format!("unknown severity: `{severity_str}`"))?;
	let title = arg_str(args, "title")?.to_owned();
	let file = arg_str(args, "file")?;
	let line_start = arg_u32(args, "line_start")?;
	let line_end = arg_u32(args, "line_end")?;
	let description = arg_str(args, "description")?.to_owned();
	let poc_unified = arg_str(args, "poc_unified")?.to_owned();
	let cwe = args.get("cwe").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_owned);

	// Sandbox-leak guard: the agent occasionally echoes the in-bwrap
	// path. Strip it so the file recorded on the server is repo-
	// relative regardless of where the agent was looking from.
	let rel_file = file.strip_prefix("/workdir/").unwrap_or(file).trim_start_matches('/');
	let fingerprint = fingerprint_for(workdir, rel_file, line_start, line_end);

	Ok(Finding {
		scanner_id: SCANNER_ID.into(),
		severity,
		title,
		description,
		file_path: Some(rel_file.to_owned()),
		line_start: Some(line_start),
		line_end: Some(line_end),
		cwe,
		patch_unified: None,
		poc_unified: Some(poc_unified),
		fingerprint,
	})
}

async fn tool_submit_finding(session: &Arc<Session>, args: &Value) -> Result<String> {
	let job_id = session.job_id.context(
		"submit_finding called but the MCP server was started without --job-id; \
		 nowhere to attribute the submission. This is a worker-side configuration \
		 bug — the tool should not have been advertised.",
	)?;
	let finding = build_finding_from_args(&session.workdir, args)?;
	let title = finding.title.clone();
	let file = finding.file_path.clone().unwrap_or_default();
	let fingerprint = finding.fingerprint.clone();
	let batch = FindingsBatch { protocol_version: PROTOCOL_VERSION, findings: vec![finding] };
	session
		.client
		.submit_findings(job_id, &batch)
		.await
		.with_context(|| format!("submitting finding for {file} to /v1/jobs/{job_id}/findings"))?;
	tracing::info!(
		job_id, repo_id = session.repo_id, %file, %title, fingerprint = %fingerprint,
		"loupe-mcp: agent submitted a finding",
	);
	Ok(format!(
		"Submitted. job={job_id} fingerprint={fingerprint}\n\
		 The server applies UNIQUE(repo_id, fingerprint) on insert; if this finding hash-matches a \
		 prior one, the row was silently skipped — that's the dedup floor and is fine."
	))
}

async fn tool_validate_poc(workdir: &Path, args: &Value) -> Result<String> {
	let diff = arg_str(args, "poc_unified")?;

	let outcome = check_diff_applies(workdir, diff).await?;
	let payload = match outcome {
		DiffCheck::Applies => json!({
			"applies": true,
			"message": "git apply --check accepted the diff",
		}),
		DiffCheck::Rejects { stderr } => json!({
			"applies": false,
			"error": stderr,
		}),
	};
	// Tools return a string `text` per MCP convention; serialise the
	// JSON payload so the agent gets a structured-looking response.
	Ok(serde_json::to_string(&payload).expect("payload serialises"))
}

#[derive(Debug)]
enum DiffCheck {
	Applies,
	Rejects { stderr: String },
}

/// Run `git apply --check` against `workdir`, feeding `diff` over
/// stdin. `--check` does not modify the worktree, only verifies that
/// the diff would apply — safe to run against the read-only bwrap
/// mount. Errors here are infrastructure-level (couldn't spawn git);
/// a clean "this diff doesn't apply" is a `DiffCheck::Rejects`.
async fn check_diff_applies(workdir: &Path, diff: &str) -> Result<DiffCheck> {
	let mut child = tokio::process::Command::new("git")
		.arg("apply")
		.arg("--check")
		// Read the diff from stdin via the conventional `-` filename.
		.arg("-")
		.current_dir(workdir)
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.context("spawning `git apply --check`")?;
	{
		let mut stdin = child.stdin.take().context("git apply stdin already taken")?;
		stdin.write_all(diff.as_bytes()).await.context("writing diff to git apply stdin")?;
		stdin.shutdown().await.ok();
	}
	let output = child.wait_with_output().await.context("waiting on git apply")?;
	if output.status.success() {
		Ok(DiffCheck::Applies)
	} else {
		// Cap stderr — pathological diffs can produce many lines and we
		// want to leave room in the agent's tool-result for surrounding
		// reasoning. 4 KiB is plenty for a "patch doesn't apply at line
		// N" message; longer diagnostics get truncated.
		let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
		const MAX_STDERR: usize = 4096;
		if stderr.len() > MAX_STDERR {
			stderr.truncate(MAX_STDERR);
			stderr.push_str("\n…(truncated)");
		}
		if stderr.trim().is_empty() {
			stderr = format!("git apply exited {}", output.status);
		}
		Ok(DiffCheck::Rejects { stderr })
	}
}

/// Read `workdir/file` and compute the fingerprint for the bug at
/// `line_start..=line_end`. Falls back to a degenerate-but-safe input
/// when the file can't be read (model hallucinated a path, file is
/// non-UTF-8, etc.) so submission still succeeds — the line range
/// alone is the worst-case fingerprint input.
fn fingerprint_for(workdir: &Path, file: &str, line_start: u32, line_end: u32) -> String {
	let abs = workdir.join(file);
	let source = match std::fs::read_to_string(&abs) {
		Ok(s) => s,
		Err(e) => {
			tracing::warn!(
				file, error = %e,
				"fingerprint: could not read worktree file; falling back to line-range-only window",
			);
			return crate::fingerprint::compute(
				SCANNER_ID,
				file,
				&format!("L{line_start}-L{line_end}"),
			);
		},
	};
	let window = crate::fingerprint::extract_window(
		&source,
		line_start,
		line_end,
		FINGERPRINT_CONTEXT_LINES,
	);
	crate::fingerprint::compute(SCANNER_ID, file, &window)
}

fn write_response<W: Write>(w: &mut W, resp: &Response) -> Result<()> {
	let line = serde_json::to_string(resp)?;
	tracing::debug!(response = %line, "loupe-mcp: sending response");
	writeln!(w, "{line}")?;
	w.flush()?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn tool_catalogue_round_trips_through_json() {
		// The MCP client (claude) parses tools/list output as JSON
		// against its own schema; pinning it here catches accidental
		// breakage of the shape (e.g. forgetting `inputSchema`).
		let v = tool_definitions(true);
		let arr = v.as_array().expect("tools must serialise as an array");
		assert!(!arr.is_empty());
		for t in arr {
			assert!(t.get("name").and_then(|n| n.as_str()).is_some(), "tool needs `name`");
			assert!(
				t.get("description").and_then(|d| d.as_str()).is_some(),
				"tool needs `description`",
			);
			let schema = t.get("inputSchema").expect("tool needs `inputSchema`");
			assert_eq!(schema.get("type").and_then(|t| t.as_str()), Some("object"));
		}
	}

	#[test]
	fn submit_finding_only_appears_when_job_id_is_set() {
		let with = tool_definitions(true);
		let names: Vec<&str> =
			with.as_array().unwrap().iter().filter_map(|t| t.get("name")?.as_str()).collect();
		assert!(names.contains(&"submit_finding"), "got: {names:?}");

		let without = tool_definitions(false);
		let names: Vec<&str> =
			without.as_array().unwrap().iter().filter_map(|t| t.get("name")?.as_str()).collect();
		assert!(!names.contains(&"submit_finding"), "got: {names:?}");
		// Read-only tools always advertised.
		assert!(names.contains(&"query_prior_findings"));
		assert!(names.contains(&"get_finding_by_id"));
	}

	#[test]
	fn build_finding_extracts_window_and_fingerprints_it() {
		// Two cosmetically-different fixtures with the same bug body
		// must produce the same fingerprint — that's the whole point
		// of the normalisation in `fingerprint::compute`. Pinned here
		// because the fingerprint logic now lives in the MCP server,
		// not the scanner; if the helper drifts off the normalisation
		// contract we want this test to flag it.
		let workdir_a = tempfile::tempdir().unwrap();
		std::fs::create_dir_all(workdir_a.path().join("src")).unwrap();
		std::fs::write(
			workdir_a.path().join("src/lib.rs"),
			"pub fn idx(arr: &[u8], i: usize) -> u8 { arr[i] }\n",
		)
		.unwrap();

		let workdir_b = tempfile::tempdir().unwrap();
		std::fs::create_dir_all(workdir_b.path().join("src")).unwrap();
		std::fs::write(
			workdir_b.path().join("src/lib.rs"),
			"pub fn idx(arr: &[u8], i: usize) -> u8 {  arr[i]  }\n", // extra spaces
		)
		.unwrap();

		let args = json!({
			"severity": "high",
			"title": "oob index",
			"file": "src/lib.rs",
			"line_start": 1,
			"line_end": 1,
			"description": "unchecked index",
			"poc_unified": "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@\n+#[test] fn t() {}\n",
		});
		let f_a = build_finding_from_args(workdir_a.path(), &args).expect("a");
		let f_b = build_finding_from_args(workdir_b.path(), &args).expect("b");
		assert_eq!(
			f_a.fingerprint, f_b.fingerprint,
			"whitespace-only difference must not shift the fingerprint",
		);
		assert_eq!(f_a.scanner_id, SCANNER_ID);
		assert_eq!(f_a.severity, Severity::High);
		assert_eq!(f_a.file_path.as_deref(), Some("src/lib.rs"));
		assert!(f_a.poc_unified.as_deref().unwrap().contains("#[test]"));
	}

	#[test]
	fn build_finding_strips_sandbox_workdir_prefix() {
		// Agents sometimes echo back the in-sandbox absolute path
		// (`/workdir/src/lib.rs`) instead of the repo-relative one we
		// asked for. Storing the absolute form would confuse
		// downstream consumers (issue trackers, etc.) — strip it.
		let workdir = tempfile::tempdir().unwrap();
		std::fs::create_dir_all(workdir.path().join("src")).unwrap();
		std::fs::write(workdir.path().join("src/lib.rs"), "fn x() {}\n").unwrap();

		let args = json!({
			"severity": "low",
			"title": "t",
			"file": "/workdir/src/lib.rs",
			"line_start": 1,
			"line_end": 1,
			"description": "d",
			"poc_unified": "x",
		});
		let f = build_finding_from_args(workdir.path(), &args).expect("ok");
		assert_eq!(f.file_path.as_deref(), Some("src/lib.rs"));
	}

	#[test]
	fn build_finding_rejects_missing_required_fields() {
		let workdir = tempfile::tempdir().unwrap();
		// No `title`.
		let args = json!({
			"severity": "low",
			"file": "src/x.rs",
			"line_start": 1,
			"line_end": 1,
			"description": "d",
			"poc_unified": "x",
		});
		let err = build_finding_from_args(workdir.path(), &args).expect_err("must fail");
		assert!(err.to_string().contains("title"), "got: {err}");
	}

	#[test]
	fn build_finding_rejects_unknown_severity() {
		let workdir = tempfile::tempdir().unwrap();
		let args = json!({
			"severity": "extreme",
			"title": "t",
			"file": "src/x.rs",
			"line_start": 1,
			"line_end": 1,
			"description": "d",
			"poc_unified": "x",
		});
		let err = build_finding_from_args(workdir.path(), &args).expect_err("must fail");
		assert!(err.to_string().to_lowercase().contains("severity"), "got: {err}");
	}

	fn git_present() -> bool {
		std::process::Command::new("git")
			.arg("--version")
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status()
			.map(|s| s.success())
			.unwrap_or(false)
	}

	#[tokio::test]
	async fn validate_poc_accepts_a_clean_diff() {
		// `git apply --check` works outside a `.git` repo as long as it
		// can find the file — set up a worktree without a `.git` so
		// the test mirrors the runner's checkout-tree shape (we
		// extract a tree, no .git is created).
		if !git_present() {
			eprintln!("skipping: git not on PATH");
			return;
		}
		let workdir = tempfile::tempdir().unwrap();
		std::fs::write(workdir.path().join("hello.txt"), "hello\nworld\n").unwrap();
		let diff = concat!(
			"diff --git a/hello.txt b/hello.txt\n",
			"--- a/hello.txt\n",
			"+++ b/hello.txt\n",
			"@@ -1,2 +1,3 @@\n",
			" hello\n",
			"+greetings\n",
			" world\n",
		);
		let args = json!({ "poc_unified": diff });
		let result = tool_validate_poc(workdir.path(), &args).await.expect("tool ok");
		let parsed: Value = serde_json::from_str(&result).expect("json");
		assert_eq!(parsed["applies"], json!(true), "expected applies=true, got: {parsed}");
	}

	#[tokio::test]
	async fn validate_poc_rejects_a_diff_against_missing_file() {
		if !git_present() {
			eprintln!("skipping: git not on PATH");
			return;
		}
		let workdir = tempfile::tempdir().unwrap();
		// Don't create any source file. The diff references a file
		// that doesn't exist in workdir.
		let diff = "\
--- a/nonexistent.txt\n\
+++ b/nonexistent.txt\n\
@@ -1,1 +1,2 @@\n\
 line\n\
+added\n\
";
		let args = json!({ "poc_unified": diff });
		let result = tool_validate_poc(workdir.path(), &args).await.expect("tool ok");
		let parsed: Value = serde_json::from_str(&result).expect("json");
		assert_eq!(parsed["applies"], json!(false), "expected applies=false");
		let err = parsed["error"].as_str().unwrap_or("");
		assert!(!err.is_empty(), "must include git stderr: {parsed}");
	}

	#[tokio::test]
	async fn validate_poc_rejects_corrupt_diff() {
		if !git_present() {
			eprintln!("skipping: git not on PATH");
			return;
		}
		let workdir = tempfile::tempdir().unwrap();
		let args = json!({ "poc_unified": "this is not a unified diff" });
		let result = tool_validate_poc(workdir.path(), &args).await.expect("tool ok");
		let parsed: Value = serde_json::from_str(&result).expect("json");
		assert_eq!(parsed["applies"], json!(false));
	}

	#[test]
	fn validate_poc_is_advertised_regardless_of_submissions_setting() {
		// Even when --job-id is omitted we keep validate_poc on the
		// list — it's read-only against the worktree and useful for
		// diagnostics. Pinned because future "tighten the surface"
		// refactors might be tempted to gate it.
		for enabled in [true, false] {
			let v = tool_definitions(enabled);
			let names: Vec<&str> =
				v.as_array().unwrap().iter().filter_map(|t| t.get("name")?.as_str()).collect();
			assert!(
				names.contains(&"validate_poc"),
				"submissions_enabled={enabled}, got: {names:?}"
			);
		}
	}
}
