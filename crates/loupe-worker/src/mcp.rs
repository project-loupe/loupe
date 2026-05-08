//! MCP server exposed to the agent (`claude` and friends) for the
//! duration of one scan session over one source file.
//!
//! Wire shape: JSON-RPC 2.0 over stdio. The agent is the JSON-RPC
//! client; this module is the server. We hand-roll the protocol to
//! avoid taking a third-party MCP dep — the surface we use is small
//! (`initialize`, `tools/list`, `tools/call`).
//! `initialize` returns both the MCP protocol version and Loupe's own
//! MCP tool protocol version, and every tool schema accepts an optional
//! `protocol_version` argument so future workers can reject tool-call
//! shapes they do not understand without mis-parsing them.
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
use std::path::{Component, Path, PathBuf};
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
const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
const LOUPE_MCP_PROTOCOL_VERSION: u16 = 1;

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

fn normalize_submitted_file(workdir: &Path, file: &str) -> Result<String> {
	let stripped = file.strip_prefix("/workdir/").unwrap_or(file);
	let path = Path::new(stripped);
	if stripped.trim().is_empty() {
		anyhow::bail!("`file` must not be empty");
	}
	if path.is_absolute() {
		anyhow::bail!("`file` must be repo-relative or under /workdir");
	}

	let mut rel = PathBuf::new();
	for component in path.components() {
		match component {
			Component::Normal(part) => rel.push(part),
			Component::CurDir => {},
			Component::ParentDir => anyhow::bail!("`file` must not contain `..` components"),
			Component::RootDir | Component::Prefix(_) => {
				anyhow::bail!("`file` must be repo-relative or under /workdir")
			},
		}
	}
	if rel.as_os_str().is_empty() {
		anyhow::bail!("`file` must name a file inside the workdir");
	}

	let workdir = workdir.canonicalize().with_context(|| {
		format!("canonicalizing workdir {} before validating submitted path", workdir.display())
	})?;
	let candidate = workdir.join(&rel);
	if candidate.exists() {
		let canonical = candidate
			.canonicalize()
			.with_context(|| format!("canonicalizing submitted file {}", candidate.display()))?;
		if !canonical.starts_with(&workdir) {
			anyhow::bail!("`file` resolves outside the workdir: {}", rel.display());
		}
	}

	Ok(rel.to_string_lossy().into_owned())
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
/// once at `run_stdio_server` start from CLI args. Discovery-mode
/// fields are immutable; verify-mode state lives behind a mutex
/// because the agent can issue `submit_verdict` and `submit_patch`
/// across multiple tool calls and the second-call locks need to
/// consult what the first call set.
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
	/// Verify-mode state. `Some` flips the tool catalog: hides
	/// `submit_finding` / `validate_poc`, advertises `submit_verdict`
	/// / `submit_patch` / `validate_patch`. `None` keeps the
	/// discovery-mode catalog.
	verify: Option<VerifySessionState>,
}

/// Verify-mode buffer. The agent calls `submit_verdict` first
/// (mandatory, locks for the rest of the session), then optionally
/// `submit_patch` (only valid after a Confirmed verdict). Both
/// tools just write to this buffer — nothing reaches the server
/// until session end, when [`flush_verify_session`] POSTs one
/// `VerdictSubmission` carrying the verdict (with the patch
/// embedded on Confirmed).
///
/// This buffer-and-flush pattern is what enforces the "verdict
/// first, patch maybe" ordering at the protocol level: the agent
/// can't see a "patch_unified row already populated" outcome and
/// then revise its verdict, because nothing has hit the server yet.
struct VerifySessionState {
	finding_id: i64,
	inner: tokio::sync::Mutex<VerifySessionInner>,
}

#[derive(Debug, Default)]
struct VerifySessionInner {
	/// Locked on first `submit_verdict`. A second call returns an
	/// error so the agent can't revise mid-session.
	verdict: Option<loupe_core::Verdict>,
	/// Locked on first `submit_patch`. Held separately from the
	/// verdict's own `patch` field so we can pin "patch tool was
	/// called once" even if the merge into Verdict::Confirmed
	/// happens later, at flush time.
	patch: Option<loupe_core::VerdictPatch>,
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
/// `/v1/jobs/{job_id}/findings`. `finding_id`, when `Some`, flips
/// the server into verify mode (the agent sees `submit_verdict` /
/// `submit_patch` / `validate_patch` instead of the discovery
/// tools); `job_id` MUST also be set in verify mode so the verdict
/// POST has a job to attribute to. `workdir` is the path the
/// agent's file references resolve against (`/workdir` inside
/// bwrap, the host worktree path in disable-sandbox mode).
///
/// In verify mode, the verdict (and the optional patch) is buffered
/// during the session and flushed in a single `POST /v1/jobs/:id/
/// verdict` after stdin closes. If the agent never called
/// `submit_verdict`, the function returns an error so the runner
/// posts `complete(failed)` and the validating-deadline reaper
/// later marks the verdict inconclusive.
pub async fn run_stdio_server(
	client: Arc<ServerClient>, repo_id: i64, job_id: Option<i64>, finding_id: Option<i64>,
	workdir: PathBuf,
) -> Result<()> {
	let verify = match (finding_id, job_id) {
		(Some(fid), Some(_)) => Some(VerifySessionState {
			finding_id: fid,
			inner: tokio::sync::Mutex::new(VerifySessionInner::default()),
		}),
		(Some(_), None) => {
			anyhow::bail!(
				"verify-mode MCP server requires both --finding-id and --job-id; got finding-id only"
			);
		},
		(None, _) => None,
	};
	let session = Arc::new(Session { client, repo_id, job_id, workdir, verify });
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

	if session.verify.is_some() {
		flush_verify_session(&session).await?;
	}

	Ok(())
}

async fn handle_request(session: &Arc<Session>, req: &Request, id: Value) -> Response {
	match req.method.as_str() {
		"initialize" => Response::ok(
			id,
			json!({
				"protocolVersion": MCP_PROTOCOL_VERSION,
				"capabilities": { "tools": { "listChanged": false } },
				"serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
				"_meta": loupe_mcp_meta(),
			}),
		),
		"tools/list" => Response::ok(
			id,
			json!({
				"tools": tool_definitions(session.job_id.is_some(), session.verify.is_some()),
				"_meta": loupe_mcp_meta(),
			}),
		),
		"tools/call" => handle_tool_call(session, req, id).await,
		// Common no-op MCP notifications/requests we just ack.
		"notifications/initialized" | "ping" => Response::ok(id, json!({})),
		other => Response::err(id, -32601, format!("method not found: {other}")),
	}
}

fn loupe_mcp_meta() -> Value {
	json!({ "loupeProtocolVersion": LOUPE_MCP_PROTOCOL_VERSION })
}

/// MCP tool catalogue. Each entry is the JSON Schema the agent uses
/// to decide when to call the tool and what shape arguments to send.
///
/// `submissions_enabled` gates the discovery-mode `submit_finding`
/// — without a job to attribute submissions to (i.e. when the
/// worker didn't pass `--job-id`), the tool is hidden so the agent
/// can't try to call it.
///
/// `verify_mode` flips the catalog into a different shape entirely:
/// `submit_finding` and `validate_poc` are hidden; `submit_verdict`,
/// `submit_patch`, and `validate_patch` are advertised instead.
/// `query_prior_findings` and `get_finding_by_id` stay in both
/// modes — they're read-only and useful for the verifier to
/// cross-check the bug it's verifying against the repo's history.
fn tool_definitions(submissions_enabled: bool, verify_mode: bool) -> Value {
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
	if verify_mode {
		// Verify-mode catalog. The ordering in the agent's tool list
		// is just a hint, but listing submit_verdict before
		// submit_patch nudges the agent toward the intended phase
		// ordering ("verdict first, patch maybe").
		tools.push(json!({
			"name": "submit_verdict",
			"description":
				"Phase 1 of the verifier flow — MANDATORY, FIRST. Record your verdict on the \
				 finding under review. Locks for the rest of the session: a second call returns \
				 an error. The lock is deliberate so you can't revise the verdict to match a \
				 fix you've already started drafting. Decide on the verdict before calling.",
			"inputSchema": {
				"type": "object",
				"required": ["verdict", "notes"],
				"properties": {
					"verdict": {
						"type": "string",
						"enum": ["confirmed", "dismissed", "inconclusive"],
						"description":
							"`confirmed` — the bug is real and exploitable as described. \
							 `dismissed` — the report is wrong (false positive, misread of the \
							 code, etc.). `inconclusive` — the file's behaviour genuinely \
							 depends on context outside the file itself (downstream caller \
							 invariants, pinned dependency internals you cannot read). Prefer a \
							 definite verdict when you can.",
					},
					"notes": {
						"type": "string",
						"description":
							"One-sentence justification for the verdict. Surfaced to human \
							 reviewers and persisted alongside the verification row.",
					},
				},
			},
		}));
		tools.push(json!({
			"name": "submit_patch",
			"description":
				"Phase 2 of the verifier flow — OPTIONAL. Propose a candidate fix for a \
				 confirmed finding. Only available after `submit_verdict(\"confirmed\", ...)`; \
				 calling before, or after a non-confirmed verdict, returns an error. **Failure \
				 is acceptable**: if you are uncertain how to fix the bug correctly, end the \
				 session without calling this tool — the verdict still stands and the human \
				 reviewer takes it from there. A wrong patch attached to a real bug is worse \
				 than no patch. The patch must be **minimally invasive** (smallest change that \
				 fixes the bug; don't refactor neighbouring code or fix unrelated issues) and \
				 **match the surrounding coding style** of the project (indentation, naming, \
				 error-handling patterns, idioms — read the neighbouring code if unsure). Pre- \
				 flight with `validate_patch` first; the server-side check rejects diffs that \
				 don't apply against the worktree.",
			"inputSchema": {
				"type": "object",
				"required": ["patch_unified", "notes"],
				"properties": {
					"patch_unified": {
						"type": "string",
						"description":
							"Unified diff of the proposed fix, in `git diff` format with \
							 `a/`/`b/` prefixes. Touch production code only — the PoC diff \
							 already covers the regression test.",
					},
					"notes": {
						"type": "string",
						"description":
							"1–2 sentence rationale: what the fix does and why this is the \
							 minimal correct change. Surfaced to human reviewers alongside \
							 the diff.",
					},
				},
			},
		}));
		tools.push(json!({
			"name": "validate_patch",
			"description":
				"Pre-flight check for a candidate patch diff. Runs `git apply --check` against \
				 the worktree without writing anything; returns `{applies: true}` when the diff \
				 would cleanly apply, or `{applies: false, error: ...}` with git's stderr. Use \
				 this before `submit_patch` to catch path drift, fuzzy context, and malformed \
				 hunks. Equivalent to discovery's `validate_poc` — same machinery, different \
				 field name to match `submit_patch`'s input.",
			"inputSchema": {
				"type": "object",
				"required": ["patch_unified"],
				"properties": {
					"patch_unified": {
						"type": "string",
						"description":
							"Unified diff to check. Same string you'd pass as `submit_patch`'s \
							 `patch_unified`.",
					},
				},
			},
		}));
		add_tool_protocol_version(&mut tools);
		return Value::Array(tools);
	}
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
	add_tool_protocol_version(&mut tools);
	Value::Array(tools)
}

fn add_tool_protocol_version(tools: &mut [Value]) {
	for tool in tools {
		let Some(properties) = tool
			.get_mut("inputSchema")
			.and_then(|schema| schema.get_mut("properties"))
			.and_then(Value::as_object_mut)
		else {
			continue;
		};
		properties.insert(
			"protocol_version".to_owned(),
			json!({
				"type": "integer",
				"const": LOUPE_MCP_PROTOCOL_VERSION,
				"description": format!(
					"Optional Loupe MCP tool protocol version. Current version is {}.",
					LOUPE_MCP_PROTOCOL_VERSION
				),
			}),
		);
	}
}

async fn handle_tool_call(session: &Arc<Session>, req: &Request, id: Value) -> Response {
	let params = req.params.as_ref();
	let tool_name = params.and_then(|p| p.get("name")).and_then(|n| n.as_str()).unwrap_or("");
	let arguments = params
		.and_then(|p| p.get("arguments"))
		.cloned()
		.unwrap_or_else(|| Value::Object(serde_json::Map::new()));

	let result: Result<String> = match check_tool_protocol_version(&arguments) {
		Err(e) => Err(e),
		Ok(()) => match tool_name {
			"query_prior_findings" => {
				tool_query_prior_findings(&session.client, session.repo_id, &arguments).await
			},
			"get_finding_by_id" => tool_get_finding_by_id(&session.client, &arguments).await,
			"submit_finding" => tool_submit_finding(session, &arguments).await,
			"validate_poc" => tool_validate_diff(&session.workdir, &arguments, "poc_unified").await,
			"submit_verdict" => tool_submit_verdict(session, &arguments).await,
			"submit_patch" => tool_submit_patch(session, &arguments).await,
			"validate_patch" => {
				tool_validate_diff(&session.workdir, &arguments, "patch_unified").await
			},
			other => Err(anyhow::anyhow!("unknown tool: {other}")),
		},
	};

	match result {
		Ok(text) => Response::ok(
			id,
			json!({
				"content": [{ "type": "text", "text": text }],
				"_meta": loupe_mcp_meta(),
			}),
		),
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
					"_meta": loupe_mcp_meta(),
				}),
			)
		},
	}
}

fn check_tool_protocol_version(args: &Value) -> Result<()> {
	let Some(value) = args.get("protocol_version") else {
		return Ok(());
	};
	let Some(version) = value.as_u64() else {
		anyhow::bail!("protocol_version must be an integer");
	};
	if version != u64::from(LOUPE_MCP_PROTOCOL_VERSION) {
		anyhow::bail!(
			"unsupported Loupe MCP protocol_version {version}; worker supports {}",
			LOUPE_MCP_PROTOCOL_VERSION
		);
	}
	Ok(())
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
	// path. Normalize it to a repo-relative path and reject traversal
	// before reading source for the fingerprint.
	let rel_file = normalize_submitted_file(workdir, file)?;
	let fingerprint = fingerprint_for(workdir, &rel_file, line_start, line_end);

	Ok(Finding {
		scanner_id: SCANNER_ID.into(),
		severity,
		title,
		description,
		file_path: Some(rel_file),
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

/// Shared `git apply --check` runner. Discovery uses it via
/// `validate_poc(poc_unified)`; verify uses it via
/// `validate_patch(patch_unified)`. The field name is the only
/// difference, so both tools dispatch into this with the
/// appropriate `field` argument.
async fn tool_validate_diff(workdir: &Path, args: &Value, field: &str) -> Result<String> {
	let diff = arg_str(args, field)?;

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

async fn tool_submit_verdict(session: &Arc<Session>, args: &Value) -> Result<String> {
	let verify = session.verify.as_ref().context(
		"submit_verdict called but the MCP server is in discovery mode \
		 (no --finding-id was passed). This is a worker-side configuration \
		 bug — the tool should not have been advertised.",
	)?;

	let verdict_str = arg_str(args, "verdict")?;
	let notes = arg_str(args, "notes")?.to_owned();
	let verdict = match verdict_str {
		"confirmed" => loupe_core::Verdict::Confirmed { notes: Some(notes), patch: None },
		"dismissed" => loupe_core::Verdict::Dismissed { notes: Some(notes) },
		"inconclusive" => loupe_core::Verdict::Inconclusive { reason: notes },
		other => anyhow::bail!(
			"unknown verdict `{other}`; must be one of `confirmed`, `dismissed`, `inconclusive`"
		),
	};

	let mut inner = verify.inner.lock().await;
	if inner.verdict.is_some() {
		anyhow::bail!(
			"verdict already locked for this session; cannot submit a second verdict. \
			 The first call's outcome is the one that will reach the server."
		);
	}
	let is_confirmed = matches!(&verdict, loupe_core::Verdict::Confirmed { .. });
	inner.verdict = Some(verdict);

	tracing::info!(
		finding_id = verify.finding_id,
		verdict = verdict_str,
		"loupe-mcp: agent submitted verify verdict",
	);

	if is_confirmed {
		Ok("Verdict locked: confirmed. You may now optionally call `submit_patch` \
		    with a candidate fix; skipping it is fine — the verdict still stands. \
		    If you propose a patch, it must be minimally invasive and match the \
		    project's coding style; abort the patch attempt rather than guessing."
			.into())
	} else {
		Ok(format!(
			"Verdict locked: {verdict_str}. `submit_patch` is not applicable for this \
			 verdict — patches only attach to `confirmed` verdicts. End the session \
			 when you're done."
		))
	}
}

async fn tool_submit_patch(session: &Arc<Session>, args: &Value) -> Result<String> {
	let verify = session.verify.as_ref().context(
		"submit_patch called but the MCP server is in discovery mode \
		 (no --finding-id was passed). This is a worker-side configuration \
		 bug — the tool should not have been advertised.",
	)?;

	let patch_unified = arg_str(args, "patch_unified")?.to_owned();
	let notes = arg_str(args, "notes")?.to_owned();

	// Cheap state checks first — verdict shape, then "patch slot
	// already taken." Saves spawning `git apply --check` when the
	// call is going to be rejected on the verdict alone. Hold the
	// lock across the diff check too so a concurrent submit_patch
	// (impossible today since the agent's MCP session is
	// single-threaded over stdin, but cheap insurance against future
	// regressions) can't race past the patch.is_some() guard.
	let mut inner = verify.inner.lock().await;
	match &inner.verdict {
		None => anyhow::bail!(
			"submit_patch called before submit_verdict. Lock a verdict first, \
			 then propose a patch (only valid after a `confirmed` verdict)."
		),
		Some(loupe_core::Verdict::Confirmed { .. }) => {},
		Some(other) => {
			let kind = match other {
				loupe_core::Verdict::Dismissed { .. } => "dismissed",
				loupe_core::Verdict::Inconclusive { .. } => "inconclusive",
				loupe_core::Verdict::Confirmed { .. } => unreachable!("handled above"),
			};
			anyhow::bail!(
				"submit_patch is only valid after a `confirmed` verdict; current verdict \
				 is `{kind}`. End the session — no patch is applicable."
			);
		},
	}
	if inner.patch.is_some() {
		anyhow::bail!("patch already submitted for this session; one patch per verify session");
	}

	// Now the expensive check. The server-side
	// `attach_proposed_patch` won't catch a bad diff because storage
	// doesn't validate; surfacing the failure here gives the agent a
	// chance to revise.
	match check_diff_applies(&session.workdir, &patch_unified).await? {
		DiffCheck::Applies => {},
		DiffCheck::Rejects { stderr } => {
			anyhow::bail!(
				"patch_unified does not apply against the worktree (`git apply --check` \
				 rejected it). Revise and re-call `validate_patch` first. stderr: {stderr}"
			);
		},
	}

	inner.patch = Some(loupe_core::VerdictPatch { patch_unified, notes });

	tracing::info!(finding_id = verify.finding_id, "loupe-mcp: agent submitted verifier patch",);

	Ok("Patch buffered. End the session when you're done; the verdict and patch \
	    will be POSTed together to the server in a single request."
		.into())
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

/// End-of-session flush for verify mode: take the buffered verdict
/// (and patch, if any), merge them into a single
/// `Verdict::Confirmed { ..., patch }` (or pass through unchanged
/// for non-Confirmed variants), and POST one `VerdictSubmission` to
/// `/v1/jobs/{job_id}/verdict`.
///
/// Errors propagate up through `run_stdio_server`'s return so the
/// runner posts `complete(failed)` and the validating-deadline
/// reaper later marks the verdict inconclusive. In particular: if
/// the agent never called `submit_verdict`, that's a verifier
/// failure — the agent didn't do its job — and we surface the
/// failure rather than silently letting the verify slot stay open.
async fn flush_verify_session(session: &Arc<Session>) -> Result<()> {
	let verify = session.verify.as_ref().expect("flush_verify_session: verify state required");
	let job_id = session
		.job_id
		.context("flush_verify_session: verify mode requires --job-id (checked at startup)")?;

	let inner = verify.inner.lock().await;
	let verdict = inner.verdict.clone().context(
		"verify session ended without `submit_verdict` being called. \
		 The verifier agent didn't produce a verdict — treating as a \
		 session failure so the runner reports the job failed and the \
		 validating-deadline reaper picks up the slack.",
	)?;
	let patch = inner.patch.clone();
	drop(inner);

	// Merge: a buffered patch only attaches to a Confirmed verdict.
	// `submit_patch` already enforces this (it refuses to buffer when
	// the verdict isn't Confirmed), but the merge makes the invariant
	// explicit at flush time too.
	let final_verdict = match verdict {
		loupe_core::Verdict::Confirmed { notes, patch: existing } => {
			loupe_core::Verdict::Confirmed {
				notes,
				// If somehow both fields carry a patch (impossible by the
				// tool plumbing), prefer the buffered one — the in-session
				// `submit_patch` is the path the operator wired the audit
				// columns through.
				patch: patch.or(existing),
			}
		},
		other => other,
	};

	tracing::info!(
		finding_id = verify.finding_id,
		job_id,
		"loupe-mcp: flushing verify session verdict",
	);
	session
		.client
		.submit_verdict(
			job_id,
			&loupe_proto::VerdictSubmission {
				protocol_version: loupe_proto::PROTOCOL_VERSION,
				verdict: final_verdict,
			},
		)
		.await
		.context("POSTing buffered verdict to /v1/jobs/:id/verdict")?;
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
		let v = tool_definitions(true, false);
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
	fn tool_catalogue_exposes_loupe_protocol_version() {
		for v in [tool_definitions(true, false), tool_definitions(true, true)] {
			for t in v.as_array().expect("tools must serialise as an array") {
				let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("<unnamed>");
				let version = t
					.pointer("/inputSchema/properties/protocol_version/const")
					.and_then(Value::as_u64);
				assert_eq!(
					version,
					Some(u64::from(LOUPE_MCP_PROTOCOL_VERSION)),
					"{name} must expose the Loupe MCP tool protocol version",
				);
			}
		}
	}

	#[test]
	fn tool_protocol_version_check_is_backward_compatible_but_rejects_mismatch() {
		check_tool_protocol_version(&json!({})).expect("missing version remains accepted");
		check_tool_protocol_version(&json!({ "protocol_version": LOUPE_MCP_PROTOCOL_VERSION }))
			.expect("current version accepted");
		let err = check_tool_protocol_version(
			&json!({ "protocol_version": LOUPE_MCP_PROTOCOL_VERSION + 1 }),
		)
		.expect_err("future version must be rejected by this worker");
		assert!(err.to_string().contains("unsupported"), "got: {err}");
	}

	#[test]
	fn submit_finding_only_appears_when_job_id_is_set() {
		let with = tool_definitions(true, false);
		let names: Vec<&str> =
			with.as_array().unwrap().iter().filter_map(|t| t.get("name")?.as_str()).collect();
		assert!(names.contains(&"submit_finding"), "got: {names:?}");

		let without = tool_definitions(false, false);
		let names: Vec<&str> =
			without.as_array().unwrap().iter().filter_map(|t| t.get("name")?.as_str()).collect();
		assert!(!names.contains(&"submit_finding"), "got: {names:?}");
		// Read-only tools always advertised.
		assert!(names.contains(&"query_prior_findings"));
		assert!(names.contains(&"get_finding_by_id"));
	}

	fn fake_session_for_verify(finding_id: i64) -> Arc<Session> {
		// `submit_verdict` / `submit_patch` only buffer locally; they
		// don't hit the network until `flush_verify_session` runs at
		// session end. So a no-op ServerClient (default reqwest +
		// any URL) is fine for the locking tests below.
		let client = Arc::new(ServerClient::from_parts(
			reqwest::Client::new(),
			"http://invalid.example/".parse().unwrap(),
		));
		Arc::new(Session {
			client,
			repo_id: 1,
			job_id: Some(42),
			workdir: tempfile::tempdir().unwrap().keep(),
			verify: Some(VerifySessionState {
				finding_id,
				inner: tokio::sync::Mutex::new(VerifySessionInner::default()),
			}),
		})
	}

	#[tokio::test]
	async fn submit_verdict_locks_after_first_call() {
		let session = fake_session_for_verify(7);
		let first =
			tool_submit_verdict(&session, &json!({ "verdict": "confirmed", "notes": "real bug" }))
				.await
				.expect("first verdict accepted");
		assert!(first.contains("locked"), "first call must report the lock; got: {first}");

		let err = tool_submit_verdict(
			&session,
			&json!({ "verdict": "dismissed", "notes": "second thoughts" }),
		)
		.await
		.expect_err("second verdict must be rejected");
		assert!(
			err.to_string().contains("already locked"),
			"second call must mention the lock; got: {err}"
		);
	}

	#[tokio::test]
	async fn submit_patch_requires_a_prior_confirmed_verdict() {
		let session = fake_session_for_verify(7);
		// No verdict yet → patch must be rejected.
		let err = tool_submit_patch(
			&session,
			&json!({
				"patch_unified": "--- a/x\n+++ b/x\n@@\n-old\n+new\n",
				"notes": "fix"
			}),
		)
		.await
		.expect_err("patch before verdict must be rejected");
		assert!(
			err.to_string().contains("submit_verdict") || err.to_string().contains("verdict"),
			"got: {err}"
		);

		// Dismissed verdict → patch still rejected (patches only ride
		// on confirmed verdicts).
		tool_submit_verdict(
			&session,
			&json!({ "verdict": "dismissed", "notes": "false positive" }),
		)
		.await
		.expect("verdict accepted");
		let err = tool_submit_patch(
			&session,
			&json!({
				"patch_unified": "--- a/x\n+++ b/x\n@@\n-old\n+new\n",
				"notes": "fix"
			}),
		)
		.await
		.expect_err("patch after dismissed must be rejected");
		assert!(
			err.to_string().to_lowercase().contains("confirmed"),
			"error must mention the `confirmed` requirement; got: {err}"
		);
	}

	#[test]
	fn verify_mode_swaps_the_tool_catalog() {
		// Discovery and verify expose disjoint write surfaces. If a
		// future refactor accidentally leaves both on at once, a
		// verifier agent could call submit_finding (no `--job-id` for
		// discovery) and a discovery agent could call submit_verdict
		// (verdict POSTs would 400 server-side, but the prompt would
		// be confused). Pin the disjointness here.
		let verify = tool_definitions(true, true);
		let verify_names: Vec<&str> =
			verify.as_array().unwrap().iter().filter_map(|t| t.get("name")?.as_str()).collect();
		assert!(verify_names.contains(&"submit_verdict"), "got: {verify_names:?}");
		assert!(verify_names.contains(&"submit_patch"), "got: {verify_names:?}");
		assert!(verify_names.contains(&"validate_patch"), "got: {verify_names:?}");
		assert!(!verify_names.contains(&"submit_finding"), "got: {verify_names:?}");
		assert!(!verify_names.contains(&"validate_poc"), "got: {verify_names:?}");
		// Read-only tools stay on in verify mode too — useful to
		// cross-check the bug under review against prior findings.
		assert!(verify_names.contains(&"query_prior_findings"));
		assert!(verify_names.contains(&"get_finding_by_id"));

		let discovery = tool_definitions(true, false);
		let discovery_names: Vec<&str> =
			discovery.as_array().unwrap().iter().filter_map(|t| t.get("name")?.as_str()).collect();
		assert!(!discovery_names.contains(&"submit_verdict"));
		assert!(!discovery_names.contains(&"submit_patch"));
		assert!(!discovery_names.contains(&"validate_patch"));
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
	fn build_finding_rejects_path_traversal() {
		let workdir = tempfile::tempdir().unwrap();
		let args = json!({
			"severity": "low",
			"title": "t",
			"file": "../outside.rs",
			"line_start": 1,
			"line_end": 1,
			"description": "d",
			"poc_unified": "x",
		});
		let err = build_finding_from_args(workdir.path(), &args).expect_err("must fail");
		assert!(err.to_string().contains(".."), "got: {err}");
	}

	#[test]
	fn build_finding_rejects_host_absolute_paths() {
		let workdir = tempfile::tempdir().unwrap();
		std::fs::create_dir_all(workdir.path().join("src")).unwrap();
		let host_path = workdir.path().join("src/lib.rs");
		std::fs::write(&host_path, "fn x() {}\n").unwrap();
		let args = json!({
			"severity": "low",
			"title": "t",
			"file": host_path.to_string_lossy(),
			"line_start": 1,
			"line_end": 1,
			"description": "d",
			"poc_unified": "x",
		});
		let err = build_finding_from_args(workdir.path(), &args).expect_err("must fail");
		assert!(err.to_string().contains("repo-relative"), "got: {err}");
	}

	#[cfg(unix)]
	#[test]
	fn build_finding_rejects_symlink_escape() {
		let workdir = tempfile::tempdir().unwrap();
		std::fs::create_dir_all(workdir.path().join("src")).unwrap();
		let outside = tempfile::tempdir().unwrap();
		let outside_file = outside.path().join("outside.rs");
		std::fs::write(&outside_file, "fn outside() {}\n").unwrap();
		std::os::unix::fs::symlink(&outside_file, workdir.path().join("src/link.rs")).unwrap();

		let args = json!({
			"severity": "low",
			"title": "t",
			"file": "src/link.rs",
			"line_start": 1,
			"line_end": 1,
			"description": "d",
			"poc_unified": "x",
		});
		let err = build_finding_from_args(workdir.path(), &args).expect_err("must fail");
		assert!(err.to_string().contains("outside the workdir"), "got: {err}");
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
		let result =
			tool_validate_diff(workdir.path(), &args, "poc_unified").await.expect("tool ok");
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
		let result =
			tool_validate_diff(workdir.path(), &args, "poc_unified").await.expect("tool ok");
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
		let result =
			tool_validate_diff(workdir.path(), &args, "poc_unified").await.expect("tool ok");
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
			let v = tool_definitions(enabled, false);
			let names: Vec<&str> =
				v.as_array().unwrap().iter().filter_map(|t| t.get("name")?.as_str()).collect();
			assert!(
				names.contains(&"validate_poc"),
				"submissions_enabled={enabled}, got: {names:?}"
			);
		}
	}
}
