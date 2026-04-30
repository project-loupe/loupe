//! MCP server exposed to the agent (`claude` and friends) for the
//! duration of a single discovery / validation call.
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

use std::io::{BufRead, Write};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::ServerClient;

/// Identity emitted on `initialize`. The version is the loupe-worker
/// build's protocol intent, not a release version — bumping it is a
/// signal to the agent that the tool surface changed.
const SERVER_NAME: &str = "loupe-mcp";
const SERVER_VERSION: &str = "0.1.0";

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

#[derive(Debug, Serialize)]
struct RpcError {
	code: i64,
	message: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	data: Option<Value>,
}

/// Run the MCP server against `client` until stdin closes.
///
/// `repo_id` is baked into the server because the agent only ever
/// reasons about the repo currently being scanned — there's no
/// cross-repo lookup. The connection target (the loupe-server URL,
/// mTLS cert) is similarly fixed at MCP-server start; tool calls
/// don't re-specify it.
pub async fn run_stdio_server(client: Arc<ServerClient>, repo_id: i64) -> Result<()> {
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
				let err = Response {
					jsonrpc: "2.0",
					id: Value::Null,
					result: None,
					error: Some(RpcError {
						code: -32700,
						message: format!("parse error: {e}"),
						data: None,
					}),
				};
				write_response(&mut stdout, &err)?;
				continue;
			},
		};

		// Notifications (no `id`) require no response per JSON-RPC.
		let Some(id) = request.id.clone() else { continue };

		let response = handle_request(&client, repo_id, &request, id).await;
		write_response(&mut stdout, &response)?;
	}

	Ok(())
}

async fn handle_request(
	client: &Arc<ServerClient>, repo_id: i64, req: &Request, id: Value,
) -> Response {
	match req.method.as_str() {
		"initialize" => Response {
			jsonrpc: "2.0",
			id,
			result: Some(json!({
				"protocolVersion": "2024-11-05",
				"capabilities": { "tools": { "listChanged": false } },
				"serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
			})),
			error: None,
		},
		"tools/list" => Response {
			jsonrpc: "2.0",
			id,
			result: Some(json!({ "tools": tool_definitions() })),
			error: None,
		},
		"tools/call" => handle_tool_call(client, repo_id, req, id).await,
		// Common no-op MCP notifications/requests we just ack.
		"notifications/initialized" | "ping" => {
			Response { jsonrpc: "2.0", id, result: Some(json!({})), error: None }
		},
		other => Response {
			jsonrpc: "2.0",
			id,
			result: None,
			error: Some(RpcError {
				code: -32601,
				message: format!("method not found: {other}"),
				data: None,
			}),
		},
	}
}

/// MCP tool catalogue. Each entry is the JSON Schema the agent uses
/// to decide when to call the tool and what shape arguments to send.
fn tool_definitions() -> Value {
	json!([
		{
			"name": "query_prior_findings",
			"description":
				"Keyword search over prior security findings on the repo currently being scanned. \
				 Use this to check whether a vulnerability you're about to report has already been \
				 surfaced in an earlier scan — same bug, possibly different wording. Returns up to \
				 `limit` matches ranked by relevance, with the title, severity, file location, \
				 state (e.g. 'reported', 'awaiting_approval', 'dismissed'), and finding id of each. \
				 If a match looks like the same vulnerability you're investigating, mention the \
				 matching id in your finding's description and consider whether emitting a fresh \
				 finding adds value beyond re-confirming the existing one.",
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
		},
		{
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
		},
	])
}

async fn handle_tool_call(
	client: &Arc<ServerClient>, repo_id: i64, req: &Request, id: Value,
) -> Response {
	let params = req.params.as_ref();
	let tool_name = params.and_then(|p| p.get("name")).and_then(|n| n.as_str()).unwrap_or("");
	let arguments = params
		.and_then(|p| p.get("arguments"))
		.cloned()
		.unwrap_or_else(|| Value::Object(serde_json::Map::new()));

	let result: Result<String> = match tool_name {
		"query_prior_findings" => tool_query_prior_findings(client, repo_id, &arguments).await,
		"get_finding_by_id" => tool_get_finding_by_id(client, &arguments).await,
		other => Err(anyhow::anyhow!("unknown tool: {other}")),
	};

	match result {
		Ok(text) => Response {
			jsonrpc: "2.0",
			id,
			result: Some(json!({ "content": [{ "type": "text", "text": text }] })),
			error: None,
		},
		Err(e) => {
			tracing::warn!(tool = tool_name, error = %e, "loupe-mcp: tool call failed");
			Response {
				jsonrpc: "2.0",
				id,
				// MCP convention: tool errors flow through `result`
				// with `isError: true`, not the JSON-RPC `error` field
				// (which is reserved for protocol-level failures).
				result: Some(json!({
					"content": [{ "type": "text", "text": format!("Error: {e}") }],
					"isError": true,
				})),
				error: None,
			}
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
	let loc = match (detail.file_path.as_deref(), detail.line_start, detail.line_end) {
		(Some(p), Some(s), Some(e)) if e > s => format!("{p}:{s}-{e}"),
		(Some(p), Some(s), _) => format!("{p}:{s}"),
		(Some(p), None, _) => p.to_owned(),
		_ => "(no location)".into(),
	};
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
	let query = args
		.get("query")
		.and_then(|v| v.as_str())
		.context("`query` argument is required and must be a string")?;
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
		let loc = match (f.file_path.as_deref(), f.line_start) {
			(Some(p), Some(l)) => format!("{p}:{l}"),
			(Some(p), None) => p.to_owned(),
			_ => "(no location)".into(),
		};
		out.push_str(&format!(
			"- #{} [{:?}] state={} {} — {}\n",
			f.id, f.severity, f.state, loc, f.title,
		));
	}
	Ok(out)
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
		let v = tool_definitions();
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
}
