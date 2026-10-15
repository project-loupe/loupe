//! Independent JSON-RPC/schema and field oracle. Value traversal starts at the
//! full envelope depth; a field-policy refusal skips params via IgnoredAny.
use std::collections::HashMap;

use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{json, Value};

use crate::worker_client_ingress::oracle::{self, TEXT_LIMIT};

#[derive(Deserialize)]
struct RawEnvelope<'a> {
	#[serde(rename = "jsonrpc")]
	_jsonrpc: String,
	#[serde(borrow)]
	id: Option<&'a RawValue>,
	method: String,
	#[serde(borrow)]
	params: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct LegacyEnvelope {
	#[serde(rename = "jsonrpc")]
	_jsonrpc: String,
	id: Option<Value>,
	method: String,
	#[serde(rename = "params")]
	_params: Option<Value>,
}
#[derive(Deserialize)]
struct RejectedFieldEnvelope {
	#[serde(rename = "jsonrpc")]
	_jsonrpc: String,
	id: Option<Value>,
	method: String,
	#[serde(rename = "params")]
	_params: Option<serde::de::IgnoredAny>,
}
pub(crate) struct Request {
	pub id: Option<Value>,
	pub method: String,
	pub tool: String,
	pub arguments: Result<Value, bool>,
}
type Fields<'a> = HashMap<String, &'a RawValue>;
fn fields(raw: Option<&RawValue>) -> Result<Fields<'_>, bool> {
	match raw {
		Some(raw) if raw.get().starts_with('{') => {
			serde_json::from_str(raw.get()).map_err(|_| false)
		},
		_ => Ok(HashMap::new()),
	}
}
fn string(raw: Option<&&RawValue>) -> Result<String, bool> {
	serde_json::from_str(raw.ok_or(false)?.get()).map_err(|_| false)
}
fn scalar(raw: Option<&&RawValue>) -> Result<Value, bool> {
	serde_json::from_str(raw.ok_or(false)?.get()).map_err(|_| false)
}

/// Count encoded JSON units with a u128 byte accumulator. On admitted-size
/// tokens serde independently supplies exact decoded bytes and syntax checks.
fn bounded(raw: Option<&&RawValue>, multiline: Option<bool>) -> Result<String, bool> {
	let token = raw.ok_or(false)?.get();
	let text = token.strip_prefix('"').and_then(|s| s.strip_suffix('"')).ok_or(false)?;
	let mut chars = text.chars();
	let mut bytes = 0u128;
	while let Some(ch) = chars.next() {
		let size = if ch != '\\' {
			ch.len_utf8()
		} else {
			match chars.next().ok_or(false)? {
				'"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' => 1,
				'u' => {
					let mut digits = String::new();
					for _ in 0..4 {
						digits.push(chars.next().ok_or(false)?);
					}
					let first = u32::from_str_radix(&digits, 16).map_err(|_| false)?;
					if (0xd800..=0xdbff).contains(&first) {
						if chars.next() != Some('\\') || chars.next() != Some('u') {
							return Err(false);
						}
						let mut digits = String::new();
						for _ in 0..4 {
							digits.push(chars.next().ok_or(false)?);
						}
						let second = u32::from_str_radix(&digits, 16).map_err(|_| false)?;
						if !(0xdc00..=0xdfff).contains(&second) {
							return Err(false);
						}
						4
					} else {
						char::from_u32(first).ok_or(false)?.len_utf8()
					}
				},
				_ => return Err(false),
			}
		};
		bytes += size as u128;
		if bytes > TEXT_LIMIT as u128 {
			return Err(true);
		}
	}
	let decoded: String = serde_json::from_str(token).map_err(|_| false)?;
	if multiline.is_some_and(|multi| !oracle::text(&decoded, multi)) {
		return Err(true);
	}
	Ok(decoded)
}
pub(crate) fn normalized_path(file: &str) -> Result<String, bool> {
	let file = file.strip_prefix("/workdir/").unwrap_or(file);
	let parts: Vec<_> = file.split('/').filter(|part| !part.is_empty() && *part != ".").collect();
	if file.trim().is_empty() || file.starts_with('/') || parts.is_empty() || parts.contains(&"..")
	{
		return Err(false);
	}
	let path = parts.join("/");
	if !oracle::path(&path) {
		return Err(true);
	}
	Ok(path)
}
fn arguments(name: &str, raw: Option<&RawValue>) -> Result<Value, bool> {
	let f = fields(raw)?;
	if f.contains_key("protocol_version") && scalar(f.get("protocol_version"))?.as_u64() != Some(1)
	{
		return Err(false);
	}
	match name {
		"query_prior_findings" => {
			let query = bounded(f.get("query"), Some(true))?;
			let limit = if f.contains_key("limit") {
				scalar(f.get("limit"))?.as_i64().unwrap_or(20)
			} else {
				20
			};
			Ok(json!({"query":query,"limit":limit.clamp(1,100)}))
		},
		"get_finding_by_id" => {
			let raw = f.get("id").ok_or(false)?;
			let id = if raw.get().starts_with('"') {
				let text = bounded(Some(raw), None)?;
				text.strip_prefix("LUP-")
					.and_then(|digits| digits.parse::<i64>().ok())
					.filter(|id| format!("LUP-{id}") == text)
			} else {
				scalar(Some(raw))?.as_i64()
			};
			Ok(json!({"id":id.filter(|id|*id>0).ok_or(false)?}))
		},
		"submit_finding" => {
			let severity = string(f.get("severity"))?;
			if !["info", "low", "medium", "high", "critical"].contains(&severity.as_str()) {
				return Err(false);
			}
			let title = bounded(f.get("title"), Some(false))?;
			let file = normalized_path(&bounded(f.get("file"), None)?)?;
			let start = scalar(f.get("line_start"))?.as_u64().ok_or(false)?.min(u32::MAX as u64);
			let end = scalar(f.get("line_end"))?.as_u64().ok_or(false)?.min(u32::MAX as u64);
			let description = bounded(f.get("description"), Some(true))?;
			let poc = bounded(f.get("poc_unified"), Some(true))?;
			let cwe = match f.get("cwe").filter(|t| t.get().starts_with('"')) {
				Some(raw) => {
					let text = bounded(Some(raw), Some(false))?;
					(!text.is_empty()).then_some(text)
				},
				None => None,
			};
			Ok(
				json!({"severity":severity,"title":title,"file":file,"line_start":start,"line_end":end,"description":description,"poc_unified":poc,"cwe":cwe}),
			)
		},
		"validate_poc" => Ok(json!({"poc_unified":bounded(f.get("poc_unified"),Some(true))?})),
		"validate_patch" => {
			Ok(json!({"patch_unified":bounded(f.get("patch_unified"),Some(true))?}))
		},
		"submit_patch" => {
			let patch = bounded(f.get("patch_unified"), Some(true))?;
			let notes = bounded(f.get("notes"), Some(true))?;
			Ok(json!({"patch_unified":patch,"notes":notes}))
		},
		"submit_verdict" => {
			let verdict = string(f.get("verdict"))?;
			// Notes presence/type is checked before the closed verdict choice.
			if !f.get("notes").is_some_and(|token| token.get().starts_with('"')) {
				return Err(false);
			}
			if !["confirmed", "dismissed", "inconclusive"].contains(&verdict.as_str()) {
				return Err(false);
			}
			let notes = bounded(f.get("notes"), Some(true))?;
			let mut out = json!({"verdict":verdict,"notes":notes});
			if verdict == "inconclusive" {
				out["terminal"] = json!(false);
			}
			Ok(out)
		},
		_ => Err(false),
	}
}
pub(crate) fn request(original: &str) -> Result<Request, ()> {
	let raw: RawEnvelope<'_> = serde_json::from_str(original).map_err(|_| ())?;
	let params = fields(raw.params).map_err(|_| ())?;
	let name = match params.get("name").filter(|raw| raw.get().starts_with('"')) {
		Some(raw) => string(Some(raw)).map_err(|_| ())?,
		None => String::new(),
	};
	let args = if raw.method == "tools/call" && raw.id.is_some() {
		arguments(&name, params.get("arguments").copied())
	} else {
		Err(false)
	};
	let (id, method) = if args == Err(true) {
		let parsed: RejectedFieldEnvelope = serde_json::from_str(original).map_err(|_| ())?;
		(parsed.id, parsed.method)
	} else {
		let parsed: LegacyEnvelope = serde_json::from_str(original).map_err(|_| ())?;
		(parsed.id, parsed.method)
	};
	Ok(Request { id, method, tool: name, arguments: args })
}

pub(crate) fn arguments_admitted(name: &str, args: &Value) -> bool {
	let original =
		serde_json::to_string(args).unwrap_or_else(|error| panic!("fixture args: {error}"));
	let token: &RawValue =
		serde_json::from_str(&original).unwrap_or_else(|error| panic!("fixture token: {error}"));
	arguments(name, Some(token)).is_ok()
}
