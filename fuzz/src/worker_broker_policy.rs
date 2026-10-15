//! Raw body bytes exercise both provider policies, header names/Connection
//! declarations, and a bounded sequence of output reservations without I/O.

use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use loupe_worker::llm::model_broker::{fuzzing, ModelBrokerBackend};
use serde_json::Value;

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	if data.len() > 128 * 1024 {
		return;
	}
	for claude in [true, false] {
		let backend = if claude {
			ModelBrokerBackend::Claude {
				model: loupe_worker::config::ConfiguredText::Builtin("pinned-model"),
				effort: loupe_worker::config::ConfiguredText::Builtin("high"),
			}
		} else {
			ModelBrokerBackend::Codex {
				model: loupe_worker::config::ConfiguredText::Builtin("pinned-model"),
				effort: loupe_worker::config::ConfiguredText::Builtin("high"),
			}
		};
		let original = serde_json::from_slice::<Value>(data).ok();
		let expected = original.as_ref().is_some_and(|value| policy_allows(value, claude));
		let actual = fuzzing::request_policy(data, &backend);
		assert_eq!(actual.is_ok(), expected, "broker policy acceptance differs from oracle");
		assert_eq!(
			actual.as_ref().err().copied(),
			denial(original.as_ref(), claude),
			"closed denial class/precedence differs"
		);
		if let Ok(body) = actual {
			let value: Value = serde_json::from_slice(&body)
				.unwrap_or_else(|_| panic!("broker emitted invalid JSON"));
			assert_eq!(value["model"], "pinned-model");
			let field = if claude { "output_config" } else { "reasoning" };
			assert_eq!(value[field]["effort"], "high");
			assert!(policy_allows(&value, claude));
			assert_eq!(
				fuzzing::request_policy(&body, &backend),
				Ok(body.clone()),
				"policy rewrite is not idempotent"
			);
			// Rewriting model/effort must preserve every unrelated request field.
			let mut expected = original.unwrap_or(Value::Null);
			expected["model"] = Value::String("pinned-model".into());
			if !expected[field].is_object() {
				expected[field] = serde_json::json!({});
			}
			expected[field]["effort"] = Value::String("high".into());
			assert_eq!(value, expected, "policy rewrite changed unrelated fields");
			if original_matches(data, claude) {
				assert_eq!(body, data, "matching request lost original wire bytes");
			}
		}
	}
	let headers = headers(data);
	for name in headers.keys() {
		let expected = request_denied(name.as_str()) || connection_names(&headers).contains(name);
		assert_eq!(fuzzing::strip_header(name, &headers), expected, "request header strip differs");
	}
	if let Ok(name) = HeaderName::from_bytes(data) {
		assert_eq!(
			fuzzing::strip_header(&name, &headers),
			request_denied(name.as_str()) || connection_names(&headers).contains(&name)
		);
	}
	let words: Vec<u64> =
		data.as_chunks::<8>().0.iter().take(129).copied().map(u64::from_le_bytes).collect();
	let ceiling = words.first().copied().unwrap_or(0);
	let budget = fuzzing::OutputBudget::default();
	let mut total = 0_u128;
	for request in words.iter().skip(1).copied().chain([0, 1, u64::MAX]) {
		let requested = usize::try_from(request).unwrap_or(usize::MAX);
		let expected = (u128::from(ceiling) - total).min(requested as u128);
		assert_eq!(
			budget.reserve(requested, ceiling) as u128,
			expected,
			"output reservation exceeds remaining ceiling"
		);
		total += expected;
		assert_eq!(u128::from(budget.total()), total);
	}
}

fn original_matches(bytes: &[u8], claude: bool) -> bool {
	serde_json::from_slice::<Value>(bytes).ok().is_some_and(|value| {
		value["model"] == "pinned-model"
			&& value[if claude { "output_config" } else { "reasoning" }]["effort"] == "high"
	})
}

fn denial(value: Option<&Value>, claude: bool) -> Option<fuzzing::PolicyError> {
	use fuzzing::PolicyError;
	let Some(object) = value.and_then(Value::as_object) else {
		return Some(PolicyError::InvalidJson);
	};
	if object
		.get("mcp_servers")
		.is_some_and(|servers| servers.as_array().is_none_or(|items| !items.is_empty()))
	{
		return Some(PolicyError::McpServers);
	}
	for tool in object.get("tools").and_then(Value::as_array).into_iter().flatten() {
		if let Some(kind) = tool.get("type").and_then(Value::as_str) {
			if kind == "web_fetch" || kind.starts_with("web_fetch_") {
				return Some(PolicyError::ProviderFetch);
			}
			if !claude && ["mcp", "remote_mcp"].contains(&kind) {
				return Some(PolicyError::RemoteMcp);
			}
		}
	}
	None
}

fn policy_allows(value: &Value, claude: bool) -> bool {
	let Some(object) = value.as_object() else { return false };
	if object
		.get("mcp_servers")
		.is_some_and(|servers| servers.as_array().is_none_or(|items| !items.is_empty()))
	{
		return false;
	}
	!object
		.get("tools")
		.and_then(Value::as_array)
		.into_iter()
		.flatten()
		.filter_map(|tool| tool.get("type").and_then(Value::as_str))
		.any(|kind| {
			kind.split_once('_').is_some_and(|(prefix, tail)| {
				prefix == "web" && (tail == "fetch" || tail.starts_with("fetch_"))
			}) || (!claude && ["mcp", "remote_mcp"].contains(&kind))
		})
}

pub(crate) fn headers(data: &[u8]) -> HeaderMap {
	let mut headers = HeaderMap::new();
	for line in data.split(|byte| *byte == b'\n').take(64) {
		let Some(colon) = line.iter().position(|byte| *byte == b':') else { continue };
		if let (Ok(name), Ok(value)) =
			(HeaderName::from_bytes(&line[..colon]), HeaderValue::from_bytes(&line[colon + 1..]))
		{
			headers.append(name, value);
		}
	}
	headers
}

pub(crate) fn connection_names(headers: &HeaderMap) -> std::collections::HashSet<HeaderName> {
	let mut names = std::collections::HashSet::new();
	for value in headers.get_all("connection") {
		if let Ok(text) = value.to_str() {
			for token in text.split(',') {
				if let Ok(name) = token.trim().parse() {
					names.insert(name);
				}
			}
		}
	}
	names
}

pub(crate) fn hop_by_hop(name: &str) -> bool {
	[
		"connection",
		"keep-alive",
		"proxy-authenticate",
		"proxy-authorization",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade",
	]
	.contains(&name)
}

fn request_denied(name: &str) -> bool {
	["authorization", "cookie", "x-api-key", "host", "content-length"].contains(&name)
		|| hop_by_hop(name)
		|| name.starts_with("proxy-")
}

pub fn worker_broker_policy_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_broker_policy_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	#[test]
	fn fixed_sandbox_request_owner_preserves_denials_and_allowed_bytes() {
		for body in [b"invalid".as_slice(),b"[]",br#"{}"#,br#"{"mcp_servers":[],"tools":[{"type":"web_search"}]}"#,br#"{"mcp_servers":[{}],"tools":[{"type":"web_fetch"}]}"#,br#"{"tools":[{"type":"web_fetch"}]}"#,br#"{"tools":[{"type":"web_fetch_20250910"}]}"#,br#"{"tools":[{"type":"mcp"}]}"#,br#"{"tools":[{"type":"remote_mcp"}]}"#,br#"{ "model":"pinned-model", "output_config":{"effort":"high"}, "reasoning":{"effort":"high"}, "messages":[{"content":"exact"}] }"#] { super::do_test(body); }
	}
}
