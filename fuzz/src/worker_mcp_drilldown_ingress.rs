//! The actual drilldown-catalog MCP decoder over original Sandbox records:
//! Agent carries stay inside the record, rejected arguments never echo their
//! content, nested finalize objects admit only their own members, and
//! admitted arguments always serialize as a valid phase request.
use loupe_worker::mcp::fuzz_support::observe_drilldown_record;

use crate::utils::test_logger;

const SENTINEL: &str = "zq9sentinel";
const FIXED_ERRORS: [&str; 2] = ["unknown argument for this tool", "unknown tool"];
const TOOLS: [&str; 6] = [
	"get_job_limits",
	"query_same_project_lead_candidates",
	"submit_sibling_lead",
	"finalize_drilldown",
	"submit_lead",
	"finalize_survey",
];
const FIELDS: [&str; 24] = [
	"disposition",
	"promotion",
	"counterargument",
	"explanation",
	"target",
	"rationale",
	"reason",
	"continuation",
	"retry_explanation",
	"revalidation",
	"source_refs",
	"client_lead_key",
	"identity_family",
	"identity_anchor",
	"hypothesis",
	"next_proof_step",
	"counterevidence",
	"proof_gaps",
	"review_unit_id",
	"version",
	"query",
	"limit",
	"argument",
	"current_source_refs",
];
const DISPOSITIONS: [&str; 5] = ["promote", "reject", "duplicate", "hardening", "defer"];

/// A structured record whose every string carries the sentinel.
fn structured(data: &[u8]) -> Vec<u8> {
	let tool = TOOLS[usize::from(data.first().copied().unwrap_or(0)) % TOOLS.len()];
	let mut members = Vec::new();
	for chunk in data.get(1..).unwrap_or_default().chunks(3) {
		let field = FIELDS[usize::from(chunk[0]) % FIELDS.len()];
		let length = usize::from(chunk.get(1).copied().unwrap_or(0)) * 24;
		let text = format!("{SENTINEL}{}", "a".repeat(length));
		let shape = chunk.get(2).copied().unwrap_or(0);
		let value = match shape % 10 {
			0 => format!("{text:?}"),
			1 => format!("[{{\"path\":{text:?}}}]"),
			2 => format!("{{\"argument\":{text:?},\"source_refs\":[{{\"path\":\"a.rs\"}}]}}"),
			3 => format!("{{\"kind\":\"lead\",\"id\":{}}}", shape / 10),
			4 => "7".to_owned(),
			5 => format!("{:?}", DISPOSITIONS[usize::from(shape / 10) % DISPOSITIONS.len()]),
			6 => "\"source_analysis_remaining\"".to_owned(),
			7 => promotion(&text, shape / 10),
			8 => format!(
				"{{\"current_source_refs\":[{{\"path\":\"a.rs\"}}],\"rationale\":{text:?}}}"
			),
			_ => "null".to_owned(),
		};
		members.push(format!("{field:?}:{value}"));
	}
	format!(
		r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{tool}","arguments":{{{}}}}}}}"#,
		members.join(",")
	)
	.into_bytes()
}

/// A promotion object, complete except for one variation chosen by `pick`.
fn promotion(text: &str, pick: u8) -> String {
	let extra = match pick % 4 {
		0 => String::new(),
		1 => ",\"version\":1".to_owned(),
		2 => format!(",\"cwe\":{text:?}"),
		_ => ",\"owner\":1".to_owned(),
	};
	format!(
		r#"{{"severity":"high","title":{text:?},"description":"d","identity_family":"memory-safety","identity_anchor":"a","evidence":{{"l2_argument":{{"attacker_source":"s","control":"c","sink":"k","reachable_path":"p","trust_boundary":"b"}},"material_locations":[{{"role":"sink","file":"a.rs","line_start":{},"line_end":2}}],"counterevidence":"c","assumptions_gaps":"g","confidence":"low"}}{extra}}}"#,
		pick % 3
	)
}

pub fn do_test(data: &[u8]) {
	if data.len() > 65_536 {
		return;
	}
	let record = match data.first().copied().unwrap_or(0) % 2 {
		0 => data.get(1..).unwrap_or_default().to_vec(),
		_ => structured(data.get(1..).unwrap_or_default()),
	};
	if record.contains(&b'\n') {
		return;
	}
	let observed = observe_drilldown_record(&record);
	for span in &observed.agent_spans {
		assert!(record.get(span.clone()).is_some(), "Agent carry escaped the original record");
	}
	let Some((tool, arguments)) = observed.decoded else { return };
	if tool == "unknown" || tool == "submit_lead" || tool == "finalize_survey" {
		assert!(arguments.is_err(), "a name outside the drilldown catalog decoded arguments");
	}
	if let Err(error) = arguments {
		assert!(!error.contains(SENTINEL), "argument error echoed Agent content: {error}");
		if FIXED_ERRORS.contains(&error.as_str()) {
			return;
		}
		// A raw token may spell part of a fixed text by chance, so an echo
		// is detected through filler: overwrite one token and look for the
		// filler in the error.
		for span in &observed.agent_spans {
			if span.len() < 14 {
				continue;
			}
			if let Some(masked) = error_with_masked(&record, span) {
				let filler = "q".repeat(span.len() - 2);
				assert!(
					!masked.contains(&filler),
					"argument error echoed an Agent token: {masked}"
				);
			}
		}
	}
}

/// The decoder's error for `record` with the content of the quoted token at
/// `span` replaced by lowercase filler of the same length.
fn error_with_masked(record: &[u8], span: &std::ops::Range<usize>) -> Option<String> {
	let mut masked = record.to_vec();
	let token = masked.get_mut(span.clone())?;
	if token.len() < 2 || token[0] != b'"' || token[token.len() - 1] != b'"' {
		return None;
	}
	let end = token.len() - 1;
	token[1..end].fill(b'q');
	match observe_drilldown_record(&masked).decoded {
		Some((_, Err(error))) => Some(error),
		_ => None,
	}
}

pub fn worker_mcp_drilldown_ingress_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}
/// # Safety
/// The caller supplies `len` readable bytes at `data` for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_mcp_drilldown_ingress_run(data: *const u8, len: usize) {
	// SAFETY: the C runner guarantees the readable input buffer.
	do_test(unsafe { std::slice::from_raw_parts(data, len) });
}

#[cfg(test)]
mod tests {
	#[test]
	fn structured_records_cover_every_tool() {
		for tool in 0..6u8 {
			for field in 0..24u8 {
				for shape in 0..40u8 {
					super::do_test(&[1, tool, field, 1, shape, field, 0, shape]);
				}
			}
		}
	}
	#[test]
	fn raw_records_hold_the_invariants() {
		for record in [
			&br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_job_limits","arguments":{}}}"#[..],
			br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"finalize_drilldown","arguments":{"disposition":"defer","reason":"r","continuation":"external_dependency"}}}"#,
			br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"finalize_drilldown","arguments":{"disposition":"reject","counterargument":{"argument":"zq9sentinel-long-argument","source_refs":[]}}}}"#,
			br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"submit_sibling_lead","arguments":{"client_lead_key":"zq9sentinel-long-key!"}}}"#,
			br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"finalize_drilldown","arguments":{"disposition":"reject","owner":"known argument for this tool"}}}"#,
			br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"finalize_drilldown","arguments":{"disposition":"reject","counterargument":{"source_refs":[],"argument":"t` argument is require"}}}}"#,
			b"{",
		] {
			let mut data = vec![0];
			data.extend_from_slice(record);
			super::do_test(&data);
		}
	}
}
