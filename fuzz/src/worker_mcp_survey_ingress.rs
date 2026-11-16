//! The actual survey-catalog MCP decoder over original Sandbox records:
//! Agent carries stay inside the record, rejected arguments never echo their
//! content, and admitted arguments always serialize as a valid phase request.
use loupe_worker::mcp::fuzz_support::observe_survey_record;

use crate::utils::test_logger;

const SENTINEL: &str = "zq9sentinel";
const TOOLS: [&str; 9] = [
	"get_job_limits",
	"publish_profile",
	"propose_review_unit",
	"submit_lead",
	"submit_review_unit_result",
	"submit_inventory_disposition",
	"query_same_project_lead_candidates",
	"finalize_survey",
	"submit_finding",
];
const FIELDS: [&str; 24] = [
	"client_review_unit_key",
	"title",
	"objective",
	"priority_band",
	"source_refs",
	"client_lead_key",
	"identity_family",
	"identity_anchor",
	"hypothesis",
	"next_proof_step",
	"counterevidence",
	"proof_gaps",
	"review_unit_id",
	"client_result_key",
	"disposition",
	"inspected_refs",
	"client_inventory_disposition_key",
	"path",
	"reason",
	"mapped_review_unit_ids",
	"query",
	"limit",
	"terminal_reason",
	"profile",
];

/// A structured record whose every string carries the sentinel.
fn structured(data: &[u8]) -> Vec<u8> {
	let tool = TOOLS[usize::from(data.first().copied().unwrap_or(0)) % TOOLS.len()];
	let mut members = Vec::new();
	for chunk in data.get(1..).unwrap_or_default().chunks(3) {
		let field = FIELDS[usize::from(chunk[0]) % FIELDS.len()];
		let length = usize::from(chunk.get(1).copied().unwrap_or(0)) * 24;
		let text = format!("{SENTINEL}{}", "a".repeat(length));
		let value = match chunk.get(2).copied().unwrap_or(0) % 8 {
			0 => format!("{text:?}"),
			1 => format!("[{{\"path\":{text:?}}}]"),
			2 => format!("{{\"k\":{text:?}}}"),
			3 => "[4,5]".to_owned(),
			4 => "7".to_owned(),
			5 => "\"mapped\"".to_owned(),
			6 => "\"high\"".to_owned(),
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
	let observed = observe_survey_record(&record);
	for span in &observed.agent_spans {
		assert!(record.get(span.clone()).is_some(), "Agent carry escaped the original record");
	}
	let Some((tool, arguments)) = observed.decoded else { return };
	if tool == "unknown" || tool == "submit_finding" {
		assert!(arguments.is_err(), "a name outside the survey catalog decoded arguments");
	}
	if let Err(error) = arguments {
		assert!(!error.contains(SENTINEL), "argument error echoed Agent content: {error}");
		for span in &observed.agent_spans {
			let token = &record[span.clone()];
			let inner =
				token.strip_prefix(b"\"").and_then(|t| t.strip_suffix(b"\"")).unwrap_or(token);
			if inner.len() >= 12 {
				let inner = String::from_utf8_lossy(inner);
				assert!(!error.contains(&*inner), "argument error echoed an Agent token: {error}");
			}
		}
	}
}

pub fn worker_mcp_survey_ingress_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}
/// # Safety
/// The caller supplies `len` readable bytes at `data` for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_mcp_survey_ingress_run(data: *const u8, len: usize) {
	// SAFETY: the C runner guarantees the readable input buffer.
	do_test(unsafe { std::slice::from_raw_parts(data, len) });
}

#[cfg(test)]
mod tests {
	#[test]
	fn structured_records_cover_every_tool() {
		for tool in 0..9u8 {
			for field in 0..24u8 {
				for shape in 0..8u8 {
					super::do_test(&[1, tool, field, 1, shape, field, 0, shape]);
				}
			}
		}
	}
	#[test]
	fn raw_records_hold_the_invariants() {
		for record in [
			&br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_job_limits","arguments":{}}}"#[..],
			br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"finalize_survey","arguments":{"terminal_reason":"completed"}}}"#,
			br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"submit_lead","arguments":{"client_lead_key":"zq9sentinel-long-key!"}}}"#,
			b"{",
		] {
			let mut data = vec![0];
			data.extend_from_slice(record);
			super::do_test(&data);
		}
	}
}
