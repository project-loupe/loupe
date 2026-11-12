//! Byte zero selects Impact, Access or Reachability; the rest is one UTF-8
//! JSON value placed as that field of a priority proposal inside otherwise
//! fixed lead evidence, the agent ingress that decodes these values. The
//! oracle is the closed snake_case vocabulary of each proposal type:
//! exactly the listed JSON strings are admitted, and each re-serializes
//! with its own spelling.

use loupe_core::review_payload::LeadEvidenceV1;
use loupe_provenance::Agent;
use serde_json::{json, Value};

use crate::utils::test_logger;

const FIELDS: [(&str, &[&str]); 3] = [
	("impact", &["low", "medium", "high", "critical"]),
	("access", &["privileged", "local", "remote"]),
	("reachability", &["plausible", "traced"]),
];

pub fn do_test(data: &[u8]) {
	let Some((&selector, bytes)) = data.split_first() else { return };
	let Ok(raw) = std::str::from_utf8(bytes) else { return };
	let Ok(value) = serde_json::from_str::<Value>(raw) else { return };
	let (field, vocabulary) = FIELDS[usize::from(selector) % FIELDS.len()];
	let expected = match &value {
		Value::String(word) => vocabulary.contains(&word.as_str()).then_some(word.as_str()),
		_ => None,
	};
	let mut proposal = json!({
		"impact": "high", "access": "remote", "reachability": "traced",
		"boundary_refs": [{"path": "src/lib.rs"}], "rationale": "reachable boundary",
	});
	proposal[field] = Value::Null;
	let template = json!({
		"format": "loupe.lead_evidence", "version": 1,
		"identity_family": "auth-bypass", "identity_anchor": "token boundary",
		"hypothesis": "untrusted token reaches a privileged sink",
		"source_refs": [{"path": "src/lib.rs"}],
		"next_proof_step": "trace the wrapper", "counterevidence": "none",
		"proof_gaps": "none", "priority_proposal": proposal,
	})
	.to_string();
	let placeholder = format!("\"{field}\":null");
	let document = template.replacen(&placeholder, &format!("\"{field}\":{raw}"), 1);
	assert!(template.contains(&placeholder), "the template must hold the fuzzed field");
	let decoded = crate::fixtures::agent(&document, |mark, raw| {
		LeadEvidenceV1::<Agent>::from_json(mark, raw)
	});
	assert_eq!(decoded.is_ok(), expected.is_some(), "priority vocabulary disagrees with oracle");
	if let (Ok(lead), Some(word)) = (decoded, expected) {
		let wire =
			serde_json::to_value(&lead).unwrap_or_else(|_| panic!("accepted lead serializes"));
		assert_eq!(wire["priority_proposal"][field], Value::from(word), "spelling must round-trip");
	}
}

pub fn core_review_priority_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn core_review_priority_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
