//! Byte zero selects the typed evidence payload (bits 0..3) and the mode
//! (bit 7). Free mode: the rest is UTF-8 JSON for that payload's decoder.
//! Sized mode: the next four bytes are a little-endian target length and
//! the harness builds a schema-valid payload of the type whose independent
//! canonical rendering is as close to that length as the fields allow.
//!
//! Oracle (I6, I7): an accepted payload's canonical bytes are the sorted,
//! whitespace-free rendering of themselves, fit the type's `MAX_BYTES`,
//! decode back to an equal value with identical bytes, and hash to
//! BLAKE3-256 of those bytes. A sized payload is accepted iff its canonical
//! length is within the cap; every text field it fills stays within its own
//! policy, so only the aggregate cap can refuse it. For the types whose
//! field limits sum below the aggregate cap, the sized maximum is asserted
//! to stay under the cap, and free mode must never see a byte-cap refusal.

use loupe_core::review_payload::{
	DrilldownTerminalV1, Error, FindingEvidenceV1, LeadEvidenceV1, PromotionV1, SurveyTerminalV1,
	UnitResultPayloadV1, VerificationTerminalV1, EVIDENCE_MAX_BYTES, SURVEY_TERMINAL_MAX_BYTES,
};
use loupe_provenance::{Agent, Mark};
use serde_json::{json, Value};

use crate::utils::input::ByteSource;
use crate::utils::test_logger;

trait Payload: Sized + PartialEq {
	const CAP: usize;
	/// Whether the field limits allow a canonical rendering above `CAP`.
	const CAP_REACHABLE: bool;
	fn from_json(mark: &Mark<'_, Agent>, raw: &str) -> Result<Self, Error>;
	fn canonical_bytes(&self) -> Result<Vec<u8>, Error>;
	fn digest(&self) -> Result<[u8; 32], Error>;
	fn maximal() -> Value;
}

macro_rules! payload {
	($name:ident, $cap:expr, $reachable:expr, $maximal:expr) => {
		impl Payload for $name<Agent> {
			const CAP: usize = $cap;
			const CAP_REACHABLE: bool = $reachable;
			fn from_json(mark: &Mark<'_, Agent>, raw: &str) -> Result<Self, Error> {
				$name::from_json(mark, raw)
			}
			fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
				$name::canonical_bytes(self)
			}
			fn digest(&self) -> Result<[u8; 32], Error> {
				$name::digest(self)
			}
			fn maximal() -> Value {
				$maximal
			}
		}
	};
}

payload!(FindingEvidenceV1, EVIDENCE_MAX_BYTES, false, finding_evidence());
payload!(PromotionV1, EVIDENCE_MAX_BYTES, false, promotion());
payload!(SurveyTerminalV1, SURVEY_TERMINAL_MAX_BYTES, false, survey());
payload!(DrilldownTerminalV1, EVIDENCE_MAX_BYTES, false, drilldown());
payload!(VerificationTerminalV1, EVIDENCE_MAX_BYTES, false, verification());
payload!(LeadEvidenceV1, 64 * 1024, false, lead_evidence());
payload!(UnitResultPayloadV1, 64 * 1024, true, unit_result());

pub fn do_test(data: &[u8]) {
	let Some((&selector, rest)) = data.split_first() else { return };
	let sized = selector & 0x80 != 0;
	match selector & 0x0f {
		0 => run::<FindingEvidenceV1<Agent>>(sized, rest),
		1 => run::<PromotionV1<Agent>>(sized, rest),
		2 => run::<SurveyTerminalV1<Agent>>(sized, rest),
		3 => run::<DrilldownTerminalV1<Agent>>(sized, rest),
		4 => run::<VerificationTerminalV1<Agent>>(sized, rest),
		5 => run::<LeadEvidenceV1<Agent>>(sized, rest),
		6 => run::<UnitResultPayloadV1<Agent>>(sized, rest),
		_ => {},
	}
}

fn run<T: Payload>(sized: bool, rest: &[u8]) {
	if !sized {
		let Ok(raw) = std::str::from_utf8(rest) else { return };
		free::<T>(raw);
		return;
	}
	let Some(target) = ByteSource::new(rest).u32() else { return };
	let mut value = T::maximal();
	let maximum = canonical_len(&value);
	assert_eq!(maximum > T::CAP, T::CAP_REACHABLE, "aggregate cap reachability changed");
	shrink_to(&mut value, maximum.saturating_sub(target as usize));
	let mut raw = Vec::new();
	crate::core_canonical::write_json(&value, &mut raw, false);
	let raw = String::from_utf8(raw).unwrap_or_else(|_| panic!("rendering is UTF-8"));
	let decoded = crate::fixtures::agent(&raw, |mark, raw| T::from_json(mark, raw));
	assert_eq!(
		decoded.is_ok(),
		raw.len() <= T::CAP,
		"sized payload of {} bytes against cap {}: {:?}",
		raw.len(),
		T::CAP,
		decoded.as_ref().err()
	);
	match decoded {
		Ok(payload) => accepted(&payload, &raw),
		Err(error) => {
			assert!(matches!(error, Error::Bytes { max_bytes, .. } if max_bytes == T::CAP))
		},
	}
}

fn free<T: Payload>(raw: &str) {
	match crate::fixtures::agent(raw, |mark, raw| T::from_json(mark, raw)) {
		Ok(payload) => {
			let canonical =
				payload.canonical_bytes().unwrap_or_else(|_| panic!("accepted payload"));
			let canonical =
				String::from_utf8(canonical).unwrap_or_else(|_| panic!("canonical UTF-8"));
			accepted(&payload, &canonical);
		},
		Err(Error::Bytes { max_bytes, .. }) => {
			assert_eq!(max_bytes, T::CAP);
			assert!(T::CAP_REACHABLE, "byte cap refused a payload whose fields cannot reach it");
		},
		Err(_) => {},
	}
}

/// `expected` is the canonical rendering the payload must reproduce.
fn accepted<T: Payload>(payload: &T, expected: &str) {
	let canonical = payload.canonical_bytes().unwrap_or_else(|_| panic!("accepted payload"));
	assert_eq!(canonical, expected.as_bytes(), "canonical bytes disagree with the oracle");
	assert!(canonical.len() <= T::CAP, "accepted payload exceeds its cap");
	let value: Value =
		serde_json::from_slice(&canonical).unwrap_or_else(|_| panic!("canonical bytes are JSON"));
	let mut sorted = Vec::new();
	crate::core_canonical::write_json(&value, &mut sorted, false);
	assert_eq!(sorted, canonical, "canonical bytes must be sorted and whitespace-free");
	let again = crate::fixtures::agent(expected, |mark, raw| T::from_json(mark, raw))
		.unwrap_or_else(|_| panic!("canonical bytes must decode"));
	assert!(again == *payload, "canonical bytes must decode to an equal payload");
	assert_eq!(again.canonical_bytes().ok().as_deref(), Some(canonical.as_slice()));
	assert_eq!(
		payload.digest().ok(),
		Some(*blake3::hash(&canonical).as_bytes()),
		"digest must be BLAKE3-256 of the canonical bytes"
	);
}

fn canonical_len(value: &Value) -> usize {
	let mut out = Vec::new();
	crate::core_canonical::write_json(value, &mut out, false);
	out.len()
}

/// Two-byte filler: NFC-stable, printable and unescaped, so each character
/// costs exactly two canonical bytes and one character of field budget.
const FILL: char = '\u{e9}';

fn fill(chars: usize) -> Value {
	Value::String(std::iter::repeat_n(FILL, chars).collect())
}

/// Removes `excess` canonical bytes from filler strings, keeping each at
/// least one character long.
fn shrink_to(value: &mut Value, mut excess: usize) {
	fn visit(value: &mut Value, excess: &mut usize) {
		match value {
			Value::String(text) if text.starts_with(FILL) => {
				let chars = text.chars().count();
				let remove = (*excess / 2).min(chars - 1);
				let mut kept: String = std::iter::repeat_n(FILL, chars - remove).collect();
				*excess -= remove * 2;
				if *excess == 1 && chars - remove > 1 {
					kept.pop();
					kept.push('a');
					*excess = 0;
				}
				*text = kept;
			},
			Value::Array(values) => values.iter_mut().for_each(|nested| visit(nested, excess)),
			Value::Object(fields) => fields.values_mut().for_each(|nested| visit(nested, excess)),
			_ => {},
		}
	}
	visit(value, &mut excess);
}

fn path() -> Value {
	Value::String(format!("{}/{}", "a".repeat(255), "b".repeat(256)))
}

fn source_refs(count: usize) -> Value {
	Value::Array((0..count).map(|_| json!({"path": path(), "symbol": fill(256)})).collect())
}

fn finding_evidence() -> Value {
	let location = json!({
		"role": "implementation", "file": path(), "symbol": fill(200),
		"line_start": 1_000_000_000, "line_end": u32::MAX,
	});
	json!({
		"version": 1,
		"l2_argument": {
			"attacker_source": fill(2000), "control": fill(2000), "sink": fill(2000),
			"reachable_path": fill(4000), "trust_boundary": fill(1000),
		},
		"material_locations": vec![location; 16],
		"counterevidence": fill(4000),
		"assumptions_gaps": fill(4000),
		"confidence": "medium",
	})
}

fn promotion() -> Value {
	json!({
		"version": 1, "severity": "critical", "title": fill(100), "description": fill(16384),
		"identity_family": "a".repeat(64), "identity_anchor": "a".repeat(300),
		"identity_instance_key": "a".repeat(200), "evidence": finding_evidence(),
		"cwe": format!("CWE-{}", "9".repeat(60)),
	})
}

fn revalidation() -> Value {
	json!({"current_source_refs": source_refs(16), "rationale": fill(2000)})
}

fn survey() -> Value {
	json!({
		"version": 1, "terminal_reason": "completed",
		"continuation": fill(4000), "security_model_notes": fill(8000),
	})
}

fn drilldown() -> Value {
	json!({
		"disposition": "promote", "version": 1, "promotion": promotion(),
		"revalidation": revalidation(),
	})
}

fn verification() -> Value {
	json!({
		"verdict": "verified", "version": 1, "established_rung": "L2",
		"e2e_applicability": "not_applicable", "e2e_rationale": fill(2000),
		"evidence": finding_evidence(), "revalidation": revalidation(), "notes": fill(4000),
	})
}

fn lead_evidence() -> Value {
	json!({
		"format": "loupe.lead_evidence", "version": 1,
		"identity_family": "a".repeat(64), "identity_anchor": "a".repeat(300),
		"identity_instance_key": "a".repeat(200),
		"review_unit_id": i64::MAX, "assignment_epoch": i64::MAX,
		"hypothesis": fill(4000), "invariant_or_boundary": fill(1000),
		"source_refs": source_refs(16), "next_proof_step": fill(1000),
		"counterevidence": fill(2000), "proof_gaps": fill(2000),
		"priority_proposal": {
			"impact": "critical", "access": "privileged", "reachability": "plausible",
			"boundary_refs": source_refs(16), "rationale": fill(1000),
		},
		"duplicate_hint": {"lead_id": i64::MAX, "rationale": fill(1000)},
	})
}

fn unit_result() -> Value {
	json!({
		"format": "loupe.unit_result", "version": 1,
		"review_unit_id": i64::MAX, "assignment_epoch": i64::MAX,
		"disposition": "needs_follow_up", "inspected_refs": source_refs(64),
		"created_lead_ids": [], "counterevidence": fill(2000), "proof_gaps": fill(2000),
		"follow_up": fill(2000), "notes": fill(4000), "continuation": "requires_successor",
	})
}

pub fn core_review_payload_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn core_review_payload_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn maximal_payloads_are_valid_and_report_their_size() {
		for selector in 0..7_u8 {
			let mut data = vec![0x80 | selector];
			data.extend(u32::MAX.to_le_bytes());
			do_test(&data);
		}
	}
}
