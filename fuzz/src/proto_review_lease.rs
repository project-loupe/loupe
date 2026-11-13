//! The worker decodes phase leases from original Server response bytes
//! through its lease validator (`loupe_worker::client::fuzz_support`).
//! Byte zero 0 takes the rest as a whole lease response; 1 splices the rest
//! in as the `payload` of a fixed protocol-3 lease envelope.
//!
//! This composes with `worker_client_ingress`, which owns the legacy lease
//! differential, logs and closed errors: a refused phase body must still
//! fail with one of its closed phase errors. An admitted phase lease runs the
//! shared `proto_review_common` oracles over the whole response, with
//! unknown fields required to be refused everywhere in the phase payload
//! except inside a generated profile, which is open JSON by its schema.

use loupe_proto::LeaseResponse;
use loupe_provenance::{Agent, Server};
use loupe_worker::client::fuzz_support::{lease_response, observe, HostCase, ResponseCase};

use crate::proto_review_common::{to_value, Request};
use crate::utils::test_logger;

type Lease = LeaseResponse<Agent, Server>;

const ENVELOPE_HEAD: &str = r#"{"kind":"lease","protocol_version":3,"job_id":1,"job_capability":"fixture","repo_id":1,"repo":{"host":"h","owner":"o","repo":"r","clone_url":"c"},"head_branch":null,"lease_expires_at":1,"scanner_config":null,"payload":"#;
const SURVEY: &str = r#"{"kind":"review_survey","provenance":{"workflow_contract_version":1,"campaign_id":2,"attempt":1,"limits":{"soft_deadline_at":100,"submit_by":100,"hard_deadline_at":200,"token_budget":null,"new_unit_limit":32,"lead_limit":16,"sibling_limit":4}},"context":{"recipe":"ordinary","generation":{"generation_id":3,"commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"profile":{"profile_version":1,"profile_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","profile":{"purpose":"test","areas":[{"name":"parser"}]}},"ordinary_recipe":"coverage","assignments":[{"review_unit_id":5,"assignment_epoch":2,"title":"Review parser","objective":"Check input bounds","source_refs":[{"path":"src/lib.rs","symbol":"parse"}],"depends_on":[4],"closure_criteria":null}]}}"#;

/// A phase payload of a lease response; `None` for legacy and empty leases.
fn phase(lease: &Lease) -> Option<&loupe_proto::LeasePayload<Agent, Server>> {
	match lease {
		LeaseResponse::Lease(envelope) => match &envelope.payload {
			payload @ (loupe_proto::LeasePayload::ReviewSurvey(_)
			| loupe_proto::LeasePayload::ReviewDrilldown(_)
			| loupe_proto::LeasePayload::ReviewVerify(_)) => Some(payload),
			_ => None,
		},
		LeaseResponse::Empty { .. } => None,
	}
}

/// Equality is over the phase payload (the legacy envelope has no
/// `PartialEq`); the oracle also compares complete serializations.
struct PhaseLease(Lease);
impl PartialEq for PhaseLease {
	fn eq(&self, other: &Self) -> bool {
		phase(&self.0) == phase(&other.0)
	}
}
impl std::fmt::Debug for PhaseLease {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.0.fmt(f)
	}
}
impl serde::Serialize for PhaseLease {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		self.0.serialize(serializer)
	}
}

fn decode(raw: &[u8]) -> Option<PhaseLease> {
	let lease = lease_response(raw)?;
	phase(&lease)?;
	Some(PhaseLease(lease))
}

fn in_envelope(payload: &[u8]) -> Vec<u8> {
	[ENVELOPE_HEAD.as_bytes(), payload, b"}"].concat()
}

/// Objects outside the phase payload belong to the legacy envelope; a
/// generated profile is the `profile` field of a frozen profile.
fn open(keys: &[&str]) -> bool {
	keys.first() != Some(&"payload")
		|| keys.windows(2).any(|pair| pair == ["profile", "profile"])
		|| keys.windows(2).any(|pair| pair == ["published_profile", "profile"])
}

pub fn do_test(data: &[u8]) {
	let Some((&selector, rest)) = data.split_first() else { return };
	let raw = match selector {
		0 => rest.to_vec(),
		1 => in_envelope(rest),
		_ => return,
	};
	let baseline = format!(
		"{:?}",
		decode(&in_envelope(SURVEY.as_bytes())).unwrap_or_else(|| panic!("lease seed"))
	);
	let oracle = Request {
		decode: &decode,
		versions: &[("workflow_contract_version", 1), ("version", 1)],
		baseline: &baseline,
		exact_debug: false,
		open: &open,
	};
	if let Some(lease) = oracle.check(&raw) {
		let rendered = to_value(&lease);
		assert!(rendered["payload"]["kind"]
			.as_str()
			.is_some_and(|kind| kind.starts_with("review_")));
		return;
	}
	if crate::worker_client_ingress::oracle::phase_kind(&raw).is_none() {
		return;
	}
	let observed = observe(ResponseCase::Lease, &raw, HostCase::Scanner);
	match observed.result {
		Ok(value) => assert!(
			!matches!(value["payload"]["kind"].as_str(), Some(kind) if kind.starts_with("review_")),
			"the worker admits a phase lease the decoder refused"
		),
		Err(error) => assert!(
			crate::worker_client_ingress::closed_error(&error)
				|| crate::worker_client_ingress::closed_phase_error(&error),
			"phase lease refusal is not a closed error"
		),
	}
}

pub fn proto_review_lease_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proto_review_lease_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;

	pub(crate) const DRILLDOWN: &str = r#"{"kind":"review_drilldown","provenance":{"workflow_contract_version":1,"campaign_id":2,"attempt":1,"limits":{"soft_deadline_at":100,"submit_by":100,"hard_deadline_at":200,"token_budget":7,"new_unit_limit":32,"lead_limit":16,"sibling_limit":4}},"generation":{"generation_id":3,"commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"profile":{"profile_version":1,"profile_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","profile":{"purpose":"test"}},"lead":{"lead_id":4,"producer_commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","identity_family":"memory-safety","identity_anchor":"request allocation","identity_instance_key":"allocator","hypothesis":"Unbounded input","invariant_or_boundary":"Only authorized callers","source_refs":[{"path":"src/lib.rs","symbol":"allocate"}],"next_proof_step":"Trace length","counterevidence":"Authentication","proof_gaps":"Caller scope"}}"#;
	pub(crate) const VERIFY: &str = r#"{"kind":"review_verify","provenance":{"workflow_contract_version":1,"campaign_id":2,"attempt":1,"limits":{"soft_deadline_at":100,"submit_by":100,"hard_deadline_at":200,"token_budget":null,"new_unit_limit":32,"lead_limit":16,"sibling_limit":4}},"generation":{"generation_id":3,"commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"profile":{"profile_version":1,"profile_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","profile":{"purpose":"test"}},"finding":{"finding_id":4,"reviewed_commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","severity":"high","title":"Unbounded allocation","description":"Requests allocate without a limit","identity_family":"memory-safety","identity_anchor":"request allocation","identity_instance_key":null,"evidence":{"version":1,"l2_argument":{"attacker_source":"Remote request","control":"Request length","sink":"Allocation","reachable_path":"Handler calls the allocator","trust_boundary":"Request to memory"},"material_locations":[{"role":"sink","file":"src/lib.rs","line_start":3,"line_end":4}],"counterevidence":"Authentication precedes allocation","assumptions_gaps":"Authenticated attacker","confidence":"medium"}}}"#;
	pub(crate) const BOOTSTRAP: &str = r#"{"kind":"review_survey","provenance":{"workflow_contract_version":1,"campaign_id":2,"attempt":1,"limits":{"soft_deadline_at":1,"submit_by":1,"hard_deadline_at":2,"token_budget":null,"new_unit_limit":32,"lead_limit":16,"sibling_limit":4}},"context":{"recipe":"bootstrap","target":{"kind":"pinned","generation":{"generation_id":3,"commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"published_profile":{"profile_version":2,"profile_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","profile":{"purpose":"test"}}}}}"#;

	#[test]
	fn every_phase_seed_is_admitted_and_passes() {
		for payload in [SURVEY, DRILLDOWN, VERIFY, BOOTSTRAP] {
			assert!(decode(&in_envelope(payload.as_bytes())).is_some(), "{payload}");
			do_test(&[&[1][..], payload.as_bytes()].concat());
		}
		do_test(&[&[0][..], &in_envelope(SURVEY.as_bytes())].concat());
	}

	#[test]
	fn malformed_phase_payloads_are_refused_with_closed_errors() {
		for payload in [
			SURVEY.replace("\"attempt\":1", "\"attempt\":0"),
			SURVEY.replace("\"depends_on\":[4]", "\"depends_on\":[4],\"x\":1"),
			DRILLDOWN.replace("\"workflow_contract_version\":1", "\"workflow_contract_version\":2"),
		] {
			assert!(decode(&in_envelope(payload.as_bytes())).is_none());
			do_test(&[&[1][..], payload.as_bytes()].concat());
		}
	}

	#[test]
	fn legacy_leases_are_left_to_worker_client_ingress() {
		let scan = br#"{"kind":"scan"}"#;
		assert!(decode(&in_envelope(scan)).is_none());
		do_test(&[&[1][..], scan].concat());
	}
}
