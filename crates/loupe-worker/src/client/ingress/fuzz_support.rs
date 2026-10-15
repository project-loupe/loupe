//! Fixed Server fixtures invoke the same private response validators as HTTP.
#![cfg_attr(test, allow(dead_code))]
use loupe_provenance::{Ingress, Secret};
use serde_json::Value;

use super::*;
use crate::host_outcome::{CheckoutFailure, HostVerifyReason, ReviewedRevisionFact};

// debug-ok: Closed fieldless variants; no dynamic content.
#[derive(Clone, Copy, Debug)]
pub enum ResponseCase {
	Lease,
	Heartbeat,
	Search,
	Detail,
	ErrorDiagnostic,
	Submission,
}
// debug-ok: Cfg-only closed host outcome selection, with no dynamic payload.
#[derive(Clone, Copy, Debug)]
pub enum HostCase {
	Scanner,
	Missing,
	Checkout(CheckoutFailure),
}

// debug-ok: Cfg-only synthetic observation; raw values support independent source and compatibility assertions.
#[derive(Debug)]
pub struct Observation {
	pub result: Result<Value, String>,
	pub agent_spans: Vec<std::ops::Range<usize>>,
	pub reviewed_revision: Option<String>,
	pub host_submission: Option<Value>,
}
struct GuardedFixture(Secret<Vec<u8>>);
impl AsRef<[u8]> for GuardedFixture {
	fn as_ref(&self) -> &[u8] {
		self.0.expose()
	}
}

#[allow(unsafe_code)]
fn received(original: &[u8]) -> Untrusted<Bytes, Server> {
	let bytes = Bytes::from_owner(GuardedFixture(Secret::new(original.to_vec())));
	// SAFETY: cfg-only original guarded Server response fixture; no decoded source input.
	Untrusted::new(bytes, unsafe { Ingress::<Server>::new() })
}

#[cfg(test)]
pub(crate) fn lease_fixture(original: &[u8]) -> super::super::LeaseReceipt {
	lease(&received(original)).expect("original synthetic lease fixture")
}

/// Fixed Server fixture yielding the actual final lease DTO for serializer
/// checks. No normal-build decode entry or arbitrary source choice is exposed.
pub fn lease_response(original: &[u8]) -> Option<loupe_proto::LeaseResponse<Agent, Server>> {
	lease(&received(original)).ok().map(|receipt| receipt.response)
}

/// A synthetic original lease exercises the actual selected-token scanner
/// decoder. This is fixture construction, not carry from a reserialized response.
pub fn scanner_patch_fixture(
	token: &str,
) -> Result<Option<crate::source_discovery::ScannerConfigPatch>, String> {
	let body = format!(
		r#"{{"kind":"lease","protocol_version":1,"job_id":1,"repo_id":1,"job_capability":"test-capability","repo":{{"host":"github.com","owner":"a","repo":"b","clone_url":"https://github.com/a/b.git"}},"scanner_config":{token},"lease_expires_at":300,"payload":{{"kind":"scan"}}}}"#
	);
	lease(&received(body.as_bytes())).map(|v| v.scanner_patch).map_err(|e| e.to_string())
}

pub fn observe(case: ResponseCase, original: &[u8], host: HostCase) -> Observation {
	let scope = crate::ingress_text::observe::Scope::begin();
	let mut reviewed_revision = None;
	let mut host_submission = None;
	let result = if original.len() > loupe_http::MAX_RESPONSE_BYTES {
		Err("fixture exceeds response byte limit".to_owned())
	} else {
		let body = received(original);
		let value = match case {
			ResponseCase::Lease => lease(&body).map(|receipt| {
				let fact = receipt.reviewed_revision;
				reviewed_revision = match &fact {
					ReviewedRevisionFact::MissingReviewedRevision => None,
					ReviewedRevisionFact::Available(revision) => Some(revision.text().to_owned()),
				};
				let reason = match (host, fact) {
					(HostCase::Scanner, _) => HostVerifyReason::ScannerDoesNotVerify,
					(HostCase::Checkout(failure), ReviewedRevisionFact::Available(revision)) => {
						HostVerifyReason::ReviewedRevisionUnavailable { revision, failure }
					},
					_ => HostVerifyReason::MissingReviewedRevision,
				};
				host_submission = Some(
					serde_json::to_value(reason.into_submission()).expect("closed host submission"),
				);
				serde_json::to_value(receipt.response).expect("known fixture lease serialization")
			}),
			ResponseCase::Heartbeat => heartbeat(&body)
				.map(|value| serde_json::to_value(value).expect("heartbeat serialization")),
			ResponseCase::Search => search(&body)
				.map(|value| serde_json::to_value(value).expect("search serialization")),
			ResponseCase::Detail => detail(&body)
				.map(|value| serde_json::to_value(value).expect("detail serialization")),
			ResponseCase::ErrorDiagnostic => {
				Ok(Value::String(error(&body).for_diagnostic().to_owned()))
			},
			ResponseCase::Submission => {
				submission(body);
				Ok(Value::Null)
			},
		};
		value.map_err(|error| error.to_string())
	};
	Observation { result, agent_spans: scope.finish(), reviewed_revision, host_submission }
}
