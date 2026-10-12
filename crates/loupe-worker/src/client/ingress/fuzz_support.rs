//! Fixed Server fixtures invoke the same private response validators as HTTP.
use loupe_provenance::{Ingress, Secret};
use serde_json::Value;

use super::*;
use crate::host_outcome::{CheckoutFailure, HostVerifyReason, ReviewedRevisionFact};

#[derive(Clone, Copy, Debug)]
pub enum ResponseCase {
	Lease,
	Heartbeat,
	Search,
	Detail,
	ErrorDiagnostic,
	Submission,
}
#[derive(Clone, Copy, Debug)]
pub enum HostCase {
	Scanner,
	Missing,
	Checkout(CheckoutFailure),
}

#[derive(Debug)]
pub struct Observation {
	pub result: Result<Value, String>,
	pub agent_spans: Vec<std::ops::Range<usize>>,
	pub reviewed_revision: Option<String>,
	pub host_submission: Option<loupe_proto::VerdictSubmission>,
}
struct GuardedFixture(Secret<Vec<u8>>);
impl AsRef<[u8]> for GuardedFixture {
	fn as_ref(&self) -> &[u8] {
		self.0.expose()
	}
}

#[allow(unsafe_code)]
pub fn observe(case: ResponseCase, original: &[u8], host: HostCase) -> Observation {
	let scope = crate::ingress_text::observe::Scope::begin();
	let mut reviewed_revision = None;
	let mut host_submission = None;
	let result = if original.len() > loupe_http::MAX_RESPONSE_BYTES {
		Err("fixture exceeds response byte limit".to_owned())
	} else {
		let bytes = Bytes::from_owner(GuardedFixture(Secret::new(original.to_vec())));
		// SAFETY: cfg-only original guarded Server response fixture; no decoded source input.
		let body = Untrusted::new(bytes, unsafe { Ingress::<Server>::new() });
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
				host_submission = Some(reason.into_legacy_submission());
				serde_json::to_value(receipt.response).expect("known fixture lease serialization")
			}),
			ResponseCase::Heartbeat => heartbeat(&body)
				.map(|value| serde_json::to_value(value).expect("heartbeat serialization")),
			ResponseCase::Search => search(&body)
				.map(|value| serde_json::to_value(value).expect("search serialization")),
			ResponseCase::Detail => detail(&body)
				.map(|value| serde_json::to_value(value).expect("detail serialization")),
			ResponseCase::ErrorDiagnostic => Ok(Value::String(error(&body))),
			ResponseCase::Submission => {
				submission(body);
				Ok(Value::Null)
			},
		};
		value.map_err(|error| error.to_string())
	};
	Observation { result, agent_spans: scope.finish(), reviewed_revision, host_submission }
}
