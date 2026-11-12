//! Strict phase execution control on shared legacy/phase lifecycle routes.
//! ```compile_fail,E0277
//! let _: loupe_proto::review_lifecycle::PhaseFailureRequest = serde_json::from_str("{}").unwrap();
//! ```
use loupe_core::text::policy::Reason;
use loupe_core::text::{decode_json_string_bounded, BoundedText, TextPolicy};
use loupe_provenance::{Mark, Unvalidated, Validate, Worker};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::review_api::{ReviewApiDecodeError as Error, ReviewProtocol};
use crate::review_lease::ReviewId;

// debug-ok: closed protocol and execution states, no input text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailedOutcome {
	Failed,
}
loupe_core::closed_string_enum!(FailedOutcome { Failed });
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PhaseFailureRequest {
	pub protocol_version: ReviewProtocol,
	pub outcome: FailedOutcome,
	pub error: Option<BoundedText<Reason, Worker>>,
}
/// Phase heartbeat requires this body; legacy heartbeat may still be empty.
// debug-ok: closed protocol and execution states, no input text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseHeartbeatRequest {
	pub protocol_version: ReviewProtocol,
}

// debug-ok: closed protocol and execution states, no input text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseControlState {
	Queued,
	Failed,
	Cancelled,
}
// debug-ok: closed protocol and execution states, no input text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseControlResponse {
	pub protocol_version: ReviewProtocol,
	pub job_id: ReviewId,
	pub state: PhaseControlState,
	pub eligible_at: Option<i64>,
}

impl std::fmt::Debug for PhaseFailureRequest {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("PhaseFailureRequest([redacted])")
	}
}
/// Admits only the original authenticated Worker request; no public serde
/// path can manufacture a Worker-labelled failure reason.
pub struct PhaseFailureRequestDecoder;
impl Validate<&[u8], Worker> for PhaseFailureRequestDecoder {
	type Output = PhaseFailureRequest;
	type Error = Error;
	fn validate<'v>(
		self, input: Unvalidated<'v, &[u8]>, mark: Mark<'v, Worker>,
	) -> Result<Self::Output, Error> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire<'a> {
			protocol_version: ReviewProtocol,
			outcome: FailedOutcome,
			#[serde(borrow)]
			error: Option<&'a RawValue>,
		}
		if input.get().len() > 8192 {
			return Err(Error::Invalid("phase control request too large"));
		}
		let wire: Wire<'_> = serde_json::from_slice(input.get())?;
		let error = wire
			.error
			.map(|raw| {
				// Match the existing semantic TextPolicy raw allowance before
				// allocation; the final normalized limits still apply below.
				let raw_limit = Reason::MAX_BYTES.saturating_mul(4);
				let decoded =
					decode_json_string_bounded(raw.get(), Reason::FIELD, raw_limit, raw_limit)?;
				BoundedText::new(&mark, &decoded)
			})
			.transpose()?;
		Ok(PhaseFailureRequest {
			protocol_version: wire.protocol_version,
			outcome: wire.outcome,
			error,
		})
	}
}
pub struct PhaseHeartbeatRequestDecoder;
impl Validate<&[u8], Worker> for PhaseHeartbeatRequestDecoder {
	type Output = PhaseHeartbeatRequest;
	type Error = Error;
	fn validate<'v>(
		self, input: Unvalidated<'v, &[u8]>, _: Mark<'v, Worker>,
	) -> Result<Self::Output, Error> {
		if input.get().len() > 8192 {
			return Err(Error::Invalid("phase control request too large"));
		}
		Ok(serde_json::from_slice(input.get())?)
	}
}
#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn failure_reason_preserves_existing_semantic_raw_allowance() {
		let raw=serde_json::json!({"protocol_version":3,"outcome":"failed","error":"e\u{301}".repeat(700)}).to_string();
		let result = failure(&raw);
		assert!(
			result.is_ok(),
			"preflight must preserve the existing semantic normalization allowance: {result:?}"
		);
		assert_eq!(result.unwrap().error.unwrap().expose(), "é".repeat(700));
	}
	fn failure(raw: &str) -> Result<PhaseFailureRequest, Error> {
		crate::test_support::worker_request(raw.as_bytes()).validate(PhaseFailureRequestDecoder)
	}
	#[test]
	fn failure_is_strict_bounded_and_cannot_override_checkout_or_succeed() {
		for raw in [
			r#"{"protocol_version":3,"outcome":"succeeded"}"#,
			r#"{"protocol_version":3,"outcome":"failed","head_sha":null}"#,
			r#"{"protocol_version":3,"outcome":"failed","extra":true}"#,
			r#"{"protocol_version":3,"protocol_version":3,"outcome":"failed"}"#,
			r#"{"protocol_version":2,"outcome":"failed"}"#,
			r#"{"outcome":"failed"}"#,
		] {
			assert!(failure(raw).is_err(), "{raw}");
		}
		let good =
			serde_json::json!({"protocol_version":3,"outcome":"failed","error":"a".repeat(1000)});
		assert!(failure(&good.to_string()).is_ok());
		let too_long =
			serde_json::json!({"protocol_version":3,"outcome":"failed","error":"a".repeat(1001)});
		assert!(failure(&too_long.to_string()).is_err());
	}
	#[test]
	fn phase_heartbeat_requires_exact_version_only() {
		assert!(serde_json::from_str::<PhaseHeartbeatRequest>(r#"{"protocol_version":3}"#).is_ok());
		for raw in [
			"",
			"{}",
			r#"{"protocol_version":2}"#,
			r#"{"protocol_version":3,"extra":null}"#,
			r#"{"protocol_version":3,"protocol_version":3}"#,
		] {
			assert!(serde_json::from_str::<PhaseHeartbeatRequest>(raw).is_err());
		}
	}
}
