//! Administrative reset decodes the original authenticated Operator bytes.
use axum::extract::Request;
use axum::http::{header, StatusCode};
use loupe_proto::review_compatibility::ResetGenerationRequest;
use loupe_provenance::{Mark, Operator, Untrusted, Unvalidated, Validate};

use super::{collect_operator_body_limited, RequestBuffer};
use crate::auth::AuthedWorker;
use crate::review::http::{self, ApiError, Result};

pub(crate) const LIMIT: usize = 8192;

pub(crate) async fn reset(request: Request) -> Result<ResetGenerationRequest> {
	http::require_version(request.headers())?;
	if request
		.headers()
		.get_all(header::CONTENT_ENCODING)
		.iter()
		.any(|value| value.as_bytes() != b"identity")
	{
		return Err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "content_encoding"));
	}
	if !request.headers().get(header::CONTENT_TYPE).is_some_and(|value| {
		value.to_str().is_ok_and(|raw| {
			raw.split(';').next().is_some_and(|mime| mime.trim() == "application/json")
		})
	}) {
		return Err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "content_type"));
	}
	let admin = request.extensions().get::<AuthedWorker>().ok_or_else(ApiError::denied)?;
	let id = admin.id();
	let token = admin.operator_ingress().ok_or_else(ApiError::denied)?;
	let bytes = collect_operator_body_limited(request.into_body(), RequestBuffer::default(), LIMIT)
		.await
		.map_err(|(status, _)| {
			if status == StatusCode::PAYLOAD_TOO_LARGE {
				use loupe_core::security_event::{
					emit, BudgetResource, EventContext, SecurityEvent,
				};
				emit(SecurityEvent::BudgetExhausted {
					context: EventContext { worker_id: Some(id), ..Default::default() },
					resource: BudgetResource::RequestBodyBytes,
					used: None,
					limit: Some(LIMIT as u64),
				});
			}
			ApiError::new(
				status,
				if status == StatusCode::PAYLOAD_TOO_LARGE {
					"request_too_large"
				} else {
					"invalid_request"
				},
			)
		})?;
	Untrusted::new(bytes, token).as_bytes().validate(ResetDecoder)
}

struct ResetDecoder;
impl Validate<&[u8], Operator> for ResetDecoder {
	type Output = ResetGenerationRequest;
	type Error = ApiError;
	fn validate<'a>(
		self, input: Unvalidated<'a, &[u8]>, _: Mark<'a, Operator>,
	) -> Result<Self::Output> {
		if input.get().len() > LIMIT {
			return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large"));
		}
		serde_json::from_slice(input.get()).map_err(ApiError::invalid)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn strict_original_operator_bytes_have_exact_cap_and_protocol() {
		let valid = br#"{"protocol_version":3}"#;
		let decode = |raw: &[u8]| {
			Untrusted::new(raw, crate::test_support::operator()).validate(ResetDecoder)
		};
		assert!(decode(valid).is_ok());
		let mut boundary = valid.to_vec();
		boundary.resize(LIMIT, b' ');
		assert!(decode(&boundary).is_ok());
		boundary.push(b' ');
		assert!(decode(&boundary).is_err());
		for raw in [
			br#"{"protocol_version":3,"protocol_version":3}"#.as_slice(),
			br#"{"protocol_version":3,"actor":"FORGED"}"#,
			br#"{"protocol_version":2}"#,
		] {
			assert!(decode(raw).is_err());
		}
	}
}
