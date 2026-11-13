//! Shared phase transport boundaries. Serialize the bounded response before
//! committing the same transaction that granted authority or changed state.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use loupe_proto::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use loupe_provenance::{Mark, Unvalidated, Validate, Worker};
use loupe_storage::review_authority::PhaseTransaction;
use loupe_storage::Db;
use serde::Serialize;

use super::authority;
use crate::auth::AuthedWorker;
use crate::ingress::WorkerBody;

pub type Result<T> = std::result::Result<T, ApiError>;

// debug-ok: status and error code are closed host metadata, never input text.
#[derive(Debug)]
pub struct ApiError {
	status: StatusCode,
	code: &'static str,
	current_revision: Option<i64>,
}
impl ApiError {
	pub fn new(status: StatusCode, code: &'static str) -> Self {
		Self { status, code, current_revision: None }
	}
	pub fn denied() -> Self {
		Self::new(StatusCode::FORBIDDEN, "denied")
	}
	pub fn conflict(code: &'static str) -> Self {
		Self::new(StatusCode::CONFLICT, code)
	}
	/// Only a repository/entry-scoped storage conflict supplies this scalar.
	fn inventory_revision_conflict(current_revision: i64) -> Self {
		Self {
			current_revision: Some(current_revision),
			..Self::conflict("inventory_revision_conflict")
		}
	}
	pub fn invalid(_detail: impl std::fmt::Display) -> Self {
		// Decoder diagnostics can contain arbitrary input keys and tokens.
		Self::new(StatusCode::BAD_REQUEST, "invalid_request")
	}
}
impl From<loupe_storage::Error> for ApiError {
	fn from(error: loupe_storage::Error) -> Self {
		use loupe_storage::{Conflict, Error};
		match error {
			Error::ScopeDenied | Error::Ownership(_) | Error::NotFound(_, _) => Self::denied(),
			Error::Conflict(Conflict::Checkpoint) => Self::conflict("checkpoint_conflict"),
			Error::Conflict(Conflict::CheckpointLimit) => Self::conflict("checkpoint_limit"),
			Error::Conflict(Conflict::UnitResultExists) => Self::conflict("unit_result_exists"),
			Error::Conflict(Conflict::IncompatibleReviewState) => {
				Self::conflict("incompatible_review_state")
			},
			Error::Conflict(Conflict::Limits) => Self::conflict("invalid_limits"),
			Error::Conflict(Conflict::CompatibilityPolicy) => {
				Self::conflict("compatibility_policy")
			},
			Error::Conflict(Conflict::InventoryLimit) => Self::conflict("inventory_limit"),
			Error::Conflict(Conflict::InventoryRevision(revision)) => {
				Self::inventory_revision_conflict(revision)
			},
			Error::Conflict(Conflict::CampaignPinned) => Self::conflict("checkout_conflict"),
			Error::Conflict(_) => Self::conflict("state_conflict"),
			Error::Validation(error) => Self::invalid(error),
			Error::ReviewPayload(error) => Self::invalid(error),
			Error::UnknownPaths(_) => Self::invalid("source outside pinned inventory"),
			error => {
				tracing::error!(error = %error, "phase transaction failed");
				Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
			},
		}
	}
}
impl IntoResponse for ApiError {
	fn into_response(self) -> Response {
		let mut error = serde_json::json!({"code":self.code,"detail":null});
		if let Some(revision) = self.current_revision {
			error["current_revision"] = serde_json::json!(revision);
		}
		let mut response = (
			self.status,
			axum::Json(serde_json::json!({
				"protocol_version": PROTOCOL_VERSION,
				"error": error
			})),
		)
			.into_response();
		response
			.headers_mut()
			.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
		response
	}
}

pub fn require_version(headers: &HeaderMap) -> Result<()> {
	let mut versions = headers.get_all(PROTOCOL_VERSION_HEADER).iter();
	let valid = versions.next().is_some_and(|value| {
		value.to_str().ok().and_then(|raw| raw.parse::<u16>().ok()) == Some(PROTOCOL_VERSION)
	});
	if !valid || versions.next().is_some() {
		return Err(ApiError::invalid("one exact X-Loupe-Protocol header is required"));
	}
	Ok(())
}

/// Matched paths served by the review phase transport. `is_phase_route`
/// mirrors this list as a `matches!` so the per-request middleware check
/// stays a compiled string switch; a unit test keeps the two in sync.
pub const PHASE_ROUTES: &[&str] = &[
	"/v1/jobs/{id}/pin-target",
	"/v1/jobs/{id}/inventory-batches",
	"/v1/jobs/{id}/seal-inventory",
	"/v1/jobs/{id}/publish-profile",
	"/v1/jobs/{id}/inventory-dispositions",
	"/v1/jobs/{id}/review-units",
	"/v1/jobs/{id}/leads",
	"/v1/jobs/{id}/sibling-leads",
	"/v1/jobs/{id}/review-unit-results",
	"/v1/jobs/{id}/finalize-survey",
	"/v1/jobs/{id}/finalize-drilldown",
	"/v1/jobs/{id}/finalize-verification",
	"/v1/jobs/{id}/limits",
	"/v1/jobs/{id}/lead-candidates",
	"/v1/review-generations/{id}/reset",
];

/// Matched paths served by the job control transport; mirrored by
/// `is_control_route`.
pub const CONTROL_ROUTES: &[&str] =
	&["/v1/jobs/{id}/complete", "/v1/jobs/{id}/heartbeat", "/v1/jobs/{id}/cancel"];

/// Use the registered matched path, not arbitrary URI suffixes. The outer
/// boundary must include role middleware and extractor rejections too.
pub fn is_phase_route(path: &str) -> bool {
	matches!(
		path,
		"/v1/jobs/{id}/pin-target"
			| "/v1/jobs/{id}/inventory-batches"
			| "/v1/jobs/{id}/seal-inventory"
			| "/v1/jobs/{id}/publish-profile"
			| "/v1/jobs/{id}/inventory-dispositions"
			| "/v1/jobs/{id}/review-units"
			| "/v1/jobs/{id}/leads"
			| "/v1/jobs/{id}/sibling-leads"
			| "/v1/jobs/{id}/review-unit-results"
			| "/v1/jobs/{id}/finalize-survey"
			| "/v1/jobs/{id}/finalize-drilldown"
			| "/v1/jobs/{id}/finalize-verification"
			| "/v1/jobs/{id}/limits"
			| "/v1/jobs/{id}/lead-candidates"
			| "/v1/review-generations/{id}/reset"
	)
}

pub fn is_control_route(path: &str) -> bool {
	matches!(path, "/v1/jobs/{id}/complete" | "/v1/jobs/{id}/heartbeat" | "/v1/jobs/{id}/cancel")
}

pub async fn bound_lease_response(response: Response) -> Response {
	let mut response = bound_errors(response, Some(legacy_lease_diagnostic)).await;
	response
		.headers_mut()
		.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
	response
}

pub async fn bound_phase_errors(response: Response) -> Response {
	bound_errors(response, None).await
}
type LegacyDiagnostic = fn(StatusCode, &[u8]) -> Option<String>;

async fn bound_errors(response: Response, diagnostic: Option<LegacyDiagnostic>) -> Response {
	if !response.status().is_client_error() && !response.status().is_server_error() {
		return response;
	}
	let (mut parts, body) = response.into_parts();
	let json = parts
		.headers
		.get(header::CONTENT_TYPE)
		.is_some_and(|value| value.as_bytes() == b"application/json");
	if let Ok(bytes) = to_bytes(body, 4096).await {
		if json {
			parts
				.headers
				.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
			return Response::from_parts(parts, Body::from(bytes));
		}
		if let Some(diagnostic) = diagnostic
			&& let Some(message) = diagnostic(parts.status, &bytes)
		{
			// Reconstruct only closed host messages, never forward untrusted suffixes.
			let mut response = (parts.status, message).into_response();
			response
				.headers_mut()
				.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
			return response;
		}
	}
	// Never echo an extractor's arbitrary-size untrusted path or middleware
	// text. Preserve its status, with the same bounded structured vocabulary.
	let code = match parts.status {
		StatusCode::UNAUTHORIZED => "unauthenticated",
		StatusCode::FORBIDDEN => "denied",
		StatusCode::NOT_FOUND => "not_found",
		StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
		StatusCode::PAYLOAD_TOO_LARGE => "request_too_large",
		StatusCode::BAD_REQUEST => "invalid_request",
		_ => "request_failed",
	};
	ApiError::new(parts.status, code).into_response()
}

pub async fn bound_control_errors(response: Response) -> Response {
	bound_errors(response, Some(legacy_control_diagnostic)).await
}

const LEGACY_DATA_CATEGORIES: &[&str] = &[
	"missing field",
	"duplicate field",
	"invalid type",
	"unknown field",
	"unknown variant",
	"invalid data",
];

fn legacy_lease_diagnostic(status: StatusCode, bytes: &[u8]) -> Option<String> {
	let raw = std::str::from_utf8(bytes).ok()?;
	const MEDIA: &str = "Expected request with Content-Type: application/json";
	if status == StatusCode::UNSUPPORTED_MEDIA_TYPE && raw == MEDIA {
		return Some(MEDIA.to_owned());
	}
	legacy_request_diagnostic(status, raw)
}

/// Control-specific diagnostics never become lease or phase diagnostics.
fn legacy_control_diagnostic(status: StatusCode, bytes: &[u8]) -> Option<String> {
	let raw = std::str::from_utf8(bytes).ok()?;
	let fixed = match status {
		StatusCode::BAD_REQUEST => &[
			"invalid heartbeat body: invalid JSON syntax",
			"successful scan completion requires non-empty head_sha",
		][..],
		StatusCode::CONFLICT => &["successful verify completion requires a submitted verdict"][..],
		_ => &[],
	};
	if let Some(message) = fixed.iter().find(|message| **message == raw) {
		return Some((*message).to_owned());
	}
	if status == StatusCode::BAD_REQUEST
		&& let Some(category) = raw
			.strip_prefix("invalid heartbeat body: ")
			.and_then(|suffix| LEGACY_DATA_CATEGORIES.iter().find(|category| **category == suffix))
	{
		return Some(format!("invalid heartbeat body: {category}"));
	}
	legacy_request_diagnostic(status, raw)
}

/// Reconstruct only the finite landed request vocabulary on matched legacy
/// routes. Every match is status-bound and exact; Policy/SQL text and arbitrary
/// suffixes are never reflected.
fn legacy_request_diagnostic(status: StatusCode, raw: &str) -> Option<String> {
	if status == StatusCode::BAD_REQUEST {
		const FIXED: &[&str] = &[
			"Failed to parse the request body as JSON: invalid syntax",
			"X-Loupe-Protocol must be an integer",
			"X-Loupe-Protocol must be valid ASCII",
		];
		if let Some(message) = FIXED.iter().find(|message| **message == raw) {
			return Some((*message).to_owned());
		}
		for prefix in ["unsupported protocol_version ", "unsupported X-Loupe-Protocol "] {
			if let Some(suffix) = raw.strip_prefix(prefix)
				&& let Ok(version) = suffix.parse::<u16>()
				&& version.to_string() == suffix
			{
				return Some(format!("{prefix}{version}"));
			}
		}
	} else if status == StatusCode::UNPROCESSABLE_ENTITY {
		const PREFIX: &str = "Failed to deserialize the JSON body into the target type: ";
		if let Some(category) = raw
			.strip_prefix(PREFIX)
			.and_then(|suffix| LEGACY_DATA_CATEGORIES.iter().find(|category| **category == suffix))
		{
			return Some(format!("{PREFIX}{category}"));
		}
	}
	None
}

/// Validate the already captured request, without bypassing worker quotas or
/// copying the body into a second unguarded plaintext buffer.
pub fn body(headers: &HeaderMap, body: WorkerBody, max_bytes: usize) -> Result<WorkerBody> {
	require_version(headers)?;
	if headers.get_all(header::CONTENT_ENCODING).iter().any(|value| value.as_bytes() != b"identity")
	{
		return Err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "content_encoding"));
	}
	if !headers.get(header::CONTENT_TYPE).is_some_and(|value| {
		value.to_str().is_ok_and(|raw| {
			raw.split(';').next().is_some_and(|mime| mime.trim() == "application/json")
		})
	}) {
		return Err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "content_type"));
	}
	body.0.as_bytes().validate(BodyLimit(max_bytes))?;
	Ok(body)
}
/// Context GETs use the same quota-charged capture as phase writes. They have
/// no media-type requirement, but reject any actual body or content encoding.
pub fn no_body(headers: &HeaderMap, body: WorkerBody) -> Result<()> {
	require_version(headers)?;
	if headers.get_all(header::CONTENT_ENCODING).iter().any(|value| value.as_bytes() != b"identity")
	{
		return Err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "content_encoding"));
	}
	body.0.as_bytes().validate(BodyLimit(0)).map_err(|_| ApiError::invalid("GET has no body"))
}

struct BodyLimit(usize);
impl Validate<&[u8], Worker> for BodyLimit {
	type Output = ();
	type Error = ApiError;
	fn validate<'v>(self, input: Unvalidated<'v, &[u8]>, _: Mark<'v, Worker>) -> Result<()> {
		if input.get().len() > self.0 {
			Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large"))
		} else {
			Ok(())
		}
	}
}

struct BoundedBody {
	bytes: Vec<u8>,
	limit: usize,
}
impl Write for BoundedBody {
	fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
		if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
			return Err(std::io::Error::other("phase response exceeds its byte limit"));
		}
		self.bytes.extend_from_slice(bytes);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

/// The result is serialized under the write lock. A response overflow or any
/// operation error drops the uncommitted transaction, including prior writes.
pub fn transaction<T: Serialize>(
	db: &Db, worker: &AuthedWorker, headers: &HeaderMap, job: i64, response_limit: usize,
	body: impl for<'tx> FnOnce(&mut PhaseTransaction<'tx>) -> Result<T>,
) -> Result<Response> {
	authority::with_transaction(
		db,
		worker,
		headers,
		job,
		|| SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64,
		|tx| {
			let value = body(tx)?;
			response(&value, response_limit)
		},
	)?
	.ok_or_else(ApiError::denied)
}

pub fn response(value: &impl Serialize, limit: usize) -> Result<Response> {
	let mut output = BoundedBody { bytes: Vec::new(), limit };
	serde_json::to_writer(&mut output, value)
		.map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "response_too_large"))?;
	Ok((
		[(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "no-store")],
		output.bytes,
	)
		.into_response())
}

#[cfg(test)]
mod tests {
	#[tokio::test]
	async fn lease_boundary_preserves_only_known_request_diagnostics() {
		let mut cases = vec![
			(
				StatusCode::UNSUPPORTED_MEDIA_TYPE,
				"Expected request with Content-Type: application/json".to_owned(),
			),
			(
				StatusCode::BAD_REQUEST,
				"Failed to parse the request body as JSON: invalid syntax".to_owned(),
			),
			(StatusCode::BAD_REQUEST, "unsupported protocol_version 65535".to_owned()),
			(StatusCode::BAD_REQUEST, "unsupported X-Loupe-Protocol 65535".to_owned()),
			(StatusCode::BAD_REQUEST, "X-Loupe-Protocol must be an integer".to_owned()),
			(StatusCode::BAD_REQUEST, "X-Loupe-Protocol must be valid ASCII".to_owned()),
		];
		for category in [
			"missing field",
			"duplicate field",
			"invalid type",
			"unknown field",
			"unknown variant",
			"invalid data",
		] {
			cases.push((
				StatusCode::UNPROCESSABLE_ENTITY,
				format!("Failed to deserialize the JSON body into the target type: {category}"),
			));
		}
		for (status, message) in cases {
			let response = bound_lease_response((status, message.clone()).into_response()).await;
			assert_eq!(response.status(), status);
			assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
			let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
			assert_eq!(
				bytes.as_ref(),
				message.as_bytes(),
				"lease boundary must preserve the exact closed request diagnostic"
			);
		}
	}

	#[test]
	fn predicates_match_route_lists() {
		let probes = PHASE_ROUTES.iter().chain(CONTROL_ROUTES).copied().chain([
			"/v1/jobs/lease",
			"/v1/jobs/{id}",
			"/v1/jobs/{id}/leads/x",
			"",
		]);
		for path in probes {
			assert_eq!(is_phase_route(path), PHASE_ROUTES.contains(&path), "{path}: phase");
			assert_eq!(is_control_route(path), CONTROL_ROUTES.contains(&path), "{path}: control");
		}
	}

	#[tokio::test]
	async fn lease_boundary_keeps_unknown_control_suffix_oversize_and_auth_errors_closed() {
		const SENTINEL: &str = "FAKE_UNTRUSTED_LEASE_DIAGNOSTIC";
		for (status, message) in [
			(StatusCode::BAD_REQUEST, SENTINEL.to_owned()),
			(StatusCode::BAD_REQUEST, format!("Failed to parse the request body as JSON: invalid syntax {SENTINEL}")),
			(StatusCode::UNPROCESSABLE_ENTITY, format!("Failed to deserialize the JSON body into the target type: missing field {SENTINEL}")),
			(StatusCode::UNSUPPORTED_MEDIA_TYPE, format!("Expected request with Content-Type: application/json {SENTINEL}")),
			(StatusCode::BAD_REQUEST, "unsupported X-Loupe-Protocol 65536".to_owned()),
			(StatusCode::BAD_REQUEST, "unsupported X-Loupe-Protocol 065535".to_owned()),
			(StatusCode::BAD_REQUEST, "unsupported protocol_version +3".to_owned()),
			(StatusCode::BAD_REQUEST, format!("unsupported protocol_version 65535{SENTINEL}")),
			(StatusCode::BAD_REQUEST, SENTINEL.repeat(1000)),
			(StatusCode::FORBIDDEN, "Failed to parse the request body as JSON: invalid syntax".to_owned()),
			(StatusCode::UNAUTHORIZED, "X-Loupe-Protocol must be an integer".to_owned()),
			(StatusCode::INTERNAL_SERVER_ERROR, "Expected request with Content-Type: application/json".to_owned()),
			(StatusCode::BAD_REQUEST, "invalid heartbeat body: missing field".to_owned()),
			(StatusCode::BAD_REQUEST, "successful scan completion requires non-empty head_sha".to_owned()),
			(StatusCode::CONFLICT, "successful verify completion requires a submitted verdict".to_owned()),
		] {
			let response = bound_lease_response((status, message).into_response()).await;
			assert_eq!(response.status(), status);
			assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
			let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
			let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
			assert_eq!(value["error"]["detail"], serde_json::Value::Null);
			assert!(!std::str::from_utf8(&bytes).unwrap().contains(SENTINEL));
		}
	}

	#[tokio::test]
	async fn shared_controls_preserve_only_reconstructed_known_diagnostics() {
		for (status, message) in [
			(StatusCode::BAD_REQUEST, "invalid heartbeat body: invalid JSON syntax"),
			(StatusCode::BAD_REQUEST, "invalid heartbeat body: missing field"),
			(StatusCode::BAD_REQUEST, "invalid heartbeat body: invalid data"),
			(
				StatusCode::UNPROCESSABLE_ENTITY,
				"Failed to deserialize the JSON body into the target type: unknown variant",
			),
			(StatusCode::BAD_REQUEST, "Failed to parse the request body as JSON: invalid syntax"),
			(StatusCode::BAD_REQUEST, "successful scan completion requires non-empty head_sha"),
			(StatusCode::CONFLICT, "successful verify completion requires a submitted verdict"),
			(StatusCode::BAD_REQUEST, "unsupported protocol_version 65535"),
			(StatusCode::BAD_REQUEST, "unsupported X-Loupe-Protocol 65535"),
			(StatusCode::BAD_REQUEST, "X-Loupe-Protocol must be an integer"),
			(StatusCode::BAD_REQUEST, "X-Loupe-Protocol must be valid ASCII"),
		] {
			let response = bound_control_errors((status, message).into_response()).await;
			assert_eq!(response.status(), status);
			assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
			let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
			assert_eq!(
				bytes.as_ref(),
				message.as_bytes(),
				"shared control must preserve the closed legacy diagnostic"
			);
		}
	}
	#[tokio::test]
	async fn shared_control_unknown_suffix_oversize_and_auth_errors_stay_closed() {
		const SENTINEL: &str = "FAKE_UNTRUSTED_DIAGNOSTIC";
		for (status,message) in [
   (StatusCode::BAD_REQUEST,SENTINEL.to_owned()),
   (StatusCode::BAD_REQUEST,format!("invalid heartbeat body: missing field {SENTINEL}")),
   (StatusCode::BAD_REQUEST,format!("successful scan completion requires non-empty head_sha{SENTINEL}")),
   (StatusCode::CONFLICT,format!("successful verify completion requires a submitted verdict{SENTINEL}")),
   (StatusCode::UNPROCESSABLE_ENTITY,format!("Failed to deserialize the JSON body into the target type: unknown variant {SENTINEL}")),
   (StatusCode::BAD_REQUEST,"unsupported X-Loupe-Protocol 65536".to_owned()),
   (StatusCode::BAD_REQUEST,"unsupported X-Loupe-Protocol 065535".to_owned()),
   (StatusCode::BAD_REQUEST,"unsupported protocol_version +3".to_owned()),
   (StatusCode::BAD_REQUEST,format!("unsupported protocol_version 65535{SENTINEL}")),
   (StatusCode::BAD_REQUEST,format!("invalid heartbeat body: {}",SENTINEL.repeat(1000))),
   (StatusCode::FORBIDDEN,"invalid heartbeat body: missing field".to_owned()),
   (StatusCode::UNAUTHORIZED,"successful scan completion requires non-empty head_sha".to_owned()),
   (StatusCode::INTERNAL_SERVER_ERROR,"successful verify completion requires a submitted verdict".to_owned()),
   (StatusCode::BAD_REQUEST,format!("reason: Character (U+0000) {SENTINEL}")),
  ] {
   let response=bound_control_errors((status,message).into_response()).await;
   assert_eq!(response.status(),status);
   assert_eq!(response.headers()[header::CACHE_CONTROL],"no-store");
   let bytes=to_bytes(response.into_body(),4096).await.unwrap();
   let value:serde_json::Value=serde_json::from_slice(&bytes).unwrap();
   assert_eq!(value["error"]["detail"],serde_json::Value::Null);
   assert!(!std::str::from_utf8(&bytes).unwrap().contains(SENTINEL));
  }
		let response = bound_phase_errors(
			(StatusCode::BAD_REQUEST, "invalid heartbeat body: missing field").into_response(),
		)
		.await;
		let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
		assert_eq!(
			serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"]["code"],
			"invalid_request",
			"only shared controls preserve legacy diagnostic framing"
		);
	}
	use loupe_proto::review_api::SealInventoryRequestDecoder;

	use super::*;

	fn headers() -> HeaderMap {
		let mut headers = HeaderMap::new();
		headers.insert(PROTOCOL_VERSION_HEADER, "3".parse().unwrap());
		headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
		headers
	}

	#[tokio::test]
	async fn limits_count_actual_bytes_without_a_content_length() {
		let headers = headers();
		let raw = " ".repeat(2048) + r#"{"protocol_version":3}"#;
		let err =
			body(&headers, crate::test_support::worker_body(raw.as_bytes()), 2048).err().unwrap();
		assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
		let captured =
			body(&headers, crate::test_support::worker_body(br#"{"protocol_version":3}"#), 2048)
				.ok()
				.unwrap();
		assert!(captured.0.as_bytes().validate(SealInventoryRequestDecoder).is_ok());
	}

	#[tokio::test]
	async fn phase_transport_rejects_missing_version_and_encoded_bodies() {
		let mut headers = headers();
		headers.remove(PROTOCOL_VERSION_HEADER);
		assert!(require_version(&headers).is_err());
		headers.insert(PROTOCOL_VERSION_HEADER, "3".parse().unwrap());
		headers.append(PROTOCOL_VERSION_HEADER, "3".parse().unwrap());
		assert!(require_version(&headers).is_err());
		headers.insert(PROTOCOL_VERSION_HEADER, "3".parse().unwrap());
		headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
		assert_eq!(
			body(&headers, crate::test_support::worker_body(b""), 2048).err().unwrap().status,
			StatusCode::UNSUPPORTED_MEDIA_TYPE
		);
	}

	#[tokio::test]
	async fn phase_errors_never_echo_untrusted_diagnostics() {
		let response = ApiError::invalid("SECRET_PHASE_DIAGNOSTIC").into_response();
		let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
		assert!(
			!String::from_utf8_lossy(&bytes).contains("SECRET_PHASE_DIAGNOSTIC"),
			"phase error echoed untrusted diagnostic"
		);
	}
	#[test]
	fn context_get_admits_empty_capture_without_media_type() {
		let mut headers = headers();
		headers.remove(header::CONTENT_TYPE);
		assert!(no_body(&headers, crate::test_support::worker_body(b"")).is_ok());
		assert_eq!(
			no_body(&headers, crate::test_support::worker_body(b" ")).unwrap_err().status,
			StatusCode::BAD_REQUEST
		);
		headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
		assert_eq!(
			no_body(&headers, crate::test_support::worker_body(b"")).unwrap_err().status,
			StatusCode::UNSUPPORTED_MEDIA_TYPE
		);
	}
	#[test]
	fn context_gets_share_the_registered_phase_error_boundary() {
		assert!(is_phase_route("/v1/jobs/{id}/limits"));
		assert!(is_phase_route("/v1/jobs/{id}/lead-candidates"));
		assert!(!is_phase_route("/v1/repos/{id}/lead-candidates"));
		assert!(!is_phase_route("/arbitrary/limits"));
	}
	#[test]
	fn scope_denial_is_not_an_internal_error() {
		assert_eq!(
			ApiError::from(loupe_storage::Error::ScopeDenied).status,
			StatusCode::FORBIDDEN,
			"phase scope denial must be forbidden"
		);
	}
}
