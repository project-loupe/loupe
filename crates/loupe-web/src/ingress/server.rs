//! One actual HTTP response owns its Server token, original guarded bytes and
//! optional guarded UTF-8 replacement through the fixed dashboard response sink.
//! Forwarding never mints Agent text from replacement or reserialized bytes.
use std::marker::PhantomData;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use loupe_proto::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use loupe_provenance::{Ingress, Mark, Server, Untrusted, Unvalidated, Validate};

use super::json::{self, Buffer};
use crate::client::{UpstreamError, UpstreamResult};

#[derive(Debug)]
pub(crate) enum Failure {
	Url,
	Transport,
	MissingProtocol,
	ProtocolAscii,
	ProtocolNumber,
	ProtocolVersion(u16),
	BodyTooLarge(Option<StatusCode>),
	BodyRead(Option<StatusCode>),
	Json,
	Encoding,
	EmptyHealth,
}
impl Failure {
	pub(crate) fn status(&self) -> Option<StatusCode> {
		match self {
			Self::BodyTooLarge(s) | Self::BodyRead(s) => *s,
			_ => None,
		}
	}
	pub(crate) fn message(&self) -> String {
		match self {
            Self::Url => "building upstream URL failed".into(),
            Self::Transport => "upstream request failed".into(),
            Self::MissingProtocol => format!("server response missing {PROTOCOL_VERSION_HEADER}"),
            Self::ProtocolAscii => "server protocol header is not ASCII".into(),
            Self::ProtocolNumber => "server protocol header is not a u16".into(),
            Self::ProtocolVersion(version) => format!("server speaks protocol {version}, this loupe-web build speaks {PROTOCOL_VERSION} — rebuild loupe-web against the running server"),
            Self::BodyTooLarge(_) => format!("reading upstream body: response body exceeds {} bytes",loupe_http::MAX_RESPONSE_BYTES),
            Self::BodyRead(_) => "reading upstream body failed".into(),
            Self::Json => "upstream sent invalid JSON".into(),
            Self::Encoding => "encoding upstream response failed".into(),
            Self::EmptyHealth => "/v1/health returned an empty body".into(),
        }
	}
	pub(crate) fn into_error(self) -> UpstreamError {
		UpstreamError::host(self)
	}
}
impl IntoResponse for Failure {
	fn into_response(self) -> Response {
		let status = browser_status(self.status());
		// Only closed host diagnostics and numeric metadata reach this Value.
		(status, axum::Json(serde_json::json!({"error":self.message()}))).into_response()
	}
}
fn browser_status(status: Option<StatusCode>) -> StatusCode {
	match status {
		Some(StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) | None => StatusCode::BAD_GATEWAY,
		Some(status) => status,
	}
}
struct DashboardServerHeader;
impl Validate<&HeaderMap, Server> for DashboardServerHeader {
	type Output = ();
	type Error = Failure;
	fn validate<'v>(
		self, raw: Unvalidated<'v, &HeaderMap>, _: Mark<'v, Server>,
	) -> Result<(), Failure> {
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::ServerHeader);
		let value = raw.get().get(PROTOCOL_VERSION_HEADER).ok_or(Failure::MissingProtocol)?;
		let version = value
			.to_str()
			.map_err(|_| Failure::ProtocolAscii)?
			.parse::<u16>()
			.map_err(|_| Failure::ProtocolNumber)?;
		if version != PROTOCOL_VERSION {
			return Err(Failure::ProtocolVersion(version));
		}
		Ok(())
	}
}
struct ServerText {
	original: Bytes,
	replacement: Option<Bytes>,
	source: PhantomData<Server>,
}
impl ServerText {
	// Called only inside the two fixed Server validators. Keep original bytes
	// even when legacy lossy UTF-8 needs a distinct view (up to three times size).
	fn decode(original: &Bytes, _: &Mark<'_, Server>) -> Result<Self, Failure> {
		let replacement = if std::str::from_utf8(original).is_ok() {
			None
		} else {
			let size = original
				.utf8_chunks()
				.try_fold(0usize, |size, chunk| {
					size.checked_add(chunk.valid().len())?
						.checked_add(if chunk.invalid().is_empty() { 0 } else { 3 })
				})
				.ok_or(Failure::Encoding)?;
			let mut buffer = Buffer::new(size);
			for chunk in original.utf8_chunks() {
				buffer.append(chunk.valid().as_bytes()).map_err(|_| Failure::Encoding)?;
				if !chunk.invalid().is_empty() {
					buffer.append("�".as_bytes()).map_err(|_| Failure::Encoding)?;
				}
			}
			Some(Bytes::from_owner(buffer))
		};
		let text = Self { original: original.clone(), replacement, source: PhantomData };
		#[cfg(fuzzing)]
		crate::fuzz_support::record(crate::fuzz_support::Observation::ServerText {
			original_len: text.original.len(),
			original_hash: *blake3::hash(&text.original).as_bytes(),
			shared_pointer: text.original.as_ptr() == original.as_ptr(),
			replacement_len: text.replacement.as_ref().map(Bytes::len),
			text_len: text.text().len(),
		});
		Ok(text)
	}
	fn text(&self) -> &str {
		// Both branches were admitted above; this conversion cannot allocate.
		std::str::from_utf8(self.replacement.as_ref().unwrap_or(&self.original))
			.expect("validated Server UTF-8")
	}
}
pub(crate) struct ServerJson(ServerText);
impl std::fmt::Debug for ServerJson {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("ServerJson([redacted])")
	}
}
struct DashboardServerJson;
impl Validate<Bytes, Server> for DashboardServerJson {
	type Output = Option<ServerJson>;
	type Error = Failure;
	fn validate<'v>(
		self, raw: Unvalidated<'v, Bytes>, mark: Mark<'v, Server>,
	) -> Result<Self::Output, Failure> {
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::ServerJson);
		let text = ServerText::decode(raw.get(), &mark)?;
		if text.text().trim().is_empty() {
			return Ok(None);
		}
		json::admit(text.text().as_bytes()).map_err(|_| Failure::Json)?;
		Ok(Some(ServerJson(text)))
	}
}
impl ServerJson {
	fn into_response(self, status: StatusCode) -> Result<Response, Failure> {
		#[cfg(fuzzing)]
		crate::fuzz_support::record(crate::fuzz_support::Observation::ServerJsonDebug(format!(
			"{self:?}"
		)));
		let bytes = json::encode_server(self.0.text().as_bytes()).map_err(|_| Failure::Encoding)?;
		Ok((status, [(axum::http::header::CONTENT_TYPE, "application/json")], bytes)
			.into_response())
	}
}
pub(crate) struct ServerDiagnostic {
	text: ServerText,
	status: StatusCode,
}
struct DashboardServerDiagnostic(StatusCode);
impl Validate<Bytes, Server> for DashboardServerDiagnostic {
	type Output = ServerDiagnostic;
	type Error = Failure;
	fn validate<'v>(
		self, raw: Unvalidated<'v, Bytes>, mark: Mark<'v, Server>,
	) -> Result<Self::Output, Failure> {
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::ServerDiagnostic);
		Ok(ServerDiagnostic { text: ServerText::decode(raw.get(), &mark)?, status: self.0 })
	}
}
impl ServerDiagnostic {
	fn into_error_response(self) -> Result<Response, Failure> {
		let text = self.text.text().trim();
		let fallback;
		let text = if text.is_empty() {
			fallback = format!("server returned {}", self.status);
			&fallback
		} else {
			text
		};
		let bytes = json::encode_diagnostic(text).map_err(|_| Failure::Encoding)?;
		Ok((
			browser_status(Some(self.status)),
			[(axum::http::header::CONTENT_TYPE, "application/json")],
			bytes,
		)
			.into_response())
	}
	pub(crate) fn status(&self) -> StatusCode {
		self.status
	}
	pub(crate) fn fmt_message(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let text = self.text.text().trim();
		if text.is_empty() {
			write!(f, "server returned {}", self.status)
		} else {
			f.write_str(text)
		}
	}
	fn into_error(self) -> UpstreamError {
		UpstreamError::diagnostic(self)
	}
}
pub(crate) enum Outcome {
	Success { status: StatusCode, body: Option<ServerJson> },
	Diagnostic(ServerDiagnostic),
}
impl Outcome {
	pub(crate) fn into_response(self) -> Response {
		let response = match self {
			Self::Success { status, body: None } => Ok(status.into_response()),
			Self::Success { status, body: Some(body) } => body.into_response(status),
			Self::Diagnostic(diagnostic) => diagnostic.into_error_response(),
		};
		response.unwrap_or_else(IntoResponse::into_response)
	}
	pub(crate) fn into_health(self) -> UpstreamResult<crate::client::HealthResponse> {
		match self {
			Self::Success { body: Some(body), .. } => Ok(crate::client::HealthResponse(body)),
			Self::Success { body: None, .. } => Err(Failure::EmptyHealth.into_error()),
			Self::Diagnostic(diagnostic) => Err(diagnostic.into_error()),
		}
	}
}
/// Actual receive boundary, shared by health and every dashboard forward call.
#[allow(unsafe_code)]
pub(crate) async fn receive(response: reqwest::Response) -> Result<Outcome, Failure> {
	// SAFETY: this owner captures an actual upstream HTTP response; this token
	// never leaves its concrete Server header/body validators.
	let token = unsafe { Ingress::<Server>::new() };
	let status = response.status();
	if status.is_success() {
		Untrusted::new(response.headers(), token).validate(DashboardServerHeader)?;
	}
	let failure_status = (!status.is_success()).then_some(status);
	#[cfg(fuzzing)]
	crate::fuzz_support::hit(crate::fuzz_support::Entry::ServerCollect);
	let bytes = loupe_http::read_response_bytes(response).await.map_err(|error| match error {
		loupe_http::ResponseBodyError::TooLarge => Failure::BodyTooLarge(failure_status),
		loupe_http::ResponseBodyError::Transport(_) => Failure::BodyRead(failure_status),
	})?;
	if status.is_success() {
		Ok(Outcome::Success {
			status,
			body: Untrusted::new(bytes, token).validate(DashboardServerJson)?,
		})
	} else {
		Ok(Outcome::Diagnostic(
			Untrusted::new(bytes, token).validate(DashboardServerDiagnostic(status))?,
		))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	async fn outcome(status: StatusCode, body: &[u8]) -> Outcome {
		let response = axum::http::Response::builder()
			.status(status)
			.header(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string())
			.body(body.to_vec())
			.unwrap();
		receive(reqwest::Response::from(response)).await.unwrap()
	}
	#[tokio::test]
	async fn upstream_statuses_and_diagnostics_are_real_encoded_data() {
		for upstream in [
			StatusCode::UNAUTHORIZED,
			StatusCode::FORBIDDEN,
			StatusCode::NOT_FOUND,
			StatusCode::CONFLICT,
			StatusCode::BAD_REQUEST,
		] {
			let response = outcome(upstream, b" \"<script>FAKE_SERVER_DIAGNOSTIC</script>\"\n ")
				.await
				.into_response();
			assert_eq!(
				response.status(),
				if matches!(upstream, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
					StatusCode::BAD_GATEWAY
				} else {
					upstream
				}
			);
			let bytes = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
			assert_eq!(
				serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
				serde_json::json!({"error":"\"<script>FAKE_SERVER_DIAGNOSTIC</script>\""})
			);
		}
		assert_eq!(Failure::Transport.into_response().status(), StatusCode::BAD_GATEWAY);
	}
	#[tokio::test]
	async fn the_upstream_success_status_and_json_shape_are_preserved() {
		for (status, body) in [
			(StatusCode::CREATED, b"{\"repo_id\":1}".as_slice()),
			(StatusCode::OK, b"{}"),
			(StatusCode::NO_CONTENT, b""),
		] {
			let response = outcome(status, body).await.into_response();
			assert_eq!(response.status(), status);
			let bytes = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
			assert_eq!(bytes.as_ref(), body);
		}
	}
	#[tokio::test]
	async fn original_pointer_and_guarded_lossy_view_survive_validation() {
		let audit = json::audit::start();
		let raw = Bytes::from_static(b"{\"x\":1}");
		let pointer = raw.as_ptr();
		let response = axum::http::Response::builder()
			.header(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string())
			.body(raw)
			.unwrap();
		// The real shared collector owns a distinct guarded allocation; after
		// validation there is no additional plaintext copy or replacement.
		let Outcome::Success { body: Some(body), .. } =
			receive(reqwest::Response::from(response)).await.unwrap()
		else {
			panic!()
		};
		assert_ne!(body.0.original.as_ptr(), pointer);
		assert!(body.0.replacement.is_none());
		assert_eq!(body.0.text().as_ptr(), body.0.original.as_ptr());
		assert_eq!(format!("{body:?}"), "ServerJson([redacted])");
		drop(body);
		assert!(audit.lock().unwrap().is_empty());
		let Outcome::Success { body: Some(body), .. } =
			outcome(StatusCode::OK, b"\"\xff\xe2\x82\" ").await
		else {
			panic!()
		};
		assert_eq!(body.0.original.as_ref(), b"\"\xff\xe2\x82\" ");
		assert_eq!(body.0.text(), "\"��\" ");
		assert!(body.0.replacement.is_some());
		drop(body);
		let records = audit.lock().unwrap();
		assert_eq!(records.len(), 1);
		assert_eq!(records[0], (9, 9, true));
	}
}

#[cfg(test)]
mod stream_controls {
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::sync::Arc;

	use super::*;
	#[tokio::test]
	async fn success_header_rejection_precedes_collection_and_error_header_is_ignored() {
		for (status, polls_expected) in [(StatusCode::OK, 0), (StatusCode::CONFLICT, 1)] {
			let polls = Arc::new(AtomicUsize::new(0));
			let observed = polls.clone();
			let body = reqwest::Body::wrap_stream(futures_util::stream::once(async move {
				observed.fetch_add(1, Ordering::SeqCst);
				Ok::<_, std::io::Error>(Bytes::from_static(b"diagnostic"))
			}));
			let response = axum::http::Response::builder()
				.status(status)
				.header(PROTOCOL_VERSION_HEADER, "invalid")
				.body(body)
				.unwrap();
			let result = receive(reqwest::Response::from(response)).await;
			assert_eq!(result.is_ok(), status == StatusCode::CONFLICT);
			assert_eq!(polls.load(Ordering::SeqCst), polls_expected);
		}
	}
	#[tokio::test]
	async fn guarded_lossy_view_matches_standard_maximal_subpart_behavior() {
		let mut cases = (0u8..=255).map(|b| vec![b]).collect::<Vec<_>>();
		cases.extend([
			vec![0xe2, 0x82],
			vec![0xf0, 0x90, 0x80, 0x80],
			vec![0xf0, 0x80, 0x80, 0x80],
			vec![0xe2, b'(', 0xa1],
			vec![0xed, 0xa0, 0x80],
		]);
		for raw in cases {
			let expected = String::from_utf8_lossy(&raw);
			let response = axum::http::Response::builder()
				.status(StatusCode::CONFLICT)
				.body(raw.clone())
				.unwrap();
			let Outcome::Diagnostic(diagnostic) =
				receive(reqwest::Response::from(response)).await.unwrap()
			else {
				panic!()
			};
			assert_eq!(diagnostic.text.original.as_ref(), raw);
			assert_eq!(diagnostic.text.text(), expected);
		}
	}
}
