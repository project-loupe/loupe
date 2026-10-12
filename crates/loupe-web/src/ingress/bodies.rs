//! Six concrete Browser input owners; credentials remain encoded in wiping
//! storage, including replaced/unknown values. No PAT-bearing Value is built.
use std::fmt;
use std::marker::PhantomData;

use axum::extract::{FromRequest, Request};
use axum::http::header;
use bytes::Bytes;
use futures_util::StreamExt;
use loupe_provenance::{Browser, Mark, Untrusted, Unvalidated, Validate};

use super::{json, BrowserRequest, Failure};
use crate::WebState;
const BODY_LIMIT: usize = 2 * 1024 * 1024;

enum Document {
	Absent,
	Present(Bytes, PhantomData<Browser>),
}
impl Document {
	fn into_upstream_legacy(self) -> Result<Bytes, Failure> {
		match self {
			Self::Absent => json::encode_browser(b"{}"),
			Self::Present(bytes, _) => json::encode_browser(&bytes),
		}
	}
}
macro_rules! owner {
	($name:ident, $validator:ident) => {
		pub(crate) struct $name(Document);
		impl fmt::Debug for $name {
			fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.write_str(concat!(stringify!($name), "([redacted])"))
			}
		}
		struct $validator;
		impl Validate<Bytes, Browser> for $validator {
			type Output = $name;
			type Error = Failure;
			fn validate<'v>(
				self, u: Unvalidated<'v, Bytes>, _: Mark<'v, Browser>,
			) -> Result<Self::Output, Failure> {
				json::admit(u.get())?;
				Ok($name(Document::Present(u.get().clone(), PhantomData)))
			}
		}
		impl FromRequest<WebState> for $name {
			type Rejection = Failure;
			async fn from_request(req: Request, _: &WebState) -> Result<Self, Failure> {
				let context =
					req.extensions().get::<BrowserRequest>().cloned().ok_or(Failure::Context)?;
				let Some(media) = req.headers().get(header::CONTENT_TYPE) else {
					return Ok(Self(Document::Absent));
				};
				let media = media
					.to_str()
					.ok()
					.and_then(|s| s.parse::<mime::Mime>().ok())
					.ok_or(Failure::Media)?;
				if media.type_() != mime::APPLICATION
					|| (media.subtype() != mime::JSON && media.suffix() != Some(mime::JSON))
				{
					return Err(Failure::Media);
				}
				let mut buffer = json::Buffer::new(BODY_LIMIT);
				let mut chunks = req.into_body().into_data_stream();
				while let Some(chunk) = chunks.next().await {
					buffer.append(&chunk.map_err(|_| Failure::BodyRead)?)?;
				}
				Untrusted::new(Bytes::from_owner(buffer), context.token).validate($validator)
			}
		}
		impl $name {
			pub(crate) fn into_upstream_legacy(self) -> Result<Bytes, Failure> {
				self.0.into_upstream_legacy()
			}
		}
	};
}
owner!(BrowserCreateRepo, CreateRepo);
owner!(BrowserUpdateRepo, UpdateRepo);
owner!(BrowserRotatePat, RotatePat);
owner!(BrowserSetGithubReporting, SetGithubReporting);
owner!(BrowserEnqueueScan, EnqueueScan);
owner!(BrowserRetryVerify, RetryVerify);

#[cfg(test)]
mod tests {
	use axum::body::{to_bytes, Body};
	use axum::http::StatusCode;
	use axum::response::IntoResponse;
	use axum::routing::post;
	use axum::Router;
	use tower::ServiceExt;

	use super::*;
	const PAT: &str = "FAKE_WEB_FORWARD_PAT_SENTINEL";
	fn app() -> Router {
		let state = WebState::for_tests("127.0.0.1:8455");
		Router::new()
			.route(
				"/rotate",
				post(async |body: BrowserRotatePat| {
					assert!(!format!("{body:?}").contains(PAT));
					body.into_upstream_legacy().unwrap().into_response()
				}),
			)
			.route(
				"/create",
				post(async |body: BrowserCreateRepo| {
					assert!(!format!("{body:#?}").contains(PAT));
					body.into_upstream_legacy().unwrap().into_response()
				}),
			)
			.route(
				"/report",
				post(async |body: BrowserSetGithubReporting| {
					assert!(!format!("{body:?}").contains(PAT));
					body.into_upstream_legacy().unwrap().into_response()
				}),
			)
			.layer(axum::middleware::from_fn_with_state(state.clone(), crate::guard::browser_guard))
			.with_state(state)
	}
	async fn through(path: &str, body: Option<&str>) -> serde_json::Value {
		let mut request = Request::builder()
			.method("POST")
			.uri(path)
			.header("Host", "127.0.0.1:8455")
			.header("Sec-Fetch-Site", "same-origin")
			.header(crate::guard::REQUEST_HEADER, "");
		if body.is_some() {
			request = request.header("Content-Type", "application/json");
		}
		let response = app()
			.oneshot(request.body(Body::from(body.unwrap_or("").to_owned())).unwrap())
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
		serde_json::from_slice(&to_bytes(response.into_body(), 4 * 1024 * 1024).await.unwrap())
			.unwrap()
	}
	#[tokio::test]
	async fn a_missing_body_becomes_an_object_with_the_protocol_version() {
		assert_eq!(
			through("/create", None).await,
			serde_json::json!({"protocol_version":loupe_proto::PROTOCOL_VERSION})
		);
	}
	#[tokio::test]
	async fn a_supplied_body_keeps_its_fields() {
		assert_eq!(
			through("/create", Some(r#"{"incremental":true}"#)).await,
			serde_json::json!({"protocol_version":loupe_proto::PROTOCOL_VERSION,"incremental":true})
		);
	}
	#[tokio::test]
	async fn actual_forward_body_owner_does_not_disclose_pat() {
		for path in ["/rotate", "/create", "/report"] {
			let raw = format!(r#"{{"github_pat":"{PAT}","reporting":{{"github_pat":"{PAT}"}}}}"#);
			let value = through(path, Some(&raw)).await;
			assert_eq!(value["github_pat"], PAT);
			assert_eq!(value["reporting"]["github_pat"], PAT);
		}
	}
}

#[cfg(test)]
mod cleanup_tests {
	use std::convert::Infallible;
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::sync::Arc;
	use std::time::Duration;

	use axum::body::{to_bytes, Body};
	use axum::http::StatusCode;
	use axum::response::IntoResponse;
	use axum::routing::post;
	use axum::Router;
	use futures_util::{stream, StreamExt};
	use tower::ServiceExt;

	use super::*;
	fn app() -> Router {
		let state = WebState::for_tests("127.0.0.1:8455");
		Router::new()
			.route(
				"/",
				post(async |body: BrowserRotatePat| {
					body.into_upstream_legacy().unwrap().into_response()
				}),
			)
			.layer(axum::middleware::from_fn_with_state(state.clone(), crate::guard::browser_guard))
			.with_state(state)
	}
	fn request(body: Body, media: Option<&str>, host: &str) -> Request {
		let mut r = Request::builder()
			.method("POST")
			.uri("/")
			.header("Host", host)
			.header("Sec-Fetch-Site", "same-origin")
			.header(crate::guard::REQUEST_HEADER, "");
		if let Some(media) = media {
			r = r.header("Content-Type", media);
		}
		r.body(body).unwrap()
	}
	#[tokio::test]
	async fn guards_and_optional_media_do_not_poll_ignored_body() {
		for (media, host, status) in [
			(Some("application/json"), "evil.test", 403),
			(None, "127.0.0.1:8455", 200),
			(Some("text/plain"), "127.0.0.1:8455", 415),
		] {
			let polls = Arc::new(AtomicUsize::new(0));
			let count = polls.clone();
			let body = Body::from_stream(stream::once(async move {
				count.fetch_add(1, Ordering::SeqCst);
				Ok::<_, Infallible>(Bytes::from_static(b"ignored"))
			}));
			assert_eq!(app().oneshot(request(body, media, host)).await.unwrap().status(), status);
			assert_eq!(polls.load(Ordering::SeqCst), 0);
		}
	}
	#[tokio::test]
	async fn admitted_limit_and_over_limit_keep_cleanup_and_stamp_expansion() {
		let mut exact = b"{}".to_vec();
		exact.resize(BODY_LIMIT, b' ');
		let response = app()
			.oneshot(request(Body::from(exact.clone()), Some("application/json"), "127.0.0.1:8455"))
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
		let value: serde_json::Value = serde_json::from_slice(
			&to_bytes(response.into_body(), BODY_LIMIT + 128).await.unwrap(),
		)
		.unwrap();
		assert_eq!(value["protocol_version"], loupe_proto::PROTOCOL_VERSION);
		let expanded = format!("{{\"x\":\"{}\"}}", "a".repeat(BODY_LIMIT - 8));
		assert_eq!(expanded.len(), BODY_LIMIT);
		let response = app()
			.oneshot(request(Body::from(expanded), Some("application/json"), "127.0.0.1:8455"))
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
		let encoded = to_bytes(response.into_body(), BODY_LIMIT + 128).await.unwrap();
		assert!(encoded.len() > BODY_LIMIT, "stamping must not introduce a second body cap");
		let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
		assert_eq!(value["x"].as_str().unwrap().len(), BODY_LIMIT - 8);
		assert_eq!(value["protocol_version"], loupe_proto::PROTOCOL_VERSION);
		let audit = json::audit::start();
		let stream =
			stream::iter([Ok::<_, Infallible>(Bytes::from(exact)), Ok(Bytes::from_static(b"x"))]);
		let response = app()
			.oneshot(request(Body::from_stream(stream), Some("application/json"), "127.0.0.1:8455"))
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
		let records = audit.lock().unwrap();
		assert_eq!(records.as_slice(), &[(BODY_LIMIT, BODY_LIMIT, true)]);
	}
	#[tokio::test]
	async fn parse_transport_and_cancel_failures_wipe_still_live_storage() {
		let audit = json::audit::start();
		let response = app()
			.oneshot(request(
				Body::from("FAKE_PAT invalid json"),
				Some("application/json"),
				"127.0.0.1:8455",
			))
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::BAD_REQUEST);
		let stream = stream::iter([
			Ok(Bytes::from_static(b"FAKE_PAT")),
			Err(std::io::Error::other("fixture failure")),
		]);
		let response = app()
			.oneshot(request(Body::from_stream(stream), Some("application/json"), "127.0.0.1:8455"))
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::BAD_REQUEST);
		let chunks = stream::once(async { Ok::<_, Infallible>(Bytes::from_static(b"FAKE_PAT")) })
			.chain(stream::pending());
		let future = app().oneshot(request(
			Body::from_stream(chunks),
			Some("application/json"),
			"127.0.0.1:8455",
		));
		assert!(tokio::time::timeout(Duration::from_millis(20), future).await.is_err());
		let records = audit.lock().unwrap();
		assert_eq!(records.len(), 3);
		assert!(records.iter().all(|(cap, used, zero)| *cap == BODY_LIMIT && *used > 0 && *zero));
	}
}
