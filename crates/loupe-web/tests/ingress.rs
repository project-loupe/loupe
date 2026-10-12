//! Real-router admission, forwarding and client compatibility checks.
mod support;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::to_bytes;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use loupe_proto::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use loupe_web::{Token, WebState};
use serde_json::{json, Value};

struct Harness {
	base: String,
	token: String,
	calls: Arc<AtomicUsize>,
	tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Harness {
	async fn new() -> Self {
		let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let up = upstream.local_addr().unwrap();
		let calls = Arc::new(AtomicUsize::new(0));
		let seen = calls.clone();
		let echo = Router::new().fallback(any(move |request: Request| {
			let seen = seen.clone();
			async move {
				seen.fetch_add(1, Ordering::SeqCst);
				let method = request.method().to_string();
				let uri = request.uri().to_string();
				let protocol = request
					.headers()
					.get(PROTOCOL_VERSION_HEADER)
					.map(|h| h.to_str().unwrap().to_owned());
				let bytes = to_bytes(request.into_body(), 8 * 1024 * 1024).await.unwrap();
				let body = if bytes.is_empty() {
					Value::Null
				} else {
					serde_json::from_slice(&bytes).unwrap()
				};
				let mut response = (
					StatusCode::CREATED,
					axum::Json(json!({"method":method,"uri":uri,"protocol":protocol,"body":body})),
				)
					.into_response();
				response
					.headers_mut()
					.insert(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string().parse().unwrap());
				response
			}
		}));
		let up_task = tokio::spawn(async move { axum::serve(upstream, echo).await.unwrap() });
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr = listener.local_addr().unwrap();
		let token = Token::generate();
		let reveal = token.reveal().to_owned();
		let client =
			support::client(reqwest::Client::new(), format!("http://{up}/").parse().unwrap());
		let app = loupe_web::router(WebState::new(client, token, addr, 5));
		let web = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
		Self { base: format!("http://{addr}"), token: reveal, calls, tasks: vec![up_task, web] }
	}
	fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
		reqwest::Client::new()
			.request(method, format!("{}{path}", self.base))
			.header(loupe_web::token::HEADER_NAME, &self.token)
			.header("Sec-Fetch-Site", "same-origin")
			.header(loupe_web::guard::REQUEST_HEADER, "present")
	}
	async fn stop(mut self) {
		for task in self.tasks.drain(..) {
			task.abort();
			let _ = task.await;
		}
	}
}
impl Drop for Harness {
	fn drop(&mut self) {
		for task in &self.tasks {
			task.abort();
		}
	}
}

#[tokio::test]
async fn route_parser_errors_do_not_reflect_browser_path() {
	let h = Harness::new().await;
	let response =
		h.request(reqwest::Method::GET, "/api/jobs/FAKE_PATH_SENTINEL-%22").send().await.unwrap();
	assert_eq!(response.status(), 400);
	let value: Value = response.json().await.unwrap();
	let message = value["error"].as_str().unwrap();
	assert!(
		!message.contains("FAKE_PATH_SENTINEL"),
		"path parser error reflects browser input: {message}"
	);
	assert_eq!(h.calls.load(Ordering::SeqCst), 0);
	h.stop().await;
}
#[tokio::test]
async fn route_query_error_nonreflection_control() {
	let h = Harness::new().await;
	let response = h
		.request(reqwest::Method::GET, "/api/jobs?limit=FAKE_QUERY_SENTINEL")
		.send()
		.await
		.unwrap();
	assert_eq!(response.status(), 400);
	let value: Value = response.json().await.unwrap();
	assert!(!value["error"].as_str().unwrap().contains("FAKE_QUERY_SENTINEL"));
	assert_eq!(h.calls.load(Ordering::SeqCst), 0);
	h.stop().await;
}
#[tokio::test]
async fn transport_errors_do_not_retain_request_query() {
	let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
	let addr = reserved.local_addr().unwrap();
	drop(reserved);
	let http =
		reqwest::Client::builder().timeout(std::time::Duration::from_secs(2)).build().unwrap();
	let client = support::client(http, format!("http://{addr}/").parse().unwrap());
	let (status, value) =
		support::forward(client, "/api/repos/1/findings/search?q=FAKE_TRANSPORT_QUERY_SENTINEL")
			.await;
	assert_eq!(status, StatusCode::BAD_GATEWAY);
	let err = value.unwrap();
	assert_eq!(err["error"], "upstream request failed");
	for rendered in [format!("{err}"), format!("{err:?}")] {
		assert!(
			!rendered.contains("FAKE_TRANSPORT_QUERY_SENTINEL"),
			"transport error retained query: {rendered}"
		);
	}
}

#[tokio::test]
async fn optional_body_and_forwarding_grammar_controls() {
	let h = Harness::new().await;
	for (method, path) in [
		(reqwest::Method::POST, "/api/repos"),
		(reqwest::Method::PATCH, "/api/repos/1"),
		(reqwest::Method::POST, "/api/repos/1/reporting/github-pat"),
		(reqwest::Method::PUT, "/api/repos/1/reporting/github"),
		(reqwest::Method::POST, "/api/repos/1/scan"),
		(reqwest::Method::POST, "/api/findings/retry-verify"),
	] {
		for (media, raw, expected_status) in [
			(None, "ignored non-json", 201),
			(Some("text/plain"), "{}", 415),
			(Some("application/json"), "", 400),
			(Some("application/json"), " ", 400),
			(Some("application/json"), "null", 201),
			(Some("application/json"), "[1,true,\"x\"]", 201),
			(Some("application/json"), "false", 201),
			(Some("application/json"), "2.5", 201),
			(
				Some("application/json; charset=utf-8"),
				r#"{"protocol_version":1,"github_pat":"old","github_pat":"new","extra":{"x":1}}"#,
				201,
			),
			(
				Some("application/vnd.test+json"),
				r#"{"github_pat":"old","github_\u0070at":" escaped ","reporting":{"github_pat":"a","github_pat":"b"}}"#,
				201,
			),
			(Some("application/json"), r#"{"unknown":1e400}"#, 400),
			(Some("application/json"), r#"{"github_pat":1e400}"#, 400),
			(Some("application/json"), r#"{"unknown":"\uD800"}"#, 400),
		] {
			let before = h.calls.load(Ordering::SeqCst);
			let mut request = h.request(method.clone(), path).body(raw.to_owned());
			if let Some(media) = media {
				request = request.header(header::CONTENT_TYPE, media);
			}
			let response = request.send().await.unwrap();
			assert_eq!(response.status().as_u16(), expected_status, "{path} {media:?} {raw}");
			if expected_status == 201 {
				let value: Value = response.json().await.unwrap();
				let mut expected =
					if media.is_none() { json!({}) } else { serde_json::from_str(raw).unwrap() };
				if let Some(object) = expected.as_object_mut() {
					object.insert("protocol_version".into(), PROTOCOL_VERSION.into());
				}
				assert_eq!(value["body"], expected);
				assert_eq!(value["protocol"], PROTOCOL_VERSION.to_string());
				assert_eq!(h.calls.load(Ordering::SeqCst), before + 1);
			} else {
				assert_eq!(h.calls.load(Ordering::SeqCst), before);
			}
		}
	}
	h.stop().await;
}

#[tokio::test]
async fn path_and_query_forwarding_controls() {
	let h = Harness::new().await;
	for (path, expected) in [
		("/api/repos", "/v1/repos"),
		("/api/repos?limit=50", "/v1/repos?limit=50"),
		("/api/jobs/%2B0007", "/v1/jobs/7"),
		("/api/jobs/-9223372036854775808", "/v1/jobs/-9223372036854775808"),
		("/api/jobs?state=&kind=%20%20&limit=-2&unknown=ignored", "/v1/jobs?limit=-2&kind=++"),
		("/api/repos?limit=0", "/v1/repos?limit=0"),
		(
			"/api/repos/1/findings/search?q=++e%CC%81%0A%26%3D%2B%25++&limit=-3&unknown=x",
			"/v1/repos/1/findings/search?q=++e%CC%81%0A%26%3D%2B%25++&limit=-3",
		),
	] {
		let response = h.request(reqwest::Method::GET, path).send().await.unwrap();
		assert_eq!(response.status(), 201, "{path}");
		let value: Value = response.json().await.unwrap();
		assert_eq!(value["uri"], expected);
	}
	for path in [
		"/api/jobs/9223372036854775808",
		"/api/jobs/%FF",
		"/api/jobs?limit=1&limit=2",
		"/api/jobs?state=a&state=b",
		"/api/repos/1/findings/search?limit=1",
	] {
		let before = h.calls.load(Ordering::SeqCst);
		assert_eq!(
			h.request(reqwest::Method::GET, path).send().await.unwrap().status(),
			400,
			"{path}"
		);
		assert_eq!(h.calls.load(Ordering::SeqCst), before);
	}
	let response = h.request(reqwest::Method::GET, "/api/config").send().await.unwrap();
	assert_eq!(response.status(), 200);
	assert!(response.json::<Value>().await.is_ok());
	h.stop().await;
}

#[tokio::test]
async fn browser_guard_preserves_non_ascii_fetch_fallback_and_header_presence() {
	let h = Harness::new().await;
	let response = h
		.guard_request()
		.header("Sec-Fetch-Site", reqwest::header::HeaderValue::from_bytes(b"\xff").unwrap())
		.header("Origin", &h.base)
		.header(loupe_web::guard::REQUEST_HEADER, "")
		.send()
		.await
		.unwrap();
	assert_eq!(response.status(), 201);
	let before = h.calls.load(Ordering::SeqCst);
	let response = h
		.guard_request()
		.header("Sec-Fetch-Site", "cross-site")
		.header("Origin", &h.base)
		.send()
		.await
		.unwrap();
	assert_eq!(response.status(), 403);
	assert_eq!(h.calls.load(Ordering::SeqCst), before);
	h.stop().await;
}

impl Harness {
	fn guard_request(&self) -> reqwest::RequestBuilder {
		reqwest::Client::new()
			.post(format!("{}/api/repos/1/scan", self.base))
			.header(loupe_web::token::HEADER_NAME, &self.token)
			.header(loupe_web::guard::REQUEST_HEADER, "")
	}
}

#[tokio::test]
async fn browser_query_fields_reject_newly_prohibited_controls() {
	let h = Harness::new().await;
	let mut admitted = Vec::new();
	for path in [
		"/api/repos/1/findings/search?q=%1Bsentinel",
		"/api/jobs?state=%1Bsentinel",
		"/api/jobs?kind=future%0Akind",
	] {
		let before = h.calls.load(Ordering::SeqCst);
		let response = h.request(reqwest::Method::GET, path).send().await.unwrap();
		if response.status() != 400 || h.calls.load(Ordering::SeqCst) != before {
			admitted.push(path);
		}
	}
	h.stop().await;
	assert!(
		admitted.is_empty(),
		"actual Browser query owners admitted newly prohibited fields: {admitted:?}"
	);
}
