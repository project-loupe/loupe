//! Byte zero selects token, path, query, JSON body, Host, Origin, Fetch-Site,
//! or a valid control request. Remaining bytes exercise that browser boundary.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use axum::body::{to_bytes, Body};
use axum::http::{HeaderValue, Request, StatusCode};
use axum::{Json, Router};
use loupe_web::{AdminClient, Token, WebState};
use tower::ServiceExt;

use crate::utils::test_logger;

fn encoded(bytes: &[u8]) -> String {
	bytes.iter().map(|byte| format!("%{byte:02X}")).collect()
}

pub fn do_test(data: &[u8]) {
	if data.len() > 4096 {
		return;
	}
	let Some((&mode, bytes)) = data.split_first() else { return };
	let mode = mode % 8;
	static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
	let runtime = RUNTIME.get_or_init(|| {
		tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.unwrap_or_else(|error| panic!("web runtime: {error}"))
	});
	runtime.block_on(async {
		let calls = Arc::new(AtomicUsize::new(0));
		let seen = calls.clone();
		let upstream = Router::new().fallback(move |request: Request<Body>| {
			let seen = seen.clone();
			async move {
				seen.fetch_add(1, Ordering::Relaxed);
				let uri = request.uri().to_string();
				let body = to_bytes(request.into_body(), 16 * 1024)
					.await
					.unwrap_or_else(|error| panic!("stub request body: {error}"));
				let value = serde_json::json!({"uri": uri, "body": String::from_utf8_lossy(&body)});
				(
					[(
						loupe_proto::PROTOCOL_VERSION_HEADER,
						loupe_proto::PROTOCOL_VERSION.to_string(),
					)],
					Json(value),
				)
			}
		});
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
			.await
			.unwrap_or_else(|error| panic!("web stub listener: {error}"));
		let address =
			listener.local_addr().unwrap_or_else(|error| panic!("web stub address: {error}"));
		let server = tokio::spawn(async move { axum::serve(listener, upstream).await });
		let client = AdminClient::from_parts(
			reqwest::Client::new(),
			format!("http://{address}/")
				.parse()
				.unwrap_or_else(|error| panic!("web stub URL: {error}")),
		);
		let token = Token::generate();
		let secret = token.reveal().to_owned();
		assert_eq!(format!("{token:?}"), "[redacted]");
		let state = WebState::new(
			client,
			token,
			"127.0.0.1:8455".parse().unwrap_or_else(|_| unreachable!()),
			5,
		);
		let app = loupe_web::router(state);
		let path = match mode {
			1 => format!("/api/jobs/{}", encoded(bytes)),
			2 => format!("/api/repos?limit={}", encoded(bytes)),
			3 | 5 | 6 => "/api/repos".into(),
			_ => "/api/config".into(),
		};
		let mut request = Request::builder()
			.uri(path)
			.method(if matches!(mode, 3 | 5 | 6) { "POST" } else { "GET" })
			.header("host", "127.0.0.1:8455")
			.header(loupe_web::token::HEADER_NAME, &secret)
			.header("content-type", "application/json")
			.header(loupe_web::guard::REQUEST_HEADER, "1")
			.header("sec-fetch-site", "same-origin")
			.body(Body::from(if mode == 3 { bytes.to_vec() } else { b"{}".to_vec() }))
			.unwrap_or_else(|error| panic!("web fuzz request: {error}"));
		let header = match mode {
			0 => Some(loupe_web::token::HEADER_NAME),
			4 => Some("host"),
			5 => {
				request.headers_mut().remove("sec-fetch-site");
				Some("origin")
			},
			6 => Some("sec-fetch-site"),
			_ => None,
		};
		if let Some(header) = header {
			request.headers_mut().remove(header);
			if let Ok(value) = HeaderValue::from_bytes(bytes) {
				request.headers_mut().insert(header, value);
			}
		}
		let response =
			tokio::time::timeout(std::time::Duration::from_secs(5), app.oneshot(request))
				.await
				.unwrap_or_else(|_| panic!("web request timed out"))
				.unwrap_or_else(|_| unreachable!());
		let status = response.status();
		let body = to_bytes(response.into_body(), 128 * 1024)
			.await
			.unwrap_or_else(|error| panic!("web response exceeded budget: {error}"));
		server.abort();
		let _ = server.await;
		let rejected = match mode {
			0 => (bytes != secret.as_bytes()).then_some(StatusCode::UNAUTHORIZED),
			4 => (!matches!(bytes, b"127.0.0.1:8455" | b"localhost:8455"))
				.then_some(StatusCode::FORBIDDEN),
			5 => (!matches!(bytes, b"http://127.0.0.1:8455" | b"http://localhost:8455"))
				.then_some(StatusCode::FORBIDDEN),
			6 => (bytes != b"same-origin").then_some(StatusCode::FORBIDDEN),
			_ => None,
		};
		if let Some(expected) = rejected {
			assert_eq!(status, expected, "browser boundary admitted an invalid header");
			assert_eq!(
				calls.load(Ordering::Relaxed),
				0,
				"rejected browser request reached upstream"
			);
		}
		if !body.is_empty() && serde_json::from_slice::<serde_json::Value>(&body).is_err() {
			// Guards emit fixed messages. Every variable extractor/upstream
			// diagnostic must be JSON, never unquoted browser input.
			assert!(
				matches!(body.as_ref(),
				b"missing or invalid dashboard capability; reopen the URL printed at startup\n"
				| b"unexpected Host header; loupe-web only answers on its own loopback address\n"
				| b"cross-origin request refused\n"),
				"browser input escaped a JSON response envelope"
			);
		}
		if mode == 7 {
			assert_eq!(status, StatusCode::OK, "valid token control failed");
		}
	});
}

pub fn web_api_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_api_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
