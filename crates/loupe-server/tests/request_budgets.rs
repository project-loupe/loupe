//! Budget regressions exercise the real router and mTLS identity middleware.
mod common;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use loupe_server::{router, AppState, PeerCert};
use loupe_storage::secrets::MasterKey;
use loupe_storage::{workers, Db};
use loupe_tls::{cert_fingerprint, Ca};
use tower::ServiceExt;

fn fixture() -> (axum::Router, PeerCert) {
	let ca = Arc::new(Ca::new("budget test").unwrap());
	let cert = PeerCert(rustls::pki_types::CertificateDer::from(vec![1, 2, 3]));
	let db = Arc::new(Db::open_in_memory(&MasterKey::for_tests()).unwrap());
	db.with_conn(|conn| {
		Ok(workers::insert(
			conn,
			&common::marked::operator::text("worker"),
			workers::WorkerKind::Worker,
			&cert_fingerprint(cert.0.as_ref()),
			0,
		)?)
	})
	.unwrap();
	let state =
		AppState::new(db, ca, Arc::new(loupe_server::reporters::GithubReporter::new().unwrap()));
	(router(state), cert)
}

async fn request(
	app: &axum::Router, cert: &PeerCert, path: &str, body: Body, unsupported: bool,
) -> StatusCode {
	let mut req = Request::builder()
		.method(if path == "/v1/jobs/lease" { "POST" } else { "GET" })
		.uri(path)
		.header("content-type", "application/json");
	if unsupported {
		req = req.header(loupe_proto::PROTOCOL_VERSION_HEADER, "65535");
	}
	let mut req = req.body(body).unwrap();
	req.extensions_mut().insert(cert.clone());
	app.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn all_shared_worker_routes_consume_requests_including_bad_protocol() {
	let (app, cert) = fixture();
	for _ in 0..1500 {
		let _ = request(&app, &cert, "/v1/whoami", Body::empty(), true).await;
	}
	for path in ["/v1/whoami", "/v1/repos/1/findings/search", "/v1/findings/1"] {
		assert_eq!(
			request(&app, &cert, path, Body::empty(), false).await,
			StatusCode::TOO_MANY_REQUESTS,
			"authenticated shared route must consume the worker request budget: {path}"
		);
	}
}

#[tokio::test]
async fn actual_body_bytes_are_charged_even_on_shared_get_and_bad_protocol() {
	let (app, cert) = fixture();
	for _ in 0..40 {
		let _ = request(&app, &cert, "/v1/whoami", Body::from(vec![b'x'; 512 * 1024]), true).await;
	}
	assert_eq!(
		request(&app, &cert, "/v1/whoami", Body::from(vec![b'x'; 512 * 1024]), false).await,
		StatusCode::TOO_MANY_REQUESTS,
		"actual bytes without Content-Length must consume the worker body budget"
	);
}

#[tokio::test]
async fn lease_attempts_are_charged_before_a_long_poll_starts() {
	let (app, cert) = fixture();
	for _ in 0..100 {
		let _ = request(&app, &cert, "/v1/jobs/lease", Body::from("{}"), false).await;
	}
	let body = serde_json::json!({"protocol_version": loupe_proto::PROTOCOL_VERSION,
		"wait_seconds": 60, "capabilities": []})
	.to_string();
	let status = tokio::time::timeout(
		std::time::Duration::from_secs(2),
		request(&app, &cert, "/v1/jobs/lease", Body::from(body), false),
	)
	.await;
	assert_eq!(
		status.ok(),
		Some(StatusCode::TOO_MANY_REQUESTS),
		"lease budget must refuse before entering the long poll"
	);
}
