//! Configured budget controls exercise chunk accounting and identity isolation.
mod common;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use loupe_server::{router, AppState, PeerCert};
use loupe_storage::secrets::MasterKey;
use loupe_storage::{workers, Db};
use loupe_tls::{cert_fingerprint, Ca};
use tower::ServiceExt;

fn configured_fixture(
	config: loupe_server::request_budget::WorkerBudgetConfig,
) -> (axum::Router, PeerCert, PeerCert, PeerCert) {
	let ca = Arc::new(Ca::new("budget test").unwrap());
	let cert = PeerCert(rustls::pki_types::CertificateDer::from(vec![1, 2, 3]));
	let db = Arc::new(Db::open_in_memory(&MasterKey::for_tests()).unwrap());
	let admin = PeerCert(rustls::pki_types::CertificateDer::from(vec![4, 5, 6]));
	let other = PeerCert(rustls::pki_types::CertificateDer::from(vec![7, 8, 9]));
	db.with_conn(|conn| {
		workers::insert(
			conn,
			&common::marked::operator::text("admin"),
			workers::WorkerKind::Admin,
			&cert_fingerprint(admin.0.as_ref()),
			0,
		)?;
		Ok(workers::insert(
			conn,
			&common::marked::operator::text("other"),
			workers::WorkerKind::Worker,
			&cert_fingerprint(other.0.as_ref()),
			0,
		)?)
	})
	.unwrap();
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
	(router(state.with_worker_budgets(config).unwrap()), cert, admin, other)
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
	let response = app.clone().oneshot(req).await.unwrap();
	assert_eq!(
		response.headers()[loupe_proto::PROTOCOL_VERSION_HEADER],
		loupe_proto::PROTOCOL_VERSION.to_string()
	);
	response.status()
}

#[tokio::test]
async fn workers_are_independent_and_admin_health_bypass_worker_limits() {
	let mut config = loupe_server::request_budget::WorkerBudgetConfig::default();
	config.requests.capacity = 1;
	let (app, worker, admin, other) = configured_fixture(config);
	assert_eq!(request(&app, &worker, "/v1/whoami", Body::empty(), false).await, StatusCode::OK);
	assert_eq!(
		request(&app, &worker, "/v1/whoami", Body::empty(), false).await,
		StatusCode::TOO_MANY_REQUESTS
	);
	assert_eq!(request(&app, &other, "/v1/whoami", Body::empty(), false).await, StatusCode::OK);
	for _ in 0..3 {
		assert_eq!(request(&app, &admin, "/v1/whoami", Body::empty(), false).await, StatusCode::OK);
		assert_eq!(
			request(&app, &worker, "/v1/health", Body::empty(), false).await,
			StatusCode::OK
		);
	}
}

#[tokio::test]
async fn partial_stream_errors_keep_the_charge_for_received_bytes() {
	let mut config = loupe_server::request_budget::WorkerBudgetConfig::default();
	config.bytes.capacity = 3;
	let (app, worker, _, _) = configured_fixture(config);
	let body = Body::from_stream(futures_util::stream::iter([
		Ok(axum::body::Bytes::from_static(b"ab")),
		Err(std::io::Error::other("broken stream")),
	]));
	assert_eq!(request(&app, &worker, "/v1/whoami", body, false).await, StatusCode::BAD_REQUEST);
	assert_eq!(
		request(&app, &worker, "/v1/whoami", Body::from("cd"), false).await,
		StatusCode::TOO_MANY_REQUESTS
	);
}

#[tokio::test]
async fn chunks_override_content_length_and_existing_body_cap_still_applies() {
	let mut config = loupe_server::request_budget::WorkerBudgetConfig::default();
	config.bytes.capacity = 3;
	let (app, worker, _, _) = configured_fixture(config);
	let body = Body::from_stream(futures_util::stream::iter([
		Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"ab")),
		Ok(axum::body::Bytes::from_static(b"cd")),
	]));
	let mut req =
		Request::builder().uri("/v1/whoami").header("content-length", "1").body(body).unwrap();
	req.extensions_mut().insert(worker);
	assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::TOO_MANY_REQUESTS);

	let mut config = loupe_server::request_budget::WorkerBudgetConfig::default();
	config.bytes.capacity = 2 * 1024 * 1024 + 2;
	let (app, worker, _, _) = configured_fixture(config);
	assert_eq!(
		request(&app, &worker, "/v1/whoami", Body::from(vec![0; 2 * 1024 * 1024 + 1]), false).await,
		StatusCode::PAYLOAD_TOO_LARGE
	);
	assert_eq!(
		request(&app, &worker, "/v1/whoami", Body::from("ab"), false).await,
		StatusCode::TOO_MANY_REQUESTS
	);
}

#[tokio::test]
async fn worker_byte_charge_precedes_body_cap_and_protocol_rejection() {
	let config = loupe_server::request_budget::WorkerBudgetConfig {
		bytes: loupe_server::request_budget::BucketConfig {
			capacity: 2 * 1024 * 1024,
			refill_per_second: 1,
		},
		..Default::default()
	};
	let (app, worker, _, _) = configured_fixture(config);
	// One chunk exceeds both limits. Charge-before-cap gives 429, not 413 or the
	// unsupported-header 400. The existing cap test covers sufficient byte credit.
	assert_eq!(
		request(&app, &worker, "/v1/whoami", Body::from(vec![0; 2 * 1024 * 1024 + 1]), true).await,
		StatusCode::TOO_MANY_REQUESTS
	);
}

#[tokio::test]
async fn json_extraction_does_not_charge_the_worker_body_twice() {
	let body = serde_json::json!({
		"protocol_version": loupe_proto::PROTOCOL_VERSION,
		"capabilities": [],
		"wait_seconds": 0,
		"future_padding": "x".repeat(128 * 1024),
	})
	.to_string();
	let config = loupe_server::request_budget::WorkerBudgetConfig {
		bytes: loupe_server::request_budget::BucketConfig {
			capacity: (2 * body.len() + 64 * 1024) as u64,
			refill_per_second: 1,
		},
		..Default::default()
	};
	let (app, worker, _, _) = configured_fixture(config);
	for _ in 0..2 {
		assert_eq!(
			request(&app, &worker, "/v1/jobs/lease", Body::from(body.clone()), false).await,
			StatusCode::OK,
			"each admitted JSON body consumes its bytes only once"
		);
	}
	assert_eq!(
		request(&app, &worker, "/v1/jobs/lease", Body::from(body), false).await,
		StatusCode::TOO_MANY_REQUESTS,
		"successful JSON extraction must not bypass byte charging"
	);
}
