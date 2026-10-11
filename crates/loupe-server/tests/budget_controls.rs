//! Configured budget controls exercise chunk accounting and identity isolation.
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
			"admin",
			workers::WorkerKind::Admin,
			&cert_fingerprint(admin.0.as_ref()),
			0,
		)?;
		Ok(workers::insert(
			conn,
			"other",
			workers::WorkerKind::Worker,
			&cert_fingerprint(other.0.as_ref()),
			0,
		)?)
	})
	.unwrap();
	db.with_conn(|conn| {
		Ok(workers::insert(
			conn,
			"worker",
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
	app.clone().oneshot(req).await.unwrap().status()
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
