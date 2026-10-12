//! Real router/auth/budget fixture with a fresh bounded database for each case.
use std::sync::{Arc, Mutex, OnceLock};

use axum::body::{to_bytes, Body, Bytes};
use axum::http::{Method, Request};
use futures_util::{stream, StreamExt};
use loupe_proto::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use loupe_storage::{workers, Db};
use loupe_tls::{cert_fingerprint, Ca};
use tower::ServiceExt;

use crate::{router, AppState, PeerCert};

#[derive(Clone, Copy)]
pub struct RequestCase {
	/// 0 shared ignored body, 1 worker lease, 2 operator create repo, 3 operator ignored.
	pub route: u8,
	/// 0 Worker, 1 Operator, 2 missing, 3 unknown, 4 revoked.
	pub actor: u8,
	/// 0 absent, 1 correct, 2 incompatible, 3 malformed.
	pub protocol: u8,
	/// 0 JSON, 1 suffix JSON, 2 absent, 3 wrong media.
	pub media: u8,
	/// 0 valid body, 1 malformed syntax, 2 wrong schema, 3 wrong body version.
	pub body: u8,
	/// 0 short, 1 cap-1, 2 cap, 3 cap+1.
	pub boundary: u8,
	pub chunk_size: usize,
	pub bytes_capacity: u64,
	pub stream_error: bool,
	pub misleading_length: bool,
}

pub struct RequestObservation {
	pub status: u16,
	pub protocol: Option<String>,
	pub response: String,
	pub length: usize,
	pub polled_chunks: Vec<usize>,
	pub worker_budget: Option<(u64, u64)>,
	pub byte_charges: Vec<(u64, u64, bool)>,
	pub repo_count: usize,
}

struct Identities {
	ca: Arc<Ca>,
	peers: [PeerCert; 4],
}

fn identities() -> &'static Identities {
	static IDENTITIES: OnceLock<Identities> = OnceLock::new();
	IDENTITIES.get_or_init(|| {
		let ca = Arc::new(Ca::new("transport-fuzz-ca").expect("fixture CA"));
		let peers = ["worker", "operator", "unknown", "revoked"].map(|name| {
			let bundle = ca.mint_client(name).expect("fixture certificate");
			let cert = rustls_pemfile::certs(&mut bundle.cert_pem.as_bytes())
				.next()
				.expect("certificate block")
				.expect("certificate DER");
			PeerCert(cert)
		});
		Identities { ca, peers }
	})
}

fn fixture(bytes_capacity: u64) -> (Arc<Db>, AppState, i64) {
	let ids = identities();
	let db = Arc::new(
		Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).expect("fixture DB"),
	);
	let worker_id = db
		.with_conn(|conn| {
			let mut worker_id = 0;
			for (index, peer) in ids.peers.iter().enumerate() {
				if index == 2 {
					continue;
				}
				let kind = if index == 1 {
					workers::WorkerKind::Admin
				} else {
					workers::WorkerKind::Worker
				};
				let id = workers::insert(
					conn,
					&format!("fixture-{index}"),
					kind,
					&cert_fingerprint(peer.0.as_ref()),
					0,
				)?;
				if index == 0 {
					worker_id = id;
				}
				if index == 3 {
					assert!(workers::revoke(conn, id, 1)?);
				}
			}
			Ok(worker_id)
		})
		.expect("fixture worker rows");
	let mut config = crate::request_budget::WorkerBudgetConfig::default();
	config.bytes.capacity = bytes_capacity;
	config.bytes.refill_per_second = 1;
	let state = AppState::new(
		db.clone(),
		ids.ca.clone(),
		Arc::new(crate::reporters::GithubReporter::new().expect("fixture reporter")),
	)
	.with_worker_budgets(config)
	.expect("fixture budgets");
	(db, state, worker_id)
}

pub async fn request_route(case: RequestCase) -> RequestObservation {
	assert!(case.route < 4 && case.actor < 5 && case.body < 4 && case.boundary < 4);
	assert!((1..=8192).contains(&case.chunk_size));
	assert!((1..=8 * 1024 * 1024).contains(&case.bytes_capacity));
	let (db, state, worker_id) = fixture(case.bytes_capacity);
	let ids = identities();
	let budgets = state.worker_budgets.clone();
	let app = router(state);
	let version = if case.body == 3 { 65535 } else { PROTOCOL_VERSION };
	let prefix = match case.body {
		1 => "{private_body_sentinel".to_owned(),
		2 => "[]".to_owned(),
		_ if case.route == 1 => format!(r#"{{"protocol_version":{version},"capabilities":[],"wait_seconds":0}}"#),
		_ => format!(r#"{{"protocol_version":{version},"clone_url":"https://example.org/fixture/repo","reporting":{{"kind":"manual"}}}}"#),
	}.into_bytes();
	let length = match case.boundary {
		0 => prefix.len(),
		1 => 2 * 1024 * 1024 - 1,
		2 => 2 * 1024 * 1024,
		_ => 2 * 1024 * 1024 + 1,
	};
	let chunk_size = if case.boundary == 0 { case.chunk_size } else { case.chunk_size.max(4096) };
	let polled = Arc::new(Mutex::new(Vec::new()));
	let observation = polled.clone();
	let chunks = stream::unfold((prefix, 0usize), move |(prefix, offset)| {
		let observation = observation.clone();
		async move {
			if offset == length {
				return None;
			}
			let end = (offset + chunk_size).min(length);
			let mut bytes = vec![b' '; end - offset];
			if offset < prefix.len() {
				let count = bytes.len().min(prefix.len() - offset);
				bytes[..count].copy_from_slice(&prefix[offset..offset + count]);
			}
			observation.lock().expect("poll observation").push(bytes.len());
			Some((Ok::<_, std::io::Error>(Bytes::from(bytes)), (prefix, end)))
		}
	});
	let tail = stream::iter(
		case.stream_error
			.then(|| Err::<Bytes, _>(std::io::Error::other("private_stream_sentinel"))),
	);
	let (method, path) = match case.route {
		0 => (Method::GET, "/v1/whoami"),
		1 => (Method::POST, "/v1/jobs/lease"),
		2 => (Method::POST, "/v1/repos"),
		_ => (Method::GET, "/v1/repos"),
	};
	let mut request = Request::builder().method(method).uri(path);
	request = match case.protocol {
		1 => request.header(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string()),
		2 => request.header(PROTOCOL_VERSION_HEADER, "65535"),
		3 => request.header(PROTOCOL_VERSION_HEADER, "not-an-integer"),
		_ => request,
	};
	request = match case.media {
		0 => request.header("content-type", "application/json"),
		1 => request.header("content-type", "application/vnd.fixture+json; charset=utf-8"),
		3 => request.header("content-type", "text/plain"),
		_ => request,
	};
	if case.misleading_length {
		request = request.header("content-length", "1");
	}
	let mut request = request.body(Body::from_stream(chunks.chain(tail))).expect("fixture request");
	let peer = match case.actor {
		0 => Some(0),
		1 => Some(1),
		3 => Some(2),
		4 => Some(3),
		_ => None,
	};
	if let Some(peer) = peer {
		request.extensions_mut().insert(ids.peers[peer].clone());
	}
	let response = app.oneshot(request).await.expect("router infallible");
	let status = response.status().as_u16();
	let protocol = response
		.headers()
		.get(PROTOCOL_VERSION_HEADER)
		.map(|v| v.to_str().expect("response protocol").to_owned());
	let response =
		to_bytes(response.into_body(), 64 * 1024).await.expect("bounded fixture response");
	let response = String::from_utf8(response.to_vec()).expect("fixture response UTF-8");
	let worker_budget = budgets.observed_bytes(worker_id);
	let byte_charges = budgets.observed_charges();
	let polled_chunks = polled.lock().expect("poll observation").clone();
	let repo_count = db
		.with_conn(|conn| Ok(loupe_storage::repos::list(conn, None)?.len()))
		.expect("fixture repos");
	RequestObservation {
		status,
		protocol,
		response,
		length,
		polled_chunks,
		worker_budget,
		byte_charges,
		repo_count,
	}
}

/// Real registered repository, queued scan and server-issued active lease.
/// No caller can supply an authenticated extension or invent a capability.
pub async fn leased_heartbeat(body: u8, media: bool, wrong_capability: bool) -> (u16, String) {
	assert!(body < 7);
	let (_, state, _) = fixture(8 * 1024 * 1024);
	let app = router(state);
	let ids = identities();
	async fn post(
		app: &axum::Router, peer: &PeerCert, path: &str, body: String,
	) -> serde_json::Value {
		let mut request = Request::builder()
			.method(Method::POST)
			.uri(path)
			.header("content-type", "application/json")
			.body(Body::from(body))
			.expect("fixture request");
		request.extensions_mut().insert(peer.clone());
		let response = app.clone().oneshot(request).await.expect("fixture router");
		assert!(response.status().is_success(), "fixture setup failed: {}", response.status());
		let bytes =
			to_bytes(response.into_body(), 64 * 1024).await.expect("fixture setup response");
		serde_json::from_slice(&bytes).expect("fixture setup JSON")
	}
	let repo = post(&app, &ids.peers[1], "/v1/repos", format!(
		r#"{{"protocol_version":{PROTOCOL_VERSION},"clone_url":"https://example.org/fixture/repo","reporting":{{"kind":"manual"}}}}"#
	)).await;
	let repo_id = repo["repo_id"].as_i64().expect("registered repo id");
	let queued = post(
		&app,
		&ids.peers[1],
		&format!("/v1/repos/{repo_id}/scan"),
		format!(r#"{{"protocol_version":{PROTOCOL_VERSION}}}"#),
	)
	.await;
	let leased = post(
		&app,
		&ids.peers[0],
		"/v1/jobs/lease",
		format!(
			r#"{{"protocol_version":{PROTOCOL_VERSION},"capabilities":["scan:secrets"],"wait_seconds":0}}"#
		),
	)
	.await;
	assert_eq!(leased["kind"], "lease");
	assert_eq!(leased["job_id"], queued["job_id"]);
	let id = leased["job_id"].as_i64().expect("leased job id");
	let capability = leased["job_capability"].as_str().expect("server-issued capability");
	let raw = match body {
		0 => String::new(),
		1 => format!(r#"{{"protocol_version":{PROTOCOL_VERSION}}}"#),
		2 => "{private_body_sentinel".into(),
		3 => r#"{"protocol_version":65535}"#.into(),
		4 => " ".into(),
		5 => format!(
			r#"{{"protocol_version":{PROTOCOL_VERSION},"protocol_version":{PROTOCOL_VERSION}}}"#
		),
		_ => r#"{"protocol_version":"private_body_sentinel"}"#.into(),
	};
	let mut request =
		Request::builder().method(Method::POST).uri(format!("/v1/jobs/{id}/heartbeat")).header(
			loupe_proto::JOB_CAPABILITY_HEADER,
			if wrong_capability { "wrong-capability" } else { capability },
		);
	if media {
		request = request.header("content-type", "text/plain");
	}
	let mut request = request.body(Body::from(raw)).expect("heartbeat request");
	request.extensions_mut().insert(ids.peers[0].clone());
	let response = app.oneshot(request).await.expect("heartbeat router");
	let status = response.status().as_u16();
	assert_eq!(response.headers()[PROTOCOL_VERSION_HEADER], PROTOCOL_VERSION.to_string());
	let bytes = to_bytes(response.into_body(), 64 * 1024).await.expect("heartbeat response");
	(status, String::from_utf8(bytes.to_vec()).expect("heartbeat UTF-8"))
}
