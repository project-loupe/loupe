//! Authenticated router compatibility and diagnostic redaction checks.

mod common;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use common::wire::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use loupe_server::{router, AppState, PeerCert};
use loupe_storage::secrets::MasterKey;
use loupe_storage::{registry, Db};
use loupe_tls::{cert_fingerprint, Ca};
use tower::ServiceExt;

struct Fixture {
	app: axum::Router,
	db: Arc<Db>,
	admin: PeerCert,
	worker: PeerCert,
	revoked: PeerCert,
}

fn fixture() -> Fixture {
	let db = Arc::new(Db::open_in_memory(&MasterKey::for_tests()).unwrap());
	let admin = PeerCert(vec![1, 2, 3].into());
	let worker = PeerCert(vec![4, 5, 6].into());
	let revoked = PeerCert(vec![7, 8, 9].into());
	registry::bootstrap_admin(&db, &cert_fingerprint(admin.0.as_ref()), 0).unwrap();
	let operator = common::marked::operator_ingress();
	for (name, cert) in [("worker", &worker), ("revoked", &revoked)] {
		let id = registry::register_worker(
			&db,
			&operator,
			&common::marked::operator::text(name),
			&cert_fingerprint(cert.0.as_ref()),
			0,
		)
		.unwrap();
		if name == "revoked" {
			assert!(registry::revoke_worker(&db, &operator, id, 1).unwrap());
		}
	}
	let state = AppState::new(
		db.clone(),
		Arc::new(Ca::new("ingress compatibility").unwrap()),
		Arc::new(loupe_server::reporters::GithubReporter::new().unwrap()),
	);
	Fixture { app: router(state), db, admin, worker, revoked }
}

async fn send(
	f: &Fixture, cert: Option<&PeerCert>, mut request: Request<Body>,
) -> (StatusCode, String) {
	if let Some(cert) = cert {
		request.extensions_mut().insert(cert.clone());
	}
	let response = f.app.clone().oneshot(request).await.unwrap();
	assert_eq!(response.headers()[PROTOCOL_VERSION_HEADER], PROTOCOL_VERSION.to_string());
	let status = response.status();
	let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
	(status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn post(path: &str, content_type: Option<&str>, body: impl Into<Body>) -> Request<Body> {
	let mut request = Request::builder().method("POST").uri(path);
	if let Some(content_type) = content_type {
		request = request.header("content-type", content_type);
	}
	request.body(body.into()).unwrap()
}

fn repo_json(name: &str) -> String {
	format!(
		r#"{{"protocol_version":{PROTOCOL_VERSION},"clone_url":"https://github.com/acme/{name}.git","reporting":{{"kind":"manual"}}}}"#
	)
}

#[tokio::test]
async fn lease_overflow_number_keeps_syntax_category() {
	let f = fixture();
	let mut observed = Vec::new();
	for (capability, expected, diagnostic) in [
		("1e400", StatusCode::BAD_REQUEST, "Failed to parse"),
		("1", StatusCode::UNPROCESSABLE_ENTITY, "invalid type"),
		("\"verify:secrets\"", StatusCode::OK, ""),
	] {
		let request =
			format!(r#"{{"protocol_version":{PROTOCOL_VERSION},"capabilities":[{capability}]}}"#);
		let (status, body) =
			send(&f, Some(&f.worker), post("/v1/jobs/lease", Some("application/json"), request))
				.await;
		observed.push((capability, status, body.contains(diagnostic)));
		if expected == StatusCode::OK {
			assert!(matches!(
				serde_json::from_str::<common::wire::LeaseResponse>(&body).unwrap(),
				common::wire::LeaseResponse::Empty { .. }
			));
		}
	}
	assert_eq!(observed, vec![
		("1e400", StatusCode::BAD_REQUEST, true),
		("1", StatusCode::UNPROCESSABLE_ENTITY, true),
		("\"verify:secrets\"", StatusCode::OK, true),
	], "retain numeric-overflow syntax rejection, finite non-string data rejection, and string admission");
}

#[tokio::test]
async fn malformed_field_containers_receive_syntax_rejection() {
	// RawValue scans a complete token before type validation, so malformed
	// containers yield syntax/400 rather than a wrong-type/422 response.
	let f = fixture();
	let malformed_object =
		format!(r#"{{"protocol_version":{PROTOCOL_VERSION},"capabilities":[{{"x":"#);
	let malformed_array = format!(r#"{{"protocol_version":{PROTOCOL_VERSION},"capabilities":[["#);
	let unknown_overflow =
		format!(r#"{{"protocol_version":{PROTOCOL_VERSION},"capabilities":[],"future":1e400}}"#);
	let positional = format!(r#"[{PROTOCOL_VERSION},["verify:secrets"],0]"#);
	let wrong_object =
		format!(r#"{{"protocol_version":{PROTOCOL_VERSION},"capabilities":[{{}}]}}"#);
	let wrong_array = format!(r#"{{"protocol_version":{PROTOCOL_VERSION},"capabilities":[[]]}}"#);
	let malformed_string =
		format!(r#"{{"protocol_version":{PROTOCOL_VERSION},"capabilities":["\uD800"]}}"#);
	let mut observed = Vec::new();
	for (label, body) in [
		("wrong object before EOF", malformed_object),
		("wrong array before EOF", malformed_array),
		("ignored overflow", unknown_overflow),
		("positional fields", positional),
		("well-formed wrong object", wrong_object),
		("well-formed wrong array", wrong_array),
		("malformed string", malformed_string),
	] {
		let (status, _) =
			send(&f, Some(&f.worker), post("/v1/jobs/lease", Some("application/json"), body)).await;
		observed.push((label, status));
	}
	assert_eq!(
		observed,
		vec![
			("wrong object before EOF", StatusCode::BAD_REQUEST),
			("wrong array before EOF", StatusCode::BAD_REQUEST),
			("ignored overflow", StatusCode::OK),
			("positional fields", StatusCode::OK),
			("well-formed wrong object", StatusCode::UNPROCESSABLE_ENTITY),
			("well-formed wrong array", StatusCode::UNPROCESSABLE_ENTITY),
			("malformed string", StatusCode::BAD_REQUEST),
		],
		"malformed JSON uses syntax rejection; valid JSON retains type/unknown/positional rules"
	);
}

#[tokio::test]
async fn reporting_kind_overflow_keeps_syntax_category() {
	let f = fixture();
	let mut observed = Vec::new();
	for (kind, expected) in [
		("1e400", StatusCode::BAD_REQUEST),
		("1", StatusCode::UNPROCESSABLE_ENTITY),
		("\"manual\"", StatusCode::CREATED),
	] {
		let body = format!(
			r#"{{"protocol_version":{PROTOCOL_VERSION},"clone_url":"https://github.com/acme/kind-overflow.git","reporting":{{"kind":{kind}}}}}"#
		);
		let (status, body) =
			send(&f, Some(&f.admin), post("/v1/repos", Some("application/json"), body)).await;
		if expected == StatusCode::CREATED {
			let response: loupe_proto::RegisterRepoResponse = serde_json::from_str(&body).unwrap();
			assert!(response.repo_id > 0);
		}
		observed.push((kind, status));
	}
	assert_eq!(
		observed,
		vec![
			("1e400", StatusCode::BAD_REQUEST),
			("1", StatusCode::UNPROCESSABLE_ENTITY),
			("\"manual\"", StatusCode::CREATED)
		],
		"reporting tag overflow must retain syntax rejection before the fixed type error"
	);
}

#[tokio::test]
async fn job_query_errors_do_not_reflect_supplied_values() {
	let f = fixture();
	let sentinel = "FAKE_JOB_QUERY_SENTINEL";
	let mut reflected = Vec::new();
	for query in [
		"state=queued",
		"kind=scan",
		"state=FAKE_JOB_QUERY_SENTINEL",
		"kind=FAKE_JOB_QUERY_SENTINEL",
	] {
		let request =
			Request::builder().uri(format!("/v1/jobs?{query}")).body(Body::empty()).unwrap();
		let (status, body) = send(&f, Some(&f.admin), request).await;
		if query.contains(sentinel) {
			assert_eq!(status, StatusCode::BAD_REQUEST);
			assert!(body.contains("unknown job"), "retain the closed rejection category");
			if body.contains(sentinel) {
				reflected.push(query);
			}
		} else {
			assert_eq!(status, StatusCode::OK);
		}
	}
	assert!(reflected.is_empty(), "job query rejection reflected supplied text: {reflected:?}");
}

#[tokio::test]
async fn registration_nested_depth_keeps_envelope_recursion_budget() {
	let f = fixture();
	let mut observed = Vec::new();
	for (field, depths) in [("reporting", [125, 126, 127]), ("scanner_config", [126, 127, 128])] {
		for depth in depths {
			let nested = format!("{}null{}", "[".repeat(depth), "]".repeat(depth));
			let fields = if field == "reporting" {
				format!(r#""reporting":{{"kind":"manual","ignored":{nested}}}"#)
			} else {
				format!(r#""reporting":{{"kind":"manual"}},"scanner_config":{nested}"#)
			};
			let body = format!(
				r#"{{"protocol_version":{PROTOCOL_VERSION},"clone_url":"https://github.com/acme/depth-{field}-{depth}.git",{fields}}}"#
			);
			let (status, _) =
				send(&f, Some(&f.admin), post("/v1/repos", Some("application/json"), body)).await;
			observed.push((field, depth, status));
		}
	}
	assert_eq!(
		observed,
		vec![
			("reporting", 125, StatusCode::CREATED),
			("reporting", 126, StatusCode::BAD_REQUEST),
			("reporting", 127, StatusCode::BAD_REQUEST),
			("scanner_config", 126, StatusCode::CREATED),
			("scanner_config", 127, StatusCode::BAD_REQUEST),
			("scanner_config", 128, StatusCode::BAD_REQUEST),
		],
		"nested parsers must preserve the legacy request envelope recursion budget"
	);
}

#[tokio::test]
async fn json_media_types_and_unknown_fields_preserve_route_values() {
	let f = fixture();
	for (index, media_type) in
		["application/json", "application/json; charset=utf-8", "application/vnd.loupe+json"]
			.into_iter()
			.enumerate()
	{
		let body = format!(
			r#"{{"protocol_version":{PROTOCOL_VERSION},"clone_url":"https://github.com/acme/repo-{index}.git","branch":" Main-é ","reporting":{{"kind":"manual","future":true}},"future":{{"nested":[1,2]}},"future":false}}"#
		);
		let (status, body) =
			send(&f, Some(&f.admin), post("/v1/repos", Some(media_type), body)).await;
		assert_eq!(status, StatusCode::CREATED, "{media_type}: {body}");
		let reply: loupe_proto::RegisterRepoResponse = serde_json::from_str(&body).unwrap();
		assert_eq!(reply.protocol_version, PROTOCOL_VERSION);
		let row = common::repo(&f.db, reply.repo_id);
		assert_eq!(row.clone_url.expose(), format!("https://github.com/acme/repo-{index}.git"));
		assert_eq!(row.default_branch.as_ref().map(|v| v.expose()), Some(" Main-é "));
		assert_eq!(row.reporting, loupe_core::ReportingDestination::Manual);
	}
}

#[tokio::test]
async fn json_media_syntax_data_and_duplicate_rejections_keep_their_categories() {
	let f = fixture();
	let valid = repo_json("valid");
	let duplicate = valid.replacen("{", &format!(r#"{{"protocol_version":{PROTOCOL_VERSION},"#), 1);
	let trailing = format!("{valid} true");
	for (label, content_type, body, expected, diagnostic) in [
		(
			"missing media type",
			None,
			valid.as_str(),
			StatusCode::UNSUPPORTED_MEDIA_TYPE,
			"Content-Type",
		),
		(
			"wrong media type",
			Some("text/plain"),
			valid.as_str(),
			StatusCode::UNSUPPORTED_MEDIA_TYPE,
			"Content-Type",
		),
		(
			"non-application json",
			Some("text/json"),
			valid.as_str(),
			StatusCode::UNSUPPORTED_MEDIA_TYPE,
			"Content-Type",
		),
		("syntax", Some("application/json"), "{", StatusCode::BAD_REQUEST, "Failed to parse"),
		("empty", Some("application/json"), "", StatusCode::BAD_REQUEST, "Failed to parse"),
		(
			"trailing data",
			Some("application/json"),
			trailing.as_str(),
			StatusCode::BAD_REQUEST,
			"Failed to parse",
		),
		(
			"missing fields",
			Some("application/json"),
			"{}",
			StatusCode::UNPROCESSABLE_ENTITY,
			"missing field",
		),
		(
			"wrong field type",
			Some("application/json"),
			r#"{"protocol_version":"wrong"}"#,
			StatusCode::UNPROCESSABLE_ENTITY,
			"invalid type",
		),
		(
			"null",
			Some("application/json"),
			"null",
			StatusCode::UNPROCESSABLE_ENTITY,
			"invalid type",
		),
		(
			"duplicate known field",
			Some("application/json"),
			duplicate.as_str(),
			StatusCode::UNPROCESSABLE_ENTITY,
			"duplicate field",
		),
	] {
		let (status, body) =
			send(&f, Some(&f.admin), post("/v1/repos", content_type, body.to_owned())).await;
		assert_eq!(status, expected, "{label}: {body}");
		assert!(body.contains(diagnostic), "{label}: {body}");
	}
	assert_eq!(
		registry::repositories(&f.db, &common::marked::operator_ingress(), None).unwrap().len(),
		0
	);
}

#[tokio::test]
async fn worker_json_admission_preserves_media_and_field_semantics() {
	let f = fixture();
	let valid =
		format!(r#"{{"protocol_version":{PROTOCOL_VERSION},"capabilities":[],"future":true}}"#);
	let duplicate = valid.replacen("{", &format!(r#"{{"protocol_version":{PROTOCOL_VERSION},"#), 1);
	for (label, content_type, body, expected, diagnostic) in [
		("json with unknown field", Some("application/json"), valid.as_str(), StatusCode::OK, ""),
		("json suffix", Some("application/vnd.loupe+json"), valid.as_str(), StatusCode::OK, ""),
		(
			"missing media type",
			None,
			valid.as_str(),
			StatusCode::UNSUPPORTED_MEDIA_TYPE,
			"Content-Type",
		),
		("syntax", Some("application/json"), "{", StatusCode::BAD_REQUEST, "Failed to parse"),
		(
			"missing fields",
			Some("application/json"),
			"{}",
			StatusCode::UNPROCESSABLE_ENTITY,
			"missing field",
		),
		(
			"duplicate known field",
			Some("application/json"),
			duplicate.as_str(),
			StatusCode::UNPROCESSABLE_ENTITY,
			"duplicate field",
		),
		(
			"wrong body version",
			Some("application/json"),
			r#"{"protocol_version":65535,"capabilities":[]}"#,
			StatusCode::BAD_REQUEST,
			"unsupported protocol_version 65535",
		),
	] {
		let (status, body) =
			send(&f, Some(&f.worker), post("/v1/jobs/lease", content_type, body.to_owned())).await;
		assert_eq!(status, expected, "{label}: {body}");
		if expected == StatusCode::OK {
			assert!(matches!(
				serde_json::from_str::<common::wire::LeaseResponse>(&body).unwrap(),
				common::wire::LeaseResponse::Empty { protocol_version: PROTOCOL_VERSION }
			));
		} else {
			assert!(body.contains(diagnostic), "{label}: {body}");
		}
	}
}

#[tokio::test]
async fn authentication_protocol_role_and_body_checks_keep_their_order() {
	let f = fixture();
	let unknown = PeerCert(vec![99, 99, 99].into());
	for cert in [None, Some(&unknown), Some(&f.revoked)] {
		let mut request = post("/v1/repos", Some("text/plain"), "{");
		request.headers_mut().insert(PROTOCOL_VERSION_HEADER, "65535".parse().unwrap());
		assert_eq!(send(&f, cert, request).await.0, StatusCode::UNAUTHORIZED);
	}
	for (cert, path) in [(&f.worker, "/v1/repos"), (&f.admin, "/v1/jobs/lease")] {
		// A header mismatch precedes role gating; the same body with an admitted header
		// reaches the role check before media-type or JSON extraction.
		let mut request = post(path, Some("text/plain"), "{");
		request.headers_mut().insert(PROTOCOL_VERSION_HEADER, "65535".parse().unwrap());
		let (status, body) = send(&f, Some(cert), request).await;
		assert_eq!(status, StatusCode::BAD_REQUEST);
		assert!(body.contains(&format!("unsupported {PROTOCOL_VERSION_HEADER}")), "{body}");
		let mut request = post(path, Some("text/plain"), "{");
		request.headers_mut().insert(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.into());
		assert_eq!(send(&f, Some(cert), request).await.0, StatusCode::FORBIDDEN);
	}
	for raw in ["not-an-integer", "65535"] {
		let mut request = post("/v1/repos", None, "{");
		request.headers_mut().insert(PROTOCOL_VERSION_HEADER, raw.parse().unwrap());
		let (status, body) = send(&f, Some(&f.admin), request).await;
		assert_eq!(status, StatusCode::BAD_REQUEST);
		assert!(body.contains(PROTOCOL_VERSION_HEADER), "{body}");
	}
	let bad_version = repo_json("wrong-version").replacen(
		&format!("\"protocol_version\":{PROTOCOL_VERSION}"),
		"\"protocol_version\":65535",
		1,
	);
	let (status, body) =
		send(&f, Some(&f.admin), post("/v1/repos", Some("application/json"), bad_version)).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body, "unsupported protocol_version 65535");
	let request = post("/v1/repos", Some("application/json"), repo_json("positive"));
	assert_eq!(send(&f, Some(&f.admin), request).await.0, StatusCode::CREATED);
}

#[tokio::test]
async fn operator_json_body_cap_is_exactly_two_mib() {
	const CAP: usize = 2 * 1024 * 1024;
	let f = fixture();
	for (name, size, expected) in
		[("at-cap", CAP, StatusCode::CREATED), ("over-cap", CAP + 1, StatusCode::PAYLOAD_TOO_LARGE)]
	{
		// JSON whitespace exercises the enclosing body cap, independently of field caps.
		let mut body = repo_json(name);
		body.extend(std::iter::repeat_n(' ', size - body.len()));
		assert_eq!(body.len(), size);
		let (status, body) =
			send(&f, Some(&f.admin), post("/v1/repos", Some("application/json"), body)).await;
		assert_eq!(status, expected, "{name}: {body}");
	}
	let rows = registry::repositories(&f.db, &common::marked::operator_ingress(), None).unwrap();
	assert_eq!(rows.len(), 1);
	assert_eq!(rows[0].repo.expose(), "at-cap");
}

#[tokio::test]
async fn operator_no_body_handler_keeps_ignoring_the_body() {
	let f = fixture();
	for body in [
		Body::from(vec![0; 2 * 1024 * 1024 + 1]),
		Body::from_stream(futures_util::stream::iter([Err::<axum::body::Bytes, _>(
			std::io::Error::other("body must not be consumed"),
		)])),
	] {
		let request = Request::builder().uri("/v1/repos").body(body).unwrap();
		let (status, body) = send(&f, Some(&f.admin), request).await;
		assert_eq!(status, StatusCode::OK, "{body}");
		let repos: common::wire::ListReposResponse = serde_json::from_str(&body).unwrap();
		assert_eq!(repos.protocol_version, PROTOCOL_VERSION);
		assert!(repos.repos.is_empty());
	}
}

#[tokio::test]
async fn ingress_json_error_does_not_reflect_supplied_values() {
	const SENTINEL: &str = "FAKE_OPERATOR_JSON_ERROR_SENTINEL";
	let f = fixture();
	let positive = post("/v1/repos", Some("application/json"), repo_json("error-positive"));
	assert_eq!(send(&f, Some(&f.admin), positive).await.0, StatusCode::CREATED);
	let body = format!(r#"{{"protocol_version":"{SENTINEL}"}}"#);
	let (status, error) =
		send(&f, Some(&f.admin), post("/v1/repos", Some("application/json"), body)).await;
	assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
	assert!(error.starts_with("Failed to deserialize"), "{error}");
	assert!(!error.contains(SENTINEL), "JSON rejection reflected a supplied value: {error}");
}

#[test]
fn ingress_toml_error_does_not_retain_supplied_values() {
	const SENTINEL: &str = "FAKE_CONFIG_ERROR_SENTINEL";
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("config.toml");
	std::fs::write(&path, "[review]\nactive_jobs_total = 8\n").unwrap();
	let positive = loupe_server::FileConfig::load(&path).unwrap();
	assert_eq!(positive.review.active_jobs_total, Some(8));
	std::fs::write(&path, format!("[review]\nactive_jobs_total = '{SENTINEL}'\n")).unwrap();
	let error = loupe_server::FileConfig::load(&path).unwrap_err();
	let rendered = format!("{error}\n{error:#}\n{error:?}\n{error:#?}");
	let chain: Vec<_> = error.chain().map(ToString::to_string).collect();
	assert!(
		!rendered.contains(SENTINEL) && chain.iter().all(|part| !part.contains(SENTINEL)),
		"TOML rejection retained supplied bytes: {rendered}"
	);
}
