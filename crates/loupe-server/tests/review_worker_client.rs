//! The worker's phase client against the actual router: every request it
//! sends is admitted by the server's own decoders, and every response by
//! the worker's.
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::Request;
use loupe_core::inventory_manifest::{ManifestEntry, ManifestHasher};
use loupe_core::review_candidates::CandidateQuery;
use loupe_proto::review_api::{
	InventoryBatchRequestDecoder, PinTargetRequestDecoder, PinTargetResponse,
	PublishProfileRequestDecoder,
};
use loupe_proto::review_evidence::{
	LeadCheckpointRequestDecoder, UnitResultCheckpointRequestDecoder,
};
use loupe_proto::review_inventory::InventoryDispositionRequestDecoder;
use loupe_proto::review_lifecycle::{PhaseControlState, PhaseFailureRequestDecoder};
use loupe_proto::review_terminal::FinalizeSurveyRequestDecoder;
use loupe_proto::review_units::ReviewUnitRequestDecoder;
use loupe_proto::{JobCapability, PROTOCOL_VERSION_HEADER};
use loupe_server::review::campaign;
use loupe_server::review::policy::ReviewPolicy;
use loupe_server::{router, AppState, PeerCert};
use loupe_storage::registry;
use loupe_tls::Ca;
use loupe_worker::client::{PhaseError, PhaseJob};
use loupe_worker::ServerClient;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use serde_json::{json, Value};
use tower::Service;

mod common;

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn now() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

struct Fixture {
	state: AppState,
	peer: PeerCert,
	_offline: common::offline::OfflineDatabase,
}

fn fixture() -> Fixture {
	let mut offline = common::offline::OfflineDatabase::new();
	let db = offline.open();
	let ca = Arc::new(Ca::new("worker-client").unwrap());
	let bundle = ca.mint_client("worker").unwrap();
	let peer = PeerCert(
		CertificateDer::pem_slice_iter(bundle.cert_pem.as_bytes()).next().unwrap().unwrap(),
	);
	assert_eq!(common::register_repo(&db, &common::new_repo(), None), 1);
	registry::register_worker(
		&db,
		&common::marked::operator_ingress(),
		&common::marked::operator::text("worker"),
		&loupe_tls::cert_fingerprint(peer.0.as_ref()),
		now(),
	)
	.unwrap();
	let policy = ReviewPolicy::default();
	common::with_repo(&db, 1, |scope| {
		let reference = common::marked::operator::text("main");
		let opened = campaign::open(
			scope,
			&campaign::OpenCampaign {
				trigger: loupe_storage::campaigns::Trigger::Manual,
				requested_ref: campaign::RequestedRef::Branch(&reference),
				base_sha: None,
				kind_hint: campaign::KindHint::Incremental,
			},
			&policy,
			now(),
		)?;
		assert!(matches!(opened, campaign::Opened::Created { .. }));
		Ok(())
	})
	.unwrap();
	let state =
		AppState::new(db, ca, Arc::new(loupe_server::reporters::GithubReporter::new().unwrap()))
			.with_review_policy(policy)
			.unwrap();
	Fixture { state, peer, _offline: offline }
}

/// Claims a survey lease directly from the router; the worker's own lease
/// call does not advertise review phases yet.
async fn claim(f: &Fixture) -> (i64, JobCapability) {
	let mut req = Request::post("/v1/jobs/lease")
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header("content-type", "application/json")
		.body(Body::from(
			json!({"protocol_version":3,"capabilities":[],
				"review_capabilities":["review:survey:v1"],"wait_seconds":0})
			.to_string(),
		))
		.unwrap();
	req.extensions_mut().insert(f.peer.clone());
	let response = router(f.state.clone()).call(req).await.unwrap();
	let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
	#[derive(serde::Deserialize)]
	struct Lease {
		job_id: i64,
		job_capability: JobCapability,
		payload: Value,
	}
	let lease: Lease = serde_json::from_slice(&bytes).unwrap();
	assert_eq!(lease.payload["kind"], "review_survey");
	(lease.job_id, lease.job_capability)
}

/// The router over plain HTTP with the worker's certificate attached, as
/// the TLS listener would attach it.
async fn serve(f: &Fixture) -> ServerClient {
	let app = router(f.state.clone()).layer(axum::Extension(f.peer.clone()));
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let base = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	ServerClient::from_parts(reqwest::Client::new(), base)
}

fn request(value: Value) -> Vec<u8> {
	value.to_string().into_bytes()
}

fn manifest_digest() -> String {
	let entry = ManifestEntry::from_encoded(
		&common::marked::repo::identifier::<loupe_proto::review_api::RawPathHexPolicy>("7a2e7273"),
		0o100644,
		&common::marked::repo::identifier::<loupe_core::review_metadata::CommitPolicy>(SHA),
	)
	.unwrap();
	let mut hash = ManifestHasher::new(SHA, 1).unwrap();
	hash.push(&entry).unwrap();
	hash.finish().unwrap().iter().map(|byte| format!("{byte:02x}")).collect()
}

#[tokio::test]
async fn phase_client_drives_a_bootstrap_survey_through_the_router() {
	use common::marked::worker_request as worker;
	let f = fixture();
	let (job_id, capability) = claim(&f).await;
	let client = serve(&f).await;
	let job = PhaseJob {
		job_id,
		capability: &capability,
		deadline: SystemTime::now() + Duration::from_secs(60),
	};

	let limits = client.limits(&job).await.unwrap();
	assert!(serde_json::to_value(&limits).unwrap().is_object());

	let pin = request(json!({"protocol_version":3,"commit_sha":SHA}));
	let pin = worker(&pin).validate(PinTargetRequestDecoder).unwrap();
	assert!(matches!(
		client.pin_target(&job, &pin).await.unwrap(),
		PinTargetResponse::Prepared { .. }
	));

	let batch = request(json!({"protocol_version":3,"format_version":1,
		"expected_entry_count":1,"expected_digest":manifest_digest(),"start_position":0,
		"entries":[{"raw_path_hex":"7a2e7273","git_mode":0o100644,"object_id":SHA}]}));
	let batch = worker(&batch).validate(InventoryBatchRequestDecoder).unwrap();
	let progress = client.inventory_batch(&job, &batch).await.unwrap();
	assert_eq!((progress.received_entry_count, progress.sealed), (1, false));
	assert!(client.seal_inventory(&job).await.unwrap().sealed);

	let profile = request(json!({"protocol_version":3,"profile":{"scope":"worker client"}}));
	let profile = worker(&profile).validate_carrying(PublishProfileRequestDecoder).unwrap();
	client.publish_profile(&job, &profile).await.unwrap();

	let unit = request(json!({"protocol_version":3,"client_review_unit_key":"boundary",
		"title":"Request boundary","objective":"Trace the boundary","priority_band":"normal",
		"source_refs":[{"path":"z.rs"}],"depends_on_review_unit_ids":[],
		"closure_criteria":"Account for callers"}));
	let unit = worker(&unit).validate_carrying(ReviewUnitRequestDecoder).unwrap();
	let unit = client.review_unit(&job, &unit).await.unwrap();
	let unit_id = i64::from(unit.review_unit_id);

	let lead = request(json!({"protocol_version":3,"client_lead_key":"allocator","evidence":{
		"format":"loupe.lead_evidence","version":1,"identity_family":"allocation",
		"identity_anchor":"allocator","hypothesis":"Length reaches allocation",
		"source_refs":[{"path":"z.rs"}],"next_proof_step":"Inspect callers",
		"counterevidence":"No dominating check","proof_gaps":"Independent verification needed",
		"review_unit_id":unit_id,"assignment_epoch":unit.assignment_epoch}}));
	let lead = worker(&lead).validate_carrying(LeadCheckpointRequestDecoder).unwrap();
	let lead = client.lead(&job, &lead).await.unwrap();
	let lead_id = i64::from(lead.lead_id);

	let result = request(json!({"protocol_version":3,"client_result_key":"source","result":{
		"format":"loupe.unit_result","version":1,"review_unit_id":unit_id,
		"assignment_epoch":unit.assignment_epoch,"disposition":"lead_created",
		"inspected_refs":[{"path":"z.rs"}],"created_lead_ids":[lead_id],
		"counterevidence":"Reviewed guard","proof_gaps":"No remaining source gap"}}));
	let result = worker(&result).validate_carrying(UnitResultCheckpointRequestDecoder).unwrap();
	assert_eq!(
		client.unit_result(&job, &result).await.unwrap().review_unit_id,
		unit.review_unit_id
	);

	let disposition = request(json!({"protocol_version":3,
		"client_inventory_disposition_key":"map","source_path":"z.rs","expected_revision":0,
		"disposition":"mapped","reason":null,
		"mappings":[{"review_unit_id":unit_id,"assignment_epoch":unit.assignment_epoch}]}));
	let disposition = worker(&disposition).validate(InventoryDispositionRequestDecoder).unwrap();
	client.inventory_disposition(&job, &disposition).await.unwrap();

	let query = CandidateQuery {
		query: common::marked::agent::text::<loupe_core::review_candidates::QueryPolicy>(
			"allocation",
		),
		limit: 5,
	};
	client.lead_candidates(&job, &query).await.unwrap();
	client.phase_heartbeat(&job).await.unwrap();

	let terminal = request(json!({"protocol_version":3,"payload":{"version":1,
		"terminal_reason":"completed","security_model_notes":"Public source boundary"}}));
	let terminal = worker(&terminal).validate_carrying(FinalizeSurveyRequestDecoder).unwrap();
	let receipt = client.finalize_survey(&job, &terminal).await.unwrap();
	assert_eq!(i64::from(receipt.receipt.job_id), job_id);
	let replay = client.finalize_survey(&job, &terminal).await.unwrap();
	assert_eq!(replay.receipt.receipt_id, receipt.receipt.receipt_id, "exact replay is free");
}

#[tokio::test]
async fn phase_client_reports_failure_and_typed_rejections() {
	use common::marked::worker_request as worker;
	let f = fixture();
	let (job_id, capability) = claim(&f).await;
	let client = serve(&f).await;
	let job = PhaseJob {
		job_id,
		capability: &capability,
		deadline: SystemTime::now() + Duration::from_secs(60),
	};
	let profile = request(json!({"protocol_version":3,"profile":{"scope":"too early"}}));
	let profile = worker(&profile).validate_carrying(PublishProfileRequestDecoder).unwrap();
	let error = client.publish_profile(&job, &profile).await.unwrap_err();
	assert!(
		matches!(error, PhaseError::Rejected { status: 403, .. }),
		"writes before pin are denied: {error}"
	);

	let failure = request(json!({"protocol_version":3,"outcome":"failed","error":"host gave up"}));
	let failure = worker(&failure).validate(PhaseFailureRequestDecoder).unwrap();
	let control = client.phase_failure(&job, &failure).await.unwrap();
	assert_eq!(i64::from(control.job_id), job_id);
	assert!(matches!(control.state, PhaseControlState::Queued | PhaseControlState::Failed));
}
