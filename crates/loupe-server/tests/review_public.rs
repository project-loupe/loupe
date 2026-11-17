//! B4 acceptance starts only campaigns directly. Every phase lease, child,
//! assignment and piece of accepted evidence uses the authenticated router.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use loupe_core::inventory_manifest::{ManifestEntry, ManifestHasher};
use loupe_proto::{JobCapability, JOB_CAPABILITY_HEADER, PROTOCOL_VERSION_HEADER};
use loupe_server::review::campaign;
use loupe_server::review::policy::ReviewPolicy;
use loupe_server::{router, AppState, PeerCert};
use loupe_storage::registry;
use loupe_tls::Ca;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use serde_json::{json, Value};
use tower::Service;

mod common;

// Independent wire observations: no source-labelled production value is constructed.
#[derive(serde::Deserialize)]
struct LeaseEnvelope {
	job_id: i64,
	job_capability: JobCapability,
	payload: Value,
	github_pat: Option<Value>,
}

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
	state: AppState,
	offline: common::offline::OfflineDatabase,
	peers: Vec<PeerCert>,
	campaign: i64,
}

fn now() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn fixture(mut offline: common::offline::OfflineDatabase, policy: ReviewPolicy) -> Fixture {
	let db = offline.open();
	let ca = Arc::new(Ca::new("public-review").unwrap());
	let peers: Vec<_> = (0..3)
		.map(|i| {
			let bundle = ca.mint_client(&format!("worker-{i}")).unwrap();
			PeerCert(
				CertificateDer::pem_slice_iter(bundle.cert_pem.as_bytes()).next().unwrap().unwrap(),
			)
		})
		.collect();
	assert_eq!(common::register_repo(&db, &common::new_repo(), None), 1);
	for (i, peer) in peers.iter().enumerate() {
		registry::register_worker(
			&db,
			&common::marked::operator_ingress(),
			&common::marked::operator::text(&format!("worker-{i}")),
			&loupe_tls::cert_fingerprint(peer.0.as_ref()),
			now(),
		)
		.unwrap();
	}
	let campaign = common::with_repo(&db, 1, |scope| {
		let reference = common::marked::operator::text("main");
		let campaign::Opened::Created { campaign_id, .. } = campaign::open(
			scope,
			&campaign::OpenCampaign {
				trigger: loupe_storage::campaigns::Trigger::Manual,
				requested_ref: campaign::RequestedRef::Branch(&reference),
				base_sha: None,
				kind_hint: campaign::KindHint::Incremental,
			},
			&policy,
			now(),
		)?
		else {
			panic!("new campaign")
		};
		Ok(campaign_id)
	})
	.unwrap();
	let state =
		AppState::new(db, ca, Arc::new(loupe_server::reporters::GithubReporter::new().unwrap()))
			.with_review_policy(policy)
			.unwrap();
	Fixture { state, offline, peers, campaign }
}

fn memory(policy: ReviewPolicy) -> Fixture {
	fixture(common::offline::OfflineDatabase::new(), policy)
}

async fn call(
	f: &Fixture, worker: usize, route: &str, token: Option<&str>, body: Value,
) -> (StatusCode, Value) {
	let mut req = Request::post(route)
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header("content-type", "application/json");
	if let Some(token) = token {
		req = req.header(JOB_CAPABILITY_HEADER, token);
	}
	let mut req = req.body(Body::from(body.to_string())).unwrap();
	req.extensions_mut().insert(f.peers[worker].clone());
	let response = router(f.state.clone()).call(req).await.unwrap();
	let status = response.status();
	let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024).await.unwrap();
	common::admit_phase_response(route, status, &bytes);
	let body = serde_json::from_slice(&bytes)
		.unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)}));
	(status, body)
}

async fn claim(
	f: &Fixture, worker: usize, capabilities: &[&str], review: &[&str],
) -> Option<LeaseEnvelope> {
	let (status, body) = call(f, worker, "/v1/jobs/lease", None,
		json!({"protocol_version":3,"capabilities":capabilities,"review_capabilities":review,"wait_seconds":0})).await;
	assert_eq!(status, StatusCode::OK, "claim: {body}");
	match body["kind"].as_str().unwrap() {
		"empty" => None,
		"lease" => {
			let envelope: LeaseEnvelope = serde_json::from_value(body).unwrap();
			assert!(
				envelope.github_pat.is_none(),
				"reporting credentials never travel with leases"
			);
			Some(envelope)
		},
		other => panic!("unexpected lease response {other}"),
	}
}

async fn phase(f: &Fixture, worker: usize, capability: &str) -> LeaseEnvelope {
	let lease = claim(f, worker, &[], &[capability])
		.await
		.expect("advertised supported phase must be publicly claimable");
	let expected = match capability {
		"review:survey:v1" => "review_survey",
		"review:drilldown:v1" => "review_drilldown",
		"review:verify:v1" => "review_verify",
		_ => panic!("test must request a known phase"),
	};
	assert_eq!(lease.payload["kind"], expected);
	lease
}

async fn post(
	f: &Fixture, worker: usize, lease: &LeaseEnvelope, route: &str, payload: Value,
) -> Value {
	let (status, body) = call(
		f,
		worker,
		&format!("/v1/jobs/{}/{route}", lease.job_id),
		Some(lease.job_capability.expose_secret()),
		payload,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{route}: {body}");
	body
}

async fn pin(f: &Fixture, worker: usize, lease: &LeaseEnvelope) -> Value {
	post(f, worker, lease, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await
}

async fn bootstrap(f: &Fixture) -> LeaseEnvelope {
	assert!(
		claim(f, 2, &["verify:llm-review", "review:survey:v1"], &[]).await.is_none(),
		"legacy tags must not advertise review phases"
	);
	let lease = phase(f, 0, "review:survey:v1").await;
	pin(f, 0, &lease).await;
	let entry = ManifestEntry::from_encoded(
		&common::marked::repo::identifier::<loupe_proto::review_api::RawPathHexPolicy>("7a2e7273"),
		0o100644,
		&common::marked::repo::identifier::<loupe_core::review_metadata::CommitPolicy>(SHA),
	)
	.unwrap();
	let mut hash = ManifestHasher::new(SHA, 1).unwrap();
	hash.push(&entry).unwrap();
	let digest: String = hash.finish().unwrap().iter().map(|byte| format!("{byte:02x}")).collect();
	post(
		f,
		0,
		&lease,
		"inventory-batches",
		json!({"protocol_version":3,"format_version":1,
		"expected_entry_count":1,"expected_digest":digest,"start_position":0,
		"entries":[{"raw_path_hex":"7a2e7273","git_mode":0o100644,"object_id":SHA}]}),
	)
	.await;
	post(f, 0, &lease, "seal-inventory", json!({"protocol_version":3})).await;
	post(
		f,
		0,
		&lease,
		"publish-profile",
		json!({"protocol_version":3,"profile":{"scope":"public acceptance"}}),
	)
	.await;
	lease
}

async fn unit(f: &Fixture, lease: &LeaseEnvelope, key: &str) -> i64 {
	post(
		f,
		0,
		lease,
		"review-units",
		json!({"protocol_version":3,"client_review_unit_key":key,
		"title":"Request boundary","objective":"Trace the boundary","priority_band":"normal",
		"source_refs":[{"path":"z.rs"}],"depends_on_review_unit_ids":[],
		"closure_criteria":"Account for callers"}),
	)
	.await["review_unit_id"]
		.as_i64()
		.unwrap()
}

fn result(key: &str, unit: i64, epoch: i64, leads: &[i64]) -> Value {
	json!({"protocol_version":3,"client_result_key":key,"result":{"format":"loupe.unit_result",
		"version":1,"review_unit_id":unit,"assignment_epoch":epoch,
		"disposition":if leads.is_empty(){"no_lead_found"}else{"lead_created"},
		"inspected_refs":[{"path":"z.rs"}],"created_lead_ids":leads,
		"counterevidence":"Reviewed guard","proof_gaps":"No remaining source gap"}})
}

async fn lead(
	f: &Fixture, lease: &LeaseEnvelope, key: &str, urgent: bool, unit: Option<i64>,
) -> i64 {
	let mut evidence = json!({"format":"loupe.lead_evidence","version":1,
		"identity_family":"allocation","identity_anchor":key,"hypothesis":"Length reaches allocation",
		"source_refs":[{"path":"z.rs"}],"next_proof_step":"Inspect callers",
		"counterevidence":"No dominating check","proof_gaps":"Independent verification needed"});
	if urgent {
		evidence["invariant_or_boundary"] = json!("network to process memory");
		evidence["priority_proposal"] = json!({"impact":"critical","access":"remote","reachability":"traced",
			"boundary_refs":[{"path":"z.rs"}],"rationale":"Reachable unbounded allocation"});
	}
	if let Some(unit) = unit {
		evidence["review_unit_id"] = json!(unit);
		evidence["assignment_epoch"] = json!(0);
	}
	post(
		f,
		0,
		lease,
		"leads",
		json!({"protocol_version":3,"client_lead_key":key,"evidence":evidence}),
	)
	.await["lead_id"]
		.as_i64()
		.unwrap()
}

fn terminal_survey() -> Value {
	json!({"protocol_version":3,"payload":{"version":1,"terminal_reason":"completed",
		"security_model_notes":"Public source boundary"}})
}

fn evidence() -> Value {
	json!({"version":1,"l2_argument":{"attacker_source":"remote request","control":"request length",
		"sink":"allocator","reachable_path":"handler to allocator","trust_boundary":"network to memory"},
		"material_locations":[{"role":"entry_point","file":"z.rs","line_start":3},
			{"role":"sink","file":"z.rs","line_start":12}],
		"counterevidence":"caller check absent","assumptions_gaps":"source inspection only","confidence":"high"})
}

fn promotion() -> Value {
	json!({"protocol_version":3,"payload":{"version":1,"disposition":"promote","promotion":{
		"version":1,"severity":"high","title":"Untrusted allocation control",
		"description":"The remote request controls allocation","identity_family":"allocation",
		"identity_anchor":"allocator","evidence":evidence()}}})
}

fn scalar(f: &Fixture, sql: &str) -> i64 {
	f.offline.external_corruption(|conn| Ok(conn.query_row(sql, [], |row| row.get(0))?)).unwrap()
}

fn open_next(f: &Fixture) {
	common::with_repo(&f.state.db, 1, |scope| {
		let reference = common::marked::operator::text("main");
		let base = common::marked::operator::text(SHA);
		assert!(matches!(
			campaign::open(
				scope,
				&campaign::OpenCampaign {
					trigger: loupe_storage::campaigns::Trigger::Manual,
					requested_ref: campaign::RequestedRef::Branch(&reference),
					base_sha: Some(&base),
					kind_hint: campaign::KindHint::Incremental,
				},
				&f.state.review_policy,
				now(),
			)?,
			campaign::Opened::Created { .. }
		));
		Ok(())
	})
	.unwrap();
}

#[tokio::test]
async fn public_incremental_pin_initializes_empty_batch_and_holds_future_successor() {
	let f = memory(ReviewPolicy::default());
	let mut maintenance = campaign::Maintenance::default();
	let survey = bootstrap(&f).await;
	post(&f, 0, &survey, "finalize-survey", terminal_survey()).await;
	campaign::tick(&f.state.db, now(), &mut maintenance).unwrap();
	open_next(&f);
	let incremental = phase(&f, 1, "review:survey:v1").await;
	assert_eq!(
		serde_json::to_value(&incremental.payload).unwrap()["context"]["recipe"],
		"resolve_target"
	);
	let scope = pin(&f, 1, &incremental).await;
	assert_eq!(scope["assignments"], json!([]));
	assert_eq!(scope["profile"]["profile"]["scope"], "public acceptance");
	assert_eq!(
		pin(&f, 1, &incremental).await,
		scope,
		"pin retry cannot refill an empty initialized batch"
	);
	post(&f, 1, &incremental, "finalize-survey", terminal_survey()).await;
	campaign::tick(&f.state.db, now(), &mut maintenance).unwrap();
	open_next(&f);
	let preparation = phase(&f, 2, "review:survey:v1").await;
	let input =
		json!({"protocol_version":3,"commit_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"});
	let held = post(&f, 2, &preparation, "pin-target", input.clone()).await;
	assert_eq!(held["outcome"], "deferred");
	assert_eq!(held["receipt"]["reason"], "unsupported_recipe");
	assert_eq!(post(&f, 2, &preparation, "pin-target", input).await, held);
	assert_eq!(
		call(
			&f,
			2,
			&format!("/v1/jobs/{}/publish-profile", preparation.job_id),
			Some(preparation.job_capability.expose_secret()),
			json!({"protocol_version":3,"profile":{}})
		)
		.await
		.0,
		StatusCode::FORBIDDEN
	);
	assert!(claim(&f, 0, &[], &["review:survey:v1", "review:drilldown:v1", "review:verify:v1"])
		.await
		.is_none());
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM jobs"), 3);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM review_generations WHERE state='active'"), 1);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM review_generations WHERE state='building' AND predecessor_generation_id IS NOT NULL"), 1);
}

#[tokio::test]
async fn public_flow_creates_children_only_on_claim_and_retains_canonical_replay_after_restart() {
	let f = memory(ReviewPolicy::default());
	let survey = bootstrap(&f).await;
	let pending_unit = unit(&f, &survey, "remaining-boundary").await;
	let unit = unit(&f, &survey, "boundary").await;
	let lead = lead(&f, &survey, "allocator", true, Some(unit)).await;
	post(&f, 0, &survey, "review-unit-results", result("source", unit, 0, &[lead])).await;
	post(
		&f,
		0,
		&survey,
		"inventory-dispositions",
		json!({"protocol_version":3,
		"client_inventory_disposition_key":"map","source_path":"z.rs","expected_revision":0,
		"disposition":"mapped","mappings":[{"review_unit_id":unit,"assignment_epoch":0}]}),
	)
	.await;
	assert_eq!(
		scalar(&f, "SELECT COUNT(*) FROM jobs"),
		1,
		"checkpoint creates intent, not a child job"
	);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_admission_charges"), 1);
	let drilldown = phase(&f, 1, "review:drilldown:v1").await;
	assert_eq!(serde_json::to_value(&drilldown.payload).unwrap()["lead"]["lead_id"], lead);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM jobs"), 2);
	pin(&f, 1, &drilldown).await;
	let survey_reply = post(&f, 0, &survey, "finalize-survey", terminal_survey()).await;
	assert_eq!(survey_reply["receipt"]["summary"]["missing_results"], 1);
	assert_eq!(
		survey_reply["receipt"]["summary"]["coverage"], "partial",
		"B8 corroboration remains pending"
	);
	let coverage = phase(&f, 0, "review:survey:v1").await;
	let scope = pin(&f, 0, &coverage).await;
	let assignments = scope["assignments"].as_array().unwrap();
	assert_eq!(assignments.len(), 1);
	assert_eq!(assignments[0]["review_unit_id"], pending_unit);
	post(
		&f,
		0,
		&coverage,
		"review-unit-results",
		result(
			"remaining",
			pending_unit,
			assignments[0]["assignment_epoch"].as_i64().unwrap(),
			&[],
		),
	)
	.await;
	let covered = post(&f, 0, &coverage, "finalize-survey", terminal_survey()).await;
	assert_eq!(covered["receipt"]["summary"]["missing_results"], 0);
	let promoted = post(&f, 1, &drilldown, "finalize-drilldown", promotion()).await;
	let finding = promoted["receipt"]["summary"]["promoted_finding_id"].as_i64().unwrap();
	assert_eq!(
		scalar(&f, "SELECT COUNT(*) FROM jobs"),
		3,
		"promotion creates a mandatory pending intent"
	);
	assert_eq!(
		scalar(&f, "SELECT verification_required FROM findings"),
		1,
		"legacy opt-out cannot drop canonical verification"
	);
	assert!(claim(&f, 2, &["verify:llm-review"], &[]).await.is_none());
	let verify = phase(&f, 2, "review:verify:v1").await;
	pin(&f, 2, &verify).await;
	let mut independent = evidence();
	independent["l2_argument"]["reachable_path"] =
		json!("Independent tracing confirms the remote caller reaches allocation");
	let input = json!({"protocol_version":3,"payload":{"version":1,"verdict":"verified",
		"established_rung":"L2","e2e_applicability":"not_applicable","e2e_rationale":"Source-only review",
		"evidence":independent,"notes":"Independent verifier"}});
	let verified = post(&f, 2, &verify, "finalize-verification", input.clone()).await;
	assert_eq!(verified["receipt"]["summary"]["finding_id"], finding);
	assert_eq!(verified["receipt"]["summary"]["finding_state"], "confirmed");
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_admission_charges"), 4);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_terminal_receipts"), 4);
	campaign::tick(&f.state.db, now(), &mut campaign::Maintenance::default()).unwrap();
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM review_campaigns WHERE state='active'"), 0);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM review_generations WHERE coverage='complete'"), 0);
	let Fixture { state, mut offline, peers, campaign } = f;
	let original_handle = Arc::downgrade(&state.db);
	drop(state);
	offline.edit(|_| Ok(()));
	assert!(
		original_handle.upgrade().is_none(),
		"restart must release the original database owner"
	);
	let state = AppState::new(
		offline.open(),
		Arc::new(Ca::new("restarted").unwrap()),
		Arc::new(loupe_server::reporters::GithubReporter::new().unwrap()),
	);
	let f = Fixture { state, offline, peers, campaign };
	assert_eq!(post(&f, 2, &verify, "finalize-verification", input).await, verified);
	assert_eq!(post(&f, 1, &drilldown, "finalize-drilldown", promotion()).await, promoted);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM finding_verifications"), 1);
	assert!(claim(&f, 2, &[], &["review:verify:v1"]).await.is_none());
}

#[tokio::test]
async fn public_concurrent_survey_claims_have_disjoint_batches_and_enforce_ownership() {
	let f = memory(ReviewPolicy {
		survey_units_per_job: 2,
		active_surveys_per_repo: 2,
		..ReviewPolicy::default()
	});
	let survey = bootstrap(&f).await;
	for i in 0..6 {
		unit(&f, &survey, &format!("unit-{i}")).await;
	}
	post(&f, 0, &survey, "finalize-survey", terminal_survey()).await;
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM jobs"), 1);
	let (left, right) =
		tokio::join!(phase(&f, 0, "review:survey:v1"), phase(&f, 1, "review:survey:v1"));
	let a = pin(&f, 0, &left).await;
	let b = pin(&f, 1, &right).await;
	let a = a["assignments"].as_array().unwrap();
	let b = b["assignments"].as_array().unwrap();
	assert_eq!((a.len(), b.len()), (2, 2));
	assert!(a.iter().all(|a| b.iter().all(|b| a["review_unit_id"] != b["review_unit_id"])));
	let foreign = result(
		"foreign",
		b[0]["review_unit_id"].as_i64().unwrap(),
		b[0]["assignment_epoch"].as_i64().unwrap(),
		&[],
	);
	assert_eq!(
		call(
			&f,
			0,
			&format!("/v1/jobs/{}/review-unit-results", left.job_id),
			Some(left.job_capability.expose_secret()),
			foreign
		)
		.await
		.0,
		StatusCode::FORBIDDEN
	);
	assert!(claim(&f, 2, &[], &["review:survey:v1"]).await.is_none(), "live phase concurrency cap");
	for (worker, lease, assignments) in [(0, &left, a), (1, &right, b)] {
		for item in assignments {
			let unit = item["review_unit_id"].as_i64().unwrap();
			post(
				&f,
				worker,
				lease,
				"review-unit-results",
				result(
					&format!("result-{unit}"),
					unit,
					item["assignment_epoch"].as_i64().unwrap(),
					&[],
				),
			)
			.await;
		}
		post(&f, worker, lease, "finalize-survey", terminal_survey()).await;
	}
	let third = phase(&f, 2, "review:survey:v1").await;
	let rest = pin(&f, 2, &third).await;
	assert_eq!(rest["assignments"].as_array().unwrap().len(), 2);
	assert!(rest["assignments"]
		.as_array()
		.unwrap()
		.iter()
		.all(|r| a.iter().chain(b).all(|old| r["review_unit_id"] != old["review_unit_id"])));
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_admission_charges"), 4);
}

#[tokio::test]
async fn public_ranking_promotes_late_urgent_lead_without_spending_protected_budget_on_tail() {
	let f = memory(ReviewPolicy {
		campaign_max_jobs: 4,
		campaign_urgent_reserve: 1,
		campaign_verification_reserve: 1,
		..ReviewPolicy::default()
	});
	let survey = bootstrap(&f).await;
	lead(&f, &survey, "normal-first", false, None).await;
	let urgent = lead(&f, &survey, "urgent-late", true, None).await;
	post(&f, 0, &survey, "finalize-survey", terminal_survey()).await;
	let drilldown = phase(&f, 1, "review:drilldown:v1").await;
	assert_eq!(
		serde_json::to_value(&drilldown.payload).unwrap()["lead"]["lead_id"],
		urgent,
		"global priority, not first arrival, consumes the remaining general slot"
	);
	pin(&f, 1, &drilldown).await;
	post(&f, 1, &drilldown, "finalize-drilldown", json!({"protocol_version":3,"payload":{
		"version":1,"disposition":"reject","counterargument":{"argument":"Dominating check rules out exploit",
		"source_refs":[{"path":"z.rs"}]}}})).await;
	assert!(
		claim(&f, 2, &[], &["review:drilldown:v1"]).await.is_none(),
		"normal tail cannot spend protected reserve"
	);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM jobs"), 2);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM job_admission_charges"), 2);
	campaign::tick(&f.state.db, now(), &mut campaign::Maintenance::default()).unwrap();
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM review_campaigns WHERE state='active'"), 0);
	assert_eq!(scalar(&f, "SELECT COUNT(*) FROM lead_drilldown_intents WHERE state='blocked'"), 1);
}

async fn profile_version_domain_case(version: rusqlite::types::Value, permitted: bool) {
	let f = memory(ReviewPolicy::default());
	let survey = bootstrap(&f).await;
	let accepted = unit(&f, &survey, "accepted-before-profile-change").await;
	post(&f, 0, &survey, "review-unit-results", result("accepted", accepted, 0, &[])).await;
	post(
		&f,
		0,
		&survey,
		"inventory-dispositions",
		json!({"protocol_version":3,
		"client_inventory_disposition_key":"accepted-map","source_path":"z.rs","expected_revision":0,
		"disposition":"mapped","mappings":[{"review_unit_id":accepted,"assignment_epoch":0}]}),
	)
	.await;
	let evidence = || {
		f.offline
			.external_corruption(|conn| {
				Ok(conn.query_row(
					"SELECT result_payload,result_digest FROM review_unit_results",
					[],
					|row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
				)?)
			})
			.unwrap()
	};
	let original_evidence = evidence();
	let before_units = scalar(&f, "SELECT COUNT(*) FROM review_units");
	let before_checkpoints = scalar(&f, "SELECT COUNT(*) FROM job_checkpoints");
	// All preparation and prior evidence went through the public API. Only
	// the profile version is injected to exercise its persisted numeric boundary.
	f.offline.external_corruption(|conn| {
		assert_eq!(conn.execute(
			"UPDATE review_generations SET profile_version=?1 WHERE generation_id=(SELECT generation_id FROM jobs WHERE id=?2)",
			rusqlite::params![version,survey.job_id],
		)?,1);
		Ok(())
	}).unwrap();
	let mut replies = Vec::new();
	for (route, payload) in [
		(
			"review-units",
			json!({"protocol_version":3,"client_review_unit_key":"fresh-after-profile-change",
			"title":"Fresh boundary","objective":"Inspect another caller","priority_band":"normal",
			"source_refs":[{"path":"z.rs"}],"depends_on_review_unit_ids":[],"closure_criteria":"Account for callers"}),
		),
		(
			"inventory-dispositions",
			json!({"protocol_version":3,
			"client_inventory_disposition_key":"fresh-disposition","source_path":"z.rs","expected_revision":1,
			"disposition":"context","reason":"Reviewed context","mappings":[]}),
		),
	] {
		replies.push(
			call(
				&f,
				0,
				&format!("/v1/jobs/{}/{route}", survey.job_id),
				Some(survey.job_capability.expose_secret()),
				payload,
			)
			.await,
		);
	}
	let after_domain = (
		scalar(&f, "SELECT COUNT(*) FROM review_units"),
		scalar(&f, "SELECT COUNT(*) FROM job_checkpoints"),
		scalar(&f, "SELECT disposition_revision FROM generation_inventory"),
		scalar(&f, "SELECT COUNT(*) FROM generation_inventory_units"),
	);
	// Broken domain readiness must not take away live execution control.
	post(&f, 0, &survey, "heartbeat", json!({"protocol_version":3})).await;
	let failure = post(
		&f,
		0,
		&survey,
		"complete",
		json!({"protocol_version":3,"outcome":"failed","error":"Execution interrupted"}),
	)
	.await;
	common::marked::server_response(failure.to_string().as_bytes())
		.validate(loupe_proto::review_lifecycle::PhaseControlResponseDecoder)
		.expect("phase control response");
	assert_eq!(failure["job_id"], survey.job_id);
	assert_eq!(failure["state"], "queued");
	assert_eq!(
		evidence(),
		original_evidence,
		"prior accepted evidence must survive profile corruption and execution failure"
	);
	let expected = if permitted { StatusCode::OK } else { StatusCode::FORBIDDEN };
	assert_eq!(
		replies.iter().map(|reply|reply.0).collect::<Vec<_>>(),vec![expected;2],
		"profile version {version:?}: fresh unit and inventory writes must enforce the same readiness boundary; replies={replies:?}"
	);
	assert_eq!(after_domain, if permitted {
		(before_units+1,before_checkpoints+2,2,0)
	} else {
		(before_units,before_checkpoints,1,1)
	},"denied domain writes must not consume checkpoints, create units, or replace accepted mappings");
}

#[tokio::test]
async fn public_profile_version_integer_boundaries_allow_fresh_domain_writes() {
	for version in [1, i64::from(u32::MAX)] {
		profile_version_domain_case(rusqlite::types::Value::Integer(version), true).await;
	}
}

#[tokio::test]
async fn public_profile_version_above_u32_denies_fresh_domain_writes_but_keeps_control() {
	profile_version_domain_case(rusqlite::types::Value::Integer(i64::from(u32::MAX) + 1), false)
		.await;
}

#[tokio::test]
async fn public_profile_version_real_denies_fresh_domain_writes_but_keeps_control() {
	profile_version_domain_case(rusqlite::types::Value::Real(1.5), false).await;
}
