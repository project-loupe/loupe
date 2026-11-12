//! Real router/authentication/transaction coverage. Leases are explicit setup
//! fixtures while phase claims remain closed; final B4 lifecycle tests must
//! acquire their leases and handoffs through the public claim endpoint.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use loupe_proto::{JOB_CAPABILITY_HEADER, PROTOCOL_VERSION_HEADER};
use loupe_server::review::campaign;
use loupe_server::review::policy::ReviewPolicy;
use loupe_server::{router, AppState, PeerCert};
use loupe_storage::registry;
use loupe_tls::Ca;
use rusqlite::params;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use serde_json::{json, Value};
use tower::Service;

mod common;

#[path = "review_lifecycle/mod.rs"]
mod phase_lifecycle;

#[path = "review_drilldown/mod.rs"]
mod drilldown_terminal;

#[path = "review_verification/mod.rs"]
mod verification_terminal;

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEXT_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[path = "review_context/mod.rs"]
mod context;

#[path = "review_inventory/mod.rs"]
mod inventory;

#[path = "review_units/mod.rs"]
mod unit_proposals;

#[path = "review_survey/mod.rs"]
mod survey_terminal;

#[path = "review_evidence/mod.rs"]
mod evidence_checkpoints;

#[path = "review_body_caps/mod.rs"]
mod body_caps;

#[path = "review_compatibility/mod.rs"]
mod compatibility;

struct Fixture {
	state: AppState,
	offline: common::offline::OfflineDatabase,
	peer: PeerCert,
	other_peer: PeerCert,
	worker: i64,
	job: i64,
	campaign: i64,
	token: String,
}

fn now() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn fixture() -> Fixture {
	let mut offline = common::offline::OfflineDatabase::new();
	let db = offline.open();
	let ca = Ca::new("host-tests").unwrap();
	let cert = |name| {
		let bundle = ca.mint_client(name).unwrap();
		PeerCert(
			CertificateDer::pem_slice_iter(bundle.cert_pem.as_bytes()).next().unwrap().unwrap(),
		)
	};
	let peer = cert("host");
	let other_peer = cert("other");
	let token = "a".repeat(43);
	assert_eq!(common::register_repo(&db, &common::new_repo(), None), 1);
	let worker = registry::register_worker(
		&db,
		&common::marked::operator_ingress(),
		&common::marked::operator::text("host"),
		&loupe_tls::cert_fingerprint(peer.0.as_ref()),
		now(),
	)
	.unwrap();
	registry::register_worker(
		&db,
		&common::marked::operator_ingress(),
		&common::marked::operator::text("other"),
		&loupe_tls::cert_fingerprint(other_peer.0.as_ref()),
		now(),
	)
	.unwrap();
	let (campaign, job) = common::with_repo(&db, 1, |scope| {
		let campaign::Opened::Created { campaign_id, job_id } = campaign::open(
			scope,
			&campaign::OpenCampaign {
				trigger: loupe_storage::campaigns::Trigger::Manual,
				requested_ref: campaign::RequestedRef::Branch(&common::marked::operator::text(
					"main",
				)),
				base_sha: None,
				kind_hint: campaign::KindHint::Incremental,
			},
			&ReviewPolicy::default(),
			now(),
		)?
		else {
			panic!("created")
		};
		Ok((campaign_id, job_id))
	})
	.unwrap();
	offline
		.external_corruption(|conn| {
			conn.execute(
				"UPDATE jobs SET state='leased',worker_id=?2,attempts=1,lease_expires_at=?3,
		 hard_deadline_at=?3,job_capability_hash=?4 WHERE id=?1",
				params![
					job,
					worker,
					now() + 3600,
					blake3::hash(token.as_bytes()).as_bytes().as_slice()
				],
			)?;
			Ok(())
		})
		.unwrap();
	let state = AppState::new(
		db,
		Arc::new(ca),
		Arc::new(loupe_server::reporters::GithubReporter::new().unwrap()),
	);
	Fixture { state, offline, peer, other_peer, worker, job, campaign, token }
}

async fn request(f: &Fixture, job: i64, route: &str, payload: Value) -> (StatusCode, Value) {
	let body = payload.to_string();
	let mut request = Request::post(format!("/v1/jobs/{job}/{route}"))
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header(JOB_CAPABILITY_HEADER, &f.token)
		.header("content-type", "application/json")
		.body(Body::from(body))
		.unwrap();
	request.extensions_mut().insert(f.peer.clone());
	response(f, request).await
}

async fn response(f: &Fixture, request: Request<Body>) -> (StatusCode, Value) {
	let response = router(f.state.clone()).call(request).await.unwrap();
	let status = response.status();
	let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024).await.unwrap();
	let json = serde_json::from_slice(&bytes)
		.unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)}));
	(status, json)
}

async fn post(f: &Fixture, route: &str, payload: Value) -> Value {
	let (status, value) = request(f, f.job, route, payload).await;
	assert_eq!(status, StatusCode::OK, "{route}: {value}");
	value
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Independent wire fixture: no synthetic mark or production manifest decoder.
struct ManifestEntry {
	raw_path: Vec<u8>,
	git_mode: u32,
	object_id: [u8; 20],
}

fn entries() -> Vec<ManifestEntry> {
	vec![b"a%FF".to_vec(), vec![b'a', 255], b"z.rs".to_vec()]
		.into_iter()
		.map(|raw_path| ManifestEntry { raw_path, git_mode: 0o100644, object_id: [0xaa; 20] })
		.collect()
}

fn chunk(all: &[ManifestEntry], start: usize, end: usize) -> Value {
	// Pin the canonical v1 manifest byte layout independently of ManifestHasher.
	let mut digest = blake3::Hasher::new();
	digest.update(b"loupe.inventory.v1\0");
	digest.update(&[20]);
	digest.update(&[0xaa; 20]);
	digest.update(&(all.len() as u64).to_be_bytes());
	for entry in all {
		digest.update(&(entry.raw_path.len() as u32).to_be_bytes());
		digest.update(&entry.raw_path);
		digest.update(&entry.git_mode.to_be_bytes());
		digest.update(&[20]);
		digest.update(&entry.object_id);
	}
	json!({"protocol_version":3,"format_version":1,"expected_entry_count":all.len(),
		"expected_digest":hex(digest.finalize().as_bytes()),"start_position":start,"entries":all[start..end].iter().map(|entry|json!({
			"raw_path_hex":hex(&entry.raw_path),"git_mode":entry.git_mode,"object_id":hex(&entry.object_id)
		})).collect::<Vec<_>>()})
}

async fn prepare(f: &Fixture) -> i64 {
	let pin = post(f, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await;
	let entries = entries();
	post(f, "inventory-batches", chunk(&entries, 0, entries.len())).await;
	post(f, "seal-inventory", json!({"protocol_version":3})).await;
	post(f, "publish-profile", json!({"protocol_version":3,"profile":{"scope":"crate"}})).await;
	pin["generation"]["generation_id"].as_i64().unwrap()
}

#[tokio::test]
async fn bootstrap_manifest_is_complete_resumable_and_immutable() {
	let f = fixture();
	let pin = post(&f, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await;
	assert!(pin["profile"].is_null() && pin["assignments"].is_null());
	let entries = entries();
	let first = post(&f, "inventory-batches", chunk(&entries, 0, 1)).await;
	assert_eq!(first["received_entry_count"], 1);
	assert_eq!(post(&f, "inventory-batches", chunk(&entries, 0, 1)).await, first);
	assert_eq!(
		request(&f, f.job, "seal-inventory", json!({"protocol_version":3})).await.0,
		StatusCode::CONFLICT
	);
	assert_eq!(
		request(&f, f.job, "publish-profile", json!({"protocol_version":3,"profile":{}})).await.0,
		StatusCode::CONFLICT
	);
	let last = post(&f, "inventory-batches", chunk(&entries, 1, 3)).await;
	assert_eq!(last["received_entry_count"], 3);
	let sealed = post(&f, "seal-inventory", json!({"protocol_version":3})).await;
	assert_eq!(sealed["sealed"], true);
	assert_eq!(post(&f, "seal-inventory", json!({"protocol_version":3})).await, sealed);
	let profile = json!({"protocol_version":3,"profile":{"scope":"crate"}});
	let published = post(&f, "publish-profile", profile.clone()).await;
	assert_eq!(published["profile_version"], 1);
	assert_eq!(post(&f, "publish-profile", profile).await, published);
	assert_eq!(
		request(
			&f,
			f.job,
			"publish-profile",
			json!({"protocol_version":3,"profile":{"scope":"other"}})
		)
		.await
		.0,
		StatusCode::CONFLICT
	);
	let mut changed = chunk(&entries, 1, 3);
	changed["entries"][0]["object_id"] = json!(NEXT_SHA);
	assert_eq!(request(&f, f.job, "inventory-batches", changed).await.0, StatusCode::CONFLICT);
	f.offline
		.external_corruption(|conn| {
			assert_eq!(
				conn.query_row(
					"SELECT COUNT(*) FROM generation_inventory WHERE manifest_position IS NOT NULL",
					[],
					|r| r.get::<_, i64>(0)
				)?,
				3
			);
			assert_eq!(
				conn.query_row(
					"SELECT COUNT(*) FROM generation_inventory WHERE source_path IS NOT NULL",
					[],
					|r| r.get::<_, i64>(0)
				)?,
				2
			);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn retries_reconfirm_the_frozen_checkout_before_reusing_progress() {
	let mut f = fixture();
	prepare(&f).await;
	let old_token = f.token.clone();
	f.token = "b".repeat(43);
	f.offline
		.external_corruption(|conn| {
			conn.execute(
				"UPDATE jobs SET attempts=attempts+1,job_capability_hash=?2 WHERE id=?1",
				params![f.job, blake3::hash(f.token.as_bytes()).as_bytes().as_slice()],
			)?;
			Ok(())
		})
		.unwrap();
	assert_eq!(
		request(&f, f.job, "seal-inventory", json!({"protocol_version":3})).await.0,
		StatusCode::FORBIDDEN
	);
	assert_eq!(
		request(&f, f.job, "pin-target", json!({"protocol_version":3,"commit_sha":NEXT_SHA}))
			.await
			.0,
		StatusCode::CONFLICT
	);
	post(&f, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await;
	post(&f, "seal-inventory", json!({"protocol_version":3})).await;
	post(&f, "publish-profile", json!({"protocol_version":3,"profile":{"scope":"crate"}})).await;
	f.token = old_token;
	assert_eq!(
		request(&f, f.job, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await.0,
		StatusCode::FORBIDDEN
	);
}

fn follow_up(f: &mut Fixture, generation: i64) {
	f.offline
		.external_corruption(|conn| {
			conn.execute(
				"UPDATE jobs SET state='succeeded',job_capability_hash=NULL WHERE id=?1",
				[f.job],
			)?;
			Ok(())
		})
		.unwrap();
	let (campaign_id, job_id) = common::with_repo(&f.state.db, 1, |scope| {
		campaign::activate_generation(scope, f.campaign, now())?;
		let summary = loupe_storage::campaigns::summarize(scope, f.campaign)?;
		loupe_storage::campaigns::finish(
			scope,
			f.campaign,
			&summary,
			&common::marked::operator::text("partial"),
			now(),
		)?;
		let campaign::Opened::Created { campaign_id, job_id } = campaign::open(
			scope,
			&campaign::OpenCampaign {
				trigger: loupe_storage::campaigns::Trigger::Manual,
				requested_ref: campaign::RequestedRef::Branch(&common::marked::operator::text(
					"main",
				)),
				base_sha: Some(&common::marked::operator::text(SHA)),
				kind_hint: campaign::KindHint::Incremental,
			},
			&ReviewPolicy::default(),
			now(),
		)?
		else {
			panic!("new follow-up")
		};
		assert!(loupe_storage::generations::get(scope, generation)?.is_some());
		Ok((campaign_id, job_id))
	})
	.unwrap();
	f.offline
		.external_corruption(|conn| {
			conn.execute(
				"UPDATE jobs SET state='leased',worker_id=?2,attempts=1,lease_expires_at=?3,
		 hard_deadline_at=?3,job_capability_hash=?4 WHERE id=?1",
				params![
					job_id,
					f.worker,
					now() + 3600,
					blake3::hash(f.token.as_bytes()).as_bytes().as_slice()
				],
			)?;
			Ok(())
		})
		.unwrap();
	f.campaign = campaign_id;
	f.job = job_id;
}

#[tokio::test]
async fn post_pin_ordinary_assignment_is_initialized_once_even_when_empty() {
	let mut f = fixture();
	let generation = prepare(&f).await;
	follow_up(&mut f, generation);
	let pin = post(&f, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await;
	assert_eq!(pin["assignments"], json!([]));
	assert_eq!(pin["profile"]["profile"]["scope"], "crate");
	f.offline.external_corruption(|conn| {
		conn.execute("INSERT INTO review_units(generation_id,client_review_unit_key,title,objective,source_refs,created_at)
		 VALUES(?1,'later','Later','Inspect later work','[]',0)",[generation])?;
		Ok(())
	}).unwrap();
	assert_eq!(
		post(&f, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await["assignments"],
		json!([])
	);
	assert_eq!(
		request(&f, f.job, "inventory-batches", chunk(&entries(), 0, 3)).await.0,
		StatusCode::FORBIDDEN
	);
	assert_eq!(
		request(&f, f.job, "publish-profile", json!({"protocol_version":3,"profile":{}})).await.0,
		StatusCode::FORBIDDEN
	);
}

#[tokio::test]
async fn successor_deferral_is_receipt_only_and_survives_generation_cleanup() {
	let mut f = fixture();
	let generation = prepare(&f).await;
	follow_up(&mut f, generation);
	let payload = json!({"protocol_version":3,"commit_sha":NEXT_SHA});
	let first = post(&f, "pin-target", payload.clone()).await;
	assert_eq!(first["outcome"], "deferred");
	assert_eq!(first["receipt"]["reason"], "unsupported_recipe");
	f.offline
		.external_corruption(|conn| {
			let (state, hash, worker): (String, Option<Vec<u8>>, Option<i64>) = conn.query_row(
				"SELECT state,job_capability_hash,worker_id FROM jobs WHERE id=?1",
				[f.job],
				|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
			)?;
			assert_eq!(state, "cancelled");
			assert!(hash.is_none());
			assert_eq!(worker, Some(f.worker));
			assert_eq!(
				conn.query_row(
					"SELECT COUNT(*) FROM job_terminal_payloads WHERE job_id=?1",
					[f.job],
					|r| r.get::<_, i64>(0)
				)?,
				0
			);
			conn.execute(
				"DELETE FROM review_generations WHERE generation_commit_sha=?1",
				[NEXT_SHA],
			)?;
			Ok(())
		})
		.unwrap();
	assert_eq!(post(&f, "pin-target", payload.clone()).await, first);
	assert_eq!(
		request(&f, f.job, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await.0,
		StatusCode::CONFLICT
	);
	assert_eq!(
		request(&f, f.job, "seal-inventory", json!({"protocol_version":3})).await.0,
		StatusCode::FORBIDDEN
	);
	let original = f.peer.clone();
	f.peer = f.other_peer.clone();
	assert_eq!(request(&f, f.job, "pin-target", payload).await.0, StatusCode::FORBIDDEN);
	f.peer = original;
}

#[tokio::test]
async fn host_routes_require_protocol_and_identical_subject_denials() {
	let f = fixture();
	let valid = json!({"protocol_version":3,"commit_sha":SHA});
	let mut missing = Request::post(format!("/v1/jobs/{}/pin-target", f.job))
		.header(JOB_CAPABILITY_HEADER, &f.token)
		.header("content-type", "application/json")
		.body(Body::from(valid.to_string()))
		.unwrap();
	missing.extensions_mut().insert(f.peer.clone());
	assert_eq!(response(&f, missing).await.0, StatusCode::BAD_REQUEST);
	let unknown = request(&f, 99999, "pin-target", valid.clone()).await;
	assert_eq!(unknown.0, StatusCode::FORBIDDEN);
	let other = f
		.offline
		.external_corruption(|conn| {
			conn.execute(
				"INSERT INTO jobs(repo_id,kind,state,enqueued_at) VALUES(1,'scan','queued',0)",
				[],
			)?;
			Ok(conn.last_insert_rowid())
		})
		.unwrap();
	assert_eq!(request(&f, other, "pin-target", valid).await, unknown);
	let mut extra = json!({"protocol_version":3,"commit_sha":SHA});
	extra["generation_id"] = json!(1);
	assert_eq!(request(&f, f.job, "pin-target", extra).await.0, StatusCode::BAD_REQUEST);
	assert_eq!(
		request(&f, f.job, "pin-target", json!({"protocol_version":2,"commit_sha":SHA})).await.0,
		StatusCode::BAD_REQUEST
	);
}

#[tokio::test]
async fn phase_protocol_errors_consume_and_respect_worker_request_budgets() {
	use loupe_server::request_budget::{BucketConfig, WorkerBudgetConfig};

	let mut f = fixture();
	f.state = f
		.state
		.clone()
		.with_worker_budgets(WorkerBudgetConfig {
			requests: BucketConfig { capacity: 2, refill_per_second: 1 },
			..WorkerBudgetConfig::default()
		})
		.unwrap();
	let phase_request = |version: Option<&str>, peer: PeerCert| {
		let mut request = Request::post(format!("/v1/jobs/{}/pin-target", f.job))
			.header(JOB_CAPABILITY_HEADER, &f.token)
			.header("content-type", "application/json");
		if let Some(version) = version {
			request = request.header(PROTOCOL_VERSION_HEADER, version);
		}
		let mut request = request
			.body(Body::from(json!({"protocol_version":3,"commit_sha":SHA}).to_string()))
			.unwrap();
		request.extensions_mut().insert(peer);
		request
	};
	for version in [Some("nope"), None] {
		assert_eq!(
			response(&f, phase_request(version, f.peer.clone())).await.0,
			StatusCode::BAD_REQUEST,
			"an available request token reaches the protocol check"
		);
	}
	assert_eq!(
		request(&f, f.job, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await.0,
		StatusCode::TOO_MANY_REQUESTS,
		"both malformed and missing protocol requests must consume request tokens"
	);
	for version in [Some("nope"), None] {
		assert_eq!(
			response(&f, phase_request(version, f.peer.clone())).await.0,
			StatusCode::TOO_MANY_REQUESTS,
			"exhausted worker budget must be checked before protocol rejection"
		);
	}
	assert_eq!(
		response(&f, phase_request(Some("3"), f.other_peer.clone())).await.0,
		StatusCode::FORBIDDEN,
		"a different worker still reaches subject authorization with its own budget"
	);
	f.offline
		.external_corruption(|conn| {
			assert_eq!(
				conn.query_row("SELECT generation_id FROM jobs WHERE id=?1", [f.job], |row| {
					row.get::<_, Option<i64>>(0)
				})?,
				None
			);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn ordinary_pin_returns_exact_epochs_and_does_not_refill_completed_work() {
	let mut f = fixture();
	let generation = prepare(&f).await;
	follow_up(&mut f, generation);
	let unit = f.offline.external_corruption(|conn| {
		conn.execute("INSERT INTO review_units(generation_id,client_review_unit_key,title,objective,source_refs,closure_criteria,created_at)
		 VALUES(?1,'selected','Selected','Inspect selected work','[]','Check every path',0)",[generation])?;
		Ok(conn.last_insert_rowid())
	}).unwrap();
	let first = post(&f, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await;
	assert_eq!(first["assignments"][0]["review_unit_id"], unit);
	assert_eq!(first["assignments"][0]["assignment_epoch"], 1);
	assert_eq!(post(&f, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await, first);
	f.offline.external_corruption(|conn| {
		conn.execute("UPDATE job_assigned_review_units SET completed=1 WHERE job_id=?1", [f.job])?;
		conn.execute("INSERT INTO review_units(generation_id,client_review_unit_key,title,objective,source_refs,created_at)
		 VALUES(?1,'unrelated','Unrelated','Inspect unrelated work','[]',0)", [generation])?;
		conn.execute("UPDATE jobs SET attempts=attempts+1 WHERE id=?1", [f.job])?;
		Ok(())
	}).unwrap();
	assert_eq!(
		post(&f, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await["assignments"],
		json!([])
	);
}

#[tokio::test]
async fn host_endpoint_denial_matrix_does_not_reveal_unrelated_jobs() {
	for route in ["pin-target", "inventory-batches", "seal-inventory", "publish-profile"] {
		let mut f = fixture();
		prepare(&f).await;
		let payload = match route {
			"pin-target" => json!({"protocol_version":3,"commit_sha":SHA}),
			"inventory-batches" => chunk(&entries(), 0, 3),
			"publish-profile" => json!({"protocol_version":3,"profile":{"scope":"crate"}}),
			_ => json!({"protocol_version":3}),
		};
		let missing = request(&f, 99999, route, payload.clone()).await;
		assert_eq!(missing.0, StatusCode::FORBIDDEN);
		let original = f.peer.clone();
		f.peer = f.other_peer.clone();
		assert_eq!(
			request(&f, f.job, route, payload.clone()).await,
			missing,
			"wrong worker: {route}"
		);
		f.peer = original;
		for change in [
			"kind='verify',campaign_id=NULL",
			"lease_expires_at=0",
			"state='cancelled'",
			"state='succeeded'",
			"job_capability_hash=zeroblob(32)",
		] {
			f.offline
				.external_corruption(|conn| {
					// Explicit legacy/foreign identity fixture, not a production transition.
					conn.execute("DELETE FROM job_admission_charges WHERE job_id=?1", [f.job])?;
					conn.execute(&format!("UPDATE jobs SET {change} WHERE id=?1"), [f.job])?;
					Ok(())
				})
				.unwrap();
			assert_eq!(
				request(&f, f.job, route, payload.clone()).await,
				missing,
				"{route}: {change}"
			);
			f.offline.external_corruption(|conn| {
				conn.execute("UPDATE jobs SET kind='survey',campaign_id=?2,state='leased',lease_expires_at=?3,job_capability_hash=?4 WHERE id=?1",
					params![f.job,f.campaign,now()+3600,blake3::hash(f.token.as_bytes()).as_bytes().as_slice()])?;
				Ok(())
			}).unwrap();
		}
	}
}

struct Chunks(std::collections::VecDeque<axum::body::Bytes>);
impl hyper::body::Body for Chunks {
	type Data = axum::body::Bytes;
	type Error = std::convert::Infallible;
	fn poll_frame(
		mut self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>,
	) -> std::task::Poll<Option<std::result::Result<hyper::body::Frame<Self::Data>, Self::Error>>>
	{
		std::task::Poll::Ready(self.0.pop_front().map(|bytes| Ok(hyper::body::Frame::data(bytes))))
	}
}

#[tokio::test]
async fn streamed_multibyte_body_is_rejected_before_any_pin_mutation() {
	let f = fixture();
	let chunks = Chunks(
		[
			axum::body::Bytes::from_static(b"{\"protocol_version\":3,"),
			axum::body::Bytes::from("🦀".repeat(512)),
			axum::body::Bytes::from_static(b"}"),
		]
		.into(),
	);
	let mut req = Request::post(format!("/v1/jobs/{}/pin-target", f.job))
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header(JOB_CAPABILITY_HEADER, &f.token)
		.header("content-type", "application/json")
		.body(Body::new(chunks))
		.unwrap();
	req.extensions_mut().insert(f.peer.clone());
	assert_eq!(response(&f, req).await.0, StatusCode::PAYLOAD_TOO_LARGE);
	f.offline
		.external_corruption(|conn| {
			assert_eq!(
				conn.query_row("SELECT generation_id FROM jobs WHERE id=?1", [f.job], |row| {
					row.get::<_, Option<i64>>(0)
				})?,
				None
			);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn ordinary_pin_requires_sealed_manifest_and_published_profile() {
	let mut accepted = Vec::new();
	for mutation in [
		"DELETE FROM generation_manifests",
		"UPDATE generation_manifests SET sealed_at=NULL",
		"UPDATE review_generations SET generated_profile=NULL,generated_profile_digest=NULL",
	] {
		let mut f = fixture();
		let generation = prepare(&f).await;
		follow_up(&mut f, generation);
		f.offline
			.external_corruption(|conn| {
				conn.execute_batch(mutation)?;
				Ok(())
			})
			.unwrap();
		let (status, _) =
			request(&f, f.job, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await;
		if status != StatusCode::FORBIDDEN {
			accepted.push(mutation);
		}
		if status == StatusCode::FORBIDDEN {
			f.offline
				.external_corruption(|conn| {
					let state: (Option<i64>, Option<i64>) = conn.query_row(
						"SELECT generation_id,prepared_attempt FROM jobs WHERE id=?1",
						[f.job],
						|row| Ok((row.get(0)?, row.get(1)?)),
					)?;
					assert_eq!(
						state,
						(None, None),
						"readiness refusal rolls pin and preparation back"
					);
					assert_eq!(
						conn.query_row(
							"SELECT COUNT(*) FROM job_checkpoints WHERE job_id=?1",
							[f.job],
							|row| row.get::<_, i64>(0)
						)?,
						0
					);
					Ok(())
				})
				.unwrap();
		}
	}
	assert!(accepted.is_empty(), "ordinary preparation accepted unready generations: {accepted:?}");
}

#[tokio::test]
async fn assignment_envelopes_reject_foreign_generation_instead_of_disclosing_it() {
	let mut f = fixture();
	let generation = prepare(&f).await;
	follow_up(&mut f, generation);
	common::with_repo(&f.state.db, 1, |scope| {
		campaign::pin(scope, f.campaign, f.job, &common::marked::operator::text(SHA), now())
	})
	.unwrap();
	f.offline.external_corruption(|tx| {
		tx.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at)
		 VALUES(2,'other','github.com','private','other','{\"kind\":\"manual\"}',0)",[])?;
		tx.execute("INSERT INTO review_generations(generation_id,repo_id,generation_commit_sha,state,workflow_contract_version,created_at)
		 VALUES(999,2,?1,'active',1,0)",[SHA])?;
		tx.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,assignment_epoch,created_at)
		 VALUES(999,999,'foreign','Private foreign title','Private foreign objective','[]',1,0)",[])?;
		tx.execute("INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(?1,999,0,1)",[f.job])?;
		Ok(())
	}).unwrap();
	let (status, body) =
		request(&f, f.job, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await;
	assert_eq!(
		status,
		StatusCode::CONFLICT,
		"foreign assignment must not become a prepared envelope: {body}"
	);
	assert!(!body.to_string().contains("Private foreign"));
	f.offline
		.external_corruption(|conn| {
			assert_eq!(
				conn.query_row("SELECT prepared_attempt FROM jobs WHERE id=?1", [f.job], |r| {
					r.get::<_, Option<i64>>(0)
				})?,
				None
			);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn middleware_and_extractor_errors_obey_the_phase_error_boundary() {
	let f = fixture();
	let mut failures = Vec::new();
	for (label, version, peer, mutation, expected) in [
		("wrong_version", "2", true, "", 400),
		("malformed_version", "nope", true, "", 400),
		("missing_peer", "3", false, "", 401),
		("revoked_worker", "3", true, "UPDATE workers SET revoked_at=1 WHERE name='host'", 401),
		("admin_role", "3", true, "UPDATE workers SET kind='admin' WHERE name='host'", 403),
		("oversized_id", "3", true, "", 400),
	] {
		f.offline
			.external_corruption(|conn| {
				conn.execute(
					"UPDATE workers SET kind='worker',revoked_at=NULL WHERE name='host'",
					[],
				)?;
				conn.execute_batch(mutation)?;
				Ok(())
			})
			.unwrap();
		let id = if label == "oversized_id" { "x".repeat(5000) } else { f.job.to_string() };
		let mut req = Request::post(format!("/v1/jobs/{id}/pin-target"))
			.header(PROTOCOL_VERSION_HEADER, version)
			.header(JOB_CAPABILITY_HEADER, &f.token)
			.header("content-type", "application/json")
			.body(Body::from(json!({"protocol_version":3,"commit_sha":SHA}).to_string()))
			.unwrap();
		if peer {
			req.extensions_mut().insert(f.peer.clone());
		}
		let reply = router(f.state.clone()).call(req).await.unwrap();
		assert_eq!(reply.status().as_u16(), expected, "{label}");
		let bytes = to_bytes(reply.into_body(), 16 * 1024).await.unwrap();
		let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
		if bytes.len() > 4096 || !body["error"]["code"].is_string() {
			failures.push((label, bytes.len()));
		}
	}
	assert!(failures.is_empty(), "structured phase boundary failed: {failures:?}");
}
