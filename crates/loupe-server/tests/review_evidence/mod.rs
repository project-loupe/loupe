//! HTTP evidence producers with explicit fixture leases.
use loupe_storage::checkpoints::Operation;
use loupe_storage::{leads, review_intents, review_units, unit_holds, Db, StoredEvidence};

use super::*;

fn policy(f: &Fixture, limit: u32) {
	f.offline.external_corruption(|conn| {
		let policy = ReviewPolicy { max_leads_per_survey: limit, ..ReviewPolicy::default() }.snapshot_v2().unwrap().canonical_bytes().unwrap();
		conn.execute("UPDATE review_campaigns SET effective_policy=?2,effective_policy_digest=?3 WHERE campaign_id=?1",params![f.campaign,std::str::from_utf8(&policy).unwrap(),blake3::hash(&policy).as_bytes().as_slice()])?;
		Ok(())
	}).unwrap();
}
async fn ready() -> (Fixture, i64) {
	let f = fixture();
	let generation = prepare(&f).await;
	policy(&f, 16);
	(f, generation)
}
fn unit(f: &Fixture, generation: i64, key: &str) -> i64 {
	common::with_repo(&f.state.db, 1, |scope| {
		review_units::create(
			scope,
			&review_units::NewUnit {
				generation_id: generation,
				client_key: &common::marked::agent::identifier(key),
				title: &common::marked::agent::text("Review entry"),
				objective: &common::marked::agent::text("Review boundary"),
				priority: review_units::Priority::Normal,
				priority_proposal: None,
				source_refs: &common::marked::agent::single_ref("z.rs"),
				depends_on: None,
				closure_criteria: None,
				semantic_context: None,
				carried_from: None,
				created_by_job: Some(f.job),
			},
			now(),
		)
	})
	.unwrap()
}
fn ordinary(f: &Fixture, generation: i64, units: &[i64]) {
	f.offline.external_corruption(|conn| {
 conn.execute("UPDATE review_generations SET state='active',activated_at=1 WHERE generation_id=?1",[generation])?;
 conn.execute("UPDATE jobs SET recipe='{\"version\":1,\"phase\":\"survey\",\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}' WHERE id=?1",[f.job])?;
 Ok(())
 }).unwrap();
	common::with_repo(&f.state.db, 1, |scope| {
		review_units::assign(
			scope,
			f.job,
			&units
				.iter()
				.map(|id| review_units::Assignment { unit_id: *id, expected_epoch: 0 })
				.collect::<Vec<_>>(),
		)
	})
	.unwrap();
}
fn lead(key: &str, anchor: &str, unit: Option<(i64, i64)>) -> Value {
	let mut evidence = json!({"format":"loupe.lead_evidence","version":1,"identity_family":"auth-bypass","identity_anchor":anchor,"hypothesis":"Attacker can cross the boundary","source_refs":[{"path":"z.rs"}],"next_proof_step":"Trace the public entry","counterevidence":"No enforced guard found","proof_gaps":"Need runnable proof"});
	if let Some((unit, epoch)) = unit {
		evidence["review_unit_id"] = json!(unit);
		evidence["assignment_epoch"] = json!(epoch);
	}
	json!({"protocol_version":3,"client_lead_key":key,"evidence":evidence})
}
fn urgent(value: &mut Value) {
	value["evidence"]["invariant_or_boundary"] = json!("public authentication boundary");
	value["evidence"]["priority_proposal"] = json!({"impact":"critical","access":"remote","reachability":"traced","boundary_refs":[{"path":"z.rs"}],"rationale":"Reachable high impact bypass"});
}
fn result(key: &str, unit: i64, epoch: i64, leads: &[i64]) -> Value {
	json!({"protocol_version":3,"client_result_key":key,"result":{"format":"loupe.unit_result","version":1,"review_unit_id":unit,"assignment_epoch":epoch,"disposition":if leads.is_empty(){"no_lead_found"}else{"lead_created"},"inspected_refs":[{"path":"z.rs"}],"created_lead_ids":leads,"counterevidence":"Reviewed the guard","proof_gaps":"No unresolved gap"}})
}
fn count(f: &Fixture, op: Operation) -> i64 {
	f.offline
		.external_corruption(|conn| {
			Ok(conn.query_row(
				"SELECT COUNT(*) FROM job_checkpoints WHERE job_id=?1 AND operation=?2",
				params![f.job, op.as_str()],
				|row| row.get(0),
			)?)
		})
		.unwrap()
}
fn rows(f: &Fixture, table: &str) -> i64 {
	f.offline
		.external_corruption(|conn| {
			Ok(conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?)
		})
		.unwrap()
}

#[tokio::test]
async fn leads_preserve_typed_evidence_intent_priority_and_replay_without_spend() {
	let (f, generation) = ready().await;
	let u = unit(&f, generation, "own");
	let mut payload = lead("first", "handler", Some((u, 0)));
	urgent(&mut payload);
	let first = post(&f, "leads", payload.clone()).await;
	assert_eq!(first["outcome"], "created");
	assert_eq!(first["accepted_priority"], json!({"band":"urgent","score":550}));
	assert!(first["observation_id"].is_null());
	let id = first["lead_id"].as_i64().unwrap();
	assert_eq!(post(&f, "leads", payload.clone()).await, first);
	common::with_repo(&f.state.db, 1, |scope| {
		let StoredEvidence::Recorded(stored) = leads::get_evidence(scope, id)? else {
			panic!("typed evidence")
		};
		assert_eq!(stored, common::marked::lead_evidence(&payload["evidence"].to_string()));
		let intent =
			review_intents::get_subject(scope, review_intents::Subject::Lead(id))?.unwrap();
		assert_eq!(intent.originating_job_id, f.job);
		assert_eq!(intent.priority.score, 550);
		Ok(())
	})
	.unwrap();
	let attached = post(&f, "leads", lead("observed", "handler", Some((u, 0)))).await;
	assert_eq!(attached["outcome"], "attached");
	assert_eq!(attached["lead_id"], id);
	assert!(attached["observation_id"].is_i64());
	assert_eq!(attached["accepted_priority"], first["accepted_priority"]);
	assert_eq!(rows(&f, "jobs"), 1);
	assert_eq!(
		rows(&f, "job_admission_charges"),
		1,
		"only the original preparation charge; accepted evidence and replay add none"
	);
	assert_eq!(rows(&f, "lead_drilldown_intents"), 1);
	assert_eq!(count(&f, Operation::SubmitLead), 2);
	let mut divergent = payload;
	divergent["evidence"]["proof_gaps"] = json!("different gap");
	let (status, error) = request(&f, f.job, "leads", divergent).await;
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(error["error"]["code"], "checkpoint_conflict");
}

#[tokio::test]
async fn concurrent_duplicate_keys_and_closed_observations_count_once_each() {
	let (f, _) = ready().await;
	let payload = lead("same", "same identity", None);
	let (a, b) = tokio::join!(
		request(&f, f.job, "leads", payload.clone()),
		request(&f, f.job, "leads", payload)
	);
	assert_eq!(a.0, StatusCode::OK);
	assert_eq!(a, b);
	let id = a.1["lead_id"].as_i64().unwrap();
	f.offline.external_corruption(|conn| {conn.execute("UPDATE leads SET status='closed',disposition='rejected',closed_at=1 WHERE lead_id=?1",[id])?;conn.execute("UPDATE lead_drilldown_intents SET state='complete' WHERE lead_id=?1",[id])?;Ok(())}).unwrap();
	let closed = post(&f, "leads", lead("closed", "same identity", None)).await;
	assert_eq!(closed["outcome"], "closed_exists");
	assert_eq!(closed["lead_id"], id);
	assert_eq!(rows(&f, "leads"), 1);
	assert_eq!(rows(&f, "lead_observations"), 1);
	assert_eq!(count(&f, Operation::SubmitLead), 2);
	common::with_repo(&f.state.db, 1, |scope| {
		assert_eq!(
			review_intents::get_subject(scope, review_intents::Subject::Lead(id))?.unwrap().state,
			review_intents::State::Complete
		);
		Ok(())
	})
	.unwrap();
}

#[tokio::test]
async fn frozen_lead_quota_survives_retries_and_exact_replay_is_free() {
	let (mut f, _) = ready().await;
	policy(&f, 2);
	Arc::make_mut(&mut f.state.review_policy).max_leads_per_survey = 99;
	let payload = lead("first", "one", None);
	let first = post(&f, "leads", payload.clone()).await;
	post(&f, "leads", lead("attached", "one", None)).await;
	f.offline
		.external_corruption(|conn| {
			conn.execute("UPDATE jobs SET attempts=2,prepared_attempt=2 WHERE id=?1", [f.job])?;
			Ok(())
		})
		.unwrap();
	assert_eq!(post(&f, "leads", payload).await, first);
	let (status, error) = request(&f, f.job, "leads", lead("excess", "two", None)).await;
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(error["error"]["code"], "checkpoint_limit");
	assert_eq!(count(&f, Operation::SubmitLead), 2);
	assert_eq!(rows(&f, "leads"), 1);
}

#[tokio::test]
async fn results_require_this_jobs_exact_unit_submission_and_allow_attached_association() {
	let (f, generation) = ready().await;
	let a = unit(&f, generation, "a");
	let b = unit(&f, generation, "b");
	ordinary(&f, generation, &[a, b]);
	let accepted = post(&f, "leads", lead("a-lead", "shared", Some((a, 1)))).await;
	let id = accepted["lead_id"].as_i64().unwrap();
	let payload = result("b-result", b, 1, &[id]);
	assert_eq!(
		request(&f, f.job, "review-unit-results", payload.clone()).await.0,
		StatusCode::FORBIDDEN
	);
	assert_eq!(rows(&f, "review_unit_results"), 0);
	let attached = post(&f, "leads", lead("b-observation", "shared", Some((b, 1)))).await;
	assert_eq!(attached["outcome"], "attached");
	post(&f, "leads", lead("later-a-observation", "shared", Some((a, 1)))).await;
	let recorded = post(&f, "review-unit-results", payload.clone()).await;
	assert_eq!(recorded["review_unit_id"], b);
	assert_eq!(recorded["disposition"], "lead_created");
	assert_eq!(post(&f, "review-unit-results", payload).await, recorded);
	f.offline.external_corruption(|conn| {assert_eq!(conn.query_row("SELECT completed FROM job_assigned_review_units WHERE job_id=?1 AND review_unit_id=?2",params![f.job,b],|r|r.get::<_,i64>(0))?,1);Ok(())}).unwrap();
	assert_eq!(
		request(&f, f.job, "review-unit-results", result("another", b, 1, &[id])).await.0,
		StatusCode::FORBIDDEN
	);
	// Completed units remain valid references for later independent lead evidence.
	post(&f, "leads", lead("later", "later identity", Some((b, 1)))).await;
	assert_eq!(count(&f, Operation::SubmitUnitResult), 1);
}

#[tokio::test]
async fn follow_up_result_hold_and_completion_are_one_checkpoint_and_replay_survives_retry() {
	let (f, generation) = ready().await;
	let u = unit(&f, generation, "held");
	ordinary(&f, generation, &[u]);
	let mut payload = result("follow", u, 1, &[]);
	payload["result"]["disposition"] = json!("needs_follow_up");
	payload["result"]["follow_up"] = json!("trace remaining branch");
	payload["result"]["continuation"] = json!("source_analysis_remaining");
	let accepted = post(&f, "review-unit-results", payload.clone()).await;
	common::with_repo(&f.state.db, 1, |scope| {
		let hold = unit_holds::get_hold(scope, u)?.unwrap();
		assert_eq!(hold.producing_result_id, accepted["result_id"].as_i64().unwrap());
		assert_eq!(hold.source_assignment_epoch, 1);
		Ok(())
	})
	.unwrap();
	f.offline
		.external_corruption(|conn| {
			assert_eq!(
				conn.query_row(
					"SELECT completed FROM job_assigned_review_units WHERE job_id=?1",
					[f.job],
					|r| r.get::<_, i64>(0)
				)?,
				1
			);
			conn.execute("UPDATE jobs SET attempts=2,prepared_attempt=2 WHERE id=?1", [f.job])?;
			Ok(())
		})
		.unwrap();
	assert_eq!(post(&f, "review-unit-results", payload.clone()).await, accepted);
	payload["client_result_key"] = json!("fresh");
	assert_eq!(request(&f, f.job, "review-unit-results", payload).await.0, StatusCode::FORBIDDEN);
	assert_eq!(rows(&f, "review_unit_results"), 1);
	assert_eq!(count(&f, Operation::SubmitUnitResult), 1);
}

#[tokio::test]
async fn intent_or_hold_failure_rolls_back_evidence_assignment_and_receipt() {
	let (f, generation) = ready().await;
	let u = unit(&f, generation, "own");
	ordinary(&f, generation, &[u]);
	f.offline.external_corruption(|conn| {conn.execute_batch("CREATE TRIGGER fail_intent BEFORE INSERT ON lead_drilldown_intents BEGIN SELECT RAISE(ABORT,'injected intent failure'); END;")?;Ok(())}).unwrap();
	assert_eq!(
		request(&f, f.job, "leads", lead("fail", "identity", Some((u, 1)))).await.0,
		StatusCode::INTERNAL_SERVER_ERROR
	);
	assert_eq!(rows(&f, "leads"), 0);
	assert_eq!(count(&f, Operation::SubmitLead), 0);
	f.offline.external_corruption(|conn| {conn.execute_batch("CREATE TRIGGER fail_complete BEFORE UPDATE OF completed ON job_assigned_review_units BEGIN SELECT RAISE(ABORT,'injected completion failure'); END;")?;Ok(())}).unwrap();
	assert_eq!(
		request(&f, f.job, "review-unit-results", result("fail", u, 1, &[])).await.0,
		StatusCode::INTERNAL_SERVER_ERROR
	);
	assert_eq!(rows(&f, "review_unit_results"), 0);
	assert_eq!(count(&f, Operation::SubmitUnitResult), 0);
	f.offline
		.external_corruption(|conn| {
			assert_eq!(
				conn.query_row(
					"SELECT completed FROM job_assigned_review_units WHERE job_id=?1",
					[f.job],
					|r| r.get::<_, i64>(0)
				)?,
				0
			);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn siblings_have_separate_quota_and_only_the_assigned_leads_unit() {
	let (f, generation) = ready().await;
	let own = unit(&f, generation, "assigned");
	let other = unit(&f, generation, "other");
	let initial = post(&f, "leads", lead("parent", "parent", Some((own, 0)))).await;
	let parent = initial["lead_id"].as_i64().unwrap();
	f.offline.external_corruption(|conn| {conn.execute("UPDATE jobs SET kind='drilldown',assigned_lead_id=?2,recipe='{\"version\":1,\"phase\":\"drilldown\"}' WHERE id=?1",params![f.job,parent])?;Ok(())}).unwrap();
	for association in [(other, 0), (own, 1), (999999, 0)] {
		assert_eq!(
			request(&f, f.job, "sibling-leads", lead("bad", "bad", Some(association))).await.0,
			StatusCode::FORBIDDEN
		);
	}
	let first = post(&f, "sibling-leads", lead("first", "sibling-0", Some((own, 0)))).await;
	for i in 1..4 {
		post(&f, "sibling-leads", lead(&format!("sibling-{i}"), &format!("sibling-{i}"), None))
			.await;
	}
	f.offline
		.external_corruption(|conn| {
			conn.execute("UPDATE jobs SET attempts=2,prepared_attempt=2 WHERE id=?1", [f.job])?;
			Ok(())
		})
		.unwrap();
	assert_eq!(post(&f, "sibling-leads", lead("first", "sibling-0", Some((own, 0)))).await, first);
	let (status, error) = request(&f, f.job, "sibling-leads", lead("fifth", "fifth", None)).await;
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(error["error"]["code"], "checkpoint_limit");
	assert_eq!(count(&f, Operation::SubmitSiblingLead), 4);
	assert_eq!(count(&f, Operation::SubmitLead), 1);
	assert_eq!(
		request(&f, f.job, "leads", lead("wrong-phase", "wrong phase", None)).await.0,
		StatusCode::FORBIDDEN
	);
}

#[tokio::test]
async fn source_membership_and_duplicate_hint_issuance_have_no_existence_oracle() {
	let (f, _) = ready().await;
	let first = post(&f, "leads", lead("first", "candidate", None)).await;
	let id = first["lead_id"].as_i64().unwrap();
	let mut hint = lead("hint", "new identity", None);
	hint["evidence"]["duplicate_hint"] = json!({"lead_id":id,"rationale":"same boundary"});
	let unissued = request(&f, f.job, "leads", hint.clone()).await;
	assert_eq!(unissued.0, StatusCode::FORBIDDEN);
	let mut absent = hint.clone();
	absent["evidence"]["duplicate_hint"]["lead_id"] = json!(999999);
	assert_eq!(request(&f, f.job, "leads", absent).await, unissued);
	let mut get = Request::get(format!("/v1/jobs/{}/lead-candidates?query=candidate", f.job))
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header(JOB_CAPABILITY_HEADER, &f.token)
		.body(Body::empty())
		.unwrap();
	get.extensions_mut().insert(f.peer.clone());
	assert_eq!(response(&f, get).await.0, StatusCode::OK);
	post(&f, "leads", hint).await;
	for field in ["source_refs", "priority_proposal"] {
		let mut invalid = lead(field, field, None);
		if field == "source_refs" {
			invalid["evidence"][field] = json!([{"path":"absent.rs"}]);
		} else {
			urgent(&mut invalid);
			invalid["evidence"][field]["boundary_refs"] = json!([{"path":"absent.rs"}]);
		}
		assert_eq!(request(&f, f.job, "leads", invalid).await.0, StatusCode::BAD_REQUEST);
	}
	assert_eq!(rows(&f, "leads"), 2);
	assert_eq!(count(&f, Operation::SubmitLead), 2);
}

#[tokio::test]
async fn foreign_job_unassociated_and_old_epoch_leads_cannot_supply_result_ids() {
	let (f, generation) = ready().await;
	let u = unit(&f, generation, "own");
	let old = post(&f, "leads", lead("old", "old epoch", Some((u, 0)))).await["lead_id"]
		.as_i64()
		.unwrap();
	let unassociated =
		post(&f, "leads", lead("no-unit", "unassociated", None)).await["lead_id"].as_i64().unwrap();
	ordinary(&f, generation, &[u]);
	let current = post(&f, "leads", lead("current", "current", Some((u, 1)))).await["lead_id"]
		.as_i64()
		.unwrap();
	f.offline.external_corruption(|conn| {conn.execute("INSERT INTO jobs(id,repo_id,kind,state,generation_id,enqueued_at) VALUES(1000,1,'survey','succeeded',?1,0)",[generation])?;conn.execute("UPDATE leads SET created_by_job_id=1000 WHERE lead_id=?1",[current])?;Ok(())}).unwrap();
	for id in [old, unassociated, current, 999999] {
		assert_eq!(
			request(&f, f.job, "review-unit-results", result(&format!("bad-{id}"), u, 1, &[id]))
				.await
				.0,
			StatusCode::FORBIDDEN
		);
	}
	assert_eq!(rows(&f, "review_unit_results"), 0);
	assert_eq!(count(&f, Operation::SubmitUnitResult), 0);
	assert_eq!(
		request(&f, f.job, "leads", lead("stale", "stale", Some((u, 0)))).await.0,
		StatusCode::FORBIDDEN
	);
	let fresh = post(&f, "leads", lead("attached-current", "current", Some((u, 1)))).await;
	assert_eq!(fresh["outcome"], "attached");
	post(&f, "review-unit-results", result("accepted", u, 1, &[current])).await;
}

#[tokio::test]
async fn fresh_results_remain_unique_when_prior_evidence_is_invalidated() {
	let (f, generation) = ready().await;
	let u = unit(&f, generation, "own");
	let initial = result("first", u, 0, &[]);
	let accepted = post(&f, "review-unit-results", initial.clone()).await;
	f.offline.external_corruption(|conn| {conn.execute("UPDATE review_unit_results SET invalidated=1,invalidated_reason='test stale evidence' WHERE review_unit_id=?1",[u])?;Ok(())}).unwrap();
	let (status, error) =
		request(&f, f.job, "review-unit-results", result("again", u, 0, &[])).await;
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(error["error"]["code"], "unit_result_exists");
	assert_eq!(post(&f, "review-unit-results", initial).await, accepted);
	assert_eq!(rows(&f, "review_unit_results"), 1);
}

#[tokio::test]
async fn every_evidence_route_requires_live_exact_worker_capability_phase_and_preparation() {
	for fault in ["worker", "token", "expired", "unprepared", "deadline", "phase"] {
		let (mut f, generation) = ready().await;
		let u = unit(&f, generation, "own");
		match fault {
			"worker" => f.peer = f.other_peer.clone(),
			"token" => f.token = "z".repeat(43),
			"expired" => {
				f.offline
					.external_corruption(|c| {
						c.execute("UPDATE jobs SET lease_expires_at=0 WHERE id=?1", [f.job])?;
						Ok(())
					})
					.unwrap();
			},
			"unprepared" => {
				f.offline.external_corruption(|c| {
					c.execute("UPDATE jobs SET prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id=?1", [f.job])?;
						Ok(())
					})
					.unwrap();
			},
			"deadline" => {
				f.offline
					.external_corruption(|c| {
						c.execute("UPDATE jobs SET hard_deadline_at=0 WHERE id=?1", [f.job])?;
						Ok(())
					})
					.unwrap();
			},
			"phase" => {
				f.offline.external_corruption(|c| {c.execute("UPDATE jobs SET recipe='{\"version\":1,\"phase\":\"verify\"}' WHERE id=?1",[f.job])?;Ok(())}).unwrap();
			},
			_ => unreachable!(),
		}
		for (route, payload) in [
			("leads", lead("lead", "identity", None)),
			("sibling-leads", lead("sibling", "identity", None)),
			("review-unit-results", result("result", u, 0, &[])),
		] {
			assert_eq!(
				request(&f, f.job, route, payload).await.0,
				StatusCode::FORBIDDEN,
				"{fault}: {route}"
			);
		}
		assert_eq!(rows(&f, "leads"), 0);
		assert_eq!(rows(&f, "review_unit_results"), 0);
	}
}

#[tokio::test]
async fn strict_duplicate_fields_encoding_and_actual_stream_bounds_are_enforced() {
	let (f, generation) = ready().await;
	let u = unit(&f, generation, "own");
	for (route, payload) in [
		("leads", lead("lead", "identity", None)),
		("sibling-leads", lead("sibling", "identity", None)),
		("review-unit-results", result("result", u, 0, &[])),
	] {
		let raw = payload.to_string();
		for raw in [
			raw.replace("\"protocol_version\":3", "\"protocol_version\":3,\"protocol_version\":3"),
			raw.replace("\"version\":1", "\"version\":1,\"version\":1"),
			raw.replacen('{', "{\"unknown\":true,", 1),
		] {
			let mut req = Request::post(format!("/v1/jobs/{}/{route}", f.job))
				.header(PROTOCOL_VERSION_HEADER, "3")
				.header(JOB_CAPABILITY_HEADER, &f.token)
				.header("content-type", "application/json")
				.body(Body::from(raw))
				.unwrap();
			req.extensions_mut().insert(f.peer.clone());
			let response = router(f.state.clone()).call(req).await.unwrap();
			assert_eq!(response.status(), StatusCode::BAD_REQUEST);
			assert_eq!(response.headers()["cache-control"], "no-store");
			assert!(to_bytes(response.into_body(), 4096).await.is_ok());
		}
		let mut encoded = Request::post(format!("/v1/jobs/{}/{route}", f.job))
			.header(PROTOCOL_VERSION_HEADER, "3")
			.header(JOB_CAPABILITY_HEADER, &f.token)
			.header("content-type", "application/json")
			.header("content-encoding", "gzip")
			.body(Body::from(payload.to_string()))
			.unwrap();
		encoded.extensions_mut().insert(f.peer.clone());
		assert_eq!(response(&f, encoded).await.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);
		let chunks = Chunks(
			[
				axum::body::Bytes::from(payload.to_string()),
				axum::body::Bytes::from("🦀".repeat(65536)),
			]
			.into(),
		);
		let mut req = Request::post(format!("/v1/jobs/{}/{route}", f.job))
			.header(PROTOCOL_VERSION_HEADER, "3")
			.header(JOB_CAPABILITY_HEADER, &f.token)
			.header("content-type", "application/json")
			.header("content-length", "1")
			.body(Body::new(chunks))
			.unwrap();
		req.extensions_mut().insert(f.peer.clone());
		assert_eq!(response(&f, req).await.0, StatusCode::PAYLOAD_TOO_LARGE);
	}
	assert_eq!(rows(&f, "leads"), 0);
	assert_eq!(rows(&f, "review_unit_results"), 0);
	let mut raw = lead("boundary", "boundary", None).to_string();
	raw.push_str(&" ".repeat(256 * 1024 - raw.len()));
	let mut req = Request::post(format!("/v1/jobs/{}/leads", f.job))
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header(JOB_CAPABILITY_HEADER, &f.token)
		.header("content-type", "application/json")
		.body(Body::from(raw))
		.unwrap();
	req.extensions_mut().insert(f.peer.clone());
	assert_eq!(response(&f, req).await.0, StatusCode::OK);
}

#[tokio::test]
async fn encrypted_restart_keeps_lead_result_receipts_and_completed_provenance() {
	let key = loupe_storage::secrets::MasterKey::for_tests();
	let mut f = fixture();
	let generation = prepare(&f).await;
	policy(&f, 16);
	let u = unit(&f, generation, "own");
	let lead_request = lead("durable", "durable", Some((u, 0)));
	let lead_response = post(&f, "leads", lead_request.clone()).await;
	let result_request = result("durable", u, 0, &[lead_response["lead_id"].as_i64().unwrap()]);
	let result_response = post(&f, "review-unit-results", result_request.clone()).await;
	let old = std::mem::replace(&mut f.state.db, Arc::new(Db::open_in_memory(&key).unwrap()));
	drop(old);
	f.offline.edit(|_| Ok(()));
	f.state.db = f.offline.open();
	assert_eq!(post(&f, "leads", lead_request).await, lead_response);
	assert_eq!(post(&f, "review-unit-results", result_request).await, result_response);
	assert_eq!(rows(&f, "lead_drilldown_intents"), 1);
	assert_eq!(rows(&f, "review_unit_results"), 1);
}

#[tokio::test]
async fn evidence_source_identity_does_not_normalize_git_paths() {
	let f = fixture();
	post(&f, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await;
	let entries = vec![ManifestEntry {
		raw_path: "e\u{301}.rs".as_bytes().to_vec(),
		git_mode: 0o100644,
		object_id: [0xaa; 20],
	}];
	post(&f, "inventory-batches", chunk(&entries, 0, 1)).await;
	post(&f, "seal-inventory", json!({"protocol_version":3})).await;
	post(&f, "publish-profile", json!({"protocol_version":3,"profile":{}})).await;
	policy(&f, 16);
	let mut submission = lead("nfd", "identity", None);
	submission["evidence"]["source_refs"] = json!([{"path":"e\u{301}.rs"}]);
	let accepted = post(&f, "leads", submission.clone()).await;
	common::with_repo(&f.state.db, 1, |scope| {
		let StoredEvidence::Recorded(evidence) =
			leads::get_evidence(scope, accepted["lead_id"].as_i64().unwrap())?
		else {
			panic!("typed")
		};
		assert_eq!(evidence.source_refs[0].path.expose(), "e\u{301}.rs");
		Ok(())
	})
	.unwrap();
	submission["evidence"]["source_refs"] = json!([{"path":"é.rs"}]);
	assert_eq!(
		request(&f, f.job, "leads", submission.clone()).await.0,
		StatusCode::CONFLICT,
		"entire exact-path request digest differs"
	);
	submission["client_lead_key"] = json!("nfc");
	assert_eq!(
		request(&f, f.job, "leads", submission).await.0,
		StatusCode::BAD_REQUEST,
		"NFC twin is not a manifest member"
	);
	assert_eq!(rows(&f, "leads"), 1);
	assert_eq!(rows(&f, "lead_observations"), 0);
}

#[tokio::test]
async fn attachments_never_upgrade_rank_or_resurrect_blocked_intent() {
	let (f, _) = ready().await;
	let original = post(&f, "leads", lead("original", "identity", None)).await;
	let id = original["lead_id"].as_i64().unwrap();
	f.offline.external_corruption(|conn| {conn.execute("UPDATE lead_drilldown_intents SET state='blocked',block_reason='external_dependency' WHERE lead_id=?1",[id])?;Ok(())}).unwrap();
	let mut stronger = lead("stronger", "identity", None);
	urgent(&mut stronger);
	let attached = post(&f, "leads", stronger.clone()).await;
	assert_eq!(attached["accepted_priority"], json!({"band":"normal","score":0}));
	common::with_repo(&f.state.db, 1, |scope| {
		let intent =
			review_intents::get_subject(scope, review_intents::Subject::Lead(id))?.unwrap();
		assert_eq!(intent.state, review_intents::State::Blocked);
		assert_eq!(intent.block_reason, Some(review_intents::BlockReason::ExternalDependency));
		let observation = loupe_storage::lead_observations::list_evidence(scope, id)?
			.into_iter()
			.rfind(|observation| observation.submitted_by_job == Some(f.job))
			.unwrap();
		let StoredEvidence::Recorded(evidence) = observation.payload else { panic!("typed") };
		assert!(evidence.priority_proposal.is_some());
		Ok(())
	})
	.unwrap();
	// Fresh attachment rollback covers observation + checkpoint, not just creation.
	f.offline.external_corruption(|conn| {conn.execute_batch("CREATE TRIGGER fail_receipt BEFORE INSERT ON job_checkpoints WHEN NEW.operation='submit_lead' BEGIN SELECT RAISE(ABORT,'injected receipt failure'); END;")?;Ok(())}).unwrap();
	stronger["client_lead_key"] = json!("failed-receipt");
	assert_eq!(request(&f, f.job, "leads", stronger).await.0, StatusCode::INTERNAL_SERVER_ERROR);
	assert_eq!(rows(&f, "lead_observations"), 1);
	assert_eq!(count(&f, Operation::SubmitLead), 2);
}

#[tokio::test]
async fn admitted_exact_batch_releases_each_hold_and_completes_atomically() {
	let (mut f, generation) = ready().await;
	let a = unit(&f, generation, "a");
	let b = unit(&f, generation, "b");
	for u in [a, b] {
		let mut payload = result(&format!("hold-{u}"), u, 0, &[]);
		payload["result"]["disposition"] = json!("needs_follow_up");
		payload["result"]["follow_up"] = json!("Inspect remaining caller");
		payload["result"]["continuation"] = json!("source_analysis_remaining");
		post(&f, "review-unit-results", payload).await;
	}
	let child_token = "b".repeat(43);
	let child_hash = blake3::hash(child_token.as_bytes());
	f.offline
		.external_corruption(|conn| {
			conn.execute("UPDATE jobs SET state='succeeded' WHERE id=?1", [f.job])?;
			Ok(())
		})
		.unwrap();
	let batch = common::with_repo(&f.state.db, 1, |scope| {
		Ok(unit_holds::freeze_survey_batches(scope, f.job, now() - 100)?.remove(0).batch_id)
	})
	.unwrap();
	f.offline.external_corruption(|tx| {
		tx.execute("UPDATE review_generations SET state='active',activated_at=1 WHERE generation_id=?1",[generation])?;
		tx.execute("INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,head_sha,parent_job_id,continuation_of_job_id,worker_id,attempts,lease_expires_at,hard_deadline_at,job_capability_hash,workflow_contract_version,scheduling_band,enqueued_at,prepared_attempt,prepared_capability_hash,prepared_at,recipe) SELECT 1000,repo_id,'survey','leased',campaign_id,generation_id,head_sha,id,id,worker_id,1,lease_expires_at,hard_deadline_at,?2,workflow_contract_version,'normal',enqueued_at,1,?2,prepared_at,'{\"version\":1,\"phase\":\"survey\",\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}' FROM jobs WHERE id=?1",params![f.job,child_hash.as_bytes().as_slice()])?;
		Ok(())
	}).unwrap();
	common::with_repo(&f.state.db, 1, |scope| {
		let units = unit_holds::admit_exact_batch(scope, batch, 1000, now())?;
		assert_eq!(units.len(), 2);
		assert!(units.iter().all(|u| u.assignment_epoch == 1));
		Ok(())
	})
	.unwrap();
	f.job = 1000;
	f.token = child_token;
	let first = post(&f, "review-unit-results", result("first", a, 1, &[])).await;
	common::with_repo(&f.state.db, 1, |scope| {
		assert!(unit_holds::get_hold(scope, a)?.is_none());
		assert!(unit_holds::get_hold(scope, b)?.is_some());
		assert_eq!(
			unit_holds::get_batch(scope, batch)?.unwrap().state,
			review_intents::State::Admitted
		);
		Ok(())
	})
	.unwrap();
	f.offline.external_corruption(|conn| {conn.execute_batch("CREATE TRIGGER fail_result_receipt BEFORE INSERT ON job_checkpoints WHEN NEW.operation='submit_unit_result' BEGIN SELECT RAISE(ABORT,'injected result receipt failure'); END;")?;Ok(())}).unwrap();
	assert_eq!(
		request(&f, f.job, "review-unit-results", result("second", b, 1, &[])).await.0,
		StatusCode::INTERNAL_SERVER_ERROR
	);
	common::with_repo(&f.state.db, 1, |scope| {
		assert!(unit_holds::get_hold(scope, b)?.is_some());
		assert_eq!(
			unit_holds::get_batch(scope, batch)?.unwrap().state,
			review_intents::State::Admitted
		);
		Ok(())
	})
	.unwrap();
	f.offline.external_corruption(|conn| {assert_eq!(conn.query_row("SELECT completed FROM job_assigned_review_units WHERE job_id=?1 AND review_unit_id=?2",params![f.job,b],|r|r.get::<_,i64>(0))?,0);conn.execute_batch("DROP TRIGGER fail_result_receipt;")?;Ok(())}).unwrap();
	post(&f, "review-unit-results", result("second", b, 1, &[])).await;
	assert_eq!(post(&f, "review-unit-results", result("first", a, 1, &[])).await, first);
	common::with_repo(&f.state.db, 1, |scope| {
		assert!(unit_holds::get_hold(scope, b)?.is_none());
		assert_eq!(
			unit_holds::get_batch(scope, batch)?.unwrap().state,
			review_intents::State::Complete
		);
		Ok(())
	})
	.unwrap();
	assert_eq!(count(&f, Operation::SubmitUnitResult), 2);
	assert_eq!(rows(&f, "review_unit_results"), 4);
}

#[tokio::test]
async fn result_lead_scope_precedes_malformed_metadata_and_evidence_decode() {
	for damage in ["identity", "digest", "payload"] {
		let (f, generation) = ready().await;
		let unit = unit(&f, generation, "owned");
		let accepted = post(&f, "leads", lead("owned", "original", Some((unit, 0)))).await;
		let id = accepted["lead_id"].as_i64().unwrap();
		f.offline
			.external_corruption(|conn| {
				// The lead's creator alone is not proof of an accepted checkpoint.
				conn.execute(
					"DELETE FROM job_checkpoints WHERE job_id=?1 AND operation='submit_lead'",
					[f.job],
				)?;
				conn.execute(
					match damage {
						"identity" => "UPDATE leads SET identity_family='INVALID' WHERE lead_id=?1",
						"digest" => {
							"UPDATE leads SET anchored_digest=zeroblob(32) WHERE lead_id=?1"
						},
						"payload" => "UPDATE leads SET anchored_payload='{' WHERE lead_id=?1",
						_ => unreachable!(),
					},
					[id],
				)?;
				Ok(())
			})
			.unwrap();
		let missing =
			request(&f, f.job, "review-unit-results", result("missing", unit, 0, &[999999])).await;
		assert_eq!(missing.0, StatusCode::FORBIDDEN);
		let unaccepted =
			request(&f, f.job, "review-unit-results", result("unaccepted", unit, 0, &[id])).await;
		assert_eq!(unaccepted, missing, "unaccepted {damage} must be denied before decoding");
		assert_eq!(rows(&f, "review_unit_results"), 0);
		assert_eq!(count(&f, Operation::SubmitUnitResult), 0);
	}
}

#[tokio::test]
async fn historical_priority_cannot_become_new_accepted_authority() {
	let (f, _) = ready().await;
	let original = post(&f, "leads", lead("original", "identity", None)).await;
	let id = original["lead_id"].as_i64().unwrap();
	f.offline.external_corruption(|conn| {
		conn.execute("DELETE FROM lead_drilldown_intents WHERE lead_id=?1",[id])?;
		conn.execute("UPDATE leads SET anchored_payload='{}',anchored_digest=?2,priority_band='urgent' WHERE lead_id=?1",params![id,loupe_core::canonical::digest(b"{}").as_slice()])?;
		Ok(())
	}).unwrap();
	let (status, error) = request(&f, f.job, "leads", lead("attachment", "identity", None)).await;
	assert_eq!(
		status,
		StatusCode::CONFLICT,
		"historical urgency must not grant modern admission authority: {error}"
	);
	assert_eq!(error["error"]["code"], "incompatible_review_state");
	assert_eq!(rows(&f, "lead_drilldown_intents"), 0);
	assert_eq!(rows(&f, "lead_observations"), 0);
	assert_eq!(rows(&f, "leads"), 1, "historical data remains intact");
	assert_eq!(count(&f, Operation::SubmitLead), 1);
}

#[tokio::test]
async fn stored_band_must_agree_with_recorded_priority_support() {
	let (f, _) = ready().await;
	let original = post(&f, "leads", lead("original", "identity", None)).await;
	let id = original["lead_id"].as_i64().unwrap();
	f.offline
		.external_corruption(|conn| {
			conn.execute("DELETE FROM lead_drilldown_intents WHERE lead_id=?1", [id])?;
			conn.execute("UPDATE leads SET priority_band='urgent' WHERE lead_id=?1", [id])?;
			Ok(())
		})
		.unwrap();
	let (status, error) = request(&f, f.job, "leads", lead("attachment", "identity", None)).await;
	assert_eq!(
		status,
		StatusCode::CONFLICT,
		"a stored band cannot replace validated priority support: {error}"
	);
	assert_eq!(rows(&f, "lead_drilldown_intents"), 0);
	assert_eq!(rows(&f, "lead_observations"), 0);
	assert_eq!(count(&f, Operation::SubmitLead), 1);
}

#[tokio::test]
async fn sibling_unit_membership_precedes_foreign_payload_decode() {
	let (f, generation) = ready().await;
	let own = unit(&f, generation, "original");
	let parent = post(&f, "leads", lead("parent", "parent", Some((own, 0)))).await["lead_id"]
		.as_i64()
		.unwrap();
	f.offline.external_corruption(|conn| {
		conn.execute("INSERT INTO review_generations(repo_id,generation_commit_sha,state,workflow_contract_version,created_at) SELECT repo_id,?2,'building',1,?3 FROM jobs WHERE id=?1",params![f.job,"b".repeat(40),now()])?;
		let foreign=conn.last_insert_rowid();
		conn.execute("UPDATE review_units SET generation_id=?2,source_refs='{' WHERE review_unit_id=?1",params![own,foreign])?;
		conn.execute("UPDATE jobs SET kind='drilldown',assigned_lead_id=?2,recipe='{\"version\":1,\"phase\":\"drilldown\"}' WHERE id=?1",params![f.job,parent])?;
		Ok(())
	}).unwrap();
	let missing =
		request(&f, f.job, "sibling-leads", lead("missing", "new", Some((999999, 0)))).await;
	assert_eq!(missing.0, StatusCode::FORBIDDEN);
	let foreign = request(&f, f.job, "sibling-leads", lead("foreign", "new", Some((own, 0)))).await;
	assert_eq!(foreign, missing, "foreign unit must be denied before decoding its payload");
	assert_eq!(count(&f, Operation::SubmitSiblingLead), 0);
}

#[tokio::test]
async fn unaccepted_observation_is_not_decoded_for_result_provenance() {
	let (f, generation) = ready().await;
	let a = unit(&f, generation, "a");
	let b = unit(&f, generation, "b");
	let original = post(&f, "leads", lead("original", "identity", Some((a, 0)))).await;
	let id = original["lead_id"].as_i64().unwrap();
	let attached = post(&f, "leads", lead("attached", "identity", Some((b, 0)))).await;
	let observation = attached["observation_id"].as_i64().unwrap();
	f.offline.external_corruption(|conn| {
		assert_eq!(conn.execute("DELETE FROM job_checkpoints WHERE job_id=?1 AND client_key='submit_lead:attached' AND operation='submit_lead'",[f.job])?,1);
		conn.execute("UPDATE lead_observations SET observation_digest=zeroblob(32) WHERE lead_observation_id=?1",[observation])?;
		Ok(())
	}).unwrap();
	let missing =
		request(&f, f.job, "review-unit-results", result("missing", b, 0, &[999999])).await;
	let unaccepted =
		request(&f, f.job, "review-unit-results", result("unaccepted", b, 0, &[id])).await;
	assert_eq!(missing.0, StatusCode::FORBIDDEN);
	assert_eq!(unaccepted, missing, "the observation needs its own accepted receipt before decode");
	assert_eq!(rows(&f, "review_unit_results"), 0);
}

#[tokio::test]
async fn accepted_evidence_corruption_still_fails_integrity_checks() {
	let (f, generation) = ready().await;
	let a = unit(&f, generation, "a");
	let b = unit(&f, generation, "b");
	let original = post(&f, "leads", lead("original", "identity", Some((a, 0)))).await;
	let id = original["lead_id"].as_i64().unwrap();
	let attached = post(&f, "leads", lead("attached", "identity", Some((b, 0)))).await;
	f.offline.external_corruption(|conn| {
		conn.execute("UPDATE lead_observations SET observation_digest=zeroblob(32) WHERE lead_observation_id=?1",[attached["observation_id"].as_i64().unwrap()])?;
		Ok(())
	}).unwrap();
	assert_eq!(
		request(&f, f.job, "review-unit-results", result("corrupted", b, 0, &[id])).await.0,
		StatusCode::CONFLICT
	);
	assert_eq!(rows(&f, "review_unit_results"), 0);
}

#[tokio::test]
// Pending frozen I12/I13 join; all original end-to-end assertions retained.
async fn bootstrap_checkpoint_and_terminal_routes_form_one_public_flow() {
	let (f, _) = ready().await;
	let created=post(&f,"review-units",json!({"protocol_version":3,"client_review_unit_key":"public-unit","title":"Entry boundary","objective":"Inspect the caller","priority_band":"normal","source_refs":[{"path":"z.rs"}]})).await;
	let unit = created["review_unit_id"].as_i64().unwrap();
	let submitted = post(&f, "leads", lead("public-lead", "boundary", Some((unit, 0)))).await;
	let lead = submitted["lead_id"].as_i64().unwrap();
	post(&f, "review-unit-results", result("public-result", unit, 0, &[lead])).await;
	for (path, disposition, mappings) in [
		("z.rs", "mapped", json!([{"review_unit_id":unit,"assignment_epoch":0}])),
		("a%FF", "context", json!([])),
	] {
		post(&f,"inventory-dispositions",json!({"protocol_version":3,"client_inventory_disposition_key":if path=="z.rs"{"source"}else{"context"},"source_path":path,"expected_revision":0,"disposition":disposition,"reason":"Reviewed scope","mappings":mappings})).await;
	}
	let terminal =
		json!({"protocol_version":3,"payload":{"version":1,"terminal_reason":"completed"}});
	let receipt = post(&f, "finalize-survey", terminal.clone()).await;
	assert_eq!(receipt["receipt"]["summary"]["missing_results"], 0);
	assert_eq!(receipt["receipt"]["summary"]["unresolved_inventory"], 0);
	assert_eq!(
		receipt["receipt"]["summary"]["coverage"], "partial",
		"B4 does not fabricate corroboration"
	);
	assert_eq!(post(&f, "finalize-survey", terminal).await, receipt);
	assert_eq!(rows(&f, "lead_drilldown_intents"), 1);
	assert_eq!(rows(&f, "jobs"), 1, "acceptance does not allocate a child");
}
