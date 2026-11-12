//! Shared-route lifecycle tests use actual worker/admin middleware.
use super::*;

pub(super) fn v2(f: &Fixture) {
	f.offline.external_corruption(|conn| {
		let policy=ReviewPolicy::default().snapshot_v2().unwrap().canonical_bytes().unwrap();
		conn.execute("UPDATE review_campaigns SET effective_policy=?2,effective_policy_digest=?3 WHERE campaign_id=?1",params![f.campaign,std::str::from_utf8(&policy).unwrap(),loupe_core::canonical::digest(&policy).as_slice()])?;Ok(())
	}).unwrap();
}
pub(super) fn admin(f: &Fixture) -> PeerCert {
	let bundle = f.state.ca.mint_client("lifecycle-admin").unwrap();
	let peer = PeerCert(
		CertificateDer::pem_slice_iter(bundle.cert_pem.as_bytes()).next().unwrap().unwrap(),
	);
	registry::bootstrap_admin(&f.state.db, &loupe_tls::cert_fingerprint(peer.0.as_ref()), now())
		.unwrap();
	peer
}
async fn admin_post(
	f: &Fixture, peer: &PeerCert, path: &str, payload: Value,
) -> (StatusCode, Value) {
	let mut request = Request::post(path)
		.header("content-type", "application/json")
		.body(Body::from(payload.to_string()))
		.unwrap();
	request.extensions_mut().insert(peer.clone());
	response(f, request).await
}
#[tokio::test]
async fn legacy_admin_recovery_excludes_canonical_phase_findings() {
	let f = fixture();
	let admin = admin(&f);
	f.offline.external_corruption(|conn| {
		conn.execute("INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,verification_required,created_at,report_identity) VALUES(1,1,?1,'review','high','Phase','Canonical evidence','canonical','validating',1,0,randomblob(16)),(2,1,?1,'legacy','high','Legacy','Legacy evidence','legacy','validating',1,0,randomblob(16))",[f.job])?;
		conn.execute_batch("INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(901,1,'scan','succeeded',0); UPDATE findings SET job_id=901 WHERE id=2;")?;
		conn.execute_batch("INSERT INTO finding_review_details(finding_id,repo_id,workflow_contract_version,profile_version,profile_digest,reviewed_commit_sha,identity_family,identity_anchor,identity_fingerprint,evidence_payload,submitted_rung,created_at) VALUES(1,1,2,1,zeroblob(32),'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','family','anchor',zeroblob(32),'{}','L2',0);")?;Ok(())
	}).unwrap();
	let (status, value) = admin_post(
		&f,
		&admin,
		"/v1/findings/retry-verify",
		json!({"protocol_version":3,"dry_run":false,"include_inconclusive":true}),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{value}");
	assert_eq!(value["matched"], 1, "legacy recovery must skip canonical phase findings");
	f.offline
		.external_corruption(|conn| {
			assert_eq!(
				conn.query_row("SELECT COUNT(*) FROM jobs WHERE target_finding_id=1", [], |r| r
					.get::<_, i64>(
					0
				))?,
				0
			);
			assert_eq!(
				conn.query_row("SELECT COUNT(*) FROM jobs WHERE target_finding_id=2", [], |r| r
					.get::<_, i64>(
					0
				))?,
				1
			);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn phase_failure_requeues_same_job_and_revokes_attempt_state() {
	let f = fixture();
	prepare(&f).await;
	v2(&f);
	let (status, value) = request(
		&f,
		f.job,
		"complete",
		json!({"protocol_version":3,"outcome":"failed","error":"host process failed"}),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{value}");
	assert_eq!(value["state"], "queued");
	f.offline.external_corruption(|conn| {let (state,cap,prepared,attempts):(String,Option<Vec<u8>>,Option<i64>,i64)=conn.query_row("SELECT state,job_capability_hash,prepared_attempt,attempts FROM jobs WHERE id=?1",[f.job],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;assert_eq!(state,"queued");assert!(cap.is_none()&&prepared.is_none());assert_eq!(attempts,1);Ok(())}).unwrap();
	assert_eq!(
		request(&f, f.job, "complete", json!({"protocol_version":3,"outcome":"failed"})).await.0,
		StatusCode::FORBIDDEN
	);
}

#[tokio::test]
async fn legacy_admin_recovery_does_not_downgrade_missing_phase_details() {
	let f = fixture();
	let admin = admin(&f);
	f.offline.external_corruption(|conn| {
		conn.execute_batch("INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(901,1,'scan','succeeded',0);")?;
		conn.execute("INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,verification_required,created_at,report_identity) VALUES(1,1,?1,'review','high','Phase','Retained canonical evidence','canonical','validating',1,0,randomblob(16)),(2,1,901,'legacy','high','Legacy','Legacy evidence','legacy','validating',1,0,randomblob(16))",[f.job])?;Ok(())
	}).unwrap();
	let (status, value) = admin_post(
		&f,
		&admin,
		"/v1/findings/retry-verify",
		json!({"protocol_version":3,"dry_run":false,"include_inconclusive":true}),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{value}");
	assert_eq!(value["matched"], 1, "missing phase details must not make canonical finding legacy");
	f.offline
		.external_corruption(|conn| {
			assert_eq!(
				conn.query_row("SELECT COUNT(*) FROM jobs WHERE target_finding_id=1", [], |r| r
					.get::<_, i64>(
					0
				))?,
				0
			);
			assert_eq!(
				conn.query_row("SELECT COUNT(*) FROM jobs WHERE target_finding_id=2", [], |r| r
					.get::<_, i64>(
					0
				))?,
				1
			);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn phase_heartbeat_clamps_to_live_report_grace_without_domain_authority() {
	let mut f = fixture();
	prepare(&f).await;
	v2(&f);
	let deadline = now() - 1;
	Arc::make_mut(&mut f.state.review_policy).lease_seconds = 200;
	Arc::make_mut(&mut f.state.review_policy).lease_report_grace_seconds = 30;
	f.offline
		.external_corruption(|conn| {
			conn.execute(
				"UPDATE jobs SET hard_deadline_at=?2 WHERE id=?1",
				params![f.job, deadline],
			)?;
			Ok(())
		})
		.unwrap();
	let (status, value) = request(&f, f.job, "heartbeat", json!({"protocol_version":3})).await;
	assert_eq!(status, StatusCode::OK, "{value}");
	assert_eq!(value["lease_expires_at"], deadline + 30);
	assert_eq!(
		request(&f, f.job, "publish-profile", json!({"protocol_version":3,"profile":{}})).await.0,
		StatusCode::FORBIDDEN
	);
}

async fn raw_control(
	f: &Fixture, job: i64, route: &str, body: Body, token: Option<&str>, peer: &PeerCert,
	encoding: Option<&str>,
) -> (StatusCode, Value) {
	let mut builder = Request::post(format!("/v1/jobs/{job}/{route}"))
		.header("content-type", "application/json")
		.header(PROTOCOL_VERSION_HEADER, "3");
	if let Some(token) = token {
		builder = builder.header(JOB_CAPABILITY_HEADER, token);
	}
	if let Some(encoding) = encoding {
		builder = builder.header("content-encoding", encoding);
	}
	let mut request = builder.body(body).unwrap();
	request.extensions_mut().insert(peer.clone());
	let response = router(f.state.clone()).call(request).await.unwrap();
	let status = response.status();
	assert_eq!(
		response.headers().get("cache-control").map(|value| value.as_bytes()),
		Some(b"no-store".as_slice()),
		"lifecycle rejection must be explicitly non-cacheable"
	);
	let bytes = to_bytes(response.into_body(), 8192).await.unwrap();
	if !status.is_success() {
		assert!(bytes.len() <= 4096);
	}
	(status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn failure_reporting_ignores_preparation_and_safely_blocks_invalid_payloads() {
	for case in ["unpinned", "cancelled", "deadline", "recipe", "profile", "policy"] {
		let f = fixture();
		if case != "unpinned" {
			prepare(&f).await;
		}
		v2(&f);
		f.offline.external_corruption(|conn| {
			match case {
				"cancelled"=>{conn.execute("UPDATE review_campaigns SET state='cancelled' WHERE campaign_id=?1",[f.campaign])?;},
				"deadline"=>{conn.execute("UPDATE review_campaigns SET deadline_at=?2 WHERE campaign_id=?1",params![f.campaign,now()-1])?;},
				"recipe"=>{conn.execute("UPDATE jobs SET recipe='not json' WHERE id=?1",[f.job])?;},
				"profile"=>{conn.execute("UPDATE review_generations SET generated_profile='not json' WHERE generation_id=(SELECT generation_id FROM jobs WHERE id=?1)",[f.job])?;},
				"policy"=>{conn.execute("UPDATE review_campaigns SET effective_policy='not json' WHERE campaign_id=?1",[f.campaign])?;},
				_=>{},
			};Ok(())
		}).unwrap();
		let (status, value) =
			request(&f, f.job, "complete", json!({"protocol_version":3,"outcome":"failed"})).await;
		assert_eq!(status, StatusCode::OK, "{case}: {value}");
		assert_eq!(value["state"], if case == "unpinned" { "queued" } else { "failed" }, "{case}");
	}
}

#[tokio::test]
async fn phase_control_rejects_success_checkout_override_duplicates_encoding_and_stream_overflow() {
	let f = fixture();
	v2(&f);
	for raw in [
		r#"{"protocol_version":3,"outcome":"succeeded"}"#,
		r#"{"protocol_version":3,"outcome":"failed","head_sha":null}"#,
		r#"{"protocol_version":3,"outcome":"failed","extra":true}"#,
		r#"{"protocol_version":3,"protocol_version":3,"outcome":"failed"}"#,
		r#"{"protocol_version":2,"outcome":"failed"}"#,
	] {
		assert_eq!(
			raw_control(&f, f.job, "complete", Body::from(raw), Some(&f.token), &f.peer, None)
				.await
				.0,
			StatusCode::BAD_REQUEST
		);
	}
	assert_eq!(
		raw_control(&f, f.job, "heartbeat", Body::empty(), Some(&f.token), &f.peer, None).await.0,
		StatusCode::BAD_REQUEST
	);
	assert_eq!(
		raw_control(
			&f,
			f.job,
			"complete",
			Body::from(r#"{"protocol_version":3,"outcome":"failed"}"#),
			Some(&f.token),
			&f.peer,
			Some("gzip")
		)
		.await
		.0,
		StatusCode::UNSUPPORTED_MEDIA_TYPE
	);
	let chunks = Chunks([axum::body::Bytes::from(" ".repeat(8193))].into());
	assert_eq!(
		raw_control(&f, f.job, "complete", Body::new(chunks), Some(&f.token), &f.peer, None)
			.await
			.0,
		StatusCode::PAYLOAD_TOO_LARGE
	);
	f.offline
		.external_corruption(|conn| {
			assert_eq!(
				conn.query_row("SELECT state FROM jobs WHERE id=?1", [f.job], |r| r
					.get::<_, String>(0))?,
				"leased"
			);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn unauthorized_control_has_no_job_existence_oracle_and_old_attempt_cannot_report() {
	let f = fixture();
	v2(&f);
	for route in ["heartbeat", "complete"] {
		let payload = if route == "heartbeat" {
			json!({"protocol_version":3})
		} else {
			json!({"protocol_version":3,"outcome":"failed"})
		}
		.to_string();
		let wrong = "b".repeat(43);
		let mut previous = None;
		for (job, token, peer) in [
			(f.job, Some(f.token.as_str()), &f.other_peer),
			(f.job, Some(wrong.as_str()), &f.peer),
			(999999, Some(f.token.as_str()), &f.peer),
			(f.job, None, &f.peer),
		] {
			let actual =
				raw_control(&f, job, route, Body::from(payload.clone()), token, peer, None).await;
			assert_eq!(actual.0, StatusCode::FORBIDDEN);
			if let Some(previous) = &previous {
				assert_eq!(&actual, previous);
			} else {
				previous = Some(actual);
			}
		}
	}
	assert_eq!(
		request(&f, f.job, "complete", json!({"protocol_version":3,"outcome":"failed"})).await.0,
		StatusCode::OK
	);
	f.offline.external_corruption(|conn| {conn.execute("UPDATE jobs SET state='leased',attempts=2,worker_id=?2,lease_expires_at=?3,hard_deadline_at=?3,job_capability_hash=?4 WHERE id=?1",params![f.job,f.worker,now()+3600,blake3::hash("b".repeat(43).as_bytes()).as_bytes().as_slice()])?;Ok(())}).unwrap();
	for route in ["complete", "heartbeat"] {
		assert_eq!(
			request(&f, f.job, route, json!({"protocol_version":3,"outcome":"failed"})).await.0,
			StatusCode::FORBIDDEN
		);
	}
}

#[tokio::test]
async fn admin_cancellation_missing_ids_preserve_not_found() {
	let f = fixture();
	let admin = admin(&f);
	let mut outcomes = Vec::new();
	for job in [999999, 0, -1] {
		outcomes.push(raw_control(&f, job, "cancel", Body::empty(), None, &admin, None).await);
	}
	f.offline
		.external_corruption(|conn| {
			assert!(conn.query_row(
				"SELECT state='leased' AND job_capability_hash IS NOT NULL FROM jobs WHERE id=?1",
				[f.job],
				|r| r.get::<_, bool>(0)
			)?);
			Ok(())
		})
		.unwrap();
	assert_eq!(
		outcomes.iter().map(|(status, _)| *status).collect::<Vec<_>>(),
		vec![StatusCode::NOT_FOUND; 3],
		"authenticated missing positive/zero/negative job IDs must all remain 404"
	);
	for (_, value) in outcomes {
		assert_eq!(value["error"]["code"], "not_found");
		assert_eq!(value["error"]["detail"], Value::Null);
	}
}

#[tokio::test]
async fn admin_cancellation_keeps_existing_nonpositive_legacy_jobs() {
	let f = fixture();
	let admin = admin(&f);
	f.offline.external_corruption(|conn| {
		for job in [901, 0, -1] {
			conn.execute("INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(?1,1,'scan','queued',0)", [job])?;
		}
		Ok(())
	}).unwrap();
	let mut outcomes = Vec::new();
	for job in [901, 0, -1] {
		outcomes.push(admin_post(&f, &admin, &format!("/v1/jobs/{job}/cancel"), json!({})).await);
	}
	assert_eq!(
		outcomes.iter().map(|(status, _)| *status).collect::<Vec<_>>(),
		vec![StatusCode::OK; 3],
		"existing positive/zero/negative legacy jobs must keep legacy cancellation"
	);
	for ((_, value), job) in outcomes.into_iter().zip([901, 0, -1]) {
		assert_eq!(value["job_id"], job);
		assert_eq!(value["state"], "cancelled");
	}
	f.offline
		.external_corruption(|conn| {
			assert_eq!(
				conn.query_row(
					"SELECT COUNT(*) FROM jobs WHERE id IN(901,0,-1) AND state='cancelled'",
					[],
					|r| r.get::<_, i64>(0)
				)?,
				3
			);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn admin_cancellation_keeps_actor_sql_and_phase_controls() {
	let f = fixture();
	let admin = admin(&f);
	let (status, value) =
		raw_control(&f, f.job, "cancel", Body::empty(), None, &f.peer, None).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	assert_eq!(value["error"]["code"], "denied");
	assert_eq!(value["error"]["detail"], Value::Null);
	f.offline.external_corruption(|conn| {
		conn.execute_batch("CREATE TRIGGER cancel_sql_failure BEFORE UPDATE OF state ON jobs BEGIN SELECT RAISE(ABORT,'private cancel sentinel'); END;")?;
		Ok(())
	}).unwrap();
	let (status, value) = raw_control(&f, f.job, "cancel", Body::empty(), None, &admin, None).await;
	assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
	assert_eq!(value["error"]["code"], "internal_error");
	assert_eq!(value["error"]["detail"], Value::Null);
	assert!(!value.to_string().contains("private cancel sentinel"));
	f.offline
		.external_corruption(|conn| {
			assert!(conn.query_row(
				"SELECT state='leased' AND job_capability_hash IS NOT NULL FROM jobs WHERE id=?1",
				[f.job],
				|r| r.get::<_, bool>(0)
			)?);
			conn.execute_batch("DROP TRIGGER cancel_sql_failure;")?;
			Ok(())
		})
		.unwrap();
	let (status, value) = raw_control(&f, f.job, "cancel", Body::empty(), None, &admin, None).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(value["job_id"], f.job);
	assert_eq!(value["state"], "cancelled");
}

#[tokio::test]
async fn admin_cancellation_nonpositive_phase_rolls_back_job_and_assigned_work() {
	let f = fixture();
	prepare(&f).await;
	let admin = admin(&f);
	f.offline.external_corruption(|conn| {
		for (job, unit) in [(0, 100), (-1, 101)] {
			conn.execute("INSERT INTO jobs(id,repo_id,kind,state,enqueued_at,campaign_id,generation_id) SELECT ?1,repo_id,'survey','queued',0,campaign_id,generation_id FROM jobs WHERE id=?2", params![job,f.job])?;
			conn.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,assignment_epoch,created_by_job_id,created_at) SELECT ?1,generation_id,?2,'Unexamined','Unfinished work','[]',1,?3,0 FROM jobs WHERE id=?3", params![unit,format!("nonpositive-{unit}"),job])?;
			conn.execute("INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(?1,?2,0,1)", params![job,unit])?;
		}
		Ok(())
	}).unwrap();
	let mut outcomes = Vec::new();
	for job in [0, -1] {
		outcomes.push(raw_control(&f, job, "cancel", Body::empty(), None, &admin, None).await);
	}
	f.offline.external_corruption(|conn| {
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM jobs WHERE id IN(0,-1) AND state='queued' AND finished_at IS NULL AND error IS NULL", [], |r| r.get::<_, i64>(0))?, 2);
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM review_units WHERE review_unit_id IN(100,101) AND status='open' AND defer_reason IS NULL", [], |r| r.get::<_, i64>(0))?, 2);
		assert_eq!(conn.query_row("SELECT COUNT(*) FROM job_assigned_review_units WHERE job_id IN(0,-1)", [], |r| r.get::<_, i64>(0))?, 2);
		Ok(())
	}).unwrap();
	assert_eq!(
		outcomes.iter().map(|(status, _)| *status).collect::<Vec<_>>(),
		vec![StatusCode::CONFLICT; 2]
	);
	for (_, value) in outcomes {
		assert_eq!(value["error"]["code"], "state_conflict");
		assert_eq!(value["error"]["detail"], Value::Null);
	}
}

#[tokio::test]
async fn admin_cancellation_bypasses_malformed_payload_and_refuses_legacy_retry() {
	let f = fixture();
	prepare(&f).await;
	v2(&f);
	let admin = admin(&f);
	f.offline
		.external_corruption(|conn| {
			conn.execute("UPDATE jobs SET recipe='not json' WHERE id=?1", [f.job])?;
			Ok(())
		})
		.unwrap();
	let (status, value) =
		admin_post(&f, &admin, &format!("/v1/jobs/{}/cancel", f.job), json!({})).await;
	assert_eq!(status, StatusCode::OK, "{value}");
	assert_eq!(value["state"], "cancelled");
	assert_eq!(
		request(&f, f.job, "heartbeat", json!({"protocol_version":3})).await.0,
		StatusCode::FORBIDDEN
	);
	f.offline
		.external_corruption(|conn| {
			let (cap, prepared): (Option<Vec<u8>>, Option<i64>) = conn.query_row(
				"SELECT job_capability_hash,prepared_attempt FROM jobs WHERE id=?1",
				[f.job],
				|r| Ok((r.get(0)?, r.get(1)?)),
			)?;
			assert!(cap.is_none() && prepared.is_none());
			conn.execute("UPDATE jobs SET state='failed' WHERE id=?1", [f.job])?;
			Ok(())
		})
		.unwrap();
	assert_eq!(
		admin_post(&f, &admin, &format!("/v1/jobs/{}/retry", f.job), json!({})).await.0,
		StatusCode::CONFLICT
	);
}

#[tokio::test]
async fn legacy_empty_heartbeat_and_successful_completion_are_unchanged() {
	let f = fixture();
	f.offline
		.external_corruption(|conn| {
			// Convert the fixture into a genuinely campaign-less legacy job.
			conn.execute("DELETE FROM job_admission_charges WHERE job_id=?1", [f.job])?;
			conn.execute("UPDATE jobs SET campaign_id=NULL,kind='scan' WHERE id=?1", [f.job])?;
			Ok(())
		})
		.unwrap();
	let mut heartbeat = Request::post(format!("/v1/jobs/{}/heartbeat", f.job))
		.header(JOB_CAPABILITY_HEADER, &f.token)
		.body(Body::empty())
		.unwrap();
	heartbeat.extensions_mut().insert(f.peer.clone());
	let (status, value) = response(&f, heartbeat).await;
	assert_eq!(status, StatusCode::OK, "{value}");
	assert_eq!(value["protocol_version"], 3);
	let (status, value) = request(
		&f,
		f.job,
		"complete",
		json!({"protocol_version":3,"outcome":"succeeded","head_sha":SHA}),
	)
	.await;
	assert_eq!(status, StatusCode::NO_CONTENT, "{value}");
}

#[tokio::test]
async fn exhausted_verification_keeps_canonical_evidence_and_blocks_only_admitted_work() {
	let f = fixture();
	prepare(&f).await;
	v2(&f);
	f.offline.external_corruption(|conn| {
		conn.execute("INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,verification_required,created_at,report_identity) VALUES(1,1,?1,'review','high','Canonical','Evidence must survive','canonical','validating',1,0,randomblob(16))",[f.job])?;
		conn.execute("INSERT INTO finding_review_details(finding_id,repo_id,workflow_contract_version,profile_version,profile_digest,reviewed_commit_sha,identity_family,identity_anchor,identity_fingerprint,evidence_payload,submitted_rung,created_at) SELECT 1,1,2,1,generated_profile_digest,generation_commit_sha,'family','anchor',zeroblob(32),'malformed historical prose','L2',0 FROM review_generations WHERE generation_id=(SELECT generation_id FROM jobs WHERE id=?1)",[f.job])?;
		conn.execute("INSERT INTO finding_verification_intents(finding_id,repo_id,generation_id,originating_job_id,originating_campaign_id,admission_campaign_id,source_commit_sha,profile_version,profile_digest,intent_revision,intent_kind,logical_sequence,state,admitted_job_id,accepted_band,accepted_score,priority_policy_version,created_at,updated_at) SELECT 1,1,generation_id,?1,?2,?2,generation_commit_sha,1,generated_profile_digest,1,'initial_handoff',0,'admitted',?1,'normal',0,1,0,0 FROM review_generations WHERE generation_id=(SELECT generation_id FROM jobs WHERE id=?1)",params![f.job,f.campaign])?;
		conn.execute("UPDATE jobs SET kind='verify',target_finding_id=1,attempts=3,recipe='malformed historical recipe' WHERE id=?1",[f.job])?;
		Ok(())
	}).unwrap();
	let (status, value) =
		request(&f, f.job, "complete", json!({"protocol_version":3,"outcome":"failed"})).await;
	assert_eq!(status, StatusCode::OK, "{value}");
	assert_eq!(value["state"], "failed");
	f.offline
		.external_corruption(|conn| {
			assert_eq!(
				conn.query_row("SELECT state FROM findings WHERE id=1", [], |r| r
					.get::<_, String>(0))?,
				"validating"
			);
			assert_eq!(
				conn.query_row(
					"SELECT evidence_payload FROM finding_review_details WHERE finding_id=1",
					[],
					|r| r.get::<_, String>(0)
				)?,
				"malformed historical prose"
			);
			assert_eq!(
				conn.query_row(
					"SELECT block_reason FROM finding_verification_intents WHERE finding_id=1",
					[],
					|r| r.get::<_, String>(0)
				)?,
				"compatibility_policy"
			);
			assert_eq!(
				conn.query_row("SELECT COUNT(*) FROM finding_verifications", [], |r| r
					.get::<_, i64>(0))?,
				0
			);
			Ok(())
		})
		.unwrap();
}

#[tokio::test]
async fn failure_and_assigned_work_blocking_roll_back_together() {
	let f = fixture();
	prepare(&f).await;
	v2(&f);
	f.offline.external_corruption(|conn| {
		conn.execute("UPDATE jobs SET attempts=3 WHERE id=?1",[f.job])?;
		conn.execute("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,assignment_epoch,created_by_job_id,created_at) SELECT 1,generation_id,'unexamined','Unexamined','Unfinished work','[]',1,?1,0 FROM jobs WHERE id=?1",[f.job])?;
		conn.execute("INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(?1,1,0,1)",[f.job])?;
		conn.execute_batch("CREATE TRIGGER fail_defer BEFORE UPDATE OF status ON review_units BEGIN SELECT RAISE(ABORT,'injected unit failure'); END;")?;Ok(())
	}).unwrap();
	assert_eq!(
		request(&f, f.job, "complete", json!({"protocol_version":3,"outcome":"failed"})).await.0,
		StatusCode::INTERNAL_SERVER_ERROR
	);
	f.offline.external_corruption(|conn| {
		assert_eq!(conn.query_row("SELECT state FROM jobs WHERE id=?1",[f.job],|r|r.get::<_,String>(0))?,"leased");
		assert_eq!(conn.query_row("SELECT status FROM review_units WHERE review_unit_id=1",[],|r|r.get::<_,String>(0))?,"open");
		assert!(conn.query_row("SELECT job_capability_hash IS NOT NULL AND prepared_attempt IS NOT NULL FROM jobs WHERE id=?1",[f.job],|r|r.get::<_,bool>(0))?);Ok(())
	}).unwrap();
}
