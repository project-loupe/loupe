//! Actual router/mTLS calls with explicit fixture leases. No request gets a
//! database mutation or authority bypass.
use loupe_storage::review_units;

use super::*;

const ROUTE: &str = "inventory-dispositions";
fn payload(key: &str, path: &str, revision: i64, disposition: &str) -> Value {
	let mut value = json!({"protocol_version":3,"client_inventory_disposition_key":key,"source_path":path,"expected_revision":revision,"disposition":disposition,"mappings":[]});
	if matches!(disposition, "context" | "excluded") {
		value["reason"] = json!("reviewed scope decision");
	}
	value
}
fn mapped(key: &str, path: &str, revision: i64, unit: i64, epoch: i64) -> Value {
	let mut value = payload(key, path, revision, "mapped");
	value["mappings"] = json!([{"review_unit_id":unit,"assignment_epoch":epoch}]);
	value
}
fn unit(f: &Fixture, generation: i64, path: &str, key: &str) -> i64 {
	f.offline.external_corruption(|conn| {
		conn.execute("INSERT INTO review_units(generation_id,client_review_unit_key,title,objective,source_refs,created_by_job_id,created_at) VALUES(?1,?2,'Review','Review source',?3,?4,0)",params![generation,key,json!([{"path":path}]).to_string(),f.job])?;
		Ok(conn.last_insert_rowid())
	}).unwrap()
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
fn count(f: &Fixture) -> i64 {
	f.offline.external_corruption(|conn| Ok(conn.query_row(
  "SELECT COUNT(*) FROM job_checkpoints WHERE job_id=?1 AND operation='submit_inventory_disposition'",
  [f.job], |row| row.get(0))?)).unwrap()
}
fn fill_quota(
	conn: &rusqlite::Connection, job: i64, prefix: &str, digest: &[u8; 32],
) -> loupe_storage::Result<()> {
	for i in 1..4096 {
		conn.execute("INSERT INTO job_checkpoints(job_id,client_key,operation,payload_digest,response,created_at) VALUES(?1,?2,'submit_inventory_disposition',?3,'{}',?4)",
   params![job,format!("submit_inventory_disposition:{prefix}-{i}"),digest.as_slice(),now()])?;
	}
	Ok(())
}
fn entry(f: &Fixture, path: &str) -> (String, i64, Vec<i64>) {
	f.offline.external_corruption(|conn| {
		let (id,disposition,revision):(i64,String,i64)=conn.query_row("SELECT inventory_entry_id,disposition,disposition_revision FROM generation_inventory WHERE source_path=?1",[path],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
		let mapped=conn.prepare("SELECT review_unit_id FROM generation_inventory_units WHERE inventory_entry_id=?1 ORDER BY review_unit_id")?.query_map([id],|r|r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
		Ok((disposition,revision,mapped))
	}).unwrap()
}

#[tokio::test]
async fn independent_entries_cas_and_deliberate_mapping_replacement_preserve_progress() {
	let f = fixture();
	let generation = prepare(&f).await;
	let a = unit(&f, generation, "a%FF", "a");
	let b = unit(&f, generation, "z.rs", "b");
	let first = post(&f, ROUTE, mapped("a0", "a%FF", 0, a, 0)).await;
	assert_eq!(first["revision"], 1);
	post(&f, ROUTE, mapped("b0", "z.rs", 0, b, 0)).await;
	let (status, conflict) =
		request(&f, f.job, ROUTE, payload("a-stale", "a%FF", 0, "context")).await;
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(conflict["error"]["code"], "inventory_revision_conflict");
	assert_eq!(conflict["error"]["current_revision"], 1);
	assert_eq!(entry(&f, "z.rs"), ("mapped".into(), 1, vec![b]));
	assert_eq!(entry(&f, "a%FF"), ("mapped".into(), 1, vec![a]));
	assert_eq!(count(&f), 2, "stale writes consume neither revision nor quota");
	let next = post(&f, ROUTE, payload("a1", "a%FF", 1, "context")).await;
	assert_eq!(next["inventory_entry_id"], first["inventory_entry_id"]);
	assert_eq!(entry(&f, "a%FF"), ("context".into(), 2, vec![]));
	let a2 = unit(&f, generation, "a%FF", "a2");
	post(&f, ROUTE, mapped("a2", "a%FF", 2, a2, 0)).await;
	assert_eq!(entry(&f, "a%FF"), ("mapped".into(), 3, vec![a2]));
}

#[tokio::test]
async fn exact_replay_precedes_changed_scope_epoch_cas_and_quota() {
	let f = fixture();
	let generation = prepare(&f).await;
	let u = unit(&f, generation, "z.rs", "own");
	ordinary(&f, generation, &[u]);
	let original = mapped("mapped", "z.rs", 0, u, 1);
	let accepted = post(&f, ROUTE, original.clone()).await;
	f.offline.external_corruption(|tx| {
		tx.execute("DELETE FROM job_assigned_review_units WHERE job_id=?1",[f.job])?;
		tx.execute("UPDATE review_units SET assignment_epoch=2,status='retired',source_refs='[]' WHERE review_unit_id=?1",[u])?;
		fill_quota(tx, f.job, "quota", &[7;32])?;
		tx.execute("UPDATE jobs SET attempts=attempts+1,prepared_attempt=attempts+1 WHERE id=?1",[f.job])?;
		Ok(())
	}).unwrap();
	assert_eq!(post(&f, ROUTE, original.clone()).await, accepted);
	assert_eq!(count(&f), 4096);
	let mut divergent = original;
	divergent["expected_revision"] = json!(1);
	let (status, value) = request(&f, f.job, ROUTE, divergent).await;
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(value["error"]["code"], "checkpoint_conflict");
	assert_eq!(entry(&f, "z.rs"), ("mapped".into(), 1, vec![u]));
}

#[tokio::test]
async fn every_variant_checks_entry_scope_before_revision_or_mapping_authority() {
	let f = fixture();
	let generation = prepare(&f).await;
	let u = unit(&f, generation, "z.rs", "own");
	ordinary(&f, generation, &[u]);
	for disposition in ["mapped", "context", "excluded", "unresolved"] {
		let mut outside = payload(disposition, "a%FF", 999, disposition);
		if disposition == "mapped" {
			outside["mappings"] = json!([{"review_unit_id":999999,"assignment_epoch":100}]);
		}
		let mut missing = outside.clone();
		missing["source_path"] = json!("unknown.rs");
		let denied = request(&f, f.job, ROUTE, outside).await;
		assert_eq!(denied.0, StatusCode::FORBIDDEN, "{disposition}");
		assert_eq!(denied, request(&f, f.job, ROUTE, missing).await);
		assert!(denied.1["error"].get("current_revision").is_none());
	}
	assert_eq!(count(&f), 0);
	assert_eq!(entry(&f, "a%FF").1, 0);
	let (status, conflict) =
		request(&f, f.job, ROUTE, mapped("own-stale", "z.rs", 1, 999999, 100)).await;
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(conflict["error"]["current_revision"], 0);
}

#[tokio::test]
async fn mapping_provenance_and_checkpoint_failure_roll_back_all_writes() {
	let f = fixture();
	let generation = prepare(&f).await;
	let a = unit(&f, generation, "a%FF", "a");
	let b = unit(&f, generation, "z.rs", "b");
	post(&f, ROUTE, mapped("initial", "a%FF", 0, a, 0)).await;
	let mut wrongpath = mapped("bad-map", "a%FF", 1, a, 0);
	wrongpath["mappings"]
		.as_array_mut()
		.unwrap()
		.push(json!({"review_unit_id":b,"assignment_epoch":0}));
	assert_eq!(request(&f, f.job, ROUTE, wrongpath).await.0, StatusCode::CONFLICT);
	assert_eq!(entry(&f, "a%FF"), ("mapped".into(), 1, vec![a]));
	assert_eq!(count(&f), 1);
	assert_eq!(
		request(&f, f.job, ROUTE, mapped("bad-epoch", "a%FF", 1, a, 1)).await.0,
		StatusCode::FORBIDDEN
	);
	f.offline.external_corruption(|conn| {
		conn.execute_batch("CREATE TRIGGER fail_inventory_checkpoint BEFORE INSERT ON job_checkpoints WHEN NEW.operation='submit_inventory_disposition' BEGIN SELECT RAISE(ABORT,'injected persistence failure'); END;")?;
		Ok(())
	}).unwrap();
	assert_eq!(
		request(&f, f.job, ROUTE, payload("failure", "a%FF", 1, "excluded")).await.0,
		StatusCode::INTERNAL_SERVER_ERROR
	);
	assert_eq!(entry(&f, "a%FF"), ("mapped".into(), 1, vec![a]));
	assert_eq!(count(&f), 1);
}

#[tokio::test]
async fn fresh_quota_survives_execution_retries_but_replay_is_free() {
	let f = fixture();
	prepare(&f).await;
	let original = payload("accepted", "z.rs", 0, "context");
	let response = post(&f, ROUTE, original.clone()).await;
	f.offline
		.external_corruption(|conn| {
			fill_quota(conn, f.job, "used", &[8; 32])?;
			conn.execute("UPDATE jobs SET attempts=2,prepared_attempt=2 WHERE id=?1", [f.job])?;
			Ok(())
		})
		.unwrap();
	let (status, value) =
		request(&f, f.job, ROUTE, payload("fresh", "z.rs", 1, "unresolved")).await;
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(value["error"]["code"], "checkpoint_limit");
	assert_eq!(post(&f, ROUTE, original).await, response);
	assert_eq!(entry(&f, "z.rs").1, 1);
	assert_eq!(count(&f), 4096);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_same_entry_updates_admit_one_revision_and_one_receipt() {
	let f = Arc::new(fixture());
	prepare(&f).await;
	let mut tasks = Vec::new();
	for (key, disposition) in [("one", "context"), ("two", "excluded")] {
		let f = Arc::clone(&f);
		tasks.push(tokio::spawn(async move {
			request(&f, f.job, ROUTE, payload(key, "z.rs", 0, disposition)).await
		}));
	}
	let mut statuses = Vec::new();
	for task in tasks {
		statuses.push(task.await.unwrap().0);
	}
	assert_eq!(statuses.iter().filter(|s| **s == StatusCode::OK).count(), 1);
	assert_eq!(statuses.iter().filter(|s| **s == StatusCode::CONFLICT).count(), 1);
	assert_eq!(entry(&f, "z.rs").1, 1);
	assert_eq!(count(&f), 1);
}

#[tokio::test]
async fn encrypted_reopen_replays_receipt_without_reapplying_revision() {
	let mut f = fixture();
	prepare(&f).await;
	let submission = payload("persistent", "z.rs", 0, "context");
	let expected = post(&f, ROUTE, submission.clone()).await;
	let old = std::mem::replace(
		&mut f.state.db,
		Arc::new(
			loupe_storage::Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests())
				.unwrap(),
		),
	);
	drop(old);
	f.offline.edit(|_| Ok(()));
	f.state.db = f.offline.open();
	assert_eq!(post(&f, ROUTE, submission).await, expected);
	assert_eq!(count(&f), 1);
	assert_eq!(entry(&f, "z.rs").1, 1);
}

#[tokio::test]
async fn exact_raw_source_paths_remain_distinct_and_unrepresentable_entries_host_owned() {
	let f = fixture();
	post(&f, "pin-target", json!({"protocol_version":3,"commit_sha":SHA})).await;
	let mut entries = vec![
		"é.rs".as_bytes().to_vec(),
		"e\u{301}.rs".as_bytes().to_vec(),
		b"a%FF".to_vec(),
		vec![b'a', 255],
	];
	entries.sort();
	let entries = entries
		.into_iter()
		.map(|raw_path| ManifestEntry { raw_path, git_mode: 0o100644, object_id: [0xaa; 20] })
		.collect::<Vec<_>>();
	post(&f, "inventory-batches", chunk(&entries, 0, entries.len())).await;
	post(&f, "seal-inventory", json!({"protocol_version":3})).await;
	post(&f, "publish-profile", json!({"protocol_version":3,"profile":{}})).await;
	let nfc = post(&f, ROUTE, payload("nfc", "é.rs", 0, "context")).await;
	let nfd = post(&f, ROUTE, payload("nfd", "e\u{301}.rs", 0, "excluded")).await;
	assert_ne!(nfc["inventory_entry_id"], nfd["inventory_entry_id"]);
	post(&f, ROUTE, payload("literal", "a%FF", 0, "context")).await;
	f.offline.external_corruption(|conn| {
		let raw:(String,i64)=conn.query_row("SELECT disposition,disposition_revision FROM generation_inventory WHERE raw_path=?1",[vec![b'a',255]],|r|Ok((r.get(0)?,r.get(1)?)))?;
		assert_eq!(raw,("excluded".into(),0));
		Ok(())
	}).unwrap();
	let (status, value) =
		request(&f, f.job, ROUTE, payload("nfc", "e\u{301}.rs", 0, "context")).await;
	assert_eq!(status, StatusCode::CONFLICT, "{value}");
	assert_eq!(value["error"]["code"], "checkpoint_conflict");
}

#[tokio::test]
async fn authority_denies_wrong_worker_token_phase_deadline_and_unprepared_attempt() {
	let f = fixture();
	prepare(&f).await;
	let body = payload("auth", "z.rs", 0, "context");
	for (peer, token) in [(&f.other_peer, f.token.clone()), (&f.peer, "b".repeat(43))] {
		let mut req = Request::post(format!("/v1/jobs/{}/{ROUTE}", f.job))
			.header(PROTOCOL_VERSION_HEADER, "3")
			.header(JOB_CAPABILITY_HEADER, token)
			.header("content-type", "application/json")
			.body(Body::from(body.to_string()))
			.unwrap();
		req.extensions_mut().insert(peer.clone());
		assert_eq!(response(&f, req).await.0, StatusCode::FORBIDDEN);
	}
	for sql in [
		"UPDATE jobs SET prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id=?1",
		"UPDATE jobs SET hard_deadline_at=0 WHERE id=?1",
		"UPDATE jobs SET kind='verify' WHERE id=?1",
		"UPDATE jobs SET lease_expires_at=0 WHERE id=?1",
		"UPDATE review_campaigns SET deadline_at=0 WHERE campaign_id=(SELECT campaign_id FROM jobs WHERE id=?1)",
		"UPDATE generation_manifests SET sealed_at=NULL WHERE generation_id=(SELECT generation_id FROM jobs WHERE id=?1)",
		"UPDATE jobs SET recipe='{\"version\":1,\"phase\":\"survey\",\"recipe\":\"corroboration\",\"assignment_key\":\"ordinary\"}' WHERE id=?1",
	] {
		let f=fixture();prepare(&f).await;
		f.offline.external_corruption(|conn| {conn.execute(sql,[f.job])?;Ok(())}).unwrap();
		assert_eq!(request(&f,f.job,ROUTE,body.clone()).await.0,StatusCode::FORBIDDEN,"{sql}");
		assert_eq!(count(&f),0);
	}
	assert_eq!(count(&f), 0);
}

#[tokio::test]
async fn transport_checks_actual_bytes_strict_shape_and_no_store() {
	let f = fixture();
	prepare(&f).await;
	let body = payload("wire", "z.rs", 0, "context").to_string();
	for (raw, encoding, status) in [
		(" ".repeat(8193) + &body, None, StatusCode::PAYLOAD_TOO_LARGE),
		(body.clone(), Some("gzip"), StatusCode::UNSUPPORTED_MEDIA_TYPE),
		(
			body.replace(
				"\"expected_revision\":0",
				"\"expected_revision\":0,\"expected_revision\":0",
			),
			None,
			StatusCode::BAD_REQUEST,
		),
		(
			body.replace("\"protocol_version\":3", "\"protocol_version\":3,\"repo_id\":1"),
			None,
			StatusCode::BAD_REQUEST,
		),
	] {
		let mut req = Request::post(format!("/v1/jobs/{}/{ROUTE}", f.job))
			.header(PROTOCOL_VERSION_HEADER, "3")
			.header(JOB_CAPABILITY_HEADER, &f.token)
			.header("content-type", "application/json");
		if let Some(encoding) = encoding {
			req = req.header("content-encoding", encoding);
		}
		let mut req = req.body(Body::from(raw)).unwrap();
		req.extensions_mut().insert(f.peer.clone());
		let response = router(f.state.clone()).call(req).await.unwrap();
		assert_eq!(response.status(), status);
		assert_eq!(response.headers()["cache-control"], "no-store");
		let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
		assert!(serde_json::from_slice::<Value>(&bytes).unwrap()["error"].is_object());
	}
	assert_eq!(count(&f), 0);
	let mut req = Request::post(format!("/v1/jobs/{}/{ROUTE}", f.job))
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header(JOB_CAPABILITY_HEADER, &f.token)
		.header("content-type", "application/json")
		.body(Body::from(" ".repeat(8192 - body.len()) + &body))
		.unwrap();
	req.extensions_mut().insert(f.peer.clone());
	let response = router(f.state.clone()).call(req).await.unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(response.headers()["cache-control"], "no-store");
	assert!(to_bytes(response.into_body(), 8192).await.is_ok());
}

#[tokio::test]
async fn own_completed_results_and_follow_up_holds_remain_mappable_references() {
	for (follow_up, is_ordinary) in [(false, false), (false, true), (true, false), (true, true)] {
		let f = fixture();
		let generation = prepare(&f).await;
		let u = unit(&f, generation, "z.rs", "own");
		let unassigned = unit(&f, generation, "z.rs", "unassigned");
		let epoch = if is_ordinary {
			ordinary(&f, generation, &[u]);
			1
		} else {
			0
		};
		f.offline.external_corruption(|tx| {
			tx.execute("UPDATE review_units SET created_by_job_id=NULL WHERE review_unit_id=?1",[unassigned])?;
			tx.execute("INSERT INTO review_unit_results(review_unit_id,produced_by_job_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,created_at) VALUES(?1,?2,?3,1,?4,'[{\"path\":\"z.rs\"}]','{}',zeroblob(32),0)",params![u,f.job,SHA,if follow_up {"needs_follow_up"}else{"no_lead_found"}])?;
			let result=tx.last_insert_rowid();
			tx.execute("UPDATE job_assigned_review_units SET completed=1 WHERE job_id=?1 AND review_unit_id=?2",params![f.job,u])?;
			if follow_up {
				tx.execute("INSERT INTO review_unit_holds(review_unit_id,generation_id,producing_job_id,producing_result_id,source_assignment_epoch,continuation_class,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,'source_analysis_remaining',0,0)",params![u,generation,f.job,result,epoch])?;
			}
			Ok(())
		}).unwrap();
		let (status, response) =
			request(&f, f.job, ROUTE, mapped("after-result", "z.rs", 0, u, epoch)).await;
		assert_eq!(
			status,
			StatusCode::OK,
			"a completed own result remains a mapping reference; follow_up={follow_up}: {response}"
		);
		assert_eq!(entry(&f, "z.rs"), ("mapped".into(), 1, vec![u]));
		assert_eq!(
			request(&f, f.job, ROUTE, mapped("wrong-owner", "z.rs", 1, unassigned, 0)).await.0,
			StatusCode::FORBIDDEN
		);
		assert_eq!(
			request(&f, f.job, ROUTE, mapped("stale-epoch", "z.rs", 1, u, epoch + 1)).await.0,
			StatusCode::FORBIDDEN
		);
		assert_eq!(count(&f), 1);
	}
}

#[tokio::test]
async fn stream_and_outer_auth_extractor_failures_stay_bounded_without_mutation() {
	let f = fixture();
	prepare(&f).await;
	let chunks = Chunks(
		[
			axum::body::Bytes::from_static(b"{\"protocol_version\":3,\"reason\":\""),
			axum::body::Bytes::from("界".repeat(3000)),
			axum::body::Bytes::from_static(b"\"}"),
		]
		.into(),
	);
	let mut req = Request::post(format!("/v1/jobs/{}/{ROUTE}", f.job))
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header(JOB_CAPABILITY_HEADER, &f.token)
		.header("content-type", "application/json")
		.body(Body::new(chunks))
		.unwrap();
	req.extensions_mut().insert(f.peer.clone());
	assert_eq!(response(&f, req).await.0, StatusCode::PAYLOAD_TOO_LARGE);
	for (job, peer, status) in [
		(f.job.to_string(), None, StatusCode::UNAUTHORIZED),
		("x".repeat(2000), Some(f.peer.clone()), StatusCode::BAD_REQUEST),
	] {
		let mut req = Request::post(format!("/v1/jobs/{job}/{ROUTE}"))
			.header(PROTOCOL_VERSION_HEADER, "3")
			.header(JOB_CAPABILITY_HEADER, &f.token)
			.header("content-type", "application/json")
			.body(Body::empty())
			.unwrap();
		if let Some(peer) = peer {
			req.extensions_mut().insert(peer);
		}
		let response = router(f.state.clone()).call(req).await.unwrap();
		assert_eq!(response.status(), status);
		assert_eq!(response.headers()["cache-control"], "no-store");
		let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
		assert!(serde_json::from_slice::<Value>(&bytes).unwrap()["error"].is_object());
	}
	assert_eq!(count(&f), 0);
	assert_eq!(entry(&f, "z.rs").1, 0);
}
