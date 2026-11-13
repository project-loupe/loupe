//! Direct leased-authority fixtures; real-router flows live in review_public.rs.
//! SQL here edits only an independently owned encrypted test database. Runtime
//! authority is obtained through the real authentication middleware and storage
//! facade, never a public SQL connection or a worker-as-operator adapter.
use std::sync::Arc;

use axum::body::Body;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{middleware, Extension, Router};
use loupe_core::review_payload::{SurveyTerminalReason, SurveyTerminalV1};
use loupe_storage::terminal_payloads::TerminalPayload;
use loupe_storage::{terminal_receipt, Db};
use rusqlite::params;
use tower::ServiceExt;

use super::*;

const NOW: i64 = 100;
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn response_overflow_and_callback_error_roll_back_preparation() {
	use crate::review::http::{self, ApiError};
	for fail_callback in [false, true] {
		let f = fixture();
		let now =
			std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
				as i64;
		f.database
			.external_corruption(|conn| {
				let policy=serde_json::to_string(&loupe_storage::scheduler::CampaignPolicy::default()).unwrap();
				conn.execute("UPDATE review_campaigns SET effective_policy=?1",[policy])?;
				conn.execute(
					"UPDATE jobs SET lease_expires_at=?1,hard_deadline_at=?1,prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id=101",
					[now + 1000],
				)?;
				conn.execute("UPDATE review_campaigns SET deadline_at=?1", [now + 1000])?;
				Ok(())
			})
			.unwrap();
		let raw = serde_json::json!({"protocol_version":3,"commit_sha":SHA}).to_string();
		let body = crate::test_support::worker_body(raw.as_bytes());
		let request =
			body.0.as_bytes().validate(loupe_proto::review_api::PinTargetRequestDecoder).unwrap();
		let result = http::transaction(&f.db, &f.worker, &f.headers, 101, 4, |tx| {
			assert!(matches!(
				tx.pin_target(&request.commit_sha, &[1; 32], policy)
					.expect("fixture pin must succeed before the injected response failure"),
				loupe_storage::host_preparation::PinOutcome::Prepared(_)
			));
			if fail_callback {
				return Err(ApiError::conflict("injected"));
			}
			Ok("too large")
		});
		assert!(result.is_err());
		f.database
			.external_corruption(|conn| {
				assert_eq!(
					conn.query_row("SELECT prepared_at FROM jobs WHERE id=101", [], |row| row
						.get::<_, Option<
						i64,
					>>(
						0
					))?,
					None,
					"failed response must roll back preparation"
				);
				assert_eq!(
					conn.query_row(
						"SELECT COUNT(*) FROM job_checkpoints WHERE job_id=101",
						[],
						|row| row.get::<_, i64>(0)
					)?,
					0,
					"failed response must roll back assignments"
				);
				Ok(())
			})
			.unwrap();
		http::transaction(&f.db, &f.worker, &f.headers, 101, 100, |tx| {
			assert!(matches!(
				tx.pin_target(&request.commit_sha, &[1; 32], policy)?,
				loupe_storage::host_preparation::PinOutcome::Prepared(_)
			));
			Ok("fits")
		})
		.unwrap();
		f.database
			.external_corruption(|conn| {
				assert!(
					conn.query_row("SELECT prepared_at FROM jobs WHERE id=101", [], |row| row
						.get::<_, i64>(0))?
						> 1
				);
				assert_eq!(
					conn.query_row(
						"SELECT COUNT(*) FROM job_checkpoints WHERE job_id=101",
						[],
						|row| row.get::<_, i64>(0)
					)?,
					1,
					"successful response commits the same preparation and batch"
				);
				Ok(())
			})
			.unwrap();
	}
}
struct Fixture {
	database: crate::test_support::offline::OfflineDatabase,
	db: Arc<Db>,
	worker: AuthedWorker,
	headers: HeaderMap,
	hash: [u8; 32],
}
fn fixture() -> Fixture {
	let mut database = crate::test_support::offline::OfflineDatabase::new();
	let db = database.open();
	let (capability, hash) = job_capability::issue();
	let mut headers = HeaderMap::new();
	headers.insert(loupe_proto::JOB_CAPABILITY_HEADER, capability.expose_secret().parse().unwrap());
	database.external_corruption(|conn| {
  conn.execute_batch("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at)
  VALUES(1,'u1','github.com','o','r1','{\"kind\":\"manual\"}',0),(2,'u2','github.com','o','r2','{\"kind\":\"manual\"}',0);
  INSERT INTO workers VALUES(1,'worker','worker',x'01',0,0,NULL),(2,'other','worker',x'02',0,0,NULL),(3,'admin','admin',x'03',0,0,NULL);
  INSERT INTO review_generations(generation_id,repo_id,generation_commit_sha,state,workflow_contract_version,created_at)
  VALUES(11,1,'placeholder','active',1,0),(21,2,'foreign','active',1,0);
  INSERT INTO review_campaigns(campaign_id,repo_id,recipe,trigger,target_commit_sha,generation_id,state,effective_policy,effective_policy_digest,deadline_at,created_at)
  VALUES(1,1,'bootstrap','manual','placeholder',11,'active','{}',zeroblob(32),1000,0);
  INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,worker_id,lease_expires_at,attempts,workflow_contract_version,recipe,hard_deadline_at,enqueued_at)
  VALUES(101,1,'survey','leased',1,11,1,500,2,1,'{\"version\":1,\"phase\":\"survey\",\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}',1000,0),
  (102,1,'survey','queued',1,11,NULL,NULL,0,1,NULL,NULL,0);
  INSERT INTO jobs(id,repo_id,kind,state,enqueued_at) VALUES(201,2,'scan','queued',0);
  INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,expected_entry_count,expected_digest,created_at,sealed_at)
  VALUES(11,1,101,0,zeroblob(32),0,1);")?;
  conn.execute("UPDATE jobs SET head_sha=?1,job_capability_hash=?2,prepared_attempt=2,prepared_capability_hash=?2,prepared_at=1 WHERE id=101", params![SHA,hash.as_slice()])?;
  conn.execute("UPDATE review_campaigns SET target_commit_sha=?1",[SHA])?;
  conn.execute("UPDATE jobs SET workflow_contract_version=?1",[loupe_core::WORKFLOW_CONTRACT_VERSION])?;
  conn.execute("UPDATE review_generations SET workflow_contract_version=?1",[loupe_core::WORKFLOW_CONTRACT_VERSION])?;
  conn.execute("UPDATE review_generations SET generation_commit_sha=?1,profile_version=1,generated_profile='{}',generated_profile_digest=?2 WHERE generation_id=11",params![SHA,blake3::hash(b"{}").as_bytes().as_slice()])?;
  Ok(())
 }).unwrap();
	let worker = authenticated(&db, &database, 1);
	Fixture { database, db, worker, headers, hash }
}
fn authenticated(
	db: &Arc<Db>, database: &crate::test_support::offline::OfflineDatabase, id: i64,
) -> AuthedWorker {
	let certificate = crate::PeerCert(vec![u8::try_from(id).unwrap(), 4, 9].into());
	database
		.external_corruption(|conn| {
			conn.execute(
				"UPDATE workers SET cert_fingerprint=?1 WHERE id=?2",
				params![loupe_tls::cert_fingerprint(certificate.0.as_ref()), id],
			)?;
			Ok(())
		})
		.unwrap();
	let state = crate::state::AppState::new(
		db.clone(),
		Arc::new(loupe_tls::Ca::new("authority-fixture").unwrap()),
		Arc::new(crate::reporters::GithubReporter::new().unwrap()),
	);
	async fn capture(Extension(worker): Extension<AuthedWorker>) -> axum::response::Response {
		let mut response = axum::http::StatusCode::OK.into_response();
		response.extensions_mut().insert(worker);
		response
	}
	let router = Router::new()
		.route("/", get(capture))
		.layer(middleware::from_fn_with_state(state, crate::auth::mtls_auth));
	let mut request = axum::http::Request::builder().uri("/").body(Body::empty()).unwrap();
	request.extensions_mut().insert(certificate);
	let mut response = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap()
		.block_on(router.oneshot(request))
		.unwrap();
	assert_eq!(response.status(), 200);
	response.extensions_mut().remove::<AuthedWorker>().unwrap()
}
fn mutate(f: &Fixture, sql: &str) {
	f.database
		.external_corruption(|conn| {
			conn.execute_batch(sql)?;
			Ok(())
		})
		.unwrap();
}
fn run<T>(
	f: &Fixture, body: impl for<'tx> FnOnce(&mut stored::PhaseTransaction<'tx>) -> Result<T>,
) -> Result<T> {
	Ok(with_transaction(&f.db, &f.worker, &f.headers, 101, || NOW, body)?
		.expect("fixture capability header"))
}
fn allowed(f: &Fixture, phase: Phase, access: Access) -> bool {
	with_transaction(
		&f.db,
		&f.worker,
		&f.headers,
		101,
		|| NOW,
		|tx| Ok::<_, Error>(authorize(tx, phase, access)?.is_some()),
	)
	.unwrap()
	.unwrap_or(false)
}

#[test]
fn preparation_and_readiness_matrix() {
	for (sql, checkout, host) in [
		("UPDATE jobs SET prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id=101", true, false),
		("UPDATE jobs SET prepared_attempt=1 WHERE id=101", true, false),
		("UPDATE jobs SET prepared_capability_hash=zeroblob(32) WHERE id=101", true, false),
		("UPDATE jobs SET prepared_at=101 WHERE id=101", true, false),
		("UPDATE jobs SET head_sha='old' WHERE id=101", true, false),
		("UPDATE review_campaigns SET target_commit_sha='different'", false, false),
		("UPDATE generation_manifests SET owner_job_id=NULL; UPDATE jobs SET generation_id=NULL WHERE id=101", false, false),
		(format!("UPDATE jobs SET workflow_contract_version={} WHERE id=101", loupe_core::WORKFLOW_CONTRACT_VERSION + 1).as_str(), false, false),
		(format!("UPDATE review_generations SET workflow_contract_version={} WHERE generation_id=11", loupe_core::WORKFLOW_CONTRACT_VERSION + 1).as_str(), false, false),
		("UPDATE generation_manifests SET sealed_at=NULL", true, true),
		("DELETE FROM generation_manifests", true, true),
		("UPDATE review_generations SET generated_profile=NULL WHERE generation_id=11", true, true),
		("UPDATE review_generations SET generated_profile='[]' WHERE generation_id=11", true, true),
		("UPDATE review_generations SET generated_profile_digest=zeroblob(32) WHERE generation_id=11", true, true),
	] {
		let f = fixture();
		assert!(allowed(&f, Phase::Survey, Access::Domain));
		mutate(&f, sql);
		assert_eq!(allowed(&f, Phase::Survey, Access::Checkout), checkout, "checkout: {sql}");
		assert_eq!(allowed(&f, Phase::Survey, Access::PreparedHost), host, "prepared host: {sql}");
		assert!(!allowed(&f, Phase::Survey, Access::Domain), "domain: {sql}");
	}
}

#[test]
fn lease_control_survives_deadlines_and_rebuildable_cleanup_only() {
	for sql in [
		"UPDATE review_campaigns SET state='cancelled'",
		"UPDATE review_campaigns SET deadline_at=100",
		"UPDATE jobs SET hard_deadline_at=100,submit_by=1000 WHERE id=101",
		"UPDATE jobs SET recipe='broken JSON' WHERE id=101",
		"DELETE FROM review_generations WHERE generation_id=11",
	] {
		let f = fixture();
		mutate(&f, sql);
		assert!(allowed(&f, Phase::Survey, Access::LeaseControl), "control: {sql}");
		for access in [Access::Checkout, Access::PreparedHost, Access::Domain] {
			assert!(!allowed(&f, Phase::Survey, access), "domain/host: {sql}");
		}
	}
}

#[test]
fn missing_phase_deadline_denies_analysis_not_failure_reports() {
	let f = fixture();
	assert!(allowed(&f, Phase::Survey, Access::Domain));
	mutate(&f, "UPDATE jobs SET hard_deadline_at=NULL WHERE id=101");
	assert!(allowed(&f, Phase::Survey, Access::LeaseControl));
	for access in [Access::Checkout, Access::PreparedHost, Access::Domain] {
		assert!(!allowed(&f, Phase::Survey, access), "missing deadline must deny {access:?}");
	}
}

#[test]
fn strict_recipe_decoder_rejects_unsupported_shapes() {
	for raw in [
		"{}",
		r#"{"version":2,"phase":"survey","recipe":"coverage","assignment_key":"ordinary"}"#,
		r#"{"version":1,"phase":"verify"}"#,
		r#"{"version":1,"phase":"survey","recipe":"coverage","assignment_key":"ordinary","extra":1}"#,
		r#"{"version":1,"version":1,"phase":"survey","recipe":"coverage","assignment_key":"ordinary"}"#,
		r#"{"version":1,"phase":"survey","phase":"survey","recipe":"coverage","assignment_key":"ordinary"}"#,
		r#"{"version":1,"phase":"survey","recipe":"coverage","assignment_key":"other"}"#,
		r#"{"version":1,"phase":"survey","recipe":"reconciliation","assignment_key":"ordinary"}"#,
		r#"{"version":1,"phase":"survey","recipe":"corroboration","assignment_key":"ordinary"}"#,
	] {
		let f = fixture();
		assert!(allowed(&f, Phase::Survey, Access::Domain));
		f.database
			.external_corruption(|conn| {
				conn.execute("UPDATE jobs SET recipe=?1 WHERE id=101", [raw])?;
				Ok(())
			})
			.unwrap();
		assert!(!allowed(&f, Phase::Survey, Access::Domain), "{raw}");
		assert!(!allowed(&f, Phase::Survey, Access::Checkout), "{raw}");
		assert!(allowed(&f, Phase::Survey, Access::LeaseControl));
	}
}

fn survey_recipe(f: &Fixture, recipe: &str) {
	f.database
		.external_corruption(|conn| {
			conn.execute(
				"UPDATE jobs SET recipe=?1 WHERE id=101",
				[format!(
					r#"{{"version":1,"phase":"survey","recipe":"{recipe}","assignment_key":"ordinary"}}"#
				)],
			)?;
			Ok(())
		})
		.unwrap();
}

#[test]
fn bootstrap_incremental_and_coverage_have_distinct_eligibility() {
	let f = fixture();
	survey_recipe(&f, "bootstrap");
	assert!(
		!allowed(&f, Phase::Survey, Access::Domain),
		"bootstrap cannot reactivate active baseline"
	);
	mutate(&f, "UPDATE review_generations SET state='building' WHERE generation_id=11");
	assert!(allowed(&f, Phase::Survey, Access::Domain));
	mutate(&f, "UPDATE review_generations SET predecessor_generation_id=21 WHERE generation_id=11");
	assert!(!allowed(&f, Phase::Survey, Access::Checkout), "successor needs B8");
	for recipe in ["bootstrap", "incremental"] {
		let f = fixture();
		survey_recipe(&f, recipe);
		f.database
			.external_corruption(|conn| {
				conn.execute(
				"UPDATE review_campaigns SET recipe=?1,generation_id=NULL,target_commit_sha='main'",
				[recipe],
			)?;
				conn.execute("UPDATE generation_manifests SET owner_job_id=NULL", [])?;
				conn.execute("UPDATE jobs SET generation_id=NULL,head_sha=NULL WHERE id=101", [])?;
				Ok(())
			})
			.unwrap();
		assert!(allowed(&f, Phase::Survey, Access::Checkout));
		assert!(!allowed(&f, Phase::Survey, Access::PreparedHost));
		assert!(!allowed(&f, Phase::Survey, Access::Domain));
	}
	let f = fixture();
	survey_recipe(&f, "incremental");
	mutate(&f, "UPDATE review_campaigns SET recipe='incremental'");
	assert!(allowed(&f, Phase::Survey, Access::Domain));
	mutate(&f, "UPDATE review_generations SET state='building' WHERE generation_id=11");
	assert!(!allowed(&f, Phase::Survey, Access::Checkout));
	for recipe in ["reconciliation", "corroboration"] {
		let f = fixture();
		f.database
			.external_corruption(|conn| {
				conn.execute("UPDATE review_campaigns SET recipe=?1", [recipe])?;
				Ok(())
			})
			.unwrap();
		assert!(
			!allowed(&f, Phase::Survey, Access::Domain),
			"campaign recipe cannot be bypassed by coverage"
		);
	}
}

fn units(f: &Fixture) {
	mutate(f, "INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,assignment_epoch,created_by_job_id,created_at)
	 VALUES(31,11,'owned','title','objective','[]',3,101,0),(32,11,'other','title','objective','bad JSON',3,102,0),(41,21,'foreign','title','objective','bad JSON',3,NULL,0);
	 INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(101,31,0,3);");
}

#[test]
fn exact_unit_membership_epoch_and_freshness_are_required() {
	let f = fixture();
	units(&f);
	assert!(unit_allowed(&f, 31, 3));
	for id in [32, 41, 999] {
		assert!(!unit_allowed(&f, id, 3), "uniform foreign/missing denial: {id}");
	}
	assert!(!unit_allowed(&f, 31, 2));
	for sql in [
		"UPDATE job_assigned_review_units SET assignment_epoch=NULL",
		"UPDATE job_assigned_review_units SET assignment_epoch=2",
		"UPDATE review_units SET assignment_epoch=4 WHERE review_unit_id=31",
		"UPDATE review_units SET stale=1 WHERE review_unit_id=31",
		"UPDATE review_units SET status='retired' WHERE review_unit_id=31",
	] {
		let f = fixture();
		units(&f);
		mutate(&f, sql);
		assert!(!unit_allowed(&f, 31, 3), "{sql}");
	}
	// The conclusive control is current Recorded evidence, not historical
	// metadata that deliberately leaves modern coverage incomplete.
	let f = fixture();
	units(&f);
	assert!(unit_allowed(&f, 31, 3));
	f.database.external_corruption(|conn| {
		conn.execute("UPDATE generation_manifests SET expected_entry_count=1,received_entry_count=1 WHERE generation_id=11",[])?;
		conn.execute("INSERT INTO generation_inventory(generation_id,path,source_path,raw_path,blob_sha,entry_kind,git_mode,manifest_position,disposition,created_at) VALUES(11,'src.rs','src.rs',?1,?2,'tracked',33188,0,'context',0)",params![b"src.rs".as_slice(),SHA])?;
		let raw=serde_json::json!({"protocol_version":loupe_proto::PROTOCOL_VERSION,"client_result_key":"current","result":{"format":"loupe.unit_result","version":1,"review_unit_id":31,"assignment_epoch":3,"disposition":"no_lead_found","inspected_refs":[{"path":"src.rs"}],"created_lead_ids":[],"counterevidence":"Guard traced","proof_gaps":"None"}}).to_string();
		let body=crate::test_support::worker_body(raw.as_bytes());
		let payload=body.0.as_bytes().validate_carrying(loupe_proto::review_evidence::UnitResultCheckpointRequestDecoder).unwrap().result;
		let bytes=payload.canonical_bytes().unwrap();
		let refs=loupe_core::canonical::canonical_bytes(&serde_json::to_value(&payload.inspected_refs).unwrap());
		conn.execute("INSERT INTO review_unit_results(review_unit_id,produced_by_job_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,source,created_at) VALUES(31,101,?1,1,'no_lead_found',?5,?2,?3,'agent',?4)",params![SHA,std::str::from_utf8(&bytes).unwrap(),loupe_core::canonical::digest(&bytes).as_slice(),NOW,std::str::from_utf8(&refs).unwrap()])?;
		Ok(())
	}).unwrap();
	assert!(!unit_allowed(&f, 31, 3), "current conclusive evidence excludes another fresh result");
	let f = fixture();
	units(&f);
	survey_recipe(&f, "bootstrap");
	mutate(&f,"UPDATE review_generations SET state='building' WHERE generation_id=11; DELETE FROM job_assigned_review_units;");
	assert!(unit_allowed(&f, 31, 3), "bootstrap uses creating-job provenance");
	assert!(!unit_allowed(&f, 32, 3));
}

fn child(f: &Fixture, phase: Phase) {
	mutate(f,"INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at)
	 VALUES(31,11,'family','anchor',zeroblob(32),'{}',zeroblob(32),'base',0),(41,21,'family','anchor',zeroblob(32),'broken',zeroblob(32),'foreign',0);
	 INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,created_at,report_identity)
	 VALUES(51,1,101,'test','high','title','description','a',0,randomblob(16)),(61,2,201,'test','high','title','description','b',0,randomblob(16));");
	f.database.external_corruption(|conn| { conn.execute("UPDATE jobs SET kind=?1,recipe=?2,assigned_lead_id=?3,target_finding_id=?4 WHERE id=101", params![phase.job_kind().as_str(),format!(r#"{{"version":1,"phase":"{}"}}"#,phase.job_kind().as_str()), if phase==Phase::Drilldown {Some(31)} else {None},if phase==Phase::Verify {Some(51)} else {None}])?; Ok(()) }).unwrap();
}

#[test]
fn child_authority_requires_its_own_subject_and_ready_generation() {
	for phase in [Phase::Drilldown, Phase::Verify] {
		for sql in [
			"UPDATE generation_manifests SET sealed_at=NULL",
			"UPDATE jobs SET assigned_lead_id=NULL,target_finding_id=NULL WHERE id=101",
			"UPDATE jobs SET assigned_lead_id=41,target_finding_id=61 WHERE id=101",
			"UPDATE review_campaigns SET recipe='corroboration'",
		] {
			let f = fixture();
			child(&f, phase);
			assert!(allowed(&f, phase, Access::Domain));
			mutate(&f, sql);
			assert!(!allowed(&f, phase, Access::Checkout), "{phase:?}: {sql}");
			assert!(!allowed(&f, phase, Access::Domain));
		}
	}
}

fn unit_allowed(f: &Fixture, id: i64, epoch: i64) -> bool {
	run(f, |tx| authorize(tx, Phase::Survey, Access::Domain)?.unwrap().survey_unit(id, epoch))
		.unwrap()
}
#[test]
fn identity_and_transaction_time_revocation_are_uniformly_denied() {
	for sql in [
		"UPDATE workers SET revoked_at=1 WHERE id=1",
		"UPDATE workers SET kind='admin' WHERE id=1",
		"UPDATE jobs SET worker_id=2 WHERE id=101",
		"UPDATE jobs SET state='queued' WHERE id=101",
		"UPDATE jobs SET lease_expires_at=99 WHERE id=101",
		"UPDATE jobs SET attempts=0 WHERE id=101",
		"UPDATE jobs SET campaign_id=NULL WHERE id=101",
		"UPDATE jobs SET job_capability_hash=zeroblob(32) WHERE id=101",
	] {
		let f = fixture();
		assert!(allowed(&f, Phase::Survey, Access::Domain), "precheck: {sql}");
		mutate(&f, sql);
		assert!(!allowed(&f, Phase::Survey, Access::Domain), "recheck: {sql}");
		assert!(!allowed(&f, Phase::Survey, Access::LeaseControl));
	}
	let mut f = fixture();
	assert!(!allowed(&f, Phase::Drilldown, Access::Domain));
	for job in [102, 999] {
		assert!(!with_transaction(
			&f.db,
			&f.worker,
			&f.headers,
			job,
			|| NOW,
			|tx| Ok::<_, Error>(authorize(tx, Phase::Survey, Access::Domain)?.is_some())
		)
		.unwrap()
		.unwrap());
	}
	// Landed lease policy accepts exact expiry; deadlines still reject equality.
	mutate(&f, "UPDATE jobs SET lease_expires_at=100 WHERE id=101");
	assert!(allowed(&f, Phase::Survey, Access::Domain));
	f.headers.clear();
	assert!(!allowed(&f, Phase::Survey, Access::LeaseControl));
	assert!(with_transaction(
		&f.db,
		&f.worker,
		&f.headers,
		999,
		|| NOW,
		|_| -> Result<()> { panic!("missing header cannot enter transaction callback") }
	)
	.unwrap()
	.is_none());
}
#[test]
fn lease_control_ignores_malformed_nonidentity_sql_values() {
	for column in ["recipe", "head_sha", "hard_deadline_at", "workflow_contract_version"] {
		let f = fixture();
		mutate(&f, &format!("UPDATE jobs SET {column}=x'ff' WHERE id=101"));
		let result =
			run(&f, |tx| Ok(authorize(tx, Phase::Survey, Access::LeaseControl)?.is_some()));
		assert!(
			matches!(result, Ok(true)),
			"nonidentity {column} must not block failure reporting: {result:?}"
		);
	}
}
#[test]
fn children_are_exact_subject_scoped_and_cannot_bypass_recipe_policy() {
	for phase in [Phase::Drilldown, Phase::Verify] {
		let f = fixture();
		child(&f, phase);
		assert!(allowed(&f, phase, Access::Domain));
		run(&f, |tx| {
			let auth = authorize(tx, phase, Access::Domain)?.unwrap();
			assert_eq!(auth.assigned_lead(31)?, phase == Phase::Drilldown);
			assert_eq!(auth.assigned_finding(51)?, phase == Phase::Verify);
			for id in [41, 61, 999] {
				assert!(!auth.assigned_lead(id)?);
				assert!(!auth.assigned_finding(id)?);
			}
			assert!(!auth.survey_unit(31, 0)?);
			Ok(())
		})
		.unwrap();
		mutate(&f, "UPDATE review_generations SET state='building' WHERE generation_id=11");
		assert!(allowed(&f, phase, Access::Domain), "ready initial bootstrap permits children");
		mutate(&f, "UPDATE review_campaigns SET recipe='reconciliation'");
		assert!(!allowed(&f, phase, Access::Domain));
		assert!(!allowed(&f, phase, Access::Checkout));
		assert!(allowed(&f, phase, Access::LeaseControl));
	}
}
fn terminal_payload() -> TerminalPayload {
	TerminalPayload::Survey(SurveyTerminalV1 {
		version: Version1,
		terminal_reason: SurveyTerminalReason::Completed,
		continuation: None,
		security_model_notes: None,
	})
}
fn different_payload() -> TerminalPayload {
	TerminalPayload::Survey(SurveyTerminalV1 {
		version: Version1,
		terminal_reason: SurveyTerminalReason::Partial,
		continuation: None,
		security_model_notes: None,
	})
}
fn finish(f: &Fixture) {
	f.database.external_corruption(|conn| {
  conn.execute("INSERT INTO job_terminal_receipts(job_id,phase,terminal_reason,pinned_commit_sha,effective_recipe,result_digest,finishing_capability_hash,created_at)
  VALUES(101,'survey','completed',?1,'{}',?2,?3,100)",params![SHA,terminal_payload().digest()?.as_slice(),f.hash.as_slice()])?;
  conn.execute("UPDATE jobs SET state='succeeded',job_capability_hash=NULL,lease_expires_at=NULL WHERE id=101",[])?;
  Ok(())
 }).unwrap();
}
#[test]
fn profile_version_bounds_revoke_domain_not_lease_control() {
	let mut domain = Vec::new();
	for version in ["1", "4294967295", "4294967296", "1.5"] {
		let f = fixture();
		assert!(allowed(&f, Phase::Survey, Access::Domain));
		mutate(
			&f,
			&format!(
				"UPDATE review_generations SET profile_version={version} WHERE generation_id=11"
			),
		);
		domain.push(allowed(&f, Phase::Survey, Access::Domain));
		assert!(allowed(&f, Phase::Survey, Access::LeaseControl), "control: {version}");
		finish(&f);
		assert!(
			matches!(
				run(&f, |tx| tx.replay_terminal(Phase::Survey, &terminal_payload())).unwrap(),
				terminal_receipt::Replayed::Receipt(_)
			),
			"receipt: {version}"
		);
	}
	assert_eq!(
		domain,
		[true, true, false, false],
		"fresh domain authority requires an integer profile version in the lease range"
	);
}
#[test]
fn sealed_terminal_replay_survives_rebuildable_cleanup_not_identity_changes() {
	let f = fixture();
	finish(&f);
	mutate(&f,"DELETE FROM review_generations WHERE generation_id=11; UPDATE review_campaigns SET state='cancelled'; UPDATE jobs SET recipe='invalid',prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id=101;");
	assert!(matches!(
		run(&f, |tx| tx.replay_terminal(Phase::Survey, &terminal_payload())).unwrap(),
		terminal_receipt::Replayed::Receipt(_)
	));
	assert!(matches!(
		run(&f, |tx| tx.replay_terminal(Phase::Survey, &different_payload())).unwrap(),
		terminal_receipt::Replayed::Reject(terminal_receipt::Reject::WrongDigest)
	));
	for sql in [
		"UPDATE workers SET revoked_at=1 WHERE id=1",
		"UPDATE workers SET kind='admin' WHERE id=1",
		"UPDATE jobs SET worker_id=2 WHERE id=101",
		"UPDATE jobs SET worker_id=NULL WHERE id=101",
		"UPDATE jobs SET campaign_id=NULL WHERE id=101",
		"UPDATE jobs SET state='queued' WHERE id=101",
	] {
		let f = fixture();
		finish(&f);
		mutate(&f, sql);
		assert!(
			matches!(
				run(&f, |tx| tx.replay_terminal(Phase::Survey, &terminal_payload())).unwrap(),
				terminal_receipt::Replayed::Reject(terminal_receipt::Reject::Denied)
			),
			"{sql}"
		);
	}
	let mut f = fixture();
	finish(&f);
	let (old, _) = job_capability::issue();
	f.headers.insert(loupe_proto::JOB_CAPABILITY_HEADER, old.expose_secret().parse().unwrap());
	assert!(
		matches!(
			run(&f, |tx| tx.replay_terminal(Phase::Survey, &different_payload())).unwrap(),
			terminal_receipt::Replayed::Reject(terminal_receipt::Reject::Denied)
		),
		"old capability cannot learn digest match"
	);
}
#[test]
fn terminal_binding_is_checked_before_receipt_decoding() {
	let f = fixture();
	finish(&f);
	mutate(&f, "UPDATE job_terminal_receipts SET effective_recipe='broken JSON' WHERE job_id=101");
	let other = authenticated(&f.db, &f.database, 2);
	let (old, _) = job_capability::issue();
	let mut wrong_headers = HeaderMap::new();
	wrong_headers.insert(loupe_proto::JOB_CAPABILITY_HEADER, old.expose_secret().parse().unwrap());
	for (job, worker, phase, headers) in [
		(999, &f.worker, Phase::Survey, &f.headers),
		(101, &other, Phase::Survey, &f.headers),
		(101, &f.worker, Phase::Drilldown, &f.headers),
		(101, &f.worker, Phase::Survey, &wrong_headers),
	] {
		assert!(
			matches!(
				with_transaction(
					&f.db,
					worker,
					headers,
					job,
					|| NOW,
					|tx| tx.replay_terminal(phase, &terminal_payload())
				)
				.unwrap()
				.unwrap(),
				terminal_receipt::Replayed::Reject(terminal_receipt::Reject::Denied)
			),
			"unknown/wrong binding does not decode corrupt receipt"
		);
	}
	assert!(
		run(&f, |tx| tx.replay_terminal(Phase::Survey, &terminal_payload())).is_err(),
		"valid binding must reach the corrupt receipt"
	);
}
// The original checkpoint replay-before-fresh-check and mutation rollback case
// now belongs to storage's private transaction tests: server authority has no
// SQL/RepoScope escape with which to mutate domain rows.

#[test]
fn pre_generation_support_needs_headless_checkout_of_the_campaign_recipe() {
	use support::{supported, CampaignRecipe, RecipeKind, SupportFacts};
	let facts = |access, head_present| SupportFacts {
		campaign: CampaignRecipe::Bootstrap,
		generation: None,
		head_present,
		access,
	};
	assert!(supported(RecipeKind::Bootstrap, facts(Access::Checkout, false)));
	assert!(!supported(RecipeKind::Incremental, facts(Access::Checkout, false)));
	assert!(!supported(RecipeKind::Bootstrap, facts(Access::Checkout, true)));
	for access in [Access::LeaseControl, Access::PreparedHost, Access::Domain] {
		assert!(!supported(RecipeKind::Bootstrap, facts(access, false)), "{access:?}");
	}
}
