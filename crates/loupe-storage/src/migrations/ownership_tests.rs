use rusqlite::{params, Connection};

use super::apply_pending;
use super::fixtures::*;

fn two_projects() -> Connection {
	let mut conn = Connection::open_in_memory().unwrap();
	conn.pragma_update(None, "foreign_keys", true).unwrap();
	settled(&mut conn);
	apply_pending(&mut conn).unwrap();
	for repo in [1, 2] {
		let id = repo + 10;
		conn.execute("INSERT INTO review_generations
            (generation_id, repo_id, generation_commit_sha, state, workflow_contract_version, created_at)
            VALUES (?1, ?2, 'commit', 'active', 1, 100)", params![id, repo]).unwrap();
		conn.execute("INSERT INTO review_campaigns
            (campaign_id, repo_id, recipe, trigger, target_commit_sha, generation_id, state,
             effective_policy, effective_policy_digest, created_at)
            VALUES (?1, ?2, 'bootstrap', 'manual', 'commit', ?1, 'finished', '{}', zeroblob(32), 100)", params![id, repo]).unwrap();
		conn.execute("INSERT INTO review_units
            (review_unit_id, generation_id, client_review_unit_key, title, objective, source_refs, created_at)
            VALUES (?1, ?1, 'unit', 'title', 'objective', '[]', 100)", [id]).unwrap();
		conn.execute(
			"INSERT INTO generation_inventory
            (inventory_entry_id, generation_id, path, entry_kind, created_at)
            VALUES (?1, ?1, 'src/lib.rs', 'tracked', 100)",
			[id],
		)
		.unwrap();
		conn.execute(
			"INSERT INTO review_unit_results
            (review_unit_result_id, review_unit_id, commit_sha, profile_version, disposition,
             inspected_refs, result_payload, result_digest, created_at)
            VALUES (?1, ?1, 'commit', 1, 'no_lead_found', '[]', '{}', zeroblob(32), 100)",
			[id],
		)
		.unwrap();
		conn.execute("INSERT INTO leads
            (lead_id, generation_id, review_unit_id, identity_family, identity_anchor,
             identity_fingerprint, anchored_payload, anchored_digest, commit_sha, created_at)
            VALUES (?1, ?1, ?1, 'family', 'anchor', zeroblob(32), '{}', zeroblob(32), 'commit', 100)", [id]).unwrap();
		conn.execute("INSERT INTO lead_observations
            (lead_observation_id, lead_id, observation_payload, observation_digest, commit_sha, created_at)
            VALUES (?1, ?1, '{}', zeroblob(32), 'commit', 100)", [id]).unwrap();
		conn.execute(
			"INSERT INTO jobs
            (id, repo_id, kind, state, enqueued_at, campaign_id, generation_id, assigned_lead_id)
            VALUES (?1, ?2, 'drilldown', 'succeeded', 100, ?1, ?1, ?1)",
			params![id, repo],
		)
		.unwrap();
		conn.execute(
			"INSERT INTO job_assigned_review_units (job_id, review_unit_id, position)
            VALUES (?1, ?1, 0)",
			[id],
		)
		.unwrap();
		conn.execute("INSERT INTO findings
            (id, repo_id, job_id, scanner_id, severity, title, description, fingerprint, created_at)
            VALUES (?1, ?2, ?1, 'phase', 'high', 'canonical title', 'copied argument', 'phase-fp', 100)", params![id, repo]).unwrap();
		conn.execute(
			"INSERT INTO finding_verifications (id, finding_id, job_id, verdict, created_at)
            VALUES (?1, ?1, ?1, 'confirmed', 100)",
			[id],
		)
		.unwrap();
		conn.execute(
			"INSERT INTO finding_review_details
            (finding_id, repo_id, workflow_contract_version, profile_version, reviewed_commit_sha,
             identity_family, identity_anchor, identity_fingerprint, l2_argument, counterevidence,
             assumptions_gaps, confidence, submitted_rung, origin_lead_id, created_at)
            VALUES (?1, ?2, 1, 1, 'commit', 'family', 'anchor', zeroblob(32), '{}', 'none', 'none',
                    'high', 'L2', ?1, 100)",
			params![id, repo],
		)
		.unwrap();
		conn.execute(
			"INSERT INTO proof_artifact_blobs
            (proof_artifact_blob_id, repo_id, sha256, byte_len, content, created_at)
            VALUES (?1, ?2, zeroblob(32), 3, x'010203', 100)",
			params![id, repo],
		)
		.unwrap();
		conn.execute("INSERT INTO proof_artifacts
            (proof_artifact_id, repo_id, proof_artifact_blob_id, artifact_role, media_type,
             original_name, sha256, byte_len, produced_by_job_id, created_at)
            VALUES (?1, ?2, ?1, 'command_stdout', 'text/plain', 'stdout', zeroblob(32), 3, ?1, 100)", params![id, repo]).unwrap();
		conn.execute(
			"INSERT INTO staged_proof_artifacts
            (staged_proof_artifact_id, job_id, repo_id, proof_artifact_blob_id, artifact_role,
             media_type, original_name, created_at)
            VALUES (?1, ?1, ?2, ?1, 'command_stdout', 'text/plain', 'stdout', 100)",
			params![id, repo],
		)
		.unwrap();
		conn.execute("INSERT INTO proof_executions
            (proof_execution_id, repo_id, produced_by_job_id, target_commit_sha, clean_tree,
             argv, working_dir, env_names, network_policy, limits, timeout_seconds, started_at,
             duration_ms, exit_status, stdout_artifact_id, created_at)
            VALUES (?1, ?2, ?1, 'commit', 1, '[]', '.', '{}', 'isolated', '{}', 60, 100, 1, 0, ?1, 100)", params![id, repo]).unwrap();
		conn.execute(
			"INSERT INTO verification_proofs
            (verification_proof_id, finding_id, verification_id, repo_id, rung,
             pinned_commit_sha, manifest, manifest_digest, created_at)
            VALUES (?1, ?1, ?1, ?2, 'L4', 'commit', '{}', zeroblob(32), 100)",
			params![id, repo],
		)
		.unwrap();
		conn.execute(
			"INSERT INTO verification_attempt_details
            (verification_id, workflow_contract_version, checkout_commit_sha, established_rung,
             e2e_applicability, verification_proof_id, terminal_digest, created_at)
            VALUES (?1, 1, 'commit', 'L4', 'applicable', ?1, zeroblob(32), 100)",
			[id],
		)
		.unwrap();
		conn.execute(
			"INSERT INTO verification_proof_artifacts VALUES (?1, ?2, ?2)",
			params![repo, id],
		)
		.unwrap();
		conn.execute(
			"INSERT INTO verification_proof_executions VALUES (?1, ?2, ?2)",
			params![repo, id],
		)
		.unwrap();
		conn.execute("INSERT INTO job_terminal_receipts
            (job_terminal_receipt_id, job_id, phase, terminal_reason, subject_title,
             pinned_commit_sha, effective_recipe, result_digest, created_at)
            VALUES (?1, ?1, 'drilldown', 'completed', 'copied title', 'commit', '{}', zeroblob(32), 100)", [id]).unwrap();
	}
	conn
}

fn rejects(conn: &Connection, sql: &str, code: i32) {
	let error =
		conn.execute_batch(sql).expect_err("invalid relationship or state must be rejected");
	assert_eq!(error.sqlite_error().map(|e| e.extended_code), Some(code), "{sql}: {error}");
}

#[test]
fn v3_ownership_foreign_keys_reject_cross_project_links() {
	let conn = two_projects();
	for sql in [
		"INSERT INTO proof_artifacts (repo_id, proof_artifact_blob_id, artifact_role, media_type, original_name, sha256, byte_len, created_at)
         VALUES (1, 12, 'crafted_input', 'text/plain', 'input', zeroblob(32), 3, 100)",
		"INSERT INTO staged_proof_artifacts (job_id, repo_id, proof_artifact_blob_id, artifact_role, media_type, original_name, created_at)
         VALUES (12, 1, 11, 'crafted_input', 'text/plain', 'input', 100)",
		"INSERT INTO verification_proofs (finding_id, verification_id, repo_id, rung, pinned_commit_sha, manifest, manifest_digest, created_at)
         VALUES (12, 12, 1, 'L4', 'commit', '{}', zeroblob(32), 100)",
		"INSERT INTO jobs (repo_id, kind, state, enqueued_at, campaign_id) VALUES (1, 'survey', 'queued', 100, 12)",
		"UPDATE finding_review_details SET repo_id = 3 WHERE finding_id = 11",
		"UPDATE staged_proof_artifacts SET proof_artifact_blob_id = 12 WHERE staged_proof_artifact_id = 11",
		"UPDATE proof_artifacts SET produced_by_job_id = 12 WHERE proof_artifact_id = 11",
		"UPDATE proof_executions SET produced_by_job_id = 12 WHERE proof_execution_id = 11",
		"UPDATE proof_executions SET stdout_artifact_id = 12 WHERE proof_execution_id = 11",
		"UPDATE proof_executions SET stderr_artifact_id = 12 WHERE proof_execution_id = 11",
		"UPDATE verification_proofs SET verification_id = 12 WHERE verification_proof_id = 11",
		"UPDATE verification_attempt_details SET verification_proof_id = 12 WHERE verification_id = 11",
		"UPDATE verification_proof_artifacts SET proof_artifact_id = 12 WHERE verification_proof_id = 11",
		"UPDATE verification_proof_executions SET proof_execution_id = 12 WHERE verification_proof_id = 11",
	] {
		rejects(&conn, sql, rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY);
	}
}

#[test]
fn v3_generation_purge_preserves_canonical_evidence() {
	let conn = two_projects();
	let canonical = [
		"findings",
		"finding_verifications",
		"verification_attempt_details",
		"proof_artifact_blobs",
		"proof_artifacts",
		"staged_proof_artifacts",
		"proof_executions",
		"verification_proofs",
		"verification_proof_artifacts",
		"verification_proof_executions",
		"job_terminal_receipts",
	];
	let before: Vec<_> = canonical
		.iter()
		.map(|t| rows(&conn, &format!("SELECT * FROM {t} ORDER BY rowid")))
		.collect();
	conn.execute("DELETE FROM review_generations WHERE generation_id = 11", []).unwrap();
	for (table, before) in canonical.iter().zip(before) {
		assert_eq!(
			rows(&conn, &format!("SELECT * FROM {table} ORDER BY rowid")),
			before,
			"{table} lost canonical data"
		);
	}
	assert_eq!(
		rows(
			&conn,
			"SELECT repo_id, campaign_id, generation_id, assigned_lead_id FROM jobs WHERE id = 11"
		),
		vec![vec![1.into(), 11.into(), rusqlite::types::Value::Null, rusqlite::types::Value::Null]]
	);
	assert_eq!(
		rows(&conn, "SELECT repo_id, generation_id FROM review_campaigns WHERE campaign_id = 11"),
		vec![vec![1.into(), rusqlite::types::Value::Null]]
	);
	assert_eq!(rows(&conn, "SELECT repo_id, origin_lead_id, l2_argument FROM finding_review_details WHERE finding_id = 11"), vec![vec![1.into(), rusqlite::types::Value::Null, "{}".to_owned().into()]]);
	for table in [
		"review_units",
		"review_unit_results",
		"generation_inventory",
		"leads",
		"lead_observations",
		"job_assigned_review_units",
	] {
		assert_eq!(
			rows(&conn, &format!("SELECT * FROM {table}")).len(),
			1,
			"{table}: purge must remove A and retain B"
		);
	}
	assert!(rows(&conn, "PRAGMA foreign_key_check").is_empty());
}

#[test]
fn v3_checks_and_assignment_uniqueness_are_enforced() {
	let conn = two_projects();
	for sql in [
		"UPDATE review_campaigns SET state = 'bogus' WHERE campaign_id = 11",
		"UPDATE leads SET status = 'closed' WHERE lead_id = 11",
		"UPDATE leads SET disposition = 'promoted' WHERE lead_id = 11",
		"UPDATE review_unit_results SET corroborates_review_unit_result_id = 12, corroborates_inventory_exclusion_id = 11 WHERE review_unit_result_id = 11",
		"UPDATE jobs SET token_budget = 0 WHERE id = 11",
		"UPDATE jobs SET token_budget = -1 WHERE id = 11",
	] { rejects(&conn, sql, rusqlite::ffi::SQLITE_CONSTRAINT_CHECK); }
	rejects(
		&conn,
		"UPDATE jobs SET kind = 'bogus' WHERE id = 11",
		rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
	);
	rejects(&conn, "INSERT INTO jobs (repo_id, kind, state, target_finding_id, enqueued_at) VALUES (1, 'verify', 'queued', 2, 100)", rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE);
	conn.execute("UPDATE jobs SET state = 'queued', token_budget = 1 WHERE id = 11", []).unwrap();
	rejects(&conn, "INSERT INTO jobs (repo_id, kind, state, assigned_lead_id, enqueued_at) VALUES (1, 'drilldown', 'leased', 11, 100)", rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE);
	conn.execute_batch("UPDATE leads SET status = 'closed', disposition = 'promoted' WHERE lead_id = 11;
        INSERT INTO jobs (repo_id, kind, state, target_finding_id, enqueued_at) VALUES (1, 'verify', 'failed', 2, 100);
        INSERT INTO jobs (repo_id, kind, state, assigned_lead_id, enqueued_at) VALUES (1, 'drilldown', 'succeeded', 11, 100);").unwrap();
}
