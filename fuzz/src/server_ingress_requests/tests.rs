use super::*;

const VALID: [&str; 17] = [
	r#"{"protocol_version":2}"#,
	r#"{"protocol_version":2,"outcome":"failed","head_sha":" exact ","error":"line\r\n\tline"}"#,
	r#"{"protocol_version":2,"findings":[{"scanner_id":"scan","severity":"high","title":"title","description":"description","fingerprint":"fp"}]}"#,
	r#"{"protocol_version":2,"severity":"high","title":" title ","description":"description","file_path":"src/a.rs","line_start":1,"line_end":2,"poc_unified":"","fingerprint":"fp"}"#,
	r#"{"protocol_version":2,"verdict":{"outcome":"confirmed","notes":"","patch":{"patch_unified":"","notes":"line\r\n\tline"}}}"#,
	r#"{"protocol_version":2,"capabilities":["scan:secrets"," exact "],"wait_seconds":3}"#,
	r#"{"protocol_version":2,"clone_url":"https://example.org/owner/repo.git","branch":" main ","reporting":{"kind":"github_issue","target_owner":" owner ","target_repo":"repo","github_pat":"private_body_sentinel"},"scanner_config":{"unknown":{"nil":null}},"verification_enabled":false}"#,
	r#"{"protocol_version":2,"disabled":true,"scan_interval_seconds":17,"verification_enabled":false,"require_approval":true,"inherit_require_approval":true}"#,
	r#"{"protocol_version":2,"incremental":true}"#,
	r#"{"protocol_version":2,"dry_run":true,"include_inconclusive":true,"repo_id":7,"limit":9}"#,
	r#"{"protocol_version":2,"name":" exact Cafe\u0301 "}"#,
	r#"{"protocol_version":2,"github_pat":"private_body_sentinel\r\n\t"}"#,
	r#"{"protocol_version":2,"app_id":7,"private_key_pem":"private_body_sentinel\r\n\t"}"#,
	r#"{"protocol_version":2,"target_owner":" owner ","target_repo":"repo","github_pat":"private_body_sentinel"}"#,
	"/v1/findings/search?q=a+b%2Bc%0D%0A%09Cafe%CC%81&limit=-2",
	"/v1/findings/search?q=a+b%2Bc%0D%0A%09Cafe%CC%81&limit=7",
	"/v1/jobs?state=queued,%20leased,queued&kind=verify&limit=4",
];

fn admitted_control(selector: usize) {
	let body = VALID[selector];
	if selector < 6 {
		assert!(worker_expected(selector, body.as_bytes()).is_some());
	} else if selector < 14 {
		assert!(operator_expected(selector - 6, body.as_bytes()).is_some());
	} else {
		assert!(query_expected(
			selector,
			&body.parse().unwrap_or_else(|error| panic!("fixture URI: {error}"))
		)
		.is_some());
	}
	check(selector, body.as_bytes());
}

macro_rules! direct_controls {
	($($name:ident: $selector:literal),+ $(,)?) => { $(
		#[test]
		fn $name() { admitted_control($selector); }
	)+ };
}
direct_controls! {
	direct_heartbeat: 0, direct_complete: 1, direct_findings: 2,
	direct_llm_finding: 3, direct_verdict: 4, direct_lease: 5,
	direct_register_repo: 6, direct_update_repo: 7, direct_enqueue_scan: 8,
	direct_retry_verify: 9, direct_register_worker: 10, direct_rotate_pat: 11,
	direct_set_app: 12, direct_set_reporting: 13, direct_worker_search: 14,
	direct_operator_search: 15, direct_job_query: 16,
}

#[test]
fn original_agent_spans_match_append_positions_even_for_equal_tokens() {
	for mode in 0..36 {
		span_recipe(mode);
	}
}

#[test]
fn decoded_caps_cover_both_json_spellings_and_secret_policy() {
	for field in 0..4 {
		for edge in 0..3 {
			for escaped in [false, true] {
				boundary_recipe(field, edge, escaped);
			}
		}
	}
}

#[test]
fn syntax_data_policy_and_ignored_grammar_remain_distinct() {
	for (body, status) in [
		(r#"{"protocol_version":2,"outcome":"failed","head_sha":{}}"#, 422),
		(r#"{"protocol_version":2,"outcome":"failed","head_sha":[]}"#, 422),
		(r#"{"protocol_version":2,"outcome":"failed","head_sha":{"broken":]}"#, 400),
	] {
		check(1, body.as_bytes());
		assert_eq!(
			actual::worker_request(WorkerRequest::Complete, body.as_bytes())
				.0
				.err()
				.unwrap_or_else(|| panic!("invalid Complete input admitted"))
				.0,
			status
		);
	}
	for (body, status) in [
		(r#"{"protocol_version":2,"capabilities":[1e400]}"#, 400),
		(r#"{"protocol_version":2,"capabilities":[1]}"#, 422),
		(r#"{"protocol_version":2,"capabilities":[{}]}"#, 422),
		(r#"{"protocol_version":2,"capabilities":[{"broken":]}"#, 400),
		(r#"{"protocol_version":2,"capabilities":["bad\u0001"]}"#, 400),
		(r#"{"protocol_version":2,"capabilities":["\uD800"]}"#, 400),
		(r#"{"protocol_version":2,"capabilities":[],"capabilities":[]}"#, 422),
	] {
		check(5, body.as_bytes());
		assert_eq!(
			actual::worker_request(WorkerRequest::Lease, body.as_bytes())
				.0
				.err()
				.unwrap_or_else(|| panic!("invalid Lease input admitted"))
				.0,
			status
		);
	}
	for body in [
		r#"[2,["exact"],3]"#,
		r#"{"protocol_version":2,"capabilities":["exact"],"unknown":1e400}"#,
		r#"{"protocol_version":2,"capabilities":["exact"],"unknown":"\uD800"}"#,
	] {
		check(5, body.as_bytes());
		assert!(actual::worker_request(WorkerRequest::Lease, body.as_bytes()).0.is_ok());
	}
}

#[test]
fn all_query_grammars_keep_duplicates_and_unknowns() {
	for selector in 14..17 {
		for query in [
			"",
			"?q=",
			"?q=first&q=second",
			"?q=%FF",
			"?q=%",
			"?q=bad%01",
			"?limit=0",
			"?q=x&limit=bad",
			"?state=queued,unknown",
			"?state=,",
			"?kind=unknown",
			"?state=queued&state=leased",
			"?unknown=%FF",
		] {
			check(selector, format!("/{query}").as_bytes());
		}
	}
}

#[test]
fn original_reporting_and_scanner_envelope_depths_are_preserved() {
	for (field, depths) in [("reporting", [125, 126, 127]), ("scanner_config", [126, 127, 128])] {
		for (index, depth) in depths.into_iter().enumerate() {
			let nested = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
			let body = if field == "reporting" {
				format!(
					r#"{{"protocol_version":2,"clone_url":"https://example.org/o/r","reporting":{{"kind":"manual","ignored":{nested}}}}}"#
				)
			} else {
				format!(
					r#"{{"protocol_version":2,"clone_url":"https://example.org/o/r","reporting":{{"kind":"manual"}},"scanner_config":{nested}}}"#
				)
			};
			check(6, body.as_bytes());
			let result = actual::operator_request(OperatorRequest::RegisterRepo, body.as_bytes());
			assert_eq!(result.is_ok(), index == 0, "{field} depth {depth}");
			if let Err((status, _)) = result {
				assert_eq!(status, 400);
			}
		}
	}
}

#[test]
fn reporting_kinds_preserve_scalar_syntax_classification() {
	for (token, status) in [("1e400", 400), ("1", 422), ("{}", 422), ("\"unknown\"", 422)] {
		let body = format!(
			r#"{{"protocol_version":2,"clone_url":"https://example.org/o/r","reporting":{{"kind":{token}}}}}"#
		);
		check(6, body.as_bytes());
		assert_eq!(
			actual::operator_request(OperatorRequest::RegisterRepo, body.as_bytes())
				.err()
				.unwrap_or_else(|| panic!("invalid RegisterRepo input admitted"))
				.0,
			status
		);
	}
	for reporting in [
		r#"{"kind":"manual","ignored":"valid"}"#,
		r#"["manual"]"#,
		r#"{"kind":"email","to":["exact@example.org"],"from":null,"subject_prefix":" exact "}"#,
	] {
		let body = format!(
			r#"{{"protocol_version":2,"clone_url":"https://example.org/o/r","reporting":{reporting}}}"#
		);
		check(6, body.as_bytes());
		assert!(actual::operator_request(OperatorRequest::RegisterRepo, body.as_bytes()).is_ok());
	}
}
