//! In-process drilldown MCP sessions against a route-scripted phase server.

use std::time::{Duration, SystemTime};

use super::drilldown::{
	COMPATIBILITY_CONFLICT, IDENTITY_CONFLICT, INCOMPATIBLE_STATE, INVALID, QUERIES_EXHAUSTED,
	REVALIDATION_REQUIRED, SIBLINGS_EXHAUSTED,
};
use super::survey_tests::{
	call, error_body, is_error, run, text, FakePhase, DIGEST, SENTINEL, SHA,
};
use super::*;
use crate::review::gate::{DRILLDOWN_SEALED, SIBLING_SOFT_STOP};
use crate::review::session::{DrilldownSession, PhaseSession};

struct Fixture {
	server: FakePhase,
	drilldown: Arc<DrilldownSession>,
	context: McpSessionContext,
	cancel: tokio_util::sync::CancellationToken,
}

fn limits_body(siblings: u32, queries: u32) -> String {
	json!({"protocol_version":3,"soft_deadline_at":100,"submit_by":100,"hard_deadline_at":200,
		"remaining_seconds":60,"new_units":{"limit":0,"remaining":0},
		"leads":{"limit":0,"remaining":0},"siblings":{"limit":4,"remaining":siblings},
		"candidate_queries":{"limit":32,"remaining":queries},"campaign_jobs_limit":10,
		"campaign_jobs_admitted":2,"campaign_general_remaining":5,
		"campaign_urgent_remaining":1,"campaign_verification_remaining":2,
		"proof_capacity":"unavailable","artifact_capacity":"unavailable",
		"output_capacity":"unavailable","tokens":{"status":"none"}})
	.to_string()
}

fn receipt_body(disposition: &str, finding: Option<i64>) -> String {
	let mut summary = json!({"version":1,"lead_id":4,"disposition":disposition});
	if let Some(finding) = finding {
		summary["promoted_finding_id"] = json!(finding);
	}
	json!({"protocol_version":3,"receipt":{"receipt_id":21,"job_id":7,"commit_sha":SHA,
		"result_digest":DIGEST,"summary":summary}})
	.to_string()
}

fn created_body(lead_id: i64) -> String {
	json!({"protocol_version":3,"lead_id":lead_id,"outcome":"created",
		"observation_id":null,"accepted_priority":{"band":"normal","score":50}})
	.to_string()
}

async fn fixture(offset: Duration) -> Fixture {
	let server = FakePhase::start().await;
	let now = SystemTime::now();
	let cancel = tokio_util::sync::CancellationToken::new();
	let phase = PhaseSession::new(
		7,
		JobCapability::from_secret("drilldown-capability"),
		now + Duration::from_secs(600),
		now + Duration::from_secs(1200),
		Arc::new(move || SystemTime::now() + offset),
		cancel.clone(),
	);
	let limits = crate::client::fuzz_support::review_response(
		loupe_proto::review_api::PhaseLimitsResponseDecoder,
		limits_body(4, 30).as_bytes(),
	)
	.unwrap();
	let drilldown = Arc::new(DrilldownSession::new(phase, 4, Some(&limits)));
	let context = McpSessionContext {
		security: crate::canary::JobSecurity::new(Default::default(), Vec::new()).unwrap(),
		tool_boundary: crate::llm::prompt::JobToolBoundary::from_test_bytes([0x22; 16]),
		client: server.client(),
		job_capability: JobCapability::from_secret("drilldown-capability"),
		repo_id: 1,
		scope: crate::mcp::McpScope::Phase(PhaseTools::Drilldown(drilldown.clone())),
		workdir: PathBuf::from("/nonexistent"),
	};
	Fixture { server, drilldown, context, cancel }
}

fn sibling(key: &str) -> Value {
	json!({"client_lead_key": key, "identity_family": "memory-safety",
		"identity_anchor": "parse header", "hypothesis": "Header length unchecked.",
		"source_refs": [{"path": "src/lib.rs"}], "next_proof_step": "Trace it.",
		"counterevidence": "None.", "proof_gaps": "Reachability."})
}

fn promote() -> Value {
	json!({"disposition": "promote", "promotion": {"severity": "high",
		"title": "Unbounded allocation", "description": "Length reaches allocation.",
		"identity_family": "memory-safety", "identity_anchor": "parse allocation",
		"evidence": {"l2_argument": {"attacker_source": "Request body", "control": "Length",
			"sink": "allocation", "reachable_path": "handler to parse",
			"trust_boundary": "network"},
		"material_locations": [{"role": "sink", "file": "src/lib.rs", "line_start": 3}],
		"counterevidence": "No bound.", "assumptions_gaps": "Defaults.",
		"confidence": "medium"}}})
}

fn reject() -> Value {
	json!({"disposition": "reject", "counterargument": {"argument": "The bound is checked.",
		"source_refs": [{"path": "src/lib.rs"}]}})
}

fn routes(server: &FakePhase) -> Vec<String> {
	server.seen().iter().map(|s| s.head.split(' ').nth(1).unwrap().to_owned()).collect()
}

fn status(response: &Value) -> String {
	text(response).lines().last().unwrap().to_owned()
}

#[tokio::test]
async fn the_catalog_has_four_tools_at_protocol_version_2() {
	let fixture = fixture(Duration::ZERO).await;
	let responses = run(
		fixture.context,
		&[
			json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
			json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
		],
	)
	.await;
	assert_eq!(responses[1]["result"]["_meta"]["loupeProtocolVersion"], json!(2));
	let tools = responses[1]["result"]["tools"].as_array().unwrap();
	let names: Vec<_> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
	assert_eq!(
		names,
		[
			"get_job_limits",
			"query_same_project_lead_candidates",
			"submit_sibling_lead",
			"finalize_drilldown"
		]
	);
	for tool in tools {
		assert_eq!(tool["inputSchema"]["properties"]["protocol_version"]["const"], json!(2));
	}
	let sibling = &tools[2]["inputSchema"]["properties"];
	assert!(sibling.get("review_unit_id").is_none());
	let finalize = &tools[3]["inputSchema"];
	assert_eq!(
		finalize["properties"]["disposition"]["enum"],
		json!(["promote", "reject", "duplicate", "hardening", "defer"])
	);
	assert_eq!(finalize["required"], json!(["disposition"]));
	assert_eq!(finalize["additionalProperties"], json!(false));
	let described =
		|name: &str| finalize["properties"][name]["description"].as_str().unwrap_or_default();
	for rule in [
		"promote requires promotion",
		"reject requires counterargument",
		"duplicate requires target and rationale",
		"hardening requires explanation",
		"defer requires reason and continuation",
	] {
		assert!(described("disposition").contains(rule), "{rule}");
	}
	for (name, disposition) in [
		("promotion", "promote"),
		("counterargument", "reject"),
		("target", "duplicate"),
		("rationale", "duplicate"),
		("explanation", "hardening"),
		("reason", "defer"),
		("continuation", "defer"),
		("retry_explanation", "defer"),
	] {
		assert!(described(name).contains(&format!("disposition {disposition} only")), "{name}");
	}
	let evidence = &finalize["properties"]["promotion"]["properties"]["evidence"];
	assert!(evidence["properties"]["l2_argument"]["properties"]["trust_boundary"].is_object());
	// The host supplies every `version`; the agent is never asked for one.
	assert!(!tools[3].to_string().contains("\"version\""));
}

#[tokio::test]
async fn other_catalogs_tools_are_unknown_in_a_drilldown_session() {
	let fixture = fixture(Duration::ZERO).await;
	let responses = run(
		fixture.context,
		&[
			call(1, "submit_lead", json!({})),
			call(2, "finalize_survey", json!({})),
			call(3, "submit_finding", json!({})),
		],
	)
	.await;
	assert_eq!(text(&responses[0]), "Error: unknown tool: submit_lead");
	assert_eq!(text(&responses[1]), "Error: unknown tool: finalize_survey");
	assert_eq!(text(&responses[2]), "Error: unknown tool: submit_finding");
	assert!(fixture.server.seen().is_empty());
}

#[tokio::test]
async fn every_tool_reaches_its_route_and_reports_capacity() {
	let fixture = fixture(Duration::ZERO).await;
	fixture.server.reply("/limits", 200, limits_body(3, 29));
	fixture.server.reply(
		"/lead-candidates",
		200,
		json!({"protocol_version":3,"candidates":[{"kind":"finding","id":9,
			"producer_job_id":3,"commit_sha":SHA,"created_at":10,
			"identity_family":"memory-safety","identity_anchor":"parse allocation",
			"identity_instance_key":null}]})
		.to_string(),
	);
	fixture.server.reply("/lead-candidates", 200, r#"{"protocol_version":3,"candidates":[]}"#);
	fixture.server.reply("/sibling-leads", 200, created_body(12));
	fixture.server.reply("/sibling-leads", 200, created_body(12));
	fixture.server.reply("/finalize-drilldown", 200, receipt_body("promoted", Some(9)));
	let responses = run(
		fixture.context,
		&[
			call(1, "get_job_limits", json!({})),
			call(2, "query_same_project_lead_candidates", json!({"query": "parse", "limit": 3})),
			call(3, "query_same_project_lead_candidates", json!({"query": "parse", "limit": 3})),
			call(4, "submit_sibling_lead", sibling("s-1")),
			call(5, "submit_sibling_lead", sibling("s-1")),
			call(6, "finalize_drilldown", promote()),
		],
	)
	.await;
	for response in &responses {
		assert!(!is_error(response), "{}", text(response));
		assert!(status(response).starts_with("[loupe status] submit_by: "));
	}
	assert!(text(&responses[0]).contains(r#""siblings":{"limit":4,"remaining":3}"#));
	assert!(status(&responses[0])
		.ends_with("sibling leads remaining: 3; candidate queries remaining: 29"));
	let boundary = "22".repeat(16);
	assert!(text(&responses[1]).contains(&format!(
		r#"<loupe-data field="candidates" source="agent" boundary="{boundary}">"#
	)));
	assert!(text(&responses[1]).contains(r#""identity_anchor":"parse allocation""#));
	assert!(status(&responses[1]).ends_with("candidate queries remaining: 28"));
	assert!(status(&responses[2]).ends_with("candidate queries remaining: 28"), "a replay");
	assert!(text(&responses[3])
		.starts_with("sibling lead created; it gets its own drilldown: lead_id=12"));
	assert!(status(&responses[3]).contains("sibling leads remaining: 2;"));
	assert!(status(&responses[4]).contains("sibling leads remaining: 2;"), "a replay");
	assert!(text(&responses[5]).starts_with(
		"drilldown finalized as promoted: receipt_id=21; finding_id=9; the session is complete, end it now"
	));
	assert_eq!(fixture.drilldown.receipt().map(|r| i64::from(r.receipt.receipt_id)), Some(21));

	let seen = fixture.server.seen();
	let heads: Vec<_> =
		seen.iter().map(|s| s.head.split(' ').take(2).collect::<Vec<_>>()).collect();
	assert_eq!(
		heads,
		[
			["GET", "/v1/jobs/7/limits"],
			["GET", "/v1/jobs/7/lead-candidates?query=parse&limit=3"],
			["GET", "/v1/jobs/7/lead-candidates?query=parse&limit=3"],
			["POST", "/v1/jobs/7/sibling-leads"],
			["POST", "/v1/jobs/7/sibling-leads"],
			["POST", "/v1/jobs/7/finalize-drilldown"],
		]
	);
	assert_eq!(seen[3].body["client_lead_key"], json!("s-1"));
	assert_eq!(seen[3].body["evidence"]["format"], json!("loupe.lead_evidence"));
	assert!(seen[3].body["evidence"].get("review_unit_id").is_none());
	let payload = &seen[5].body["payload"];
	assert_eq!(seen[5].body["protocol_version"], json!(3));
	assert_eq!(payload["version"], json!(1));
	assert_eq!(payload["promotion"]["version"], json!(1));
	assert_eq!(payload["promotion"]["evidence"]["version"], json!(1));
	assert_eq!(payload["promotion"]["evidence"]["material_locations"][0]["line_start"], json!(3));
}

#[tokio::test]
async fn finalize_refusals_reach_the_model_as_fixed_text_and_leave_it_open() {
	let cases = [
		(409, "revalidation_required", REVALIDATION_REQUIRED),
		(409, "finding_identity_conflict", IDENTITY_CONFLICT),
		(409, "compatibility_key_conflict", COMPATIBILITY_CONFLICT),
		(409, "incompatible_review_state", INCOMPATIBLE_STATE),
		(400, "invalid_request", INVALID),
		(409, "terminal_conflict", "already finalized with a different payload"),
	];
	for (status, code, expected) in cases {
		let fixture = fixture(Duration::ZERO).await;
		let mut body = error_body(code, None);
		body.insert_str(body.len() - 1, &format!(r#","{SENTINEL}":1"#));
		fixture.server.reply("/finalize-drilldown", status, error_body(code, None));
		fixture.server.reply("/finalize-drilldown", 200, receipt_body("rejected", None));
		let responses = run(
			fixture.context,
			&[call(1, "finalize_drilldown", promote()), call(2, "finalize_drilldown", reject())],
		)
		.await;
		assert!(is_error(&responses[0]), "{code}");
		assert!(text(&responses[0]).starts_with("Error: "), "{code}");
		assert!(text(&responses[0]).contains(expected), "{code}: {}", text(&responses[0]));
		assert!(!text(&responses[0]).contains(SENTINEL));
		assert!(
			text(&responses[1]).starts_with("drilldown finalized as rejected: receipt_id=21;"),
			"{code}: a refused finalize seals nothing"
		);
		assert!(!fixture.drilldown.phase().authority_lost(), "{code}");
	}
}

#[tokio::test]
async fn an_unreachable_finalize_is_told_to_retry_the_identical_call() {
	let fixture = fixture(Duration::ZERO).await;
	let responses = run(
		fixture.context,
		&[
			call(1, "finalize_drilldown", promote()),
			call(2, "submit_sibling_lead", sibling("s-1")),
			call(3, "get_job_limits", json!({})),
			call(4, "query_same_project_lead_candidates", json!({"query": "parse"})),
		],
	)
	.await;
	for read in &responses[2..] {
		let reply = text(read);
		assert!(reply.contains("could not be reached"), "{reply}");
		assert!(!reply.contains("client key"), "{reply}");
	}
	let finalize = text(&responses[0]);
	assert!(is_error(&responses[0]));
	assert!(finalize.contains("could not be reached"), "{finalize}");
	assert!(!finalize.contains("client key"), "{finalize}");
	assert!(finalize.contains("identical finalize_drilldown"), "{finalize}");
	let sibling = text(&responses[1]);
	assert!(sibling.contains("SAME client key"), "{sibling}");
}

#[tokio::test]
async fn the_conflict_texts_carry_the_d5_guidance() {
	assert!(
		IDENTITY_CONFLICT.contains("different text than before, such as the full identity anchor")
	);
	assert!(IDENTITY_CONFLICT.contains("duplicate"));
	assert!(
		IDENTITY_CONFLICT.contains("identity_instance_key") && IDENTITY_CONFLICT.contains("defer")
	);
	assert!(COMPATIBILITY_CONFLICT.contains("legacy"));
	assert!(COMPATIBILITY_CONFLICT.contains("identity_instance_key"));
	assert!(COMPATIBILITY_CONFLICT.contains("defer"));
	assert!(!COMPATIBILITY_CONFLICT.contains("finalize as duplicate"));
	assert!(REVALIDATION_REQUIRED.contains("revalidation"));
	assert!(INCOMPATIBLE_STATE.contains("end the session"));
}

#[tokio::test]
async fn capacity_refusals_name_the_exhausted_quota() {
	let fixture = fixture(Duration::ZERO).await;
	fixture.server.reply("/sibling-leads", 409, error_body("checkpoint_limit", None));
	fixture.server.reply("/lead-candidates", 409, error_body("checkpoint_limit", None));
	fixture.server.reply("/sibling-leads", 409, error_body("checkpoint_conflict", None));
	let responses = run(
		fixture.context,
		&[
			call(1, "submit_sibling_lead", sibling("s-1")),
			call(2, "query_same_project_lead_candidates", json!({"query": "parse"})),
			call(3, "submit_sibling_lead", sibling("s-2")),
		],
	)
	.await;
	assert!(text(&responses[0]).contains(SIBLINGS_EXHAUSTED));
	assert!(status(&responses[0])
		.contains("sibling leads remaining: 0; candidate queries remaining: 30"));
	assert!(text(&responses[1]).contains(QUERIES_EXHAUSTED));
	assert!(status(&responses[1]).ends_with("candidate queries remaining: 0"));
	assert!(text(&responses[2]).contains("already used with different content"));
	assert!(responses.iter().all(is_error));
}

#[tokio::test]
async fn a_refused_reference_is_told_apart_from_lost_authority() {
	let fixture = fixture(Duration::ZERO).await;
	fixture.server.reply("/finalize-drilldown", 403, error_body("denied", None));
	fixture.server.reply("/limits", 200, limits_body(2, 20));
	fixture.server.reply("/sibling-leads", 403, error_body("denied", None));
	fixture.server.reply("/limits", 403, error_body("denied", None));
	let duplicate = json!({"disposition": "duplicate", "target": {"kind": "lead", "id": 4},
		"rationale": "Same lead."});
	let responses = run(
		fixture.context,
		&[call(1, "finalize_drilldown", duplicate), call(2, "submit_sibling_lead", sibling("s-1"))],
	)
	.await;
	assert!(text(&responses[0])
		.contains("returned by this job's own query_same_project_lead_candidates"));
	assert!(status(&responses[0])
		.ends_with("sibling leads remaining: 2; candidate queries remaining: 20"));
	assert!(text(&responses[1]).contains("this drilldown attempt no longer has authority"));
	assert!(fixture.drilldown.phase().authority_lost());
	assert!(fixture.cancel.is_cancelled(), "lost authority stops the agent");
	assert_eq!(
		routes(&fixture.server),
		[
			"/v1/jobs/7/finalize-drilldown",
			"/v1/jobs/7/limits",
			"/v1/jobs/7/sibling-leads",
			"/v1/jobs/7/limits"
		]
	);
}

#[tokio::test]
async fn soft_stop_closes_only_sibling_leads() {
	let fixture = fixture(Duration::from_secs(900)).await;
	fixture.server.reply("/lead-candidates", 200, r#"{"protocol_version":3,"candidates":[]}"#);
	fixture.server.reply("/limits", 200, limits_body(4, 29));
	fixture.server.reply("/finalize-drilldown", 200, receipt_body("deferred", None));
	let defer = json!({"disposition": "defer", "reason": "Out of time.",
		"continuation": "source_analysis_remaining"});
	let responses = run(
		fixture.context,
		&[
			call(1, "submit_sibling_lead", sibling("s-1")),
			call(2, "query_same_project_lead_candidates", json!({"query": "parse"})),
			call(3, "get_job_limits", json!({})),
			call(4, "finalize_drilldown", defer),
		],
	)
	.await;
	assert!(text(&responses[0]).starts_with(&format!("Error: {SIBLING_SOFT_STOP}")));
	assert!(status(&responses[0]).contains("submit_by: passed"));
	for response in &responses[1..] {
		assert!(!is_error(response), "{}", text(response));
	}
	assert_eq!(
		routes(&fixture.server),
		[
			"/v1/jobs/7/lead-candidates?query=parse&limit=10",
			"/v1/jobs/7/limits",
			"/v1/jobs/7/finalize-drilldown"
		]
	);
}

#[tokio::test]
async fn a_sealed_receipt_admits_only_limits_and_a_finalize_replay() {
	let fixture = fixture(Duration::ZERO).await;
	fixture.server.reply("/finalize-drilldown", 200, receipt_body("rejected", None));
	fixture.server.reply("/finalize-drilldown", 200, receipt_body("rejected", None));
	fixture.server.reply("/limits", 200, limits_body(4, 30));
	let responses = run(
		fixture.context,
		&[
			call(1, "finalize_drilldown", reject()),
			call(2, "submit_sibling_lead", sibling("late")),
			call(3, "query_same_project_lead_candidates", json!({"query": "parse"})),
			call(4, "finalize_drilldown", reject()),
			call(5, "get_job_limits", json!({})),
		],
	)
	.await;
	assert!(!is_error(&responses[0]));
	for denied in &responses[1..3] {
		assert!(text(denied).starts_with(&format!("Error: {DRILLDOWN_SEALED}")));
	}
	assert!(!is_error(&responses[3]));
	assert!(!is_error(&responses[4]));
	assert_eq!(
		routes(&fixture.server),
		["/v1/jobs/7/finalize-drilldown", "/v1/jobs/7/finalize-drilldown", "/v1/jobs/7/limits"]
	);
}

#[tokio::test]
async fn unknown_and_host_owned_arguments_never_reach_the_server() {
	let fixture = fixture(Duration::ZERO).await;
	let mut with_unit = sibling("s-1");
	with_unit["review_unit_id"] = json!(5);
	let mut versioned = reject();
	versioned["version"] = json!(1);
	let responses = run(
		fixture.context,
		&[
			call(1, "submit_sibling_lead", with_unit),
			call(2, "finalize_drilldown", versioned),
			call(3, "get_job_limits", json!({"owner": 1})),
		],
	)
	.await;
	for response in &responses {
		assert!(
			text(response).starts_with("Error: unknown argument for this tool"),
			"{}",
			text(response)
		);
		assert!(status(response).starts_with("[loupe status]"));
	}
	assert!(fixture.server.seen().is_empty());
}
