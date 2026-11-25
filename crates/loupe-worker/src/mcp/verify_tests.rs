//! In-process verify MCP sessions against a route-scripted phase server.

use std::time::{Duration, SystemTime};

use loupe_core::review_payload::ContinuationClass;

use super::evidence_schema::CONTINUATIONS;
use super::survey_tests::{
	call, error_body, is_error, run, text, FakePhase, DIGEST, SENTINEL, SHA,
};
use super::verify::{FINALIZE_UNREACHABLE, INCOMPATIBLE_STATE, INVALID, REVALIDATION_REQUIRED};
use super::verify_catalog::HOST_BLOCKED;
use super::*;
use crate::review::gate::RecipeClass;
use crate::review::session::{
	DrilldownSession, PhaseSession, SurveySession, SurveySessionParts, VerifySession,
};

struct Fixture {
	server: FakePhase,
	verify: Arc<VerifySession>,
	context: McpSessionContext,
	cancel: tokio_util::sync::CancellationToken,
	heartbeat: tokio_util::sync::CancellationToken,
}

fn limits_body() -> String {
	json!({"protocol_version":3,"soft_deadline_at":100,"submit_by":100,"hard_deadline_at":200,
		"remaining_seconds":60,"new_units":{"limit":0,"remaining":0},
		"leads":{"limit":0,"remaining":0},"siblings":{"limit":0,"remaining":0},
		"candidate_queries":{"limit":0,"remaining":0},"campaign_jobs_limit":10,
		"campaign_jobs_admitted":2,"campaign_general_remaining":5,
		"campaign_urgent_remaining":1,"campaign_verification_remaining":2,
		"proof_capacity":"unavailable","artifact_capacity":"unavailable",
		"output_capacity":"unavailable","tokens":{"status":"none"}})
	.to_string()
}

fn receipt_body(receipt_id: i64, verdict: &str, finding_state: &str) -> String {
	let mut summary = json!({"version":1,"finding_id":5,"verification_id":9,"verdict":verdict,
		"finding_state":finding_state});
	if verdict == "inconclusive" {
		summary["continuation"] = json!({"state":"blocked","class":"awaiting_proof_infrastructure",
			"revision":1,"logical_sequence":1,"reason":"awaiting_proof_infrastructure"});
	}
	json!({"protocol_version":3,"receipt":{"receipt_id":receipt_id,"job_id":7,"commit_sha":SHA,
		"result_digest":DIGEST,"summary":summary}})
	.to_string()
}

fn phase(offset: Duration, cancel: tokio_util::sync::CancellationToken) -> PhaseSession {
	let now = SystemTime::now();
	PhaseSession::new(
		7,
		JobCapability::from_secret("verify-capability"),
		now + Duration::from_secs(600),
		now + Duration::from_secs(1200),
		Arc::new(move || SystemTime::now() + offset),
		cancel,
	)
}

fn context(server: &FakePhase, scope: McpScope) -> McpSessionContext {
	McpSessionContext {
		security: crate::canary::JobSecurity::new(Default::default(), Vec::new()).unwrap(),
		tool_boundary: crate::llm::prompt::JobToolBoundary::from_test_bytes([0x22; 16]),
		client: server.client(),
		job_capability: JobCapability::from_secret("verify-capability"),
		repo_id: 1,
		scope,
		workdir: PathBuf::from("/nonexistent"),
	}
}

async fn fixture(offset: Duration) -> Fixture {
	let server = FakePhase::start().await;
	let cancel = tokio_util::sync::CancellationToken::new();
	let heartbeat = tokio_util::sync::CancellationToken::new();
	let verify = Arc::new(
		VerifySession::new(phase(offset, cancel.clone()), 5, None)
			.with_heartbeat(heartbeat.clone()),
	);
	let context = context(&server, McpScope::Phase(PhaseTools::Verify(verify.clone())));
	Fixture { server, verify, context, cancel, heartbeat }
}

fn verified() -> Value {
	json!({"verdict": "verified", "e2e_rationale": "No runtime surface.",
		"evidence": {"l2_argument": {"attacker_source": "Request body", "control": "Length",
			"sink": "allocation", "reachable_path": "handler to parse",
			"trust_boundary": "network"},
		"material_locations": [{"role": "sink", "file": "src/lib.rs", "line_start": 3}],
		"counterevidence": "No bound.", "assumptions_gaps": "Defaults.",
		"confidence": "medium"}})
}

fn rejected() -> Value {
	json!({"verdict": "rejected", "counterargument": {"argument": "The bound is checked.",
		"source_refs": [{"path": "src/lib.rs"}]}})
}

fn awaiting_proof() -> Value {
	json!({"verdict": "inconclusive", "continuation": "awaiting_proof_infrastructure"})
}

fn routes(server: &FakePhase) -> Vec<String> {
	server.seen().iter().map(|s| s.head.split(' ').nth(1).unwrap().to_owned()).collect()
}

fn status(response: &Value) -> String {
	text(response).lines().last().unwrap().to_owned()
}

const AUTHORITY_LOST: &str = "this verification attempt no longer has authority";

#[tokio::test]
async fn the_catalog_has_two_closed_tools_at_protocol_version_2() {
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
	assert_eq!(names, ["get_job_limits", "finalize_verification"]);
	for tool in tools {
		assert_eq!(tool["inputSchema"]["properties"]["protocol_version"]["const"], json!(2));
	}
	let schema = &tools[1]["inputSchema"];
	assert_eq!(schema["required"], json!(["verdict"]));
	assert_eq!(schema["additionalProperties"], json!(false));
	let properties: Vec<_> = schema["properties"].as_object().unwrap().keys().collect();
	let mut sorted = properties.clone();
	sorted.sort();
	assert_eq!(
		sorted,
		[
			"blocker",
			"continuation",
			"counterargument",
			"e2e_rationale",
			"evidence",
			"notes",
			"partial_evidence",
			"protocol_version",
			"retry_explanation",
			"revalidation",
			"verdict"
		]
	);
	let properties = &schema["properties"];
	assert_eq!(properties["verdict"]["enum"], json!(["verified", "rejected", "inconclusive"]));
	assert_eq!(properties["e2e_rationale"]["maxLength"], json!(2000));
	assert_eq!(properties["blocker"]["maxLength"], json!(2000));
	assert_eq!(properties["notes"]["maxLength"], json!(4000));
	assert_eq!(properties["retry_explanation"]["maxLength"], json!(1000));
	assert_eq!(properties["counterargument"]["properties"]["argument"]["maxLength"], json!(8000));
	assert_eq!(properties["partial_evidence"]["properties"]["argument"]["maxLength"], json!(4000));
	for nested in ["evidence", "counterargument", "partial_evidence", "revalidation"] {
		assert_eq!(properties[nested]["additionalProperties"], json!(false), "{nested}");
	}
	assert_eq!(schema["type"], json!("object"));
	assert_eq!(
		properties["continuation"]["enum"],
		json!([
			"source_analysis_remaining",
			"awaiting_proof_infrastructure",
			"external_dependency",
			"requires_successor"
		])
	);
	let described = |name: &str| properties[name]["description"].as_str().unwrap_or_default();
	for rule in [
		"verified requires e2e_rationale and evidence",
		"rejected requires counterargument",
		"inconclusive requires continuation",
		"blocker unless continuation is awaiting_proof_infrastructure",
	] {
		assert!(described("verdict").contains(rule), "{rule}");
	}
	assert!(described("blocker").contains("refused with awaiting_proof_infrastructure"));
	for (name, verdict) in [
		("e2e_rationale", "verified"),
		("evidence", "verified"),
		("counterargument", "rejected"),
		("continuation", "inconclusive"),
		("blocker", "inconclusive"),
		("partial_evidence", "inconclusive"),
		("retry_explanation", "inconclusive"),
	] {
		assert!(described(name).contains(&format!("verdict {verdict} only")), "{name}");
	}
	// The agent is never asked for a host-supplied value.
	for host in ["\"version\"", "established_rung", "e2e_applicability"] {
		assert!(!tools[1].to_string().contains(host), "{host}");
	}
}

/// Model tool APIs may refuse a schema with one of these at its root.
#[test]
fn no_tool_schema_has_a_combinator_at_its_root() {
	let catalogs = [drilldown_catalog::tools(), verify_catalog::tools()];
	for tool in catalogs.iter().flat_map(|catalog| catalog.as_array().unwrap()) {
		let schema = tool["inputSchema"].as_object().unwrap();
		assert_eq!(schema["type"], json!("object"));
		for combinator in ["oneOf", "anyOf", "allOf", "not"] {
			assert!(!schema.contains_key(combinator), "{combinator} in {}", tool["name"]);
		}
	}
}

#[test]
fn the_schema_names_every_continuation_class() {
	// A new class does not compile until it joins this walk.
	fn next(class: ContinuationClass) -> Option<ContinuationClass> {
		match class {
			ContinuationClass::SourceAnalysisRemaining => {
				Some(ContinuationClass::AwaitingProofInfrastructure)
			},
			ContinuationClass::AwaitingProofInfrastructure => {
				Some(ContinuationClass::ExternalDependency)
			},
			ContinuationClass::ExternalDependency => Some(ContinuationClass::RequiresSuccessor),
			ContinuationClass::RequiresSuccessor => None,
		}
	}
	let first = ContinuationClass::SourceAnalysisRemaining;
	let classes: Vec<_> = std::iter::successors(Some(first), |class| next(*class)).collect();
	assert_eq!(json!(classes), json!(CONTINUATIONS));
	assert_eq!(json!(ContinuationClass::AwaitingProofInfrastructure), json!(HOST_BLOCKED));
}

#[tokio::test]
async fn other_catalogs_tools_are_unknown_in_a_verify_session() {
	let names = [
		"query_same_project_lead_candidates",
		"submit_sibling_lead",
		"finalize_drilldown",
		"finalize_survey",
		"submit_lead",
		"submit_verdict",
		"submit_patch",
		"validate_patch",
		"submit_finding",
		"query_prior_findings",
		"get_finding_by_id",
	];
	let fixture = fixture(Duration::ZERO).await;
	let calls: Vec<_> = names.iter().zip(1..).map(|(name, id)| call(id, name, json!({}))).collect();
	let responses = run(fixture.context, &calls).await;
	for (response, name) in responses.iter().zip(names) {
		let expected = format!("Error: unknown tool: {name}");
		assert_eq!(text(response).lines().next(), Some(expected.as_str()));
	}
	assert!(fixture.server.seen().is_empty());
}

#[tokio::test]
async fn finalize_verification_is_unknown_in_every_other_session() {
	let server = FakePhase::start().await;
	let cancel = tokio_util::sync::CancellationToken::new();
	let survey = SurveySession::new(SurveySessionParts {
		job_id: 7,
		capability: JobCapability::from_secret("verify-capability"),
		recipe: RecipeClass::Ordinary,
		profile_published: true,
		submit_by: SystemTime::now() + Duration::from_secs(600),
		hard_deadline: SystemTime::now() + Duration::from_secs(1200),
		assignments: Vec::new(),
		limits: None,
		cancel: cancel.clone(),
	});
	let drilldown = DrilldownSession::new(phase(Duration::ZERO, cancel), 4, None);
	for scope in [
		McpScope::LegacyDiscovery { job_id: Some(7) },
		McpScope::LegacyVerify { job_id: 7, finding_id: 5 },
		McpScope::Phase(PhaseTools::Survey(Arc::new(survey))),
		McpScope::Phase(PhaseTools::Drilldown(Arc::new(drilldown))),
	] {
		let listed = tool_catalog(&scope).to_string();
		assert!(!listed.contains("finalize_verification"));
		let mut calls = vec![call(1, "finalize_verification", rejected())];
		if matches!(scope, McpScope::LegacyVerify { .. }) {
			// A legacy verify session only ends cleanly with a verdict.
			server.reply("/verdict", 204, "");
			let verdict = json!({"verdict": "dismissed", "notes": "Checked."});
			calls.push(call(2, "submit_verdict", verdict));
		}
		let responses = run(context(&server, scope), &calls).await;
		assert_eq!(
			text(&responses[0]).lines().next(),
			Some("Error: unknown tool: finalize_verification")
		);
	}
	assert_eq!(routes(&server), ["/v1/jobs/7/verdict"]);
}

#[tokio::test]
async fn every_tool_reaches_its_route_and_the_receipt_is_sealed() {
	let cases = [
		(verified(), "verified", "confirmed"),
		(verified(), "verified", "awaiting_approval"),
		(rejected(), "rejected", "dismissed"),
		(awaiting_proof(), "inconclusive", "validating"),
	];
	for (arguments, verdict, state) in cases {
		let fixture = fixture(Duration::ZERO).await;
		fixture.server.reply("/limits", 200, limits_body());
		fixture.server.reply("/finalize-verification", 200, receipt_body(21, verdict, state));
		let responses = run(
			fixture.context,
			&[call(1, "get_job_limits", json!({})), call(2, "finalize_verification", arguments)],
		)
		.await;
		for response in &responses {
			assert!(!is_error(response), "{}", text(response));
			assert!(status(response).starts_with("[loupe status] submit_by: "));
			assert!(!status(response).contains("remaining:"), "{}", status(response));
		}
		assert!(text(&responses[0]).contains(r#""campaign_verification_remaining":2"#));
		assert!(
			text(&responses[1]).starts_with(&format!(
				"verification finalized as {verdict}: receipt_id=21; finding is {state}; the session is complete, end it now\n"
			)),
			"{}",
			text(&responses[1])
		);
		assert!(fixture.verify.phase().limits().is_some());
		assert!(fixture.heartbeat.is_cancelled());
		assert!(!fixture.cancel.is_cancelled());
		assert!(PhaseTools::Verify(fixture.verify.clone()).sealed());
		let seen = fixture.server.seen();
		let heads: Vec<_> =
			seen.iter().map(|s| s.head.split(' ').take(2).collect::<Vec<_>>()).collect();
		assert_eq!(
			heads,
			[["GET", "/v1/jobs/7/limits"], ["POST", "/v1/jobs/7/finalize-verification"]]
		);
		let body = &seen[1].body;
		assert_eq!(body["protocol_version"], json!(3));
		assert_eq!(body["payload"]["verdict"], json!(verdict));
		assert_eq!(body["payload"]["version"], json!(1));
		match verdict {
			"verified" => {
				assert_eq!(body["payload"]["established_rung"], json!("L2"));
				assert_eq!(body["payload"]["e2e_applicability"], json!("not_applicable"));
				assert_eq!(body["payload"]["evidence"]["version"], json!(1));
			},
			"inconclusive" => assert_eq!(
				body["payload"]["blocker"],
				json!(loupe_core::review_payload::AWAITING_PROOF_INFRASTRUCTURE)
			),
			_ => {},
		}
	}
}

#[tokio::test]
async fn finalize_refusals_reach_the_model_as_fixed_text_and_leave_it_open() {
	let cases = [
		(409, "revalidation_required", REVALIDATION_REQUIRED),
		(409, "incompatible_review_state", INCOMPATIBLE_STATE),
		(400, "invalid_request", INVALID),
		(
			409,
			"terminal_conflict",
			"the verification is already finalized with a different payload; it cannot be finalized again; end the session",
		),
		(409, "state_conflict", "the server rejected the request in the finding's current state"),
	];
	for (status, code, expected) in cases {
		let fixture = fixture(Duration::ZERO).await;
		fixture.server.reply("/finalize-verification", status, error_body(code, None));
		fixture.server.reply(
			"/finalize-verification",
			200,
			receipt_body(21, "rejected", "dismissed"),
		);
		let responses = run(
			fixture.context,
			&[
				call(1, "finalize_verification", verified()),
				call(2, "finalize_verification", rejected()),
			],
		)
		.await;
		assert!(is_error(&responses[0]), "{code}");
		assert_eq!(text(&responses[0]).lines().next(), Some(&*format!("Error: {expected}")));
		assert!(!is_error(&responses[1]), "{code}: a refused finalize seals nothing");
		assert!(!fixture.verify.phase().authority_lost(), "{code}");
		assert!(!fixture.cancel.is_cancelled(), "{code}");
	}
	assert!(REVALIDATION_REQUIRED.contains("`revalidation`"));
	assert!(INVALID.contains("pinned checkout exactly as written"));
	assert!(INCOMPATIBLE_STATE.contains("end the session"));
}

#[tokio::test]
async fn every_403_loses_authority_without_a_probe() {
	for code in [
		"denied",
		"invalid_request",
		"revalidation_required",
		"incompatible_review_state",
		"terminal_conflict",
		"not_found",
		"checkpoint_limit",
		"internal_error",
	] {
		for (tool, arguments, route) in [
			("finalize_verification", verified(), "/finalize-verification"),
			("get_job_limits", json!({}), "/limits"),
		] {
			let fixture = fixture(Duration::ZERO).await;
			fixture.server.reply(route, 403, error_body(code, None));
			fixture.server.reply("/limits", 200, limits_body());
			let responses = run(fixture.context, &[call(1, tool, arguments)]).await;
			assert!(is_error(&responses[0]));
			assert!(
				text(&responses[0]).contains(AUTHORITY_LOST),
				"{code}: {}",
				text(&responses[0])
			);
			assert!(text(&responses[0]).contains("end the session"));
			assert!(fixture.verify.phase().authority_lost(), "{tool} {code}");
			assert!(fixture.cancel.is_cancelled(), "{tool} {code}: the agent is stopped");
			assert!(fixture.verify.receipt().is_none());
			assert_eq!(routes(&fixture.server), [format!("/v1/jobs/7{route}")], "{code}: no probe");
		}
	}
	// A 403 whose body is not a phase error ends the session too.
	let fixture = fixture(Duration::ZERO).await;
	fixture.server.reply("/finalize-verification", 403, SENTINEL);
	let responses = run(fixture.context, &[call(1, "finalize_verification", verified())]).await;
	assert!(text(&responses[0]).contains(AUTHORITY_LOST));
	assert!(!text(&responses[0]).contains(SENTINEL));
	assert!(fixture.cancel.is_cancelled());
}

#[tokio::test]
async fn an_unreachable_server_is_retried_with_the_identical_call() {
	let fixture = fixture(Duration::ZERO).await;
	let responses = run(
		fixture.context,
		&[call(1, "finalize_verification", verified()), call(2, "get_job_limits", json!({}))],
	)
	.await;
	let first = |response: &Value| text(response).lines().next().unwrap().to_owned();
	assert!(responses.iter().all(is_error));
	assert_eq!(first(&responses[0]), format!("Error: {FINALIZE_UNREACHABLE}"));
	assert!(FINALIZE_UNREACHABLE.contains("retry the identical finalize_verification call"));
	assert_eq!(
		first(&responses[1]),
		"Error: the server could not be reached after retries; retry later"
	);
	assert!(!fixture.cancel.is_cancelled());
	assert!(fixture.verify.receipt().is_none());
}

#[tokio::test]
async fn submit_by_closes_no_verify_tool() {
	let fixture = fixture(Duration::from_secs(900)).await;
	fixture.server.reply("/limits", 200, limits_body());
	fixture.server.reply(
		"/finalize-verification",
		200,
		receipt_body(21, "inconclusive", "validating"),
	);
	let responses = run(
		fixture.context,
		&[call(1, "get_job_limits", json!({})), call(2, "finalize_verification", awaiting_proof())],
	)
	.await;
	for response in &responses {
		assert!(!is_error(response), "{}", text(response));
		assert!(status(response).contains("submit_by: passed"));
	}
}

#[tokio::test]
async fn after_a_seal_the_server_decides_a_replay_and_the_first_receipt_stands() {
	let fixture = fixture(Duration::ZERO).await;
	fixture.server.reply("/finalize-verification", 200, receipt_body(21, "rejected", "dismissed"));
	fixture.server.reply("/finalize-verification", 200, receipt_body(22, "rejected", "dismissed"));
	fixture.server.reply("/finalize-verification", 409, error_body("terminal_conflict", None));
	fixture.server.reply("/limits", 200, limits_body());
	let responses = run(
		fixture.context,
		&[
			call(1, "finalize_verification", rejected()),
			call(2, "finalize_verification", rejected()),
			call(3, "finalize_verification", verified()),
			call(4, "get_job_limits", json!({})),
		],
	)
	.await;
	assert!(!is_error(&responses[0]));
	assert!(!is_error(&responses[1]));
	assert!(text(&responses[2]).contains("already finalized with a different payload"));
	assert!(!is_error(&responses[3]));
	assert_eq!(
		fixture.verify.receipt().map(|r| i64::from(r.receipt.receipt_id)),
		Some(21),
		"the first receipt stands"
	);
	let finalize = "/v1/jobs/7/finalize-verification";
	assert_eq!(routes(&fixture.server), [finalize, finalize, finalize, "/v1/jobs/7/limits"]);
}

#[tokio::test]
async fn unknown_and_host_owned_arguments_never_reach_the_server() {
	let fixture = fixture(Duration::ZERO).await;
	let mut rung = verified();
	rung["established_rung"] = json!("L2");
	let mut versioned = rejected();
	versioned["version"] = json!(1);
	let mut blocker = awaiting_proof();
	blocker["blocker"] = json!("awaiting proof infrastructure");
	let responses = run(
		fixture.context,
		&[
			call(1, "finalize_verification", rung),
			call(2, "finalize_verification", versioned),
			call(3, "finalize_verification", blocker),
			call(4, "get_job_limits", json!({"owner": 1})),
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
