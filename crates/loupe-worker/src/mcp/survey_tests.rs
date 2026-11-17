//! In-process survey MCP sessions against a route-scripted phase server.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::review::gate::{RecipeClass, PROFILE_FIRST, SEALED, SOFT_STOP};
use crate::review::session::{SurveySession, SurveySessionParts};

pub(super) const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub(super) const DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub(super) const SENTINEL: &str = "server-body-sentinel";

pub(super) struct Seen {
	pub(super) head: String,
	pub(super) body: Value,
}

type Replies = Arc<Mutex<Vec<(&'static str, VecDeque<(u16, String)>)>>>;

/// Answers each request by the first route whose path suffix matches, in
/// the order the replies were queued for that route.
pub(super) struct FakePhase {
	base: reqwest::Url,
	replies: Replies,
	seen: Arc<Mutex<Vec<Seen>>>,
}

impl FakePhase {
	pub(super) async fn start() -> Self {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let base = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
		let replies: Replies = Arc::default();
		let seen = Arc::new(Mutex::new(Vec::new()));
		let (routes, record) = (replies.clone(), seen.clone());
		tokio::spawn(async move {
			loop {
				let (mut stream, _) = listener.accept().await.unwrap();
				let mut request = Vec::new();
				let (head, body) = loop {
					let mut buf = [0; 8192];
					let read = stream.read(&mut buf).await.unwrap();
					if read == 0 {
						break (String::new(), Vec::new());
					}
					request.extend_from_slice(&buf[..read]);
					let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
						continue;
					};
					let head = String::from_utf8(request[..end].to_vec()).unwrap();
					let length: usize = head
						.lines()
						.find_map(|line| {
							let (name, value) = line.split_once(':')?;
							name.eq_ignore_ascii_case("content-length")
								.then(|| value.trim().parse().unwrap())
						})
						.unwrap_or(0);
					if request.len() >= end + 4 + length {
						break (head, request[end + 4..end + 4 + length].to_vec());
					}
				};
				if head.is_empty() {
					continue;
				}
				let path = head.split(' ').nth(1).unwrap_or_default().to_owned();
				let path = path.split('?').next().unwrap_or_default().to_owned();
				let (status, reply) = {
					let mut routes = routes.lock().unwrap();
					routes
						.iter_mut()
						.find(|(route, queue)| path.ends_with(route) && !queue.is_empty())
						.and_then(|(_, queue)| queue.pop_front())
						.unwrap_or((500, error_body("internal_error", None)))
				};
				record.lock().unwrap().push(Seen {
					head,
					body: serde_json::from_slice(&body).unwrap_or(Value::Null),
				});
				let response = format!(
					"HTTP/1.1 {status} X\r\nX-Loupe-Protocol: 3\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
					reply.len()
				);
				let _ = stream.write_all(response.as_bytes()).await;
			}
		});
		Self { base, replies, seen }
	}

	pub(super) fn reply(&self, route: &'static str, status: u16, body: impl Into<String>) {
		let mut replies = self.replies.lock().unwrap();
		match replies.iter_mut().find(|(r, _)| *r == route) {
			Some((_, queue)) => queue.push_back((status, body.into())),
			None => replies.push((route, VecDeque::from([(status, body.into())]))),
		}
	}

	pub(super) fn seen(&self) -> Vec<Seen> {
		std::mem::take(&mut *self.seen.lock().unwrap())
	}

	pub(super) fn client(&self) -> Arc<ServerClient> {
		Arc::new(ServerClient::from_parts(reqwest::Client::new(), self.base.clone()))
	}
}

pub(super) fn error_body(code: &str, current_revision: Option<i64>) -> String {
	match current_revision {
		Some(revision) => format!(
			r#"{{"protocol_version":3,"error":{{"code":"{code}","detail":null,"current_revision":{revision}}}}}"#
		),
		None => format!(r#"{{"protocol_version":3,"error":{{"code":"{code}","detail":null}}}}"#),
	}
}

fn limits_body(units: u32, leads: u32) -> String {
	json!({"protocol_version":3,"soft_deadline_at":100,"submit_by":100,"hard_deadline_at":200,
		"remaining_seconds":60,"new_units":{"limit":32,"remaining":units},
		"leads":{"limit":16,"remaining":leads},"siblings":{"limit":4,"remaining":4},
		"candidate_queries":{"limit":8,"remaining":7},"campaign_jobs_limit":10,
		"campaign_jobs_admitted":2,"campaign_general_remaining":5,
		"campaign_urgent_remaining":1,"campaign_verification_remaining":2,
		"proof_capacity":"unavailable","artifact_capacity":"unavailable",
		"output_capacity":"unavailable","tokens":{"status":"none"}})
	.to_string()
}

fn finalize_body() -> String {
	json!({"protocol_version":3,"receipt":{"receipt_id":11,"job_id":7,"commit_sha":SHA,
		"result_digest":DIGEST,"terminal_reason":"completed","summary":{"version":1,
		"coverage":"complete","corroboration_satisfied":true,"missing_results":0,
		"needs_follow_up":0,"unresolved_inventory":0,"follow_up_batches":0,
		"follow_up_units":0}}})
	.to_string()
}

struct Fixture {
	server: FakePhase,
	survey: Arc<SurveySession>,
	context: McpSessionContext,
}

/// The catalog a fixture's session serves.
// debug-ok: test-only selector without agent text.
#[derive(Debug, Clone, Copy)]
enum SurveyRecipe {
	Bootstrap { profile_published: bool },
	Ordinary,
}

async fn fixture(recipe: SurveyRecipe, offset: Duration) -> Fixture {
	let server = FakePhase::start().await;
	let now = SystemTime::now();
	let (class, published, assignments) = match recipe {
		SurveyRecipe::Bootstrap { profile_published } => {
			(RecipeClass::Bootstrap, profile_published, Vec::new())
		},
		SurveyRecipe::Ordinary => (RecipeClass::Ordinary, true, vec![(5, 2)]),
	};
	let survey = Arc::new(SurveySession::with_clock(
		SurveySessionParts {
			job_id: 7,
			capability: JobCapability::from_secret("survey-capability"),
			recipe: class,
			profile_published: published,
			submit_by: now + Duration::from_secs(600),
			hard_deadline: now + Duration::from_secs(1200),
			assignments,
			limits: None,
			cancel: tokio_util::sync::CancellationToken::new(),
		},
		Arc::new(move || SystemTime::now() + offset),
	));
	let context = McpSessionContext {
		security: crate::canary::JobSecurity::new(Default::default(), Vec::new()).unwrap(),
		tool_boundary: crate::llm::prompt::JobToolBoundary::from_test_bytes([0x22; 16]),
		client: server.client(),
		job_capability: JobCapability::from_secret("survey-capability"),
		repo_id: 1,
		mode: McpMode::Survey,
		workdir: PathBuf::from("/nonexistent"),
		phase: Some(crate::mcp::PhaseTools::Survey(survey.clone())),
	};
	Fixture { server, survey, context }
}

pub(super) fn call(id: u64, name: &str, arguments: Value) -> Value {
	json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}})
}

pub(super) async fn run(context: McpSessionContext, requests: &[Value]) -> Vec<Value> {
	let input: String = requests.iter().map(|request| format!("{request}\n")).collect();
	let mut output = Vec::new();
	run_stream_server(context, input.as_bytes(), &mut output).await.unwrap();
	String::from_utf8(output)
		.unwrap()
		.lines()
		.map(|line| serde_json::from_str(line).unwrap())
		.collect()
}

pub(super) fn text(response: &Value) -> &str {
	response["result"]["content"][0]["text"].as_str().unwrap()
}

pub(super) fn is_error(response: &Value) -> bool {
	response["result"]["isError"] == json!(true)
}

fn lead_arguments(key: &str) -> Value {
	json!({"client_lead_key": key, "identity_family": "memory-safety", "identity_anchor": "parse",
		"review_unit_id": 5, "hypothesis": "Length unchecked.",
		"source_refs": [{"path": "src/lib.rs"}], "next_proof_step": "Test it.",
		"counterevidence": "None.", "proof_gaps": "Reachability."})
}

fn unit_arguments() -> Value {
	json!({"client_review_unit_key": "unit-1", "title": "Parser", "objective": "Review it.",
		"priority_band": "high", "source_refs": [{"path": "src/lib.rs"}]})
}

fn names(list: &Value) -> Vec<&str> {
	list["result"]["tools"]
		.as_array()
		.unwrap()
		.iter()
		.map(|t| t["name"].as_str().unwrap())
		.collect()
}

#[tokio::test]
async fn catalog_follows_the_recipe_and_speaks_protocol_version_2() {
	let common = [
		"get_job_limits",
		"propose_review_unit",
		"submit_lead",
		"submit_review_unit_result",
		"submit_inventory_disposition",
		"query_same_project_lead_candidates",
		"finalize_survey",
	];
	for (recipe, publish) in [
		(SurveyRecipe::Ordinary, false),
		(SurveyRecipe::Bootstrap { profile_published: true }, false),
		(SurveyRecipe::Bootstrap { profile_published: false }, true),
	] {
		let fixture = fixture(recipe, Duration::ZERO).await;
		let responses = run(
			fixture.context,
			&[
				json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
				json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
			],
		)
		.await;
		assert_eq!(responses[0]["result"]["_meta"]["loupeProtocolVersion"], json!(2));
		assert_eq!(responses[1]["result"]["_meta"]["loupeProtocolVersion"], json!(2));
		let mut expected = common.to_vec();
		if publish {
			expected.insert(1, "publish_profile");
		}
		assert_eq!(names(&responses[1]), expected, "{recipe:?}");
		for tool in responses[1]["result"]["tools"].as_array().unwrap() {
			let version = &tool["inputSchema"]["properties"]["protocol_version"];
			assert_eq!(version["const"], json!(2), "{}", tool["name"]);
		}
	}
}

#[tokio::test]
async fn survey_calls_require_protocol_version_2() {
	let fixture = fixture(SurveyRecipe::Ordinary, Duration::ZERO).await;
	let responses =
		run(fixture.context, &[call(1, "get_job_limits", json!({"protocol_version": 1}))]).await;
	assert!(is_error(&responses[0]));
	assert!(text(&responses[0]).contains("worker supports 2"), "{}", text(&responses[0]));
	assert!(fixture.server.seen().is_empty());
}

#[tokio::test]
async fn legacy_tools_are_unknown_in_a_survey_session() {
	let fixture = fixture(SurveyRecipe::Ordinary, Duration::ZERO).await;
	let responses = run(fixture.context, &[call(1, "submit_finding", json!({"title": "x"}))]).await;
	assert_eq!(text(&responses[0]), "Error: unknown tool: submit_finding");
}

#[tokio::test]
async fn bootstrap_writes_are_denied_until_the_profile_is_published() {
	let fixture =
		fixture(SurveyRecipe::Bootstrap { profile_published: false }, Duration::ZERO).await;
	fixture.server.reply(
		"/publish-profile",
		200,
		format!(r#"{{"protocol_version":3,"profile_version":1,"profile_digest":"{DIGEST}"}}"#),
	);
	fixture.server.reply(
		"/review-units",
		200,
		json!({"protocol_version":3,"review_unit_id":5,
		"assignment_epoch":0,"accepted_priority_band":"high"})
		.to_string(),
	);
	let responses = run(
		fixture.context,
		&[
			call(1, "propose_review_unit", unit_arguments()),
			call(2, "publish_profile", json!({"profile": {"purpose": "test"}})),
			call(3, "publish_profile", json!({"profile": {"purpose": "again"}})),
			call(4, "propose_review_unit", unit_arguments()),
		],
	)
	.await;
	assert!(is_error(&responses[0]));
	assert!(text(&responses[0]).starts_with(&format!("Error: {PROFILE_FIRST}")));
	assert!(!is_error(&responses[1]), "{}", text(&responses[1]));
	assert!(is_error(&responses[2]));
	assert!(!is_error(&responses[3]), "{}", text(&responses[3]));
	assert!(text(&responses[3]).contains("review_unit_id=5"));
	let seen = fixture.server.seen();
	assert_eq!(seen.len(), 2, "denied calls must not reach the server");
	assert!(seen[0].head.contains("/v1/jobs/7/publish-profile"));
	assert_eq!(seen[0].body["profile"], json!({"purpose": "test"}));
	assert!(fixture.survey.profile_published());
	// The proposed unit's epoch now pairs with a lead on it.
	assert_eq!(fixture.survey.epoch(5), Some(0));
}

#[tokio::test]
async fn every_survey_result_ends_with_the_host_status_line() {
	let fixture = fixture(SurveyRecipe::Ordinary, Duration::ZERO).await;
	fixture.server.reply("/limits", 200, limits_body(30, 12));
	let responses = run(
		fixture.context,
		&[
			call(1, "get_job_limits", json!({})),
			call(2, "submit_review_unit_result", json!({"review_unit_id": "x"})),
		],
	)
	.await;
	for response in &responses {
		let last = text(response).lines().last().unwrap();
		assert!(last.starts_with("[loupe status] submit_by: "), "{last}");
		assert!(last.contains("s left"), "{last}");
		assert!(last.contains("review units remaining: 30; leads remaining: 12"), "{last}");
	}
	assert!(text(&responses[0]).contains(r#""new_units":{"limit":32,"remaining":30}"#));
	assert!(is_error(&responses[1]));
}

#[tokio::test]
async fn server_errors_reach_the_model_as_fixed_text() {
	let fixture = fixture(SurveyRecipe::Ordinary, Duration::ZERO).await;
	let mut conflict = error_body("checkpoint_conflict", None);
	conflict.insert_str(conflict.len() - 1, &format!(r#","{SENTINEL}":1"#));
	fixture.server.reply("/leads", 409, error_body("checkpoint_conflict", None));
	fixture.server.reply("/leads", 409, error_body("checkpoint_limit", None));
	fixture.server.reply("/leads", 403, error_body("denied", None));
	fixture.server.reply("/limits", 403, error_body("denied", None));
	fixture.server.reply("/review-units", 409, conflict);
	let responses = run(
		fixture.context,
		&[
			call(1, "submit_lead", lead_arguments("lead-1")),
			call(2, "submit_lead", lead_arguments("lead-2")),
			call(3, "submit_lead", lead_arguments("lead-3")),
			call(4, "propose_review_unit", unit_arguments()),
		],
	)
	.await;
	assert!(text(&responses[0]).contains("already used with different content"));
	assert!(text(&responses[1]).contains("call finalize_survey"));
	assert!(text(&responses[2]).contains("no longer has authority"));
	assert!(fixture.survey.phase().authority_lost());
	for response in &responses {
		assert!(is_error(response));
		assert!(!text(response).contains(SENTINEL));
	}
	let seen = fixture.server.seen();
	assert_eq!(seen[0].body["evidence"]["review_unit_id"], json!(5));
	assert_eq!(seen[0].body["evidence"]["assignment_epoch"], json!(2));
	assert_eq!(seen[0].body["evidence"]["format"], json!("loupe.lead_evidence"));
}

#[tokio::test]
async fn ordinary_results_need_a_known_unit_and_carry_its_epoch() {
	let fixture = fixture(SurveyRecipe::Ordinary, Duration::ZERO).await;
	fixture.server.reply(
		"/review-unit-results",
		200,
		json!({"protocol_version":3,"result_id":9,
		"review_unit_id":5,"assignment_epoch":2,"disposition":"no_lead_found"})
		.to_string(),
	);
	let result = |unit: i64| {
		json!({"client_result_key": format!("r-{unit}"), "review_unit_id": unit,
			"disposition": "no_lead_found", "inspected_refs": [{"path": "src/lib.rs"}],
			"counterevidence": "Checked.", "proof_gaps": "None."})
	};
	let responses = run(
		fixture.context,
		&[
			call(1, "submit_review_unit_result", result(6)),
			call(2, "submit_review_unit_result", result(5)),
		],
	)
	.await;
	assert!(is_error(&responses[0]));
	assert!(text(&responses[0]).contains("not a unit assigned to or proposed by this survey"));
	assert!(!is_error(&responses[1]), "{}", text(&responses[1]));
	let seen = fixture.server.seen();
	assert_eq!(seen.len(), 1);
	assert_eq!(seen[0].body["result"]["assignment_epoch"], json!(2));
	assert_eq!(seen[0].body["client_result_key"], json!("r-5"));
}

#[tokio::test]
async fn inventory_revisions_follow_responses_and_conflicts() {
	let fixture = fixture(SurveyRecipe::Ordinary, Duration::ZERO).await;
	let disposition = |key: &str| {
		json!({"client_inventory_disposition_key": key, "path": "src/lib.rs",
			"disposition": "mapped", "mapped_review_unit_ids": [5]})
	};
	fixture.server.reply(
		"/inventory-dispositions",
		200,
		r#"{"protocol_version":3,"inventory_entry_id":3,"revision":3}"#,
	);
	fixture.server.reply(
		"/inventory-dispositions",
		409,
		error_body("inventory_revision_conflict", Some(7)),
	);
	fixture.server.reply(
		"/inventory-dispositions",
		200,
		r#"{"protocol_version":3,"inventory_entry_id":3,"revision":8}"#,
	);
	let responses = run(
		fixture.context,
		&[
			call(1, "submit_inventory_disposition", disposition("d-1")),
			call(2, "submit_inventory_disposition", disposition("d-2")),
			call(3, "submit_inventory_disposition", disposition("d-3")),
		],
	)
	.await;
	assert!(!is_error(&responses[0]));
	assert!(is_error(&responses[1]));
	assert!(text(&responses[1]).contains("now at revision 7"), "{}", text(&responses[1]));
	assert!(!is_error(&responses[2]));
	let seen = fixture.server.seen();
	assert_eq!(seen.len(), 3, "a revision conflict is reported, not resent by the host");
	let expected: Vec<_> = seen.iter().map(|s| s.body["expected_revision"].clone()).collect();
	assert_eq!(expected, [json!(0), json!(3), json!(7)]);
	assert_eq!(seen[0].body["mappings"], json!([{"review_unit_id":5,"assignment_epoch":2}]));
	assert_eq!(fixture.survey.revision("src/lib.rs"), 8);
}

#[tokio::test]
async fn a_sealed_receipt_denies_further_writes() {
	let fixture = fixture(SurveyRecipe::Ordinary, Duration::ZERO).await;
	fixture.server.reply("/finalize-survey", 200, finalize_body());
	fixture.server.reply("/finalize-survey", 200, finalize_body());
	fixture.server.reply("/limits", 200, limits_body(1, 1));
	let finalize = json!({"terminal_reason": "completed"});
	let responses = run(
		fixture.context,
		&[
			call(1, "finalize_survey", finalize.clone()),
			call(2, "submit_lead", lead_arguments("late")),
			call(3, "propose_review_unit", unit_arguments()),
			call(4, "finalize_survey", finalize),
			call(5, "get_job_limits", json!({})),
		],
	)
	.await;
	assert!(text(&responses[0]).contains("receipt_id=11"));
	for denied in &responses[1..3] {
		assert!(text(denied).starts_with(&format!("Error: {SEALED}")));
	}
	assert!(!is_error(&responses[3]));
	assert!(!is_error(&responses[4]));
	let routes: Vec<_> = fixture
		.server
		.seen()
		.iter()
		.map(|s| s.head.split(' ').nth(1).unwrap().to_owned())
		.collect();
	assert_eq!(
		routes,
		["/v1/jobs/7/finalize-survey", "/v1/jobs/7/finalize-survey", "/v1/jobs/7/limits"]
	);
	assert_eq!(fixture.survey.receipt().map(|r| i64::from(r.receipt.receipt_id)), Some(11));
}

#[tokio::test]
async fn soft_stop_closes_new_inquiry_but_not_leads() {
	let fixture = fixture(SurveyRecipe::Ordinary, Duration::from_secs(900)).await;
	fixture.server.reply(
		"/leads",
		200,
		json!({"protocol_version":3,"lead_id":4,"outcome":"created",
		"observation_id":null,"accepted_priority":{"band":"urgent","score":90}})
		.to_string(),
	);
	let responses = run(
		fixture.context,
		&[
			call(1, "propose_review_unit", unit_arguments()),
			call(2, "query_same_project_lead_candidates", json!({"query": "parse"})),
			call(3, "submit_lead", lead_arguments("lead-1")),
		],
	)
	.await;
	for denied in &responses[..2] {
		assert!(text(denied).starts_with(&format!("Error: {SOFT_STOP}")));
		assert!(text(denied).contains("submit_by: passed"));
	}
	assert!(!is_error(&responses[2]), "{}", text(&responses[2]));
	assert_eq!(fixture.server.seen().len(), 1);
}

#[tokio::test]
async fn candidates_are_framed_with_the_job_tool_boundary() {
	let fixture = fixture(SurveyRecipe::Ordinary, Duration::ZERO).await;
	fixture.server.reply(
		"/lead-candidates",
		200,
		json!({"protocol_version":3,"candidates":[{
		"kind":"lead","id":4,"producer_job_id":3,"commit_sha":SHA,"created_at":10,
		"identity_family":"memory-safety","identity_anchor":"parse","identity_instance_key":null}]})
		.to_string(),
	);
	let responses = run(
		fixture.context,
		&[call(1, "query_same_project_lead_candidates", json!({"query": "parse", "limit": 3}))],
	)
	.await;
	let text = text(&responses[0]);
	let boundary = "22".repeat(16);
	assert!(
		text.contains(&format!(
			r#"<loupe-data field="candidates" source="agent" boundary="{boundary}">"#
		)),
		"{text}"
	);
	assert!(text.contains(r#""identity_anchor":"parse""#), "{text}");
	let seen = fixture.server.seen();
	assert!(seen[0].head.starts_with("GET /v1/jobs/7/lead-candidates?query=parse&limit=3 "));
}

#[tokio::test]
async fn the_broker_fails_closed_when_mode_and_survey_state_disagree() {
	let fixture = fixture(SurveyRecipe::Ordinary, Duration::ZERO).await;
	let mut context = fixture.context;
	context.phase = None;
	assert!(run_stream_server(context, &b""[..], Vec::new()).await.is_err());

	let fixture = super::survey_tests::fixture(SurveyRecipe::Ordinary, Duration::ZERO).await;
	let mut context = fixture.context;
	context.mode = McpMode::LegacyDiscovery { job_id: Some(7) };
	assert!(run_stream_server(context, &b""[..], Vec::new()).await.is_err());
}

#[tokio::test]
async fn a_refused_reference_is_told_apart_from_lost_authority() {
	let fixture = fixture(SurveyRecipe::Ordinary, Duration::ZERO).await;
	fixture.server.reply("/leads", 403, error_body("denied", None));
	fixture.server.reply("/limits", 200, limits_body(3, 4));
	fixture.server.reply("/leads", 403, "not an envelope");
	fixture.server.reply("/limits", 200, limits_body(3, 4));
	let responses = run(
		fixture.context,
		&[
			call(1, "submit_lead", lead_arguments("lead-1")),
			call(2, "submit_lead", lead_arguments("lead-2")),
		],
	)
	.await;
	for response in &responses {
		assert!(is_error(response));
		assert!(text(response).contains("refused a referenced unit"), "{}", text(response));
		assert!(text(response).contains("review units remaining: 3; leads remaining: 4"));
	}
	assert!(!fixture.survey.phase().authority_lost());
	let routes: Vec<_> = fixture
		.server
		.seen()
		.iter()
		.map(|s| s.head.split(' ').nth(1).unwrap().to_owned())
		.collect();
	assert_eq!(
		routes,
		["/v1/jobs/7/leads", "/v1/jobs/7/limits", "/v1/jobs/7/leads", "/v1/jobs/7/limits"]
	);
}

#[tokio::test]
async fn an_unrecoverable_revision_conflict_says_to_leave_the_entry() {
	let fixture = fixture(SurveyRecipe::Ordinary, Duration::ZERO).await;
	fixture.server.reply(
		"/inventory-dispositions",
		409,
		error_body("inventory_revision_conflict", Some(-1)),
	);
	let responses = run(
		fixture.context,
		&[call(
			1,
			"submit_inventory_disposition",
			json!({"client_inventory_disposition_key": "d-1", "path": "src/lib.rs",
				"disposition": "mapped", "mapped_review_unit_ids": [5]}),
		)],
	)
	.await;
	assert!(is_error(&responses[0]));
	assert!(text(&responses[0]).contains("leave this entry"), "{}", text(&responses[0]));
	assert_eq!(fixture.survey.revision("src/lib.rs"), 0);
}

#[tokio::test]
async fn capacity_counts_new_leads_once_and_follows_quota_refusals() {
	let fixture = fixture(SurveyRecipe::Ordinary, Duration::ZERO).await;
	fixture.server.reply("/limits", 200, limits_body(30, 12));
	let created = json!({"protocol_version":3,"lead_id":4,"outcome":"created",
		"observation_id":null,"accepted_priority":{"band":"urgent","score":90}})
	.to_string();
	fixture.server.reply("/leads", 200, created.clone());
	fixture.server.reply("/leads", 200, created);
	fixture.server.reply("/leads", 409, error_body("checkpoint_limit", None));
	fixture.server.reply("/review-units", 409, error_body("checkpoint_limit", None));
	let responses = run(
		fixture.context,
		&[
			call(1, "get_job_limits", json!({})),
			call(2, "submit_lead", lead_arguments("lead-1")),
			call(3, "submit_lead", lead_arguments("lead-1")),
			call(4, "submit_lead", lead_arguments("lead-2")),
			call(5, "propose_review_unit", unit_arguments()),
		],
	)
	.await;
	let status = |index: usize| text(&responses[index]).lines().last().unwrap().to_owned();
	assert!(status(2).contains("review units remaining: 30; leads remaining: 11"), "{}", status(2));
	assert!(status(3).contains("review units remaining: 30; leads remaining: 0"), "{}", status(3));
	assert!(status(4).contains("review units remaining: 0; leads remaining: 0"), "{}", status(4));
}
