//! Verify leases end to end: the actual router, a git fixture repository,
//! `Runner` with the scripted MCP agent driving the real broker, catalog,
//! phase client and retry. Every case first runs a scripted bootstrap survey
//! and a scripted drilldown that promotes the finding under verification.
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use loupe_server as server;
use loupe_worker::llm::testing::{ScriptedAgent, ScriptedMcpBackend, ToolResult};
use loupe_worker::Runner;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

mod common;
#[path = "review_verification/reporter.rs"]
mod reporter;

use common::phase_promotion::{bootstrapped, bootstrapped_from, promote, promoted};
use common::phase_worker::*;

/// Past a verify job's `submit_by` (deadline − 600 s) but well before its
/// hard deadline (3600 s).
const VERIFY_PAST_SUBMIT_BY: i64 = 3100;
/// Within the kill margin of a verify job's hard deadline.
const VERIFY_PAST_LAUNCH: i64 = 3590;

const FINDING: i64 = 1;
const RATIONALE: &str = "A library contract violation without an executable target.";

fn verified_at(path: &str) -> Value {
	json!({"verdict": "verified", "e2e_rationale": RATIONALE,
		"evidence": {"l2_argument": {"attacker_source": "The request body length.",
			"control": "None before the sink.", "sink": "The allocation in parse.",
			"reachable_path": "main calls parse with the raw body.",
			"trust_boundary": "Network to process memory."},
		"material_locations": [{"role": "sink", "file": path, "line_start": 1}],
		"counterevidence": "No length check on the path.",
		"assumptions_gaps": "Default configuration.", "confidence": "high"}})
}

fn verified() -> Value {
	verified_at("src/lib.rs")
}

fn rejected_at(path: &str) -> Value {
	json!({"verdict": "rejected", "counterargument": {
		"argument": "The length is only read, never allocated.",
		"source_refs": [{"path": path}]}})
}

fn rejected() -> Value {
	rejected_at("src/lib.rs")
}

fn awaiting_proof() -> Value {
	json!({"verdict": "inconclusive", "continuation": "awaiting_proof_infrastructure",
		"partial_evidence": {"argument": "The source argument holds.",
			"source_refs": [{"path": "src/lib.rs"}]}})
}

fn analysis_remaining() -> Value {
	json!({"verdict": "inconclusive", "continuation": "source_analysis_remaining",
		"blocker": "Callers remain to be traced."})
}

fn with_revalidation(mut arguments: Value) -> Value {
	arguments["revalidation"] = json!({"current_source_refs": [{"path": "src/lib.rs"}],
		"rationale": "Re-read the parser on this checkout."});
	arguments
}

fn sealed<'a>(result: &'a ToolResult, verdict: &str, state: &str) -> &'a str {
	let text = ok(result);
	assert!(text.starts_with(&format!("verification finalized as {verdict}: ")), "{text}");
	assert!(text.contains(&format!("; finding is {state}; ")), "{text}");
	text
}

fn refused(result: &ToolResult, text: &str) {
	assert!(result.is_error && result.text.contains(text), "{result:?}");
}

/// A fixture with one promoted finding and its verification pending.
async fn ready() -> Fixture {
	let f = bootstrapped(&["parse length"]).await;
	assert_eq!(promoted(&f, "parse length").await, FINDING);
	f
}

/// [`ready`], reporting to a stub whose deliveries it records.
async fn ready_with_reporter() -> (Fixture, reporter::Stub) {
	let (f, stub) =
		fixture_with(async |state, offline| reporter::configure(state, offline, FINDING).await)
			.await;
	let f = bootstrapped_from(f, &["parse length"]).await;
	assert_eq!(promoted(&f, "parse length").await, FINDING);
	(f, stub)
}

/// Run one verify lease with `script` as the agent; returns what the script
/// observed, or `None` if it was stopped before its end.
async fn verify<T, F, Fut>(f: &Fixture, script: F) -> Option<T>
where
	T: Send + 'static,
	F: Fn(ScriptedAgent) -> Fut + Send + Sync + 'static,
	Fut: Future<Output = anyhow::Result<T>> + Send + 'static,
{
	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	let stepped = f
		.verify_step(move |agent| {
			let (seen, played) = (seen.clone(), script(agent));
			async move {
				*seen.lock().unwrap() = Some(played.await?);
				Ok(())
			}
		})
		.await;
	assert!(stepped, "a verify lease was claimed");
	observed.lock().unwrap().take()
}

/// Run one verify lease whose agent makes `calls` to `finalize_verification`;
/// returns the prompt and each result.
async fn finalize_with(f: &Fixture, calls: Vec<Value>) -> (String, Vec<ToolResult>) {
	verify(f, move |mut agent| {
		let calls = calls.clone();
		async move {
			let mut results = Vec::new();
			for arguments in calls {
				results.push(agent.call("finalize_verification", arguments).await?);
			}
			Ok((agent.prompt, results))
		}
	})
	.await
	.expect("script ran")
}

async fn finalize_once(f: &Fixture, arguments: Value) -> (String, ToolResult) {
	let (prompt, mut results) = finalize_with(f, vec![arguments]).await;
	(prompt, results.remove(0))
}

fn verifies(f: &Fixture) -> Vec<(String, Option<String>)> {
	f.jobs_of("verify")
}

fn succeeded() -> (String, Option<String>) {
	("succeeded".to_owned(), None)
}

fn agent_exited(state: &str) -> (String, Option<String>) {
	(state.to_owned(), Some("agent exited without finalizing".to_owned()))
}

fn edit(f: &Fixture, sql: &str) {
	f.offline
		.external_corruption(|conn| {
			conn.execute_batch(sql)?;
			Ok(())
		})
		.unwrap();
}

fn assert_finding(f: &Fixture, state: &str) {
	let matching = format!("SELECT COUNT(*) FROM findings WHERE id={FINDING} AND state='{state}'");
	assert_eq!(f.scalar(&matching), 1, "finding is {state}");
}

fn assert_intent(f: &Fixture, condition: &str) {
	let matching = format!(
		"SELECT COUNT(*) FROM finding_verification_intents WHERE finding_id={FINDING} AND {condition}"
	);
	assert_eq!(f.scalar(&matching), 1, "{condition}");
}

fn verdicts(f: &Fixture) -> i64 {
	f.scalar("SELECT COUNT(*) FROM finding_verifications")
}

fn verify_receipts(f: &Fixture) -> i64 {
	f.scalar(
		"SELECT COUNT(*) FROM job_terminal_receipts r JOIN jobs j ON j.id=r.job_id WHERE j.kind='verify'",
	)
}

/// The finalize statuses among `calls`.
fn finalizes(calls: &[(String, u16)]) -> Vec<u16> {
	calls.iter().filter(|(route, _)| route == "finalize-verification").map(|call| call.1).collect()
}

/// No job is leased to `runner`.
async fn assert_unclaimed(runner: &Runner, jobs: usize, f: &Fixture) {
	let step =
		tokio::time::timeout(Duration::from_secs(2), runner.step(&CancellationToken::new())).await;
	assert!(matches!(step, Err(_) | Ok(Ok(false))), "a lease was claimed");
	assert_eq!(verifies(f).len(), jobs, "no verify job without a claim");
	assert!(f.log.take().is_empty(), "no job route was touched");
}

fn never(f: &Fixture) -> Arc<ScriptedMcpBackend> {
	Arc::new(ScriptedMcpBackend::new(f.client.clone(), |_| async {
		panic!("no lease in this step may reach the agent")
	}))
}

#[tokio::test]
async fn only_a_worker_with_the_verify_backend_is_leased_a_verify() {
	let f = ready().await;
	let others = never(&f);
	let other_phases =
		f.runner().with_survey_backend(others.clone()).with_drilldown_backend(others);
	assert_unclaimed(&other_phases, 0, &f).await;

	let (_, result) = finalize_once(&f, rejected()).await;
	sealed(&result, "rejected", "dismissed");
	assert_no_complete(&f.log.take());
	assert_eq!(verifies(&f), [succeeded()]);
}

#[tokio::test]
async fn each_phase_runs_on_its_own_backend() {
	let f = fixture().await;
	let used = Arc::new(Mutex::new(Vec::new()));
	let backend = |name: &'static str, terminal: &'static str, arguments: Value| {
		let used = used.clone();
		Arc::new(ScriptedMcpBackend::new(f.client.clone(), move |mut agent| {
			let (used, arguments) = (used.clone(), arguments.clone());
			async move {
				used.lock().unwrap().push(name);
				if name == "survey" {
					ok(&agent.call("publish_profile", profile()).await?);
					let lead = common::phase_promotion::lead_at("lead-0", "parse length");
					ok(&agent.call("submit_lead", lead).await?);
				}
				ok(&agent.call(terminal, arguments).await?);
				Ok(())
			}
		}))
	};
	let runner = f
		.runner()
		.with_verify_backend(backend("verify", "finalize_verification", rejected()))
		.with_drilldown_backend(backend("drilldown", "finalize_drilldown", promote("parse length")))
		.with_survey_backend(backend("survey", "finalize_survey", finalize("completed")));
	for _ in 0..3 {
		assert!(runner.step(&CancellationToken::new()).await.unwrap());
	}
	// Each terminal tool exists in its own phase's catalog only.
	assert_eq!(*used.lock().unwrap(), ["survey", "drilldown", "verify"]);
	assert_no_complete(&f.log.take());
	for kind in ["survey", "drilldown", "verify"] {
		assert_eq!(f.jobs_of(kind), [succeeded()], "{kind}");
	}
	assert_finding(&f, "dismissed");
}

#[tokio::test]
async fn a_verified_finding_awaits_approval_without_a_report() {
	let (f, stub) = ready_with_reporter().await;
	edit(&f, "UPDATE registered_repos SET require_approval=1");
	let (tools, prompt, result) = verify(&f, |mut agent| async move {
		let tools = agent.list_tools().await?;
		let result = agent.call("finalize_verification", verified()).await?;
		Ok((tools, agent.prompt, result))
	})
	.await
	.unwrap();
	assert_eq!(tools, ["get_job_limits", "finalize_verification"]);
	assert!(prompt.contains(&format!(r#""finding_id":{FINDING}"#)), "the assigned finding");
	assert!(prompt.contains("Length reaches allocation."), "the claim under test");
	assert!(prompt.contains(r#""attacker_source":"Request body""#), "the drilldown's argument");
	assert!(!prompt.contains("This is a retry."));
	sealed(&result, "verified", "awaiting_approval");
	let calls = f.log.take();
	assert_eq!(routes(&calls), ["pin-target", "limits", "finalize-verification"], "{calls:?}");
	assert_no_complete(&calls);
	assert_eq!(verifies(&f), [succeeded()]);
	assert_eq!(verify_receipts(&f), 1);
	assert_finding(&f, "awaiting_approval");
	assert_intent(&f, "state='complete'");
	assert!(stub.capture.calls.lock().unwrap().is_empty(), "nothing is reported unapproved");

	let approved = reporter::admin(&f.state, FINDING, "approve").await;
	assert_eq!(approved, axum::http::StatusCode::NO_CONTENT);
	assert_eq!(stub.capture.calls.lock().unwrap().len(), 1, "approval reports it");
}

#[tokio::test]
async fn a_verified_finding_without_approval_is_confirmed_and_reported() {
	let (f, stub) = ready_with_reporter().await;
	let (_, result) = finalize_once(&f, verified()).await;
	sealed(&result, "verified", "confirmed");
	assert_no_complete(&f.log.take());
	assert_eq!(verifies(&f), [succeeded()]);
	// The stub itself checks that the finding was confirmed when it was called.
	assert_eq!(stub.capture.calls.lock().unwrap().len(), 1);
	assert_finding(&f, "reported");
	assert_eq!(f.scalar("SELECT COUNT(*) FROM findings WHERE confirmed_at IS NOT NULL"), 1);
	let stored = f.scalar(&format!(
		"SELECT COUNT(*) FROM verification_attempt_details WHERE \
		 json_extract(evidence_payload,'$.established_rung')='L2' AND \
		 json_extract(evidence_payload,'$.e2e_applicability')='not_applicable' AND \
		 json_extract(evidence_payload,'$.e2e_rationale')='{RATIONALE}'"
	));
	assert_eq!(stored, 1, "the host's constants and the agent's rationale are stored");
}

#[tokio::test]
async fn a_rejected_finding_is_dismissed_without_a_report() {
	let (f, stub) = ready_with_reporter().await;
	let (_, result) = finalize_once(&f, rejected()).await;
	sealed(&result, "rejected", "dismissed");
	assert_no_complete(&f.log.take());
	assert_eq!(verifies(&f), [succeeded()]);
	assert_finding(&f, "dismissed");
	assert_intent(&f, "state='complete'");
	assert!(stub.capture.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn awaiting_proof_infrastructure_parks_the_finding_with_the_canonical_blocker() {
	let f = ready().await;
	let mut with_blocker = awaiting_proof();
	with_blocker["blocker"] = json!("No proof runner.");
	let (_, results) = finalize_with(&f, vec![with_blocker, awaiting_proof()]).await;
	assert!(results[0].is_error, "the agent cannot set the host's blocker: {:?}", results[0]);
	sealed(&results[1], "inconclusive", "validating");
	let calls = f.log.take();
	assert_eq!(finalizes(&calls), [200], "the host refused the first call: {calls:?}");
	assert_no_complete(&calls);
	assert_eq!(verifies(&f), [succeeded()]);
	assert_finding(&f, "validating");
	assert_intent(&f, "state='blocked' AND block_reason='awaiting_proof_infrastructure'");
	let stored = f.scalar(&format!(
		"SELECT COUNT(*) FROM verification_attempt_details WHERE \
		 json_extract(evidence_payload,'$.blocker')='{}'",
		loupe_core::review_payload::AWAITING_PROOF_INFRASTRUCTURE
	));
	assert_eq!(stored, 1, "the canonical blocker is stored");
	assert_unclaimed(&f.runner().with_verify_backend(never(&f)), 1, &f).await;
}

#[tokio::test]
async fn remaining_source_analysis_is_verified_again_after_backoff() {
	let f = ready().await;
	let (_, result) = finalize_once(&f, analysis_remaining()).await;
	sealed(&result, "inconclusive", "validating");
	assert_no_complete(&f.log.take());
	assert_finding(&f, "validating");
	let pending = "state='pending' AND continuation_class='source_analysis_remaining'";
	assert_intent(&f, &format!("{pending} AND not_before>{}", now()));
	assert_unclaimed(&f.runner().with_verify_backend(never(&f)), 1, &f).await;

	edit(&f, "UPDATE finding_verification_intents SET not_before=0");
	let (prompt, result) = finalize_once(&f, rejected()).await;
	assert!(!prompt.contains("This is a retry."), "a continuation is a new job");
	sealed(&result, "rejected", "dismissed");
	assert_no_complete(&f.log.take());
	assert_eq!(verifies(&f), [succeeded(), succeeded()]);
	assert_eq!(
		f.scalar(
			"SELECT COUNT(*) FROM jobs n JOIN jobs o ON n.continuation_of_job_id=o.id WHERE n.kind='verify' AND o.kind='verify'"
		),
		1
	);
	assert_finding(&f, "dismissed");
}

#[tokio::test]
async fn an_unknown_source_path_is_refused_and_a_corrected_finalize_accepted() {
	for (wrong, right, verdict, state) in [
		(rejected_at("src/missing.rs"), rejected(), "rejected", "dismissed"),
		(verified_at("src/LIB.rs"), verified(), "verified", "confirmed"),
	] {
		let f = ready().await;
		let (_, results) = finalize_with(&f, vec![wrong, right]).await;
		refused(&results[0], "refused a field or source path");
		sealed(&results[1], verdict, state);
		let calls = f.log.take();
		assert_eq!(finalizes(&calls), [400, 200], "{calls:?}");
		assert_no_complete(&calls);
		assert_eq!(verifies(&f), [succeeded()]);
		assert_eq!(verdicts(&f), 1);
	}
}

#[tokio::test]
async fn a_finding_reviewed_at_another_commit_is_finalized_with_revalidation() {
	let f = ready().await;
	let offline = f.offline.clone();
	let (required, accepted) = verify(&f, move |mut agent| {
		let offline = offline.clone();
		async move {
			// Delivery requires the commits to be equal, so they can only part
			// during the attempt.
			offline.external_corruption(|conn| {
				let other = "b".repeat(40);
				conn.execute("UPDATE finding_review_details SET reviewed_commit_sha=?1", [&other])?;
				conn.execute("UPDATE jobs SET head_sha=?1 WHERE kind='drilldown'", [&other])?;
				Ok(())
			})?;
			let required = agent.call("finalize_verification", rejected()).await?;
			let accepted =
				agent.call("finalize_verification", with_revalidation(rejected())).await?;
			Ok((required, accepted))
		}
	})
	.await
	.unwrap();
	refused(&required, "finalizing was refused as revalidation required");
	sealed(&accepted, "rejected", "dismissed");
	let calls = f.log.take();
	assert_eq!(finalizes(&calls), [409, 200], "{calls:?}");
	assert_no_complete(&calls);
	assert_eq!(verifies(&f), [succeeded()]);
}

#[tokio::test]
async fn a_finding_that_left_validating_cannot_be_verified() {
	let f = ready().await;
	let offline = f.offline.clone();
	let result = verify(&f, move |mut agent| {
		let offline = offline.clone();
		async move {
			offline.external_corruption(|conn| {
				conn.execute("UPDATE findings SET state='dismissed'", [])?;
				Ok(())
			})?;
			agent.call("finalize_verification", verified()).await
		}
	})
	.await
	.unwrap();
	refused(&result, "the finding can no longer be verified by this job");
	let calls = f.log.take();
	assert_eq!(finalizes(&calls), [409], "{calls:?}");
	assert_eq!(routes(&calls).last(), Some(&"complete"), "no verdict is a failed attempt");
	assert_eq!(verifies(&f)[0].1, agent_exited("queued").1);
	assert_eq!((verdicts(&f), verify_receipts(&f)), (0, 0));
}

#[tokio::test]
async fn a_lost_finalize_response_is_replayed_and_reported_once() {
	let (f, stub) = ready_with_reporter().await;
	*f.log.drop_response.lock().unwrap() = Some("finalize-verification");
	let (_, result) = finalize_once(&f, verified()).await;
	sealed(&result, "verified", "confirmed");
	let calls = f.log.take();
	assert_eq!(finalizes(&calls), [502, 200], "{calls:?}");
	assert_no_complete(&calls);
	assert_eq!((verdicts(&f), verify_receipts(&f)), (1, 1));
	assert_eq!(stub.capture.calls.lock().unwrap().len(), 1, "a replay reports nothing");
	assert_eq!(verifies(&f), [succeeded()]);
}

#[tokio::test]
async fn a_verdict_whose_every_response_is_lost_stands_when_the_agent_exits() {
	let (f, stub) = ready_with_reporter().await;
	*f.log.drop_responses.lock().unwrap() = Some("finalize-verification");
	let (_, result) = finalize_once(&f, verified()).await;
	refused(&result, "retry the identical finalize_verification call");
	let calls = f.log.take();
	assert_eq!(finalizes(&calls), [502, 502, 502], "{calls:?}");
	assert_stands(&f, &stub, &calls, "agent exited without finalizing");
}

#[tokio::test]
async fn a_verdict_whose_every_response_is_lost_stands_after_a_limits_read() {
	let (f, stub) = ready_with_reporter().await;
	*f.log.drop_responses.lock().unwrap() = Some("finalize-verification");
	let ended = verify(&f, |mut agent| async move {
		let result = agent.call("finalize_verification", verified()).await?;
		refused(&result, "retry the identical finalize_verification call");
		let _ = agent.call("get_job_limits", json!({})).await;
		// The host stops the agent; a well-behaved script never gets here.
		tokio::time::sleep(Duration::from_secs(30)).await;
		Ok(())
	})
	.await;
	assert!(ended.is_none(), "the agent was stopped");
	let calls = f.log.take();
	assert_eq!(finalizes(&calls), [502, 502, 502], "{calls:?}");
	assert_eq!(calls[calls.len() - 2], ("limits".to_owned(), 403), "{calls:?}");
	assert_stands(&f, &stub, &calls, "authority lost");
}

/// The sealed verdict stands although the worker, which never saw the
/// receipt, reported `reason`: the server refuses that report.
fn assert_stands(f: &Fixture, stub: &reporter::Stub, calls: &[(String, u16)], reason: &str) {
	assert_eq!(*f.log.failures.lock().unwrap(), [reason]);
	assert_eq!(calls.last(), Some(&("complete".to_owned(), 403)), "{calls:?}");
	assert_eq!(verifies(f), [succeeded()]);
	assert_eq!((verdicts(f), verify_receipts(f)), (1, 1));
	assert_eq!(stub.capture.calls.lock().unwrap().len(), 1, "the finding is reported once");
	assert_finding(f, "reported");
	assert_intent(f, "state='complete'");
}

#[tokio::test]
async fn after_a_seal_an_identical_finalize_replays_and_another_conflicts() {
	let (f, stub) = ready_with_reporter().await;
	let (_, results) = finalize_with(&f, vec![verified(), verified(), rejected()]).await;
	sealed(&results[0], "verified", "confirmed");
	// The status line ends in the time left, which moves between calls.
	let receipt = |result: &ToolResult| result.text.lines().next().unwrap().to_owned();
	assert_eq!(receipt(&results[0]), receipt(&results[1]), "the sealed receipt");
	refused(&results[2], "already finalized with a different payload");
	let calls = f.log.take();
	assert_eq!(finalizes(&calls), [200, 200, 409], "{calls:?}");
	assert_no_complete(&calls);
	assert_eq!((verdicts(&f), verify_receipts(&f)), (1, 1));
	assert_eq!(stub.capture.calls.lock().unwrap().len(), 1);
	assert_finding(&f, "reported");
	assert_eq!(verifies(&f), [succeeded()]);
}

#[tokio::test]
async fn a_limits_read_after_a_seal_ends_the_session_and_keeps_the_success() {
	let f = ready().await;
	let limits = Arc::new(Mutex::new(None));
	let seen = limits.clone();
	let ended = verify(&f, move |mut agent| {
		let seen = seen.clone();
		async move {
			sealed(
				&agent.call("finalize_verification", rejected()).await?,
				"rejected",
				"dismissed",
			);
			*seen.lock().unwrap() = Some(agent.call("get_job_limits", json!({})).await);
			// The host stops the agent; a well-behaved script never gets here.
			tokio::time::sleep(Duration::from_secs(30)).await;
			Ok(())
		}
	})
	.await;
	assert!(ended.is_none(), "the agent was stopped");
	// Cancellation may stop the script before it reads the answer.
	if let Some(Ok(limits)) = limits.lock().unwrap().take() {
		refused(&limits, "no longer has authority");
	}
	let calls = f.log.take();
	assert_eq!(
		calls.iter().filter(|(route, _)| route == "limits").map(|call| call.1).collect::<Vec<_>>(),
		[200, 403],
		"{calls:?}"
	);
	assert_no_complete(&calls);
	assert_eq!(verifies(&f), [succeeded()]);
	assert_eq!((verdicts(&f), verify_receipts(&f)), (1, 1));
	assert_finding(&f, "dismissed");
}

#[tokio::test]
async fn an_agent_that_never_finalizes_is_retried_until_the_attempts_are_spent() {
	let f = ready().await;
	for attempt in 1..=3 {
		let retried = attempt > 1;
		let stepped = f
			.verify_step(move |mut agent| async move {
				assert_eq!(agent.prompt.contains("This is a retry."), retried);
				agent.list_tools().await?;
				anyhow::bail!("agent-private-error-sentinel")
			})
			.await;
		assert!(stepped, "attempt {attempt}");
		let calls = f.log.take();
		assert_eq!(routes(&calls), ["pin-target", "limits", "complete"], "{calls:?}");
		assert_eq!(calls.last(), Some(&("complete".to_owned(), 200)), "{calls:?}");
		let state = if attempt < 3 { "queued" } else { "failed" };
		assert_eq!(verifies(&f), [agent_exited(state)], "attempt {attempt}");
		f.make_eligible();
	}
	assert_finding(&f, "validating");
	assert_intent(&f, "state='blocked' AND block_reason='execution_exhausted'");
	assert_eq!((verdicts(&f), verify_receipts(&f)), (0, 0));
	assert_unclaimed(&f.runner().with_verify_backend(never(&f)), 1, &f).await;
}

#[tokio::test]
async fn a_cancelled_campaign_ends_the_session_without_a_verdict() {
	let f = ready().await;
	let state = f.state.clone();
	let refused_call = Arc::new(Mutex::new(None));
	let seen = refused_call.clone();
	let ended = verify(&f, move |mut agent| {
		let (state, seen) = (state.clone(), seen.clone());
		async move {
			cancel_campaign(&state.db);
			*seen.lock().unwrap() = Some(agent.call("finalize_verification", verified()).await);
			tokio::time::sleep(Duration::from_secs(30)).await;
			Ok(())
		}
	})
	.await;
	assert!(ended.is_none(), "the agent was stopped");
	if let Some(Ok(result)) = refused_call.lock().unwrap().take() {
		refused(&result, "no longer has authority");
	}
	let calls = f.log.take();
	assert_eq!(
		routes(&calls),
		["pin-target", "limits", "finalize-verification", "complete"],
		"a refused finalize is not probed: {calls:?}"
	);
	assert_eq!(finalizes(&calls), [403]);
	let (state, error) = verifies(&f).remove(0);
	assert_ne!(state, "leased");
	assert!(error.is_some(), "the server recorded the failure");
	assert_eq!((verdicts(&f), verify_receipts(&f)), (0, 0));
	assert_finding(&f, "validating");
}

#[tokio::test]
async fn an_expired_lease_ends_the_session_without_a_verdict() {
	let f = ready().await;
	let offline = f.offline.clone();
	let ended = verify(&f, move |mut agent| {
		let offline = offline.clone();
		async move {
			offline.external_corruption(|conn| {
				conn.execute("UPDATE jobs SET lease_expires_at=1 WHERE kind='verify'", [])?;
				Ok(())
			})?;
			let _ = agent.call("finalize_verification", verified()).await;
			tokio::time::sleep(Duration::from_secs(30)).await;
			Ok(())
		}
	})
	.await;
	assert!(ended.is_none(), "the agent was stopped");
	let calls = f.log.take();
	assert_eq!(finalizes(&calls), [403], "{calls:?}");
	assert_eq!(routes(&calls), ["pin-target", "limits", "finalize-verification", "complete"]);
	// The report is refused too, so the job stays leased until it is reaped.
	assert_eq!(*f.log.failures.lock().unwrap(), ["authority lost"]);
	assert_eq!(calls.last(), Some(&("complete".to_owned(), 403)), "{calls:?}");
	assert_eq!(verifies(&f), [("leased".to_owned(), None)]);
	assert_eq!((verdicts(&f), verify_receipts(&f)), (0, 0));
	assert_finding(&f, "validating");
}

#[tokio::test]
async fn a_verify_too_close_to_its_hard_deadline_fails_without_launch() {
	let f = ready().await;
	f.offset.store(VERIFY_PAST_LAUNCH, Ordering::SeqCst);
	let launched = Arc::new(AtomicBool::new(false));
	let flag = launched.clone();
	assert!(
		f.verify_step(move |_agent| {
			flag.store(true, Ordering::SeqCst);
			async { Ok(()) }
		})
		.await
	);
	assert!(!launched.load(Ordering::SeqCst), "no agent past the launch deadline");
	let calls = f.log.take();
	assert!(finalizes(&calls).is_empty(), "{calls:?}");
	assert_eq!(routes(&calls).last(), Some(&"complete"));
	assert_eq!(verifies(&f)[0].1.as_deref(), Some("hard deadline reached"));
}

#[tokio::test]
async fn past_submit_by_the_verdict_is_still_accepted() {
	let f = ready().await;
	let offset = f.offset.clone();
	let (limits, result) = verify(&f, move |mut agent| {
		let offset = offset.clone();
		async move {
			offset.store(VERIFY_PAST_SUBMIT_BY, Ordering::SeqCst);
			let limits = agent.call("get_job_limits", json!({})).await?;
			let result = agent.call("finalize_verification", analysis_remaining()).await?;
			Ok((limits, result))
		}
	})
	.await
	.unwrap();
	assert!(ok(&limits).contains("submit_by: passed"), "{}", limits.text);
	sealed(&result, "inconclusive", "validating");
	assert_no_complete(&f.log.take());
	assert_eq!(verifies(&f), [succeeded()]);
}

#[tokio::test]
async fn tools_of_other_sessions_are_unknown_to_a_verify_session() {
	let f = ready().await;
	let foreign = BTreeMap::from([
		("query_same_project_lead_candidates", json!({"query": "parse"})),
		("submit_sibling_lead", common::phase_promotion::lead_at("s-1", "parse header")),
		("finalize_drilldown", promote("parse length")),
		("finalize_survey", finalize("completed")),
		("submit_verdict", json!({"verdict": "confirmed", "notes": "Checked."})),
		("submit_patch", json!({"patch_unified": "x"})),
	]);
	let calls = foreign.clone();
	let results = verify(&f, move |mut agent| {
		let calls = calls.clone();
		async move {
			let mut results = Vec::new();
			for (tool, arguments) in calls {
				results.push((tool, agent.call(tool, arguments).await?));
			}
			let sealing = agent.call("finalize_verification", rejected()).await?;
			sealed(&sealing, "rejected", "dismissed");
			Ok(results)
		}
	})
	.await
	.unwrap();
	assert_eq!(results.len(), foreign.len());
	for (tool, result) in results {
		refused(&result, &format!("unknown tool: {tool}"));
	}
	let calls = f.log.take();
	assert_eq!(routes(&calls), ["pin-target", "limits", "finalize-verification"], "{calls:?}");
	assert_eq!(f.scalar("SELECT COUNT(*) FROM leads"), 1);
}
