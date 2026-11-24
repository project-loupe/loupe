//! Drilldown leases end to end: the actual router, a git fixture repository,
//! `Runner` with the scripted MCP agent driving the real broker, catalog,
//! gate, phase client and retry. Every case first runs a scripted bootstrap
//! survey that leaves the leads the drilldowns investigate.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use loupe_worker::llm::testing::{ScriptedAgent, ScriptedMcpBackend, ToolResult};
use loupe_worker::{RepoCache, Runner};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

mod common;

use common::phase_worker::*;

/// Past a drilldown's `submit_by` (deadline − 420 s) but well before its
/// hard deadline (2700 s).
const DRILLDOWN_PAST_SUBMIT_BY: i64 = 2300;
/// Within the kill margin of a drilldown's hard deadline.
const DRILLDOWN_PAST_LAUNCH: i64 = 2690;

fn lead_at(key: &str, anchor: &str) -> Value {
	json!({"client_lead_key": key, "identity_family": "memory-safety",
		"identity_anchor": anchor, "hypothesis": "The parser trusts the input length.",
		"source_refs": [{"path": "src/lib.rs"}], "next_proof_step": "Write a harness.",
		"counterevidence": "Length is only read.", "proof_gaps": "Reachability."})
}

fn sibling(key: &str, anchor: &str) -> Value {
	lead_at(key, anchor)
}

/// A bootstrap survey that publishes the profile, leaves one lead per
/// anchor and finalizes.
type Played = std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>;

fn bootstrap(
	anchors: &'static [&'static str],
) -> impl Fn(ScriptedAgent) -> Played + Send + Sync + 'static {
	move |mut agent: ScriptedAgent| {
		Box::pin(async move {
			ok(&agent.call("publish_profile", profile()).await?);
			for (index, anchor) in anchors.iter().enumerate() {
				ok(&agent.call("submit_lead", lead_at(&format!("lead-{index}"), anchor)).await?);
			}
			ok(&agent.call("finalize_survey", finalize("completed")).await?);
			Ok(())
		})
	}
}

fn promote(anchor: &str) -> Value {
	json!({"disposition": "promote", "promotion": {"severity": "high",
		"title": "Unbounded allocation", "description": "Length reaches allocation.",
		"identity_family": "memory-safety", "identity_anchor": anchor,
		"evidence": {"l2_argument": {"attacker_source": "Request body", "control": "Length",
			"sink": "allocation", "reachable_path": "main to parse",
			"trust_boundary": "network"},
		"material_locations": [{"role": "sink", "file": "src/lib.rs", "line_start": 1}],
		"counterevidence": "No bound.", "assumptions_gaps": "Defaults.",
		"confidence": "medium"}}})
}

fn reject_at(path: &str) -> Value {
	json!({"disposition": "reject", "counterargument": {"argument": "The length is only read.",
		"source_refs": [{"path": path}]}})
}

fn reject() -> Value {
	reject_at("src/lib.rs")
}

fn hardening() -> Value {
	json!({"disposition": "hardening", "explanation": {"argument": "No exploit path.",
		"source_refs": [{"path": "src/lib.rs"}]}})
}

fn defer() -> Value {
	json!({"disposition": "defer", "reason": "Callers remain to be traced.",
		"continuation": "source_analysis_remaining"})
}

fn duplicate(kind: &str, id: i64) -> Value {
	json!({"disposition": "duplicate", "target": {"kind": kind, "id": id},
		"rationale": "Same source-controlled cause."})
}

fn sealed(result: &ToolResult) -> &str {
	let text = ok(result);
	assert!(text.starts_with("drilldown finalized as "), "{text}");
	text
}

fn lead_id(f: &Fixture, anchor: &str) -> i64 {
	f.scalar(&format!("SELECT lead_id FROM leads WHERE identity_anchor='{anchor}'"))
}

/// The lead id stated in the prompt's job context.
fn prompted_lead(prompt: &str) -> i64 {
	let key = r#""lead_id":"#;
	let start = prompt.find(key).expect("lead id in the prompt") + key.len();
	prompt[start..].split(|c: char| !c.is_ascii_digit()).next().unwrap().parse().unwrap()
}

fn drilldowns(f: &Fixture) -> Vec<(String, Option<String>)> {
	f.jobs_of("drilldown")
}

/// Run one step whose script only finalizes with `arguments`; returns the
/// prompt and the finalize result.
async fn finalize_once(f: &Fixture, arguments: Value) -> (String, ToolResult) {
	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	assert!(
		f.step(move |mut agent| {
			let (seen, arguments) = (seen.clone(), arguments.clone());
			async move {
				let result = agent.call("finalize_drilldown", arguments).await?;
				*seen.lock().unwrap() = Some((agent.prompt.clone(), result));
				Ok(())
			}
		})
		.await
	);
	let finished = observed.lock().unwrap().take();
	finished.expect("script ran")
}

async fn bootstrapped(anchors: &'static [&'static str]) -> Fixture {
	let f = fixture().await;
	assert!(f.step(bootstrap(anchors)).await);
	assert_eq!(f.jobs(), [("succeeded".to_owned(), None)]);
	f.log.take();
	f
}

#[tokio::test]
async fn only_a_worker_with_the_phase_backend_is_leased_a_drilldown() {
	let f = bootstrapped(&["parse length"]).await;
	let cache = Arc::new(RepoCache::new(f.cache.path().to_owned(), u64::MAX, None).unwrap());
	let plain = Runner::new(f.client.clone(), cache.clone(), Vec::new());
	let unclaimed =
		tokio::time::timeout(Duration::from_secs(2), plain.step(&CancellationToken::new())).await;
	assert!(matches!(unclaimed, Err(_) | Ok(Ok(false))), "a phase-less worker ran a lease");
	assert!(drilldowns(&f).is_empty(), "no drilldown job without a claim");
	assert!(f.log.take().is_empty(), "the phase-less worker touched no job route");

	let backend = Arc::new(ScriptedMcpBackend::new(f.client.clone(), |mut agent| async move {
		sealed(&agent.call("finalize_drilldown", reject()).await?);
		Ok(())
	}));
	let worker = Runner::new(f.client.clone(), cache, Vec::new())
		.with_survey_backend(backend.clone())
		.with_drilldown_backend(backend);
	assert!(worker.step(&CancellationToken::new()).await.unwrap());
	assert_eq!(drilldowns(&f), [("succeeded".to_owned(), None)]);
}

#[tokio::test]
async fn a_promotion_writes_a_validating_finding_and_closes_the_lead() {
	let f = bootstrapped(&["parse length"]).await;
	let lead = lead_id(&f, "parse length");
	let tools = Arc::new(Mutex::new(Vec::new()));
	let seen = tools.clone();
	let observed = Arc::new(Mutex::new(None));
	let result = observed.clone();
	assert!(
		f.step(move |mut agent| {
			let (seen, result) = (seen.clone(), result.clone());
			async move {
				*seen.lock().unwrap() = agent.list_tools().await?;
				let promoted = agent.call("finalize_drilldown", promote("parse length")).await?;
				*result.lock().unwrap() = Some((agent.prompt.clone(), promoted));
				Ok(())
			}
		})
		.await
	);
	assert_eq!(
		*tools.lock().unwrap(),
		[
			"get_job_limits",
			"query_same_project_lead_candidates",
			"submit_sibling_lead",
			"finalize_drilldown"
		]
	);
	let (prompt, promoted) = observed.lock().unwrap().take().unwrap();
	assert_eq!(prompted_lead(&prompt), lead);
	let finding = f.scalar("SELECT id FROM findings");
	assert!(sealed(&promoted).contains(&format!("finding_id={finding}")), "{}", promoted.text);
	let calls = f.log.take();
	assert_eq!(routes(&calls), ["pin-target", "limits", "finalize-drilldown"], "{calls:?}");
	assert_no_complete(&calls);
	assert_eq!(drilldowns(&f), [("succeeded".to_owned(), None)]);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM findings WHERE state='validating'"), 1);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM finding_review_details"), 1);
	assert_eq!(
		f.scalar(&format!(
			"SELECT COUNT(*) FROM leads WHERE lead_id={lead} AND status='closed' AND disposition='promoted'"
		)),
		1
	);
	assert_eq!(
		f.scalar(&format!(
			"SELECT COUNT(*) FROM finding_verification_intents WHERE finding_id={finding}"
		)),
		1
	);
}

#[tokio::test]
async fn reject_and_hardening_close_the_lead_without_a_finding() {
	for (arguments, disposition) in [(reject(), "rejected"), (hardening(), "hardening")] {
		let f = bootstrapped(&["parse length"]).await;
		let (_, result) = finalize_once(&f, arguments).await;
		sealed(&result);
		assert_no_complete(&f.log.take());
		assert_eq!(drilldowns(&f), [("succeeded".to_owned(), None)]);
		assert_eq!(f.scalar("SELECT COUNT(*) FROM findings"), 0, "{disposition}");
		assert_eq!(
			f.scalar(&format!(
				"SELECT COUNT(*) FROM leads WHERE status='closed' AND disposition='{disposition}'"
			)),
			1
		);
	}
}

#[tokio::test]
async fn a_deferred_lead_records_its_continuation() {
	let f = bootstrapped(&["parse length"]).await;
	let lead = lead_id(&f, "parse length");
	let (_, result) = finalize_once(&f, defer()).await;
	sealed(&result);
	assert_no_complete(&f.log.take());
	assert_eq!(drilldowns(&f), [("succeeded".to_owned(), None)]);
	assert_eq!(
		f.scalar(&format!(
			"SELECT COUNT(*) FROM leads WHERE lead_id={lead} AND status='deferred' AND defer_reason='source_analysis_remaining'"
		)),
		1
	);
	assert_eq!(
		f.scalar(&format!(
			"SELECT COUNT(*) FROM lead_drilldown_intents WHERE lead_id={lead} AND state='pending' AND continuation_class='source_analysis_remaining'"
		)),
		1
	);
}

#[tokio::test]
async fn a_duplicate_of_a_queried_lead_closes_the_lead_as_duplicate() {
	let f = bootstrapped(&["parse length", "parse header"]).await;
	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	let leads = [lead_id(&f, "parse length"), lead_id(&f, "parse header")];
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				let own = prompted_lead(&agent.prompt);
				let other = if own == leads[0] { leads[1] } else { leads[0] };
				ok(&agent
					.call("query_same_project_lead_candidates", json!({"query": "parse"}))
					.await?);
				let result = agent.call("finalize_drilldown", duplicate("lead", other)).await?;
				*seen.lock().unwrap() = Some((own, other, result));
				Ok(())
			}
		})
		.await
	);
	let (own, other, result) = observed.lock().unwrap().take().unwrap();
	sealed(&result);
	let calls = f.log.take();
	assert!(routes(&calls).contains(&"lead-candidates"), "{calls:?}");
	assert_no_complete(&calls);
	assert_eq!(drilldowns(&f)[0], ("succeeded".to_owned(), None));
	assert_eq!(
		f.scalar(&format!(
			"SELECT duplicate_of_lead_id FROM leads WHERE lead_id={own} AND status='closed' AND disposition='duplicate'"
		)),
		other
	);
}

#[tokio::test]
async fn a_duplicate_target_never_queried_is_refused_and_the_session_continues() {
	let f = bootstrapped(&["parse length", "parse header"]).await;
	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	let leads = [lead_id(&f, "parse length"), lead_id(&f, "parse header")];
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				let own = prompted_lead(&agent.prompt);
				let other = if own == leads[0] { leads[1] } else { leads[0] };
				let refused = agent.call("finalize_drilldown", duplicate("lead", other)).await?;
				let rejected = agent.call("finalize_drilldown", reject()).await?;
				*seen.lock().unwrap() = Some((refused, rejected));
				Ok(())
			}
		})
		.await
	);
	let (refused, rejected) = observed.lock().unwrap().take().unwrap();
	assert!(refused.is_error, "{refused:?}");
	assert!(
		refused.text.contains("refused a referenced lead or finding for this job"),
		"{}",
		refused.text
	);
	assert!(!refused.text.contains("no longer has authority"), "{}", refused.text);
	sealed(&rejected);
	let calls = f.log.take();
	assert!(calls.contains(&("finalize-drilldown".to_owned(), 403)), "{calls:?}");
	assert!(calls.contains(&("limits".to_owned(), 200)), "the refusal was probed: {calls:?}");
	assert_no_complete(&calls);
	assert_eq!(drilldowns(&f)[0], ("succeeded".to_owned(), None));
	assert_eq!(f.scalar("SELECT COUNT(*) FROM leads WHERE disposition='rejected'"), 1);
}

#[tokio::test]
async fn an_identity_conflict_is_resolved_as_a_duplicate_of_the_finding() {
	let f = bootstrapped(&["parse length", "parse header"]).await;
	let (_, first) = finalize_once(&f, promote("parse allocation")).await;
	sealed(&first);
	let finding = f.scalar("SELECT id FROM findings");
	f.log.take();

	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				let conflict =
					agent.call("finalize_drilldown", promote("parse allocation")).await?;
				ok(&agent
					.call(
						"query_same_project_lead_candidates",
						json!({"query": "parse allocation"}),
					)
					.await?);
				let resolved =
					agent.call("finalize_drilldown", duplicate("finding", finding)).await?;
				*seen.lock().unwrap() = Some((conflict, resolved));
				Ok(())
			}
		})
		.await
	);
	let (conflict, resolved) = observed.lock().unwrap().take().unwrap();
	assert!(conflict.is_error, "{conflict:?}");
	assert!(
		conflict.text.contains("a finding with this identity already exists"),
		"{}",
		conflict.text
	);
	sealed(&resolved);
	let calls = f.log.take();
	assert!(calls.contains(&("finalize-drilldown".to_owned(), 409)), "{calls:?}");
	assert_no_complete(&calls);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM findings"), 1);
	assert_eq!(
		f.scalar(&format!(
			"SELECT COUNT(*) FROM leads WHERE disposition='duplicate' AND duplicate_of_finding_id={finding}"
		)),
		1
	);
	assert_eq!(drilldowns(&f), [("succeeded".to_owned(), None), ("succeeded".to_owned(), None)]);
}

#[tokio::test]
async fn a_lead_flagged_for_revalidation_is_finalized_with_revalidation() {
	let f = bootstrapped(&["parse length"]).await;
	f.offline
		.external_corruption(|conn| {
			conn.execute("UPDATE leads SET needs_revalidation=1", [])?;
			Ok(())
		})
		.unwrap();
	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				let refused = agent.call("finalize_drilldown", reject()).await?;
				let mut revalidated = reject();
				revalidated["revalidation"] = json!({"current_source_refs": [{"path": "src/lib.rs"}],
					"rationale": "Re-read the parser on this checkout."});
				let accepted = agent.call("finalize_drilldown", revalidated).await?;
				*seen.lock().unwrap() = Some((refused, accepted));
				Ok(())
			}
		})
		.await
	);
	let (refused, accepted) = observed.lock().unwrap().take().unwrap();
	assert!(refused.is_error, "{refused:?}");
	assert!(
		refused.text.contains("finalizing was refused as revalidation required"),
		"{}",
		refused.text
	);
	sealed(&accepted);
	assert_no_complete(&f.log.take());
	assert_eq!(drilldowns(&f), [("succeeded".to_owned(), None)]);
}

#[tokio::test]
async fn an_unknown_source_path_is_refused_and_a_corrected_finalize_accepted() {
	let f = bootstrapped(&["parse length"]).await;
	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				let refused = agent.call("finalize_drilldown", reject_at("src/missing.rs")).await?;
				let accepted = agent.call("finalize_drilldown", reject()).await?;
				*seen.lock().unwrap() = Some((refused, accepted));
				Ok(())
			}
		})
		.await
	);
	let (refused, accepted) = observed.lock().unwrap().take().unwrap();
	assert!(refused.is_error, "{refused:?}");
	assert!(refused.text.contains("refused a field or source path"), "{}", refused.text);
	sealed(&accepted);
	let calls = f.log.take();
	assert!(calls.contains(&("finalize-drilldown".to_owned(), 400)), "{calls:?}");
	assert_no_complete(&calls);
	assert_eq!(drilldowns(&f), [("succeeded".to_owned(), None)]);
}

#[tokio::test]
async fn a_sibling_lead_gets_its_own_claimable_drilldown() {
	let f = bootstrapped(&["parse length"]).await;
	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				let created =
					agent.call("submit_sibling_lead", sibling("s-1", "parse header")).await?;
				sealed(&agent.call("finalize_drilldown", reject()).await?);
				*seen.lock().unwrap() = Some(created);
				Ok(())
			}
		})
		.await
	);
	let created = observed.lock().unwrap().take().unwrap();
	assert!(ok(&created).contains("created; it gets its own drilldown"), "{}", created.text);
	let sibling = reported_id(&created, "lead_id=");
	assert_eq!(sibling, lead_id(&f, "parse header"));
	assert_eq!(
		f.scalar(&format!("SELECT COUNT(*) FROM lead_drilldown_intents WHERE lead_id={sibling}")),
		1
	);
	f.log.take();

	let (prompt, result) = finalize_once(&f, hardening()).await;
	assert_eq!(prompted_lead(&prompt), sibling, "the next step claims the sibling's drilldown");
	sealed(&result);
	assert_eq!(drilldowns(&f), [("succeeded".to_owned(), None), ("succeeded".to_owned(), None)]);
}

#[tokio::test]
async fn the_fifth_sibling_gets_the_capacity_error_and_finalize_is_accepted() {
	let f = bootstrapped(&["parse length"]).await;
	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				for index in 0..4 {
					let anchor = format!("sibling anchor {index}");
					ok(&agent
						.call("submit_sibling_lead", sibling(&format!("s-{index}"), &anchor))
						.await?);
				}
				let fifth =
					agent.call("submit_sibling_lead", sibling("s-4", "sibling anchor 4")).await?;
				let finalized = agent.call("finalize_drilldown", reject()).await?;
				*seen.lock().unwrap() = Some((fifth, finalized));
				Ok(())
			}
		})
		.await
	);
	let (fifth, finalized) = observed.lock().unwrap().take().unwrap();
	assert!(fifth.is_error, "{fifth:?}");
	assert!(fifth.text.contains("sibling lead capacity is exhausted"), "{}", fifth.text);
	sealed(&finalized);
	let calls = f.log.take();
	assert!(calls.contains(&("sibling-leads".to_owned(), 409)), "{calls:?}");
	assert_no_complete(&calls);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM leads WHERE identity_anchor LIKE 'sibling%'"), 4);
}

#[tokio::test]
async fn past_submit_by_siblings_are_denied_but_query_and_finalize_are_accepted() {
	let f = bootstrapped(&["parse length"]).await;
	let offset = f.offset.clone();
	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	assert!(
		f.step(move |mut agent| {
			let (seen, offset) = (seen.clone(), offset.clone());
			async move {
				offset.store(DRILLDOWN_PAST_SUBMIT_BY, Ordering::SeqCst);
				let sibling = agent.call("submit_sibling_lead", sibling("late", "late")).await?;
				let query = agent
					.call("query_same_project_lead_candidates", json!({"query": "parse"}))
					.await?;
				let finalized = agent.call("finalize_drilldown", defer()).await?;
				*seen.lock().unwrap() = Some((sibling, query, finalized));
				Ok(())
			}
		})
		.await
	);
	let (sibling, query, finalized) = observed.lock().unwrap().take().unwrap();
	assert!(sibling.is_error && sibling.text.contains("soft stop reached"), "{sibling:?}");
	ok(&query);
	sealed(&finalized);
	let calls = f.log.take();
	assert!(!routes(&calls).contains(&"sibling-leads"), "{calls:?}");
	assert!(routes(&calls).contains(&"lead-candidates"), "{calls:?}");
	assert_no_complete(&calls);
	assert_eq!(drilldowns(&f), [("succeeded".to_owned(), None)]);
}

#[tokio::test]
async fn a_retry_after_a_sibling_repins_with_reduced_capacity_and_finalizes() {
	let f = bootstrapped(&["parse length"]).await;
	let lead = lead_id(&f, "parse length");
	assert!(
		f.step(|mut agent| async move {
			ok(&agent.call("submit_sibling_lead", sibling("s-1", "parse header")).await?);
			Ok(())
		})
		.await
	);
	let calls = f.log.take();
	assert_eq!(routes(&calls).last(), Some(&"complete"), "{calls:?}");
	assert_eq!(
		drilldowns(&f),
		[("queued".to_owned(), Some("agent exited without finalizing".to_owned()))]
	);
	f.make_eligible();

	let (prompt, result) = finalize_once(&f, reject()).await;
	assert_eq!(prompted_lead(&prompt), lead, "the retried drilldown, not the sibling's");
	assert!(prompt.contains("This is a retry."), "retry instruction");
	assert!(prompt.contains(r#""siblings":{"limit":4,"remaining":3}"#), "reduced capacity");
	sealed(&result);
	let calls = f.log.take();
	assert_eq!(routes(&calls)[..2], ["pin-target", "limits"], "{calls:?}");
	assert_no_complete(&calls);
	assert_eq!(drilldowns(&f), [("succeeded".to_owned(), None)]);
}

#[tokio::test]
async fn a_lost_finalize_response_is_replayed_and_stored_once() {
	let f = bootstrapped(&["parse length"]).await;
	*f.log.drop_response.lock().unwrap() = Some("finalize-drilldown");
	let (_, result) = finalize_once(&f, promote("parse length")).await;
	sealed(&result);
	let calls = f.log.take();
	let finalizes: Vec<_> =
		calls.iter().filter(|(route, _)| route == "finalize-drilldown").collect();
	assert_eq!(
		finalizes,
		[&("finalize-drilldown".to_owned(), 502), &("finalize-drilldown".to_owned(), 200)]
	);
	assert_no_complete(&calls);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM findings"), 1);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM job_terminal_receipts"), 2, "survey and drilldown");
	assert_eq!(drilldowns(&f), [("succeeded".to_owned(), None)]);
}

#[tokio::test]
async fn an_agent_that_never_finalizes_fails_and_is_requeued() {
	let f = bootstrapped(&["parse length"]).await;
	assert!(
		f.step(|mut agent| async move {
			agent.list_tools().await?;
			anyhow::bail!("agent-private-error-sentinel")
		})
		.await
	);
	let calls = f.log.take();
	assert_eq!(calls.last(), Some(&("complete".to_owned(), 200)), "{calls:?}");
	assert_eq!(
		drilldowns(&f),
		[("queued".to_owned(), Some("agent exited without finalizing".to_owned()))]
	);
}

#[tokio::test]
async fn a_cancelled_campaign_stops_the_agent_and_the_failure_is_accepted() {
	let f = bootstrapped(&["parse length"]).await;
	let state = f.state.clone();
	let reached_end = Arc::new(AtomicBool::new(false));
	let flag = reached_end.clone();
	assert!(
		f.step(move |mut agent| {
			let (state, flag) = (state.clone(), flag.clone());
			async move {
				cancel_campaign(&state.db);
				let denied =
					agent.call("submit_sibling_lead", sibling("s-1", "parse header")).await?;
				assert!(denied.is_error && denied.text.contains("no longer has authority"));
				// The handler cancels the agent; a well-behaved script never gets here.
				tokio::time::sleep(Duration::from_secs(30)).await;
				flag.store(true, Ordering::SeqCst);
				Ok(())
			}
		})
		.await
	);
	assert!(!reached_end.load(Ordering::SeqCst), "the agent was stopped");
	let calls = f.log.take();
	assert!(calls.contains(&("sibling-leads".to_owned(), 403)), "{calls:?}");
	assert!(calls.contains(&("limits".to_owned(), 403)), "the refusal was probed: {calls:?}");
	assert_eq!(calls.last(), Some(&("complete".to_owned(), 200)), "{calls:?}");
	let (state, error) = drilldowns(&f).remove(0);
	assert_ne!(state, "leased");
	assert!(error.is_some(), "the server recorded the failure");
}

#[tokio::test]
async fn a_drilldown_too_close_to_its_hard_deadline_fails_without_launch() {
	let f = bootstrapped(&["parse length"]).await;
	f.offset.store(DRILLDOWN_PAST_LAUNCH, Ordering::SeqCst);
	let launched = Arc::new(AtomicBool::new(false));
	let flag = launched.clone();
	assert!(
		f.step(move |_agent| {
			flag.store(true, Ordering::SeqCst);
			async { Ok(()) }
		})
		.await
	);
	assert!(!launched.load(Ordering::SeqCst), "no agent past the launch deadline");
	let calls = f.log.take();
	assert!(!routes(&calls).contains(&"finalize-drilldown"), "{calls:?}");
	assert_eq!(routes(&calls).last(), Some(&"complete"));
	assert_eq!(drilldowns(&f)[0].1.as_deref(), Some("hard deadline reached"));
}
