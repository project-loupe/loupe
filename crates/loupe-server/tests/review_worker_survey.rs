//! Survey leases end to end: the actual router, a git fixture repository,
//! `Runner` with the scripted MCP agent driving the real broker, catalog,
//! gate, phase client and retry. Requests reach the router through a plain
//! listener with the worker's `PeerCert` injected, as in the other
//! `review_worker_*` suites, so a layer can record and fault responses.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use loupe_worker::llm::testing::{ScriptedAgent, ScriptedMcpBackend};
use loupe_worker::{RepoCache, Runner};
use serde_json::json;
use tokio_util::sync::CancellationToken;

mod common;

use common::phase_worker::*;

/// Publish the profile, propose two units, record a lead, results and
/// dispositions, and finalize.
async fn full_bootstrap(mut agent: ScriptedAgent) -> anyhow::Result<()> {
	ok(&agent.call("publish_profile", profile()).await?);
	let first = reported_id(&agent.call("propose_review_unit", unit("parser")).await?, "id=");
	let second = reported_id(&agent.call("propose_review_unit", unit("entry")).await?, "id=");
	let lead_id = reported_id(&agent.call("submit_lead", lead("length", first)).await?, "id=");
	ok(&agent
		.call("submit_review_unit_result", result("r-1", first, "lead_created", &[lead_id]))
		.await?);
	ok(&agent
		.call("submit_review_unit_result", result("r-2", second, "no_lead_found", &[]))
		.await?);
	for (key, path, disposition) in
		[("d-lib", "src/lib.rs", "mapped"), ("d-readme", "README.md", "excluded")]
	{
		let mut arguments = json!({"client_inventory_disposition_key": key, "path": path,
			"disposition": disposition});
		if disposition == "mapped" {
			arguments["mapped_review_unit_ids"] = json!([first]);
		} else {
			arguments["reason"] = json!("Documentation only.");
		}
		ok(&agent.call("submit_inventory_disposition", arguments).await?);
	}
	ok(&agent.call("finalize_survey", finalize("completed")).await?);
	Ok(())
}

/// Publish the profile and propose two units left for coverage jobs.
async fn mapping_bootstrap(mut agent: ScriptedAgent) -> anyhow::Result<()> {
	ok(&agent.call("publish_profile", profile()).await?);
	ok(&agent.call("propose_review_unit", unit("parser")).await?);
	ok(&agent.call("propose_review_unit", unit("entry")).await?);
	ok(&agent.call("finalize_survey", finalize("completed")).await?);
	Ok(())
}

#[tokio::test]
async fn only_a_worker_with_a_survey_backend_is_leased_a_survey() {
	let f = fixture().await;
	let cache = Arc::new(RepoCache::new(f.cache.path().to_owned(), u64::MAX, None).unwrap());
	let plain = Runner::new(f.client.clone(), cache.clone(), Vec::new());
	let unclaimed =
		tokio::time::timeout(Duration::from_secs(2), plain.step(&CancellationToken::new())).await;
	assert!(matches!(unclaimed, Err(_) | Ok(Ok(false))), "a survey-less worker ran a lease");
	assert_eq!(f.jobs(), [("queued".to_owned(), None)]);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM jobs WHERE worker_id IS NOT NULL"), 0);

	let surveyor = Runner::new(f.client.clone(), cache, Vec::new())
		.with_phase_backend(Arc::new(ScriptedMcpBackend::new(f.client.clone(), full_bootstrap)));
	assert!(surveyor.step(&CancellationToken::new()).await.unwrap());
	assert_eq!(f.jobs(), [("succeeded".to_owned(), None)]);
}

#[tokio::test]
async fn bootstrap_survey_finalizes_and_activates_its_generation() {
	let f = fixture().await;
	let tools = Arc::new(Mutex::new(Vec::new()));
	let seen = tools.clone();
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				*seen.lock().unwrap() = agent.list_tools().await?;
				full_bootstrap(agent).await
			}
		})
		.await
	);
	assert!(tools.lock().unwrap().contains(&"publish_profile".to_owned()));
	let calls = f.log.take();
	assert_no_complete(&calls);
	assert!(calls.iter().all(|(_, status)| *status == 200), "{calls:?}");
	assert_eq!(f.jobs(), [("succeeded".to_owned(), None)]);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM review_generations WHERE state='active'"), 1);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM review_units"), 2);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM leads"), 1);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM review_unit_results"), 2);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM job_terminal_receipts"), 1);
	assert_eq!(
		f.scalar(
			"SELECT COUNT(*) FROM generation_inventory WHERE disposition IN ('mapped','excluded')"
		),
		2
	);
}

#[tokio::test]
async fn coverage_survey_after_bootstrap_sees_only_its_assignment_and_the_profile() {
	let f = fixture().await;
	assert!(f.step(mapping_bootstrap).await);
	f.log.take();
	let units = f.unit_ids();
	assert_eq!(units.len(), 2);
	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	assert!(
		f.step(move |mut agent| {
			let (seen, units) = (seen.clone(), units.clone());
			async move {
				let tools = agent.list_tools().await?;
				let mut accepted = Vec::new();
				for (index, unit) in units.iter().enumerate() {
					let key = format!("cover-{index}");
					let outcome = agent
						.call(
							"submit_review_unit_result",
							result(&key, *unit, "no_lead_found", &[]),
						)
						.await?;
					accepted.push(!outcome.is_error);
				}
				ok(&agent.call("finalize_survey", finalize("completed")).await?);
				*seen.lock().unwrap() = Some((agent.prompt.clone(), tools, accepted));
				Ok(())
			}
		})
		.await
	);
	let (prompt, tools, accepted) = observed.lock().unwrap().take().expect("script ran");
	assert!(!tools.contains(&"publish_profile".to_owned()), "{tools:?}");
	assert!(prompt.contains("published profile: untrusted, agent-generated hypotheses"));
	assert!(prompt.contains(r#""recipe":"coverage""#), "the prompt states the coverage recipe");
	assert_eq!(accepted.iter().filter(|accepted| **accepted).count(), 1, "one assigned unit");
	let calls = f.log.take();
	assert_no_complete(&calls);
	assert!(!routes(&calls).contains(&"publish-profile"));
	assert!(!routes(&calls).contains(&"inventory-batches"));
	assert_eq!(f.jobs().iter().filter(|(state, _)| state == "succeeded").count(), 2);
}

#[tokio::test]
async fn a_retried_bootstrap_resumes_with_the_profile_and_remaining_capacity() {
	let f = fixture().await;
	assert!(
		f.step(|mut agent| async move {
			ok(&agent.call("publish_profile", profile()).await?);
			ok(&agent.call("propose_review_unit", unit("first-a")).await?);
			ok(&agent.call("propose_review_unit", unit("first-b")).await?);
			Ok(())
		})
		.await
	);
	let calls = f.log.take();
	assert_eq!(routes(&calls).last(), Some(&"complete"), "{calls:?}");
	assert_eq!(
		f.jobs(),
		[("queued".to_owned(), Some("agent exited without finalizing".to_owned()))]
	);
	f.make_eligible();

	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				let tools = agent.list_tools().await?;
				let proposed = agent.call("propose_review_unit", unit("second")).await?;
				ok(&proposed);
				ok(&agent.call("finalize_survey", finalize("completed")).await?);
				*seen.lock().unwrap() = Some((agent.prompt.clone(), tools, proposed.text));
				Ok(())
			}
		})
		.await
	);
	let (prompt, tools, proposed) = observed.lock().unwrap().take().expect("script ran");
	assert!(!tools.contains(&"publish_profile".to_owned()), "{tools:?}");
	assert!(prompt.contains("This is a retry."), "retry instruction");
	assert!(prompt.contains("published profile: untrusted"), "profile block");
	assert!(prompt.contains(r#""review_units":{"limit":3,"remaining":1}"#), "reduced capacity");
	assert!(proposed.contains("review units remaining: 0"), "{proposed}");
	let calls = f.log.take();
	assert_eq!(routes(&calls)[..2], ["pin-target", "inventory-batches"], "{calls:?}");
	assert!(!routes(&calls).contains(&"publish-profile"));
	assert!(!routes(&calls).contains(&"seal-inventory"), "the sealed manifest is not resent");
	assert_no_complete(&calls);
	assert_eq!(f.jobs(), [("succeeded".to_owned(), None)]);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM review_generations WHERE state='active'"), 1);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM review_units"), 3, "both attempts' units");
}

#[tokio::test]
async fn a_retry_at_exhausted_unit_quota_still_finalizes() {
	let f = fixture().await;
	assert!(
		f.step(|mut agent| async move {
			ok(&agent.call("publish_profile", profile()).await?);
			for key in ["a", "b", "c"] {
				ok(&agent.call("propose_review_unit", unit(key)).await?);
			}
			Ok(())
		})
		.await
	);
	f.log.take();
	f.make_eligible();
	let refused = Arc::new(Mutex::new(None));
	let seen = refused.clone();
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				let refused = agent.call("propose_review_unit", unit("d")).await?;
				ok(&agent.call("finalize_survey", finalize("partial")).await?);
				*seen.lock().unwrap() = Some(refused);
				Ok(())
			}
		})
		.await
	);
	let refused = refused.lock().unwrap().take().unwrap();
	assert!(refused.is_error);
	assert!(
		refused.text.contains("capacity for this kind of checkpoint is exhausted"),
		"{}",
		refused.text
	);
	assert!(refused.text.contains("finalize_survey"));
	assert_no_complete(&f.log.take());
	assert_eq!(f.jobs()[0].0, "succeeded");
	assert_eq!(f.scalar("SELECT COUNT(*) FROM review_units"), 3);
}

#[tokio::test]
async fn a_lost_response_is_replayed_by_the_host_and_stored_once() {
	let f = fixture().await;
	*f.log.drop_response.lock().unwrap() = Some("review-units");
	assert!(
		f.step(|mut agent| async move {
			ok(&agent.call("publish_profile", profile()).await?);
			ok(&agent.call("propose_review_unit", unit("once")).await?);
			ok(&agent.call("finalize_survey", finalize("completed")).await?);
			Ok(())
		})
		.await
	);
	let calls = f.log.take();
	let units: Vec<_> = calls.iter().filter(|(route, _)| route == "review-units").collect();
	assert_eq!(units, [&("review-units".to_owned(), 502), &("review-units".to_owned(), 200)]);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM review_units"), 1);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM job_checkpoints WHERE client_key LIKE '%once'"), 1);
	assert_eq!(f.jobs()[0].0, "succeeded");
}

#[tokio::test]
async fn the_soft_stop_closes_new_inquiry_but_finalize_is_accepted() {
	let f = fixture().await;
	let offset = f.offset.clone();
	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	assert!(
		f.step(move |mut agent| {
			let (seen, offset) = (seen.clone(), offset.clone());
			async move {
				ok(&agent.call("publish_profile", profile()).await?);
				let first =
					reported_id(&agent.call("propose_review_unit", unit("early")).await?, "id=");
				offset.store(PAST_SUBMIT_BY, Ordering::SeqCst);
				let late = agent.call("propose_review_unit", unit("late")).await?;
				let query = agent
					.call("query_same_project_lead_candidates", json!({"query": "parse"}))
					.await?;
				ok(&agent.call("submit_lead", lead("after-stop", first)).await?);
				ok(&agent.call("finalize_survey", finalize("partial")).await?);
				*seen.lock().unwrap() = Some((late, query));
				Ok(())
			}
		})
		.await
	);
	let (late, query) = observed.lock().unwrap().take().unwrap();
	for denied in [&late, &query] {
		assert!(denied.is_error && denied.text.contains("soft stop reached"), "{denied:?}");
	}
	let calls = f.log.take();
	assert!(!routes(&calls).contains(&"lead-candidates"));
	assert_eq!(routes(&calls).iter().filter(|r| **r == "review-units").count(), 1);
	assert_eq!(f.jobs()[0].0, "succeeded");
}

#[tokio::test]
async fn a_lease_already_past_submit_by_still_finalizes() {
	let f = fixture().await;
	f.offset.store(PAST_SUBMIT_BY, Ordering::SeqCst);
	let denied = Arc::new(Mutex::new(None));
	let seen = denied.clone();
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				ok(&agent.call("publish_profile", profile()).await?);
				let refused = agent.call("propose_review_unit", unit("late")).await?;
				ok(&agent.call("finalize_survey", finalize("partial")).await?);
				*seen.lock().unwrap() = Some((agent.prompt.clone(), refused));
				Ok(())
			}
		})
		.await
	);
	let (prompt, refused) = denied.lock().unwrap().take().unwrap();
	assert!(prompt.contains(r#""submit_by_remaining_seconds":0"#), "the prompt states the stop");
	assert!(refused.is_error && refused.text.contains("soft stop reached"), "{refused:?}");
	assert_no_complete(&f.log.take());
	assert_eq!(f.jobs()[0].0, "succeeded");
}

#[tokio::test]
async fn a_survey_too_close_to_its_hard_deadline_fails_without_launch() {
	let f = fixture().await;
	f.offset.store(PAST_LAUNCH, Ordering::SeqCst);
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
	assert_eq!(routes(&f.log.take()).last(), Some(&"complete"));
	assert_eq!(f.jobs()[0].1.as_deref(), Some("hard deadline reached"));
}

#[tokio::test]
async fn an_agent_that_never_finalizes_fails_the_attempt_with_a_fixed_reason() {
	let f = fixture().await;
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
		f.jobs(),
		[("queued".to_owned(), Some("agent exited without finalizing".to_owned()))]
	);
}

#[tokio::test]
async fn a_cancelled_campaign_stops_the_agent_and_the_failure_is_accepted() {
	let f = fixture().await;
	let state = f.state.clone();
	let reached_end = Arc::new(AtomicBool::new(false));
	let flag = reached_end.clone();
	assert!(
		f.step(move |mut agent| {
			let (state, flag) = (state.clone(), flag.clone());
			async move {
				ok(&agent.call("publish_profile", profile()).await?);
				cancel_campaign(&state.db);
				let denied = agent.call("propose_review_unit", unit("after-cancel")).await?;
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
	assert!(calls.contains(&("review-units".to_owned(), 403)), "{calls:?}");
	assert!(calls.contains(&("limits".to_owned(), 403)), "the refusal was probed: {calls:?}");
	assert_eq!(calls.last(), Some(&("complete".to_owned(), 200)), "{calls:?}");
	let (state, error) = f.jobs().remove(0);
	assert_ne!(state, "leased");
	assert!(error.is_some(), "the server recorded the failure");
}

#[tokio::test]
async fn a_refused_reference_keeps_the_agent_running() {
	let f = fixture().await;
	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				ok(&agent.call("publish_profile", profile()).await?);
				let refused = agent
					.call("submit_review_unit_result", result("stray", 9999, "no_lead_found", &[]))
					.await?;
				ok(&agent.call("finalize_survey", finalize("completed")).await?);
				*seen.lock().unwrap() = Some(refused);
				Ok(())
			}
		})
		.await
	);
	let refused = observed.lock().unwrap().take().expect("script ran");
	assert!(refused.is_error, "{refused:?}");
	assert!(refused.text.contains("refused a referenced unit"), "{}", refused.text);
	assert!(!refused.text.contains("no longer has authority"), "{}", refused.text);
	let calls = f.log.take();
	assert!(calls.contains(&("review-unit-results".to_owned(), 403)), "{calls:?}");
	assert!(calls.contains(&("limits".to_owned(), 200)), "{calls:?}");
	assert_no_complete(&calls);
	assert_eq!(f.jobs(), [("succeeded".to_owned(), None)]);
}

#[tokio::test]
async fn a_deferred_pin_ends_the_job_without_further_calls() {
	let f = fixture().await;
	let first = f.origin.repo.head().unwrap().peel_to_commit().unwrap().id().to_string();
	assert!(f.step(full_bootstrap).await);
	f.offline
		.external_corruption(|conn| {
			conn.execute(
				"UPDATE jobs SET state='cancelled',job_capability_hash=NULL WHERE state!='succeeded'",
				[],
			)?;
			Ok(())
		})
		.unwrap();
	common::with_repo(&f.state.db, 1, |scope| {
		let summary = loupe_storage::campaigns::summarize(scope, 1)?;
		loupe_storage::campaigns::finish(
			scope,
			1,
			&summary,
			&common::marked::operator::text("partial"),
			now(),
		)
	})
	.unwrap();
	let blob = f.origin.blob(b"moved");
	let tree = f.origin.tree(&[("100644", b"z.rs", blob)]);
	f.origin.commit(tree);
	open_campaign(&f.state.db, Some(&first));
	f.log.take();

	let launched = Arc::new(AtomicBool::new(false));
	let flag = launched.clone();
	assert!(
		f.step(move |_agent| {
			flag.store(true, Ordering::SeqCst);
			async { Ok(()) }
		})
		.await
	);
	assert!(!launched.load(Ordering::SeqCst));
	assert_eq!(routes(&f.log.take()), ["pin-target"]);
}
