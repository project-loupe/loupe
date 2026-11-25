//! Scripted setup for suites whose phase leases follow a bootstrap survey:
//! the survey that leaves the leads and the drilldown that promotes one.
use std::sync::{Arc, Mutex};

use loupe_worker::llm::testing::{ScriptedAgent, ToolResult};
use serde_json::{json, Value};

use super::phase_worker::{finalize, fixture, ok, profile, Fixture};

pub fn lead_at(key: &str, anchor: &str) -> Value {
	json!({"client_lead_key": key, "identity_family": "memory-safety",
		"identity_anchor": anchor, "hypothesis": "The parser trusts the input length.",
		"source_refs": [{"path": "src/lib.rs"}], "next_proof_step": "Write a harness.",
		"counterevidence": "Length is only read.", "proof_gaps": "Reachability."})
}

type Played = std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>;

/// A bootstrap survey that publishes the profile, leaves one lead per
/// anchor and finalizes.
pub fn bootstrap(
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

pub fn promote(anchor: &str) -> Value {
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

pub fn sealed(result: &ToolResult) -> &str {
	let text = ok(result);
	assert!(text.starts_with("drilldown finalized as "), "{text}");
	text
}

/// Run one step whose script only finalizes with `arguments`; returns the
/// prompt and the finalize result.
pub async fn finalize_once(f: &Fixture, arguments: Value) -> (String, ToolResult) {
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

/// A fixture whose bootstrap survey has left one lead per anchor.
pub async fn bootstrapped(anchors: &'static [&'static str]) -> Fixture {
	bootstrapped_from(fixture().await, anchors).await
}

/// [`bootstrapped`] on a fixture the suite built itself.
pub async fn bootstrapped_from(f: Fixture, anchors: &'static [&'static str]) -> Fixture {
	assert!(f.step(bootstrap(anchors)).await);
	assert_eq!(f.jobs(), [("succeeded".to_owned(), None)]);
	f.log.take();
	f
}

/// Promote the next claimed lead as the only finding, which is left in state
/// `validating`; returns the finding id.
pub async fn promoted(f: &Fixture, anchor: &str) -> i64 {
	let (_, result) = finalize_once(f, promote(anchor)).await;
	sealed(&result);
	let finding = f.scalar("SELECT id FROM findings");
	f.log.take();
	finding
}
