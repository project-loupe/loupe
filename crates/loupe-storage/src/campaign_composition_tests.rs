//! Payload-policy checks for mixed-source and host-authored campaign documents.
use loupe_core::{FollowUpTrigger, PendingFollowUp, ReviewIntent};

use super::*;
use crate::test_support::{config_text, db_json, json};

#[test]
fn closed_numeric_policy_matches_the_prior_payload_bytes_and_digest() {
	let max = crate::scheduler::CampaignPolicy {
		version: u32::MAX,
		campaign_deadline_seconds: i64::MIN,
		campaign_max_jobs: i64::MAX,
		max_attempts: u32::MAX,
		survey_token_budget: Some(u64::MAX),
		..Default::default()
	};
	for value in [crate::scheduler::CampaignPolicy::default(), max] {
		let original = json::<Payload>(&serde_json::to_string(&value).unwrap()).unwrap();
		let composed = CampaignPolicyInput::<Db>::Resolved(&value).canonical();
		assert_eq!(composed, original.canonical());
		assert_eq!(loupe_core::canonical::digest(&composed), *original.digest());
	}
}

fn prior_composition(previous: &serde_json::Value, requested: &str, at: i64) -> String {
	let hint = if previous["kind_hint"] == "full_review" { "full_review" } else { "incremental" };
	let mut history = previous["triggers"].as_array().cloned().unwrap_or_default();
	history.push(
		serde_json::json!({"trigger":"operator","ref":requested,"at":at,"kind_hint":"incremental"}),
	);
	if history.len() > 16 {
		history.drain(..history.len() - 16);
	}
	serde_json::json!({"version":1,"triggers":history,"newest_ref":requested,"kind_hint":hint})
		.to_string()
}

#[test]
fn mixed_follow_up_retains_unknown_entries_order_intent_and_semantic_policy() {
	let requested = config_text::<RevisionText>("branche-e\u{301}").unwrap();
	for previous in [
		serde_json::Value::Null,
		serde_json::json!({"triggers":[null,17,"old",[true],{"future":"e\u{301}"}],"kind_hint":"full_review"}),
		serde_json::json!({"triggers": (0..20).collect::<Vec<_>>(), "kind_hint":"full_review"}),
		serde_json::json!({"triggers":false,"future":42}),
	] {
		let previous = db_json::<Payload>(&previous.to_string()).unwrap();
		let prior: serde_json::Value = serde_json::from_str(previous.expose()).unwrap();
		let expected = json::<Payload>(&prior_composition(&prior, requested.expose(), 73)).unwrap();
		let actual = PendingFollowUp::new(
			Some(&previous),
			&requested,
			FollowUpTrigger::Operator,
			ReviewIntent::Incremental,
			73,
		)
		.unwrap();
		assert_eq!(actual.canonical(), expected.expose());
		assert_eq!(
			requested.expose(),
			"branche-e\u{301}",
			"normalizing composed Payload must not mutate the original exact request"
		);
	}
}

#[test]
fn mixed_follow_up_uses_the_existing_payload_cap_and_normalization_limits() {
	for requested in [
		"x".repeat(4000),
		"x".repeat(4001),
		"x".repeat(65_536),
		"\u{0344}".repeat(2000),
		"\u{0344}".repeat(2001),
		"  exact request  ".to_owned(),
	] {
		let requested = config_text::<RevisionText>(&requested).unwrap();
		let expected =
			json::<Payload>(&prior_composition(&serde_json::Value::Null, requested.expose(), 0));
		let actual = PendingFollowUp::new(
			None,
			&requested,
			FollowUpTrigger::Operator,
			ReviewIntent::Incremental,
			0,
		);
		match (expected, actual) {
			(Ok(expected), Ok(actual)) => assert_eq!(actual.canonical(), expected.expose()),
			(Err(expected), Err(actual)) => assert_eq!(actual, expected),
			_ => panic!("named composition changed Payload admission"),
		}
	}
}
