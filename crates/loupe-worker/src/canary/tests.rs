use std::os::unix::fs::PermissionsExt;

use super::*;

#[test]
fn fake_file_is_private_stable_and_owned_until_the_last_job_reference() {
	let job = JobSecurity::new(
		EventContext { job_id: Some(7), repo_id: Some(3), ..Default::default() },
		Vec::new(),
	)
	.unwrap();
	let path = job.canary.path();
	let file = std::fs::read(&path).unwrap();
	let value: serde_json::Value = serde_json::from_slice(&file).unwrap();
	let key = value["api_key"].as_str().unwrap();
	assert_eq!(key.len(), 64);
	assert!(key.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
	assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o400);
	assert_eq!(
		std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777,
		0o700
	);
	assert!(!format!("{job:?}").contains(key));
	let held = job.clone();
	drop(job);
	assert!(path.exists());
	drop(held);
	assert!(!path.exists());
}

#[test]
fn quarantine_is_monotonic_and_signals_before_any_egress_or_async_work() {
	let credential =
		crate::llm::model_broker::ModelCredential::openai_api_key("watched-synthetic-key");
	let job = JobSecurity::new(EventContext::default(), vec![credential.watch()]).unwrap();
	assert!(!job.is_quarantined());
	assert!(!job.observe(b"ordinary", Broker::Model));
	assert!(job.observe(br#"{"ignored":"watched-synthetic-key"}"#, Broker::Mcp));
	assert!(job.is_quarantined());
	assert!(job.cancellation().is_cancelled());
	assert!(job.admit(Operation::McpSubmitFinding).is_err());
	assert!(!job.observe(b"ordinary", Broker::Model));
	assert!(job.is_quarantined());
	let fresh = JobSecurity::new(EventContext::default(), Vec::new()).unwrap();
	assert!(fresh.admit(Operation::McpSubmitFinding).is_ok());
	assert!(!fresh.is_quarantined());
}

#[test]
fn lexical_observer_visits_escaped_unknown_duplicate_keys_and_malformed_neighbors() {
	let secret = b"A\xF0\x9F\x98\x80Z";
	for raw in [
		br#"{"ignored":"A\uD83D\uDE00Z"}"#.as_slice(),
		br#"{"A\uD83D\uDE00Z":0,"x":1}"#,
		br#"{"x":"A\uD83D\uDE00Z","x":"benign"}"#,
		br#"{"ignored":"\uD800","later":"A\uD83D\uDE00Z"}"#,
		br#"{"x":"\qA\uD83D\uDE00Z"}"#,
		br#"{"x":"A\uD83D\uDE00Z\q"}"#,
		br#"{"x":"\uD800\u0041\uD83D\uDE00Z"}"#,
	] {
		assert!(observe::contains(raw, |run| contains_bytes(run, secret)), "missed {raw:?}");
	}
	for raw in [
		br#"{"x":"A\uD800\uD83D\uDE00Z"}"#.as_slice(),
		br#"{"x":"A\q\uD83D\uDE00Z"}"#,
		br#"{"x":"A","y":"\uD83D\uDE00Z"}"#,
		br#"{"x":"A\uZZZZ\uD83D\uDE00Z"}"#,
		b"{\"x\":\"A\xFF\\uD83D\\uDE00Z\"}",
	] {
		assert!(
			!observe::contains(raw, |run| contains_bytes(run, secret)),
			"invented match {raw:?}"
		);
	}
	assert!(observe::contains(b"{\"x\":\"\xFF\\u0041\\uD83D\\uDE00Z\"}", |run| contains_bytes(
		run, secret
	)));
}

#[test]
fn literal_escape_runs_do_not_recursively_decode() {
	assert!(observe::contains(br#"{"x":"\u0061\u0062\u0063"}"#, |run| contains_bytes(run, b"abc")));
	assert!(!observe::contains(br#"{"x":"\\u0061\\u0062\\u0063"}"#, |run| contains_bytes(
		run, b"abc"
	)));
	assert!(observe::contains(br#"{"x":"a\"b\\c\/d\ne\rf\tg\bh\fi"}"#, |run| contains_bytes(
		run,
		b"a\"b\\c/d\ne\rf\tg\x08h\x0ci"
	)));
}
