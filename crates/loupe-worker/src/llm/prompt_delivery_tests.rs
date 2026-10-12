// Compiled as a module by both real adapters: the fixture reaches their run()
// methods with only the sandbox disabled, preserving the actual spawn path.
use std::time::Duration;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use super::tests::{sh_single_quote, test_model_broker};
use super::{LlmBackend, LlmRequest, LlmResponse, PromptTestBackend};

#[cfg(unix)]
async fn s3_prompt_delivery_fixture() -> (Vec<u8>, String, String) {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().unwrap();
	let script = dir.path().join("prompt-delivery-fixture");
	let input = dir.path().join("input");
	let arguments = dir.path().join("arguments");
	let environment = dir.path().join("environment");
	std::fs::write(
		&script,
		format!(
			"#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nenv > {}\ncat > {}\nprintf 'fixture-success'\n",
			sh_single_quote(&arguments),
			sh_single_quote(&environment),
			sh_single_quote(&input)
		),
	)
	.unwrap();
	std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
	let backend = PromptTestBackend::with_bin(script.to_string_lossy())
		.with_sandbox_disabled_for_tests()
		.with_model_broker_context(test_model_broker("/bin/true"));
	let response = backend
		.run(LlmRequest {
			tool_boundary: crate::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt: crate::llm::prompts::Prompt::instruction(S3_STDIN_SENTINEL).unwrap(),
			workdir: dir.path().to_owned(),
			timeout: Duration::from_secs(5),
			cancel: CancellationToken::new(),
			repo_id: None,
			job_id: None,
			job_capability: None,
			finding_id: None,
		})
		.await
		.expect("fixture invocation must complete successfully");
	assert_eq!(response.text.for_log(), "fixture-success");
	(
		std::fs::read(input).unwrap(),
		std::fs::read_to_string(arguments).unwrap(),
		std::fs::read_to_string(environment).unwrap(),
	)
}

const S3_STDIN_SENTINEL: &str = "S3_PROMPT_DISTINCTIVE_SENTINEL e\u{301}\r\n\t final-space ";

#[cfg(unix)]
#[tokio::test]
async fn s3_prompt_reaches_stdin_exactly_with_eof() {
	// Concurrent test forks can inherit a writable script descriptor and cause ETXTBSY.
	let name = concat!(module_path!(), "::s3_prompt_reaches_stdin_exactly_with_eof");
	if !crate::test_env::in_env(name.strip_prefix("loupe_worker::").unwrap(), "prompt-fixture", &[])
	{
		return;
	}
	let (input, _, _) = s3_prompt_delivery_fixture().await;
	assert_eq!(
		input,
		crate::llm::prompt::Prompt::instruction(S3_STDIN_SENTINEL).unwrap().expose().as_bytes(),
		"CLI stdin must receive every prompt byte unchanged and then EOF"
	);
}

#[cfg(unix)]
#[tokio::test]
async fn s3_prompt_is_absent_from_process_argv_and_environment() {
	let name = concat!(module_path!(), "::s3_prompt_is_absent_from_process_argv_and_environment");
	if !crate::test_env::in_env(name.strip_prefix("loupe_worker::").unwrap(), "prompt-fixture", &[])
	{
		return;
	}
	let (_, arguments, environment) = s3_prompt_delivery_fixture().await;
	assert!(
		!arguments.contains("S3_PROMPT_DISTINCTIVE_SENTINEL"),
		"prompt bytes must never appear in CLI argv"
	);
	assert!(
		!environment.contains("S3_PROMPT_DISTINCTIVE_SENTINEL"),
		"prompt bytes must never appear in CLI environment"
	);
}

#[cfg(unix)]
static S3_BACKPRESSURE_INPUT: [u8; 96 * 1024] = [b'x'; 96 * 1024];

#[cfg(unix)]
async fn s3_lifecycle_fixture(
	body: &str, timeout: Duration, cancel_after: Option<Duration>,
) -> (Result<LlmResponse>, Duration, Vec<u8>, bool) {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().unwrap();
	let script = dir.path().join("stdin-lifecycle-fixture");
	let input = dir.path().join("input");
	let pid = dir.path().join("pid");
	std::fs::write(
		&script,
		format!(
			"#!/bin/sh\nprintf '%s' \"$$\" > {}\ninput={}\n{body}\n",
			sh_single_quote(&pid),
			sh_single_quote(&input)
		),
	)
	.unwrap();
	std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
	let backend = PromptTestBackend::with_bin(script.to_string_lossy())
		.with_sandbox_disabled_for_tests()
		.with_model_broker_context(test_model_broker("/bin/true"));
	let cancel = CancellationToken::new();
	let cancellation = cancel_after.map(|delay| {
		let cancel = cancel.clone();
		tokio::spawn(async move {
			tokio::time::sleep(delay).await;
			cancel.cancel();
		})
	});
	let started = std::time::Instant::now();
	let result = backend
		.run(LlmRequest {
			tool_boundary: crate::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt: crate::llm::prompts::Prompt::instruction(
				std::str::from_utf8(&S3_BACKPRESSURE_INPUT).unwrap(),
			)
			.unwrap(),
			workdir: dir.path().to_owned(),
			timeout,
			cancel,
			repo_id: None,
			job_id: None,
			job_capability: None,
			finding_id: None,
		})
		.await;
	let elapsed = started.elapsed();
	if let Some(cancellation) = cancellation {
		cancellation.await.unwrap();
	}
	let pid: u32 = std::fs::read_to_string(pid).unwrap().parse().unwrap();
	let reaped = !std::path::Path::new(&format!("/proc/{pid}")).exists();
	(result, elapsed, std::fs::read(input).unwrap_or_default(), reaped)
}

#[cfg(unix)]
#[tokio::test]
async fn s3_cli_drains_both_outputs_while_delivering_stdin() {
	let name = concat!(module_path!(), "::s3_cli_drains_both_outputs_while_delivering_stdin");
	if !crate::test_env::in_env(name.strip_prefix("loupe_worker::").unwrap(), "prompt-fixture", &[])
	{
		return;
	}
	let (result, _, input, reaped) = s3_lifecycle_fixture(
		"head -c 131072 /dev/zero | tr '\\000' x\nhead -c 131072 /dev/zero | tr '\\000' x >&2\ncat > \"$input\"",
		Duration::from_secs(3), None,
	).await;
	let response = result.expect("output-first child must not deadlock with prompt input");
	assert_eq!(response.text.for_log().len(), 131072);
	assert!(reaped, "output-first child must be reaped");
	let expected = crate::llm::prompt::Prompt::instruction(
		std::str::from_utf8(&S3_BACKPRESSURE_INPUT).unwrap(),
	)
	.unwrap();
	assert!(
		input == expected.expose().as_bytes(),
		"backpressured stdin must arrive completely: received {} of {} bytes",
		input.len(),
		expected.expose().len()
	);
}

#[cfg(unix)]
#[tokio::test]
async fn s3_cli_rejects_incomplete_stdin_even_when_child_exits_zero() {
	let name =
		concat!(module_path!(), "::s3_cli_rejects_incomplete_stdin_even_when_child_exits_zero");
	if !crate::test_env::in_env(name.strip_prefix("loupe_worker::").unwrap(), "prompt-fixture", &[])
	{
		return;
	}
	let (result, _, _, reaped) =
		s3_lifecycle_fixture("exec 0<&-\nsleep 0.1\nexit 0", Duration::from_secs(3), None).await;
	assert!(reaped, "early-close child must be reaped");
	assert!(result.is_err(), "zero exit cannot establish full prompt delivery after EPIPE");
}

#[cfg(unix)]
#[tokio::test]
async fn s3_cli_reaps_a_live_child_immediately_after_stdin_closes() {
	let name =
		concat!(module_path!(), "::s3_cli_reaps_a_live_child_immediately_after_stdin_closes");
	if !crate::test_env::in_env(name.strip_prefix("loupe_worker::").unwrap(), "prompt-fixture", &[])
	{
		return;
	}
	let (result, elapsed, _, reaped) =
		s3_lifecycle_fixture("exec 0<&-\nexec sleep 10", Duration::from_secs(2), None).await;
	assert!(result.is_err());
	assert!(reaped, "live early-close child must be reaped");
	assert!(
		elapsed < Duration::from_secs(1),
		"stdin failure must not wait for the request timeout: {elapsed:?}"
	);
}

#[cfg(unix)]
#[tokio::test]
async fn s3_compatibility_cli_cancellation_reaps_a_child_that_never_reads() {
	let name = concat!(
		module_path!(),
		"::s3_compatibility_cli_cancellation_reaps_a_child_that_never_reads"
	);
	if !crate::test_env::in_env(name.strip_prefix("loupe_worker::").unwrap(), "prompt-fixture", &[])
	{
		return;
	}
	let (result, elapsed, _, reaped) = s3_lifecycle_fixture(
		"exec sleep 10",
		Duration::from_secs(3),
		Some(Duration::from_millis(150)),
	)
	.await;
	assert!(result.unwrap_err().to_string().contains("cancelled"));
	assert!(reaped, "cancelled child must be reaped");
	assert!(elapsed < Duration::from_secs(1));
}

#[cfg(unix)]
#[tokio::test]
async fn s3_compatibility_cli_timeout_reaps_a_child_that_never_reads() {
	let name =
		concat!(module_path!(), "::s3_compatibility_cli_timeout_reaps_a_child_that_never_reads");
	if !crate::test_env::in_env(name.strip_prefix("loupe_worker::").unwrap(), "prompt-fixture", &[])
	{
		return;
	}
	let (result, elapsed, _, reaped) =
		s3_lifecycle_fixture("exec sleep 10", Duration::from_millis(150), None).await;
	assert!(result.unwrap_err().to_string().contains("timed out"));
	assert!(reaped, "timed-out child must be reaped");
	assert!(elapsed < Duration::from_secs(1));
}

#[cfg(unix)]
#[tokio::test]
async fn s3_compatibility_cli_nonzero_exit_retains_the_process_failure() {
	let name =
		concat!(module_path!(), "::s3_compatibility_cli_nonzero_exit_retains_the_process_failure");
	if !crate::test_env::in_env(name.strip_prefix("loupe_worker::").unwrap(), "prompt-fixture", &[])
	{
		return;
	}
	let (result, _, _, reaped) = s3_lifecycle_fixture(
		"exec 0<&-\nprintf 'synthetic-child-failure' >&2\nexit 7",
		Duration::from_secs(3),
		None,
	)
	.await;
	assert!(reaped, "failed child must be reaped");
	assert!(
		result.unwrap_err().is::<super::super::cli_output::CliProcessFailure>(),
		"a captured nonzero exit must preserve the existing process failure"
	);
}
