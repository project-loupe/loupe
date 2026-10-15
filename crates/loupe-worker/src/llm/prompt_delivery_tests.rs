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
	let backend = PromptTestBackend::with_bin(script.as_os_str())
		.with_sandbox_disabled_for_tests()
		.with_model_broker_context(test_model_broker("/bin/true"));
	let response = backend
		.run(LlmRequest {
			security: crate::canary::JobSecurity::new(Default::default(), Vec::new()).unwrap(),
			tool_boundary: crate::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt: crate::llm::prompts::Prompt::instruction(S3_STDIN_SENTINEL).unwrap(),
			sandbox_workdir: crate::sandbox::SandboxPath::fixture(dir.path().to_owned()),
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
	let backend = PromptTestBackend::with_bin(script.as_os_str())
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
			security: crate::canary::JobSecurity::new(Default::default(), Vec::new()).unwrap(),
			tool_boundary: crate::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt: crate::llm::prompts::Prompt::instruction(
				std::str::from_utf8(&S3_BACKPRESSURE_INPUT).unwrap(),
			)
			.unwrap(),
			sandbox_workdir: crate::sandbox::SandboxPath::fixture(dir.path().to_owned()),
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

#[cfg(unix)]
#[tokio::test]
async fn sandbox_output_is_absent_from_success_logs_and_failure_chains() {
	use std::io::Write;
	use std::os::unix::fs::PermissionsExt;
	use std::sync::{Arc, Mutex};
	let name =
		concat!(module_path!(), "::sandbox_output_is_absent_from_success_logs_and_failure_chains");
	let name = name.strip_prefix("loupe_worker::").unwrap();
	if !crate::test_env::in_env(name, "sandbox-i8-output", &[]) {
		return;
	}
	#[derive(Clone, Default)]
	struct Capture(Arc<Mutex<Vec<u8>>>);
	impl Write for Capture {
		fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
			self.0.lock().unwrap().extend_from_slice(bytes);
			Ok(bytes.len())
		}
		fn flush(&mut self) -> std::io::Result<()> {
			Ok(())
		}
	}
	let capture = Capture::default();
	let writer = capture.clone();
	tracing::subscriber::set_global_default(
		tracing_subscriber::fmt()
			.without_time()
			.with_ansi(false)
			.with_max_level(tracing::Level::DEBUG)
			.with_writer(move || writer.clone())
			.finish(),
	)
	.unwrap();
	let dir = tempfile::Builder::new().prefix("sandbox-path-private-sentinel-").tempdir().unwrap();
	let script = dir.path().join("output-fixture");
	let mut failure = None;
	for status in [0, 1] {
		std::fs::write(&script, format!("#!/bin/sh\ncat >/dev/null\nprintf 'sandbox-stdout-private-sentinel'\nprintf 'sandbox-stderr-private-sentinel' >&2\nexit {status}\n")).unwrap();
		std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
		let backend = PromptTestBackend::with_bin(script.as_os_str())
			.with_sandbox_disabled_for_tests()
			.with_model_broker_context(test_model_broker("/bin/true"))
			.with_log_agent_output(true);
		let result = backend
			.run(LlmRequest {
				security: crate::canary::JobSecurity::new(Default::default(), Vec::new()).unwrap(),
				tool_boundary: crate::llm::prompt::JobToolBoundary::new().unwrap(),
				prompt: crate::llm::prompt::Prompt::instruction("fixture").unwrap(),
				sandbox_workdir: crate::sandbox::SandboxPath::fixture(dir.path().to_owned()),
				workdir: dir.path().to_owned(),
				timeout: Duration::from_secs(5),
				cancel: CancellationToken::new(),
				repo_id: None,
				job_id: None,
				job_capability: None,
				finding_id: None,
			})
			.await;
		if status == 0 {
			assert!(result.is_ok());
		} else {
			failure = Some(result.unwrap_err());
		}
	}
	let failure = failure.unwrap();
	let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
	assert!(
		logs.contains("subprocess succeeded") && logs.contains("subprocess failed"),
		"must capture both real adapters' outcomes"
	);
	for marker in ["sandbox-stdout-private-sentinel", "sandbox-stderr-private-sentinel"] {
		assert!(!logs.contains(marker), "raw sandbox output reached host logs");
		assert!(
			!format!("{failure:#}").contains(marker),
			"raw sandbox output reached the public error chain"
		);
	}
	assert!(
		!logs.contains("sandbox-path-private-sentinel"),
		"raw sandbox working path reached host logs"
	);
}

#[cfg(unix)]
#[tokio::test]
async fn common_quarantine_cancels_and_reaps_the_running_child() {
	use std::os::unix::fs::PermissionsExt;
	let name = concat!(module_path!(), "::common_quarantine_cancels_and_reaps_the_running_child");
	if !crate::test_env::in_env(name.strip_prefix("loupe_worker::").unwrap(), "prompt-fixture", &[])
	{
		return;
	}
	let dir = tempfile::tempdir().unwrap();
	let script = dir.path().join("quarantine-lifecycle-fixture");
	let pid_file = dir.path().join("pid");
	std::fs::write(
		&script,
		format!(
			"#!/bin/sh\ncat >/dev/null\nprintf '%s' \"$$\" > {}\nexec sleep 30\n",
			sh_single_quote(&pid_file)
		),
	)
	.unwrap();
	std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
	let security = crate::canary::JobSecurity::new(
		Default::default(),
		vec![crate::llm::model_broker::ModelCredential::anthropic_api_key(
			"cli-lifecycle-fixture-secret",
		)
		.watch()],
	)
	.unwrap();
	let cancel = CancellationToken::new();
	let request = LlmRequest {
		security: security.clone(),
		tool_boundary: crate::llm::prompt::JobToolBoundary::new().unwrap(),
		prompt: crate::llm::prompt::Prompt::instruction("fixture").unwrap(),
		sandbox_workdir: crate::sandbox::SandboxPath::fixture(dir.path().to_owned()),
		workdir: dir.path().to_owned(),
		timeout: Duration::from_secs(10),
		cancel: cancel.clone(),
		repo_id: None,
		job_id: None,
		job_capability: None,
		finding_id: None,
	};
	let backend = PromptTestBackend::with_bin(script.as_os_str())
		.with_sandbox_disabled_for_tests()
		.with_model_broker_context(test_model_broker("/bin/true"));
	let mut task = tokio::spawn(async move { backend.run(request).await });
	let pid = tokio::time::timeout(Duration::from_secs(2), async {
		loop {
			if let Ok(pid) = std::fs::read_to_string(&pid_file)
				&& let Ok(pid) = pid.parse::<u32>()
			{
				break pid;
			}
			tokio::time::sleep(Duration::from_millis(5)).await;
		}
	})
	.await
	.unwrap();
	assert!(
		security.observe(b"cli-lifecycle-fixture-secret", loupe_core::security_event::Broker::Mcp)
	);
	let result = tokio::time::timeout(Duration::from_millis(500), &mut task).await;
	if result.is_err() {
		cancel.cancel();
		let _ = task.await;
	}
	assert!(
		!std::path::Path::new(&format!("/proc/{pid}")).exists(),
		"child must be explicitly reaped"
	);
	let error = result
		.expect("common quarantine must cancel the running CLI promptly")
		.unwrap()
		.unwrap_err();
	assert_eq!(error.to_string(), "injection_suspected");
}
