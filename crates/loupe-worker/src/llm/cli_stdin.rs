//! One invocation's stdin delivery, bounded output drains and child wait.
//! The adapter owns the request deadline and final explicit kill/reap path.

use anyhow::{anyhow, Result};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use super::cli_output::{collect_cli_output, CapturedOutput};
use super::prompt::Prompt;
use crate::sandbox::PreparedChild;

pub(crate) struct CliRun {
	pub status: std::process::ExitStatus,
	pub stdout: CapturedOutput,
	pub stderr: CapturedOutput,
	pub stdin_failed: bool,
	pub killed_for_stdin: bool,
}

pub(crate) async fn drive(
	child: &mut PreparedChild, prompt: &Prompt, cancel: CancellationToken,
	quarantine: CancellationToken,
) -> Result<CliRun> {
	let mut stdin = child.take_stdin().ok_or_else(|| anyhow!("CLI stdin unavailable"))?;
	let stdout = child.take_stdout().ok_or_else(|| anyhow!("CLI stdout unavailable"))?;
	let stderr = child.take_stderr().ok_or_else(|| anyhow!("CLI stderr unavailable"))?;
	let wait_and_write = async {
		let delivery = async move {
			stdin.write_all(prompt.expose().as_bytes()).await?;
			let result = stdin.shutdown().await;
			drop(stdin);
			result
		};
		tokio::pin!(delivery);
		tokio::select! {
			biased;
			written = &mut delivery => {
				let failed = written.is_err();
				if failed {
					if let Some(status) = child.try_wait()? { return Ok::<_, std::io::Error>((status, true, false)); }
					// A pipe error can precede a child's final exit by a scheduling
					// turn. A short bounded grace retains that nonzero diagnostic.
					if let Ok(status) = tokio::time::timeout(std::time::Duration::from_millis(25), child.wait()).await {
						return Ok((status?, true, false));
					}
					child.kill().await?;
					Ok((child.wait().await?, true, true))
				} else { Ok((child.wait().await?, false, false)) }
			},
			status = child.wait() => Ok((status?, true, false)),
		}
	};
	let operation = async {
		let (process, stdout, stderr) =
			tokio::join!(wait_and_write, collect_cli_output(stdout), collect_cli_output(stderr));
		let (status, stdin_failed, killed_for_stdin) = process?;
		Result::<_, std::io::Error>::Ok(CliRun {
			status,
			stdout: stdout?,
			stderr: stderr?,
			stdin_failed,
			killed_for_stdin,
		})
	};
	tokio::select! {
		biased;
		_ = quarantine.cancelled() => Err(crate::canary::JobQuarantined.into()),
		_ = cancel.cancelled() => Err(anyhow!("cancelled")),
		result = operation => result.map_err(Into::into),
	}
}
