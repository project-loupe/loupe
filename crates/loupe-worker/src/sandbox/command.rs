//! Final command: only lifecycle and stdio operations remain after projection.
use std::process::{ExitStatus, Output, Stdio};
use std::sync::Arc;

use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

type KeepAlive = Arc<dyn Send + Sync>;

pub struct PreparedCommand {
	command: Command,
	owners: Vec<KeepAlive>,
}
impl PreparedCommand {
	pub(super) fn new(command: Command, owners: Vec<KeepAlive>) -> Self {
		Self { command, owners }
	}
	pub fn stdin(&mut self, config: Stdio) -> &mut Self {
		self.command.stdin(config);
		self
	}
	pub fn stdout(&mut self, config: Stdio) -> &mut Self {
		self.command.stdout(config);
		self
	}
	pub fn stderr(&mut self, config: Stdio) -> &mut Self {
		self.command.stderr(config);
		self
	}
	pub fn kill_on_drop(&mut self, enabled: bool) -> &mut Self {
		self.command.kill_on_drop(enabled);
		self
	}
	pub fn spawn(&mut self) -> std::io::Result<PreparedChild> {
		#[allow(
			clippy::disallowed_methods,
			reason = "PreparedCommand starts only finalized typed operands and retains every path owner with the child."
		)]
		Ok(PreparedChild { child: self.command.spawn()?, _owners: self.owners.clone() })
	}
	pub async fn output(&mut self) -> std::io::Result<Output> {
		#[allow(
			clippy::disallowed_methods,
			reason = "PreparedCommand collects output while its typed operand owners remain borrowed."
		)]
		self.command.output().await
	}
	pub(super) fn blocking_output(&mut self) -> std::io::Result<Output> {
		#[allow(
			clippy::disallowed_methods,
			reason = "The fixed bubblewrap smoketest executes only a finalized typed command while retaining owners."
		)]
		self.command.as_std_mut().output()
	}
	#[cfg(fuzzing)]
	pub(super) fn observation(&self) -> super::projection::ProjectionObservation {
		let command = self.command.as_std();
		super::projection::ProjectionObservation {
			argv: std::iter::once(command.get_program())
				.chain(command.get_args())
				.map(ToOwned::to_owned)
				.collect(),
			env: command
				.get_envs()
				.map(|(name, value)| (name.to_owned(), value.map(ToOwned::to_owned)))
				.collect(),
		}
	}
}

// Unit tests independently inspect exact argv/env and exercise test
// scripts. These fixture operations are absent even with test-support enabled.
#[cfg(test)]
impl PreparedCommand {
	pub(crate) fn as_std(&self) -> &std::process::Command {
		self.command.as_std()
	}
	pub(crate) fn arg(&mut self, value: impl AsRef<std::ffi::OsStr>) -> &mut Self {
		self.command.arg(value);
		self
	}
	pub(crate) fn args<I, S>(&mut self, values: I) -> &mut Self
	where
		I: IntoIterator<Item = S>,
		S: AsRef<std::ffi::OsStr>,
	{
		self.command.args(values);
		self
	}
}

/// Retain the mounted file/directory owners even if the prepared command is
/// dropped immediately after spawn. The process handle stays paired with these
/// owners; only individual pipes and lifecycle operations are exposed.
pub struct PreparedChild {
	child: Child,
	_owners: Vec<KeepAlive>,
}
impl PreparedChild {
	pub fn take_stdin(&mut self) -> Option<ChildStdin> {
		self.child.stdin.take()
	}
	pub fn take_stdout(&mut self) -> Option<ChildStdout> {
		self.child.stdout.take()
	}
	pub fn take_stderr(&mut self) -> Option<ChildStderr> {
		self.child.stderr.take()
	}
	pub fn id(&self) -> Option<u32> {
		self.child.id()
	}
	pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
		self.child.try_wait()
	}
	pub async fn wait(&mut self) -> std::io::Result<ExitStatus> {
		self.child.wait().await
	}
	pub async fn kill(&mut self) -> std::io::Result<()> {
		self.child.kill().await
	}
}
