//! Email reporter that shells out to a `sendmail`-compatible binary.
//!
//! No SMTP crate by design — operators run a local mail-submission
//! agent (`postfix`, `msmtp`, `nullmailer`, ...) and we hand it an RFC
//! 5322 message via stdin. The binary is configurable at construction
//! so tests can swap in a script that captures stdin to disk.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{anyhow, bail, Context, Result};
use loupe_core::{Finding, ReportingDestination, Severity};
use loupe_storage::repos::RepoRow;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::{DispatchReceipt, Reporter};

const DEFAULT_SENDMAIL_BIN: &str = "/usr/sbin/sendmail";
const DEFAULT_FROM: &str = "loupe-noreply@localhost";

pub struct EmailReporter {
	sendmail_bin: PathBuf,
	default_from: String,
}

impl EmailReporter {
	pub fn new() -> Self {
		Self::with_bin(DEFAULT_SENDMAIL_BIN)
	}

	pub fn with_bin(bin: impl Into<PathBuf>) -> Self {
		Self { sendmail_bin: bin.into(), default_from: DEFAULT_FROM.to_owned() }
	}
}

impl Default for EmailReporter {
	fn default() -> Self {
		Self::new()
	}
}

#[async_trait::async_trait]
impl Reporter for EmailReporter {
	fn kind(&self) -> &'static str {
		"email"
	}

	async fn dispatch(
		&self, repo: &RepoRow, findings: &[Finding], _pat: &str,
	) -> Result<DispatchReceipt> {
		let (to, from, subject_prefix) = match &repo.reporting {
			ReportingDestination::Email { to, from, subject_prefix } => {
				(to.clone(), from.clone(), subject_prefix.clone())
			},
			_ => bail!("EmailReporter dispatched against a non-email destination"),
		};
		if to.is_empty() {
			bail!("email destination has no recipients");
		}
		if findings.is_empty() {
			return Ok(DispatchReceipt { kind: self.kind(), external_id: None });
		}

		let from = from.unwrap_or_else(|| self.default_from.clone());
		let prefix = subject_prefix.as_deref().unwrap_or("[loupe]");
		let max_sev = max_severity(findings);
		let subject = format!(
			"{prefix} {} {max_sev} finding(s) in {}/{}",
			findings.len(),
			repo.owner,
			repo.repo,
		);
		let message = render_message(&from, &to, &subject, repo, findings);

		let mut child = Command::new(&self.sendmail_bin)
			// `-t` — read recipients from To/Cc/Bcc headers.
			// `-i` — don't treat a leading "." on a line as end-of-input.
			.args(["-t", "-i"])
			.stdin(Stdio::piped())
			.stdout(Stdio::null())
			.stderr(Stdio::piped())
			.spawn()
			.with_context(|| format!("spawning sendmail at {}", self.sendmail_bin.display()))?;
		{
			let mut stdin = child.stdin.take().ok_or_else(|| anyhow!("no stdin for sendmail"))?;
			stdin.write_all(message.as_bytes()).await.context("writing message to sendmail")?;
		}
		let output = child.wait_with_output().await.context("waiting on sendmail")?;
		if !output.status.success() {
			let stderr = String::from_utf8_lossy(&output.stderr);
			bail!("sendmail exited with {}: {stderr}", output.status);
		}
		Ok(DispatchReceipt { kind: self.kind(), external_id: None })
	}
}

fn render_message(
	from: &str, to: &[String], subject: &str, repo: &RepoRow, findings: &[Finding],
) -> String {
	let mut out = String::new();
	out.push_str(&format!("From: {from}\r\n"));
	out.push_str(&format!("To: {}\r\n", to.join(", ")));
	out.push_str(&format!("Subject: {subject}\r\n"));
	out.push_str("MIME-Version: 1.0\r\n");
	out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
	out.push_str("\r\n");

	out.push_str(&format!(
		"loupe has finished a scan of {}/{} (clone url {}).\n",
		repo.owner, repo.repo, repo.clone_url
	));
	out.push_str(&format!("Findings: {}\n\n", findings.len()));
	for (i, f) in findings.iter().enumerate() {
		out.push_str(&format!("{}. [{}] {}\n", i + 1, f.severity, f.title));
		if let Some(path) = &f.file_path {
			out.push_str(&format!("   file: {path}"));
			if let Some(line) = f.line_start {
				out.push_str(&format!(":{line}"));
			}
			out.push('\n');
		}
		if let Some(cwe) = &f.cwe {
			out.push_str(&format!("   cwe:  {cwe}\n"));
		}
		out.push_str(&format!("   scanner: {}\n", f.scanner_id));
		out.push_str(&format!("   {}\n\n", f.description));
	}
	out
}

fn max_severity(findings: &[Finding]) -> Severity {
	findings.iter().map(|f| f.severity).max().unwrap_or(Severity::Info)
}
