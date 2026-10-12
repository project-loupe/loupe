//! Email reporter that shells out to a `sendmail`-compatible binary.
//!
//! No SMTP crate by design — operators run a local mail-submission
//! agent (`postfix`, `msmtp`, `nullmailer`, ...) and we hand it an RFC
//! 5322 message via stdin. The binary is configurable at construction
//! so tests can swap in a script that captures stdin to disk.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{anyhow, bail, Context, Result};
use loupe_core::{format_finding_id, ReportingDestination, Severity};
use loupe_storage::repos::RepoRow;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::{DispatchReceipt, ReportFinding, Reporter, ReporterCredential};

const DEFAULT_SENDMAIL_BIN: &str = "/usr/sbin/sendmail";
const DEFAULT_FROM: &str = "loupe-noreply@localhost";

pub struct EmailReporter {
	sendmail_bin: PathBuf,
	default_from: &'static str,
}

impl EmailReporter {
	pub fn new() -> Self {
		Self::with_bin(DEFAULT_SENDMAIL_BIN)
	}

	pub fn with_bin(bin: impl Into<PathBuf>) -> Self {
		Self { sendmail_bin: bin.into(), default_from: DEFAULT_FROM }
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
		&self, repo: &RepoRow, findings: &[ReportFinding], _credential: &ReporterCredential,
	) -> Result<DispatchReceipt> {
		let to = match &repo.reporting {
			ReportingDestination::Email { to, .. } => to,
			_ => bail!("EmailReporter dispatched against a non-email destination"),
		};
		if to.is_empty() {
			bail!("email destination has no recipients");
		}
		if findings.is_empty() {
			return Ok(DispatchReceipt { kind: self.kind(), external_id: None });
		}

		let message = render_message(repo, findings, self.default_from)?;

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

pub fn validate_header_value(name: &str, value: &str) -> Result<()> {
	if value.bytes().any(|b| matches!(b, b'\r' | b'\n')) {
		bail!("{name} header contains a newline");
	}
	Ok(())
}

fn render_message(
	repo: &RepoRow, findings: &[ReportFinding], default_from: &'static str,
) -> Result<String> {
	let ReportingDestination::Email { to, from, subject_prefix } = &repo.reporting else {
		bail!("EmailReporter dispatched against a non-email destination");
	};
	let from = from.as_ref().map(|value| value.expose()).unwrap_or(default_from);
	let prefix = subject_prefix.as_ref().map(|value| value.expose()).unwrap_or("[loupe]");
	let max_sev = max_severity(findings);
	let subject = format!(
		"{prefix} {} {max_sev} finding(s) in {}/{}",
		findings.len(),
		repo.owner.expose(),
		repo.repo.expose(),
	);
	validate_header_value("From", from)?;
	for recipient in to {
		validate_header_value("To", recipient.expose())?;
	}
	validate_header_value("Subject", &subject)?;
	let mut out = String::new();
	out.push_str(&format!("From: {from}\r\n"));
	out.push_str(&format!(
		"To: {}\r\n",
		to.iter().map(|value| value.expose()).collect::<Vec<_>>().join(", ")
	));
	out.push_str(&format!("Subject: {subject}\r\n"));
	out.push_str("MIME-Version: 1.0\r\n");
	out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
	out.push_str("\r\n");

	out.push_str(&format!(
		"loupe has finished a scan of {}/{} (clone url {}).\n",
		repo.owner.expose(),
		repo.repo.expose(),
		repo.clone_url.expose()
	));
	out.push_str(&format!("Findings: {}\n\n", findings.len()));
	for report_finding in findings {
		let f = &report_finding.finding;
		out.push_str(&format!(
			"{} [{}] {}\n",
			format_finding_id(report_finding.id),
			f.severity,
			f.title.expose()
		));
		match &report_finding.reviewed_revision {
			Some(revision) => {
				out.push_str(&format!("   reviewed revision: {}\n", revision.expose()))
			},
			None => out.push_str("   reviewed revision: not recorded\n"),
		}
		if let Some(path) = &f.file_path {
			out.push_str(&format!("   file: {}", path.expose()));
			if let Some(line) = f.line_start {
				out.push_str(&format!(":{line}"));
			}
			out.push('\n');
		}
		if let Some(cwe) = &f.cwe {
			out.push_str(&format!("   cwe:  {}\n", cwe.expose()));
		}
		out.push_str(&format!("   {}\n\n", f.description.expose()));
	}
	Ok(out)
}

fn max_severity(findings: &[ReportFinding]) -> Severity {
	findings.iter().map(|f| f.finding.severity).max().unwrap_or(Severity::Info)
}

/// Observe the concrete email renderer with its final typed inputs.
#[cfg(fuzzing)]
pub fn fuzz_render_message(repo: &RepoRow, findings: &[ReportFinding]) -> Result<String> {
	render_message(repo, findings, DEFAULT_FROM)
}

#[cfg(test)]
mod tests {
	use loupe_core::Finding;
	use loupe_provenance::Agent;

	use super::super::fixtures::{path, revision, text};
	use super::*;

	fn repo_with_email(
		from: Option<String>, to: Vec<String>, subject_prefix: Option<String>,
	) -> loupe_storage::Result<RepoRow> {
		super::super::fixtures::repo(serde_json::json!({
			"kind":"email", "to":to, "from":from, "subject_prefix":subject_prefix
		}))
	}

	fn finding() -> Finding<Agent> {
		Finding {
			scanner_id: text("test"),
			severity: Severity::High,
			title: text("bug"),
			description: text("description"),
			file_path: Some(path("src/lib.rs")),
			line_start: Some(1),
			line_end: Some(1),
			cwe: None,
			patch_unified: None,
			poc_unified: None,
			fingerprint: text("fp"),
		}
	}

	fn report_finding() -> ReportFinding {
		ReportFinding { id: 1234, finding: finding(), reviewed_revision: Some(revision("abc123")) }
	}

	#[test]
	fn message_identifies_findings_with_prefixed_ids() {
		let message = render_message(
			&repo_with_email(Some("loupe@example.com".into()), vec![], None).unwrap(),
			&[report_finding()],
			DEFAULT_FROM,
		)
		.unwrap();
		assert!(message.contains("LUP-1234 [high] bug\n"), "message: {message}");
	}

	#[test]
	fn message_omits_scanner_metadata() {
		let message = render_message(
			&repo_with_email(Some("loupe@example.com".into()), vec![], None).unwrap(),
			&[report_finding()],
			DEFAULT_FROM,
		)
		.unwrap();
		assert!(!message.contains("scanner:"), "message must omit the scanner header: {message}");
	}

	#[test]
	fn stored_email_rejects_header_injection_values_before_dispatch() {
		let cases = [
			repo_with_email(
				Some("loupe@example.com\r\nBcc: attacker@example.com".into()),
				vec!["security@example.com".into()],
				None,
			),
			repo_with_email(
				Some("loupe@example.com".into()),
				vec!["security@example.com\nBcc: attacker@example.com".into()],
				None,
			),
			repo_with_email(
				Some("loupe@example.com".into()),
				vec!["security@example.com".into()],
				Some("[loupe]\r\nBcc: attacker@example.com".into()),
			),
		];

		for repo in cases {
			assert!(repo.is_err(), "invalid header fields must not reach dispatch");
		}
		let valid = repo_with_email(
			Some("loupe@example.com".into()),
			vec!["security@example.com".into()],
			Some("[loupe]".into()),
		)
		.unwrap();
		let message = render_message(&valid, &[report_finding()], DEFAULT_FROM).unwrap();
		assert!(message.starts_with("From: loupe@example.com\r\nTo: security@example.com\r\nSubject: [loupe] 1 high finding(s) in acme/widget\r\n"));
	}

	#[test]
	fn header_predicate_rejects_newlines_and_keeps_valid_values() {
		for (name, valid) in
			[("From", "loupe@example.com"), ("To", "security@example.com"), ("Subject", "[loupe]")]
		{
			validate_header_value(name, valid).unwrap();
			for suffix in ["\r\nBcc: attacker@example.com", "\nBcc: attacker@example.com"] {
				let error = validate_header_value(name, &format!("{valid}{suffix}")).unwrap_err();
				assert_eq!(error.to_string(), format!("{name} header contains a newline"));
			}
		}
	}
}
