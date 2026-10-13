//! Email reporter that shells out to a `sendmail`-compatible binary.
//!
//! No SMTP crate by design — operators run a local mail-submission
//! agent (`postfix`, `msmtp`, `nullmailer`, ...) and we hand it an RFC
//! 5322 message via stdin. The binary is configurable at construction
//! so tests can swap in a script that captures stdin to disk.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{anyhow, bail, Result};
use loupe_core::Severity;
use loupe_storage::reports::PreparedReport;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::render::{ReportBuilder, ReportView};
use super::{DispatchReceipt, Reporter};

const DEFAULT_SENDMAIL_BIN: &str = "/usr/sbin/sendmail";
const DEFAULT_FROM: &str = "loupe-noreply@localhost";
const HEADER_LINE_MAX: usize = 8192;
const HEADER_SECTION_MAX: usize = 65536;
const MESSAGE_MAX: usize = 16 * 1024 * 1024;

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

	async fn dispatch(&self, batch: &PreparedReport) -> Result<DispatchReceipt> {
		let to = batch.mail_settings()?.recipients();
		if to.is_empty() {
			bail!("email destination has no recipients");
		}
		if batch.entries().is_empty() {
			return Ok(DispatchReceipt { kind: self.kind(), external_id: None });
		}

		let message = render_message(batch, self.default_from)?;

		#[allow(
			clippy::disallowed_methods,
			reason = "email reporter invokes its configured sendmail executable with fixed arguments only after complete selected-batch render admission"
		)]
		let mut child = Command::new(&self.sendmail_bin)
			// `-t` — read recipients from To/Cc/Bcc headers.
			// `-i` — don't treat a leading "." on a line as end-of-input.
			.args(["-t", "-i"])
			.stdin(Stdio::piped())
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.spawn()
			.map_err(|_| anyhow!("sendmail delivery failed"))?;
		{
			let mut stdin =
				child.stdin.take().ok_or_else(|| anyhow!("sendmail delivery failed"))?;
			stdin
				.write_all(message.as_bytes())
				.await
				.map_err(|_| anyhow!("sendmail delivery failed"))?;
		}
		let status = child.wait().await.map_err(|_| anyhow!("sendmail delivery failed"))?;
		if !status.success() {
			bail!("sendmail delivery failed");
		}
		Ok(DispatchReceipt { kind: self.kind(), external_id: None })
	}
}

pub fn validate_header_value(name: &str, value: &str) -> Result<()> {
	if value.bytes().any(|b| matches!(b, b'\r' | b'\n')) {
		bail!("{name} header contains a newline");
	}
	if value.chars().any(|ch| loupe_core::text::rejects_code_point(ch as u32)) {
		bail!("{name} header contains a prohibited character");
	}
	Ok(())
}

// debug-ok: closed destination budget categories, never header contents.
#[derive(Debug, thiserror::Error)]
enum HeaderBudget {
	#[error("complete email header exceeds 8192 bytes")]
	Line,
	#[error("email header section exceeds 65536 bytes")]
	Section,
	#[error("From header exceeds its byte budget")]
	From,
	#[error("To contributor exceeds its byte budget")]
	To,
	#[error("Subject contributor exceeds its byte budget")]
	Subject,
	#[error("To header size overflow")]
	ToOverflow,
	#[error("Subject header size overflow")]
	SubjectOverflow,
}

pub(crate) fn is_budget_error(error: &anyhow::Error) -> bool {
	error.is::<HeaderBudget>()
}

fn count_header_line(section: &mut usize, line: Option<usize>) -> Result<()> {
	let line = line.filter(|n| *n <= HEADER_LINE_MAX).ok_or(HeaderBudget::Line)?;
	*section = section
		.checked_add(line)
		.filter(|n| *n <= HEADER_SECTION_MAX)
		.ok_or(HeaderBudget::Section)?;
	Ok(())
}

fn render_message(batch: &PreparedReport, default_from: &'static str) -> Result<String> {
	let repo = batch.repository();
	let findings = batch
		.entries()
		.iter()
		.map(|entry| entry.content().map(ReportView::selected))
		.collect::<Result<Vec<_>, _>>()?;
	let headers = stored_headers(batch, &findings, default_from)?;
	let remaining =
		MESSAGE_MAX.checked_sub(headers.wire.len()).ok_or(super::render::ReportError::MailLimit)?;
	let mut body = ReportBuilder::plain_text(remaining);
	body.heading("loupe has finished a scan")?;
	body.field("repository owner", &repo.owner)?;
	body.field("repository", &repo.repo)?;
	body.field("clone URL", &repo.clone_url)?;
	body.count(findings.len())?;
	for report_finding in findings {
		let f = report_finding.finding;
		body.finding_id(report_finding.id)?;
		body.severity(f.severity)?;
		body.field("title", &f.title)?;
		match report_finding.reviewed_revision {
			Some(revision) => body.field("reviewed revision", revision)?,
			None => body.literal("- reviewed revision: not recorded\n")?,
		}
		if let Some(path) = &f.file_path {
			body.path(path, f.line_start, None)?;
		}
		if let Some(cwe) = &f.cwe {
			body.field("cwe", cwe)?;
		}
		body.field("description", &f.description)?;
	}
	let mut body = body.render()?.into_string();
	body.insert_str(0, &headers.wire);
	Ok(body)
}

struct StoredHeaders<'a> {
	_settings: &'a loupe_storage::reports::StoredMailSettings,
	wire: String,
}
impl std::fmt::Debug for StoredHeaders<'_> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("StoredHeaders([redacted])")
	}
}

/// Only a prepared batch can authorize these stored Db contributors.
fn stored_headers<'a>(
	batch: &'a PreparedReport, findings: &[ReportView<'_>], default_from: &'static str,
) -> Result<StoredHeaders<'a>> {
	let settings = batch.mail_settings()?;
	let to = settings.recipients();
	let from = settings.from().map(|value| value.expose()).unwrap_or(default_from);
	let prefix = settings.prefix().map(|value| value.expose()).unwrap_or("[loupe]");
	let count = findings.len().to_string();
	let max_sev = max_severity(findings).as_str();
	let owner = settings.owner().expose();
	let name = settings.repository().expose();
	// These are the selected Db exact single-line types. Their named row
	// validators establish the full character policy; retain that provenance
	// and independently check all contributors and assembled destination caps.
	validate_header_value("From", from)?;
	if from.len() > HEADER_LINE_MAX - 8 {
		return Err(HeaderBudget::From.into());
	}
	let mut joined_to = 0usize;
	for recipient in to {
		validate_header_value("To", recipient.expose())?;
		if recipient.expose().len() > HEADER_LINE_MAX - 6 {
			return Err(HeaderBudget::To.into());
		}
		joined_to =
			joined_to.checked_add(recipient.expose().len()).ok_or(HeaderBudget::ToOverflow)?;
	}
	joined_to = to
		.len()
		.saturating_sub(1)
		.checked_mul(2)
		.and_then(|n| joined_to.checked_add(n))
		.ok_or(HeaderBudget::ToOverflow)?;
	for contributor in [prefix, owner, name] {
		validate_header_value("Subject", contributor)?;
		if contributor.len() > HEADER_LINE_MAX - 11 {
			return Err(HeaderBudget::Subject.into());
		}
	}
	let subject_parts = [prefix, " ", &count, " ", max_sev, " finding(s) in ", owner, "/", name];
	let subject_len = subject_parts
		.iter()
		.try_fold(0usize, |n, part| n.checked_add(part.len()))
		.ok_or(HeaderBudget::SubjectOverflow)?;
	let lines = [
		from.len().checked_add(8),
		joined_to.checked_add(6),
		subject_len.checked_add(11),
		Some(19),
		Some(41),
	];
	let mut header_bytes = 0usize;
	for line in lines {
		count_header_line(&mut header_bytes, line)?;
	}
	let mut out = String::with_capacity(header_bytes + 2);
	out.push_str("From: ");
	out.push_str(from);
	out.push_str("\r\nTo: ");
	for (index, recipient) in to.iter().enumerate() {
		if index != 0 {
			out.push_str(", ");
		}
		out.push_str(recipient.expose());
	}
	out.push_str("\r\nSubject: ");
	for part in subject_parts {
		out.push_str(part);
	}
	out.push_str("\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n");
	debug_assert_eq!(out.len(), header_bytes + 2);
	// Repeat admission over the assembled complete To and Subject lines.
	for line in out.split("\r\n").take(5) {
		validate_header_value("assembled", line)?;
		if line.len().checked_add(2).is_none_or(|n| n > HEADER_LINE_MAX) {
			return Err(HeaderBudget::Line.into());
		}
	}
	Ok(StoredHeaders { _settings: settings, wire: out })
}

fn max_severity(findings: &[ReportView<'_>]) -> Severity {
	findings.iter().map(|f| f.finding.severity).max().unwrap_or(Severity::Info)
}

/// Observe the concrete email renderer with typed inputs.
#[cfg(fuzzing)]
pub fn fuzz_render_message(batch: &PreparedReport) -> Result<String> {
	render_message(batch, DEFAULT_FROM)
}

#[cfg(test)]
mod tests {
	use loupe_core::Finding;
	use loupe_provenance::Agent;
	use loupe_storage::repos::RepoRow;

	use super::super::fixtures::{path, revision, text, ReportFinding};
	use super::*;
	fn render_message(
		repo: &RepoRow, findings: &[ReportFinding], default_from: &'static str,
	) -> Result<String> {
		super::render_message(&super::super::fixtures::prepared(repo, findings), default_from)
	}

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
		assert!(message.contains("Finding LUP-1234\n"), "message: {message}");
		assert!(message.contains("- severity: high\n"));
		assert!(message.contains("- title:\n```\nbug\n```"));
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

	#[test]
	fn header_predicate_rejects_all_exact_single_line_controls() {
		for forbidden in [
			'\0', '\t', '\u{007f}', '\u{0085}', '\u{202e}', '\u{2028}', '\u{2029}', '\u{200b}',
			'\u{e000}', '\u{fdd0}', '\u{0378}',
		] {
			for value in [format!("{forbidden}mail"), format!("mail{forbidden}")] {
				assert!(
					validate_header_value("Subject", &value).is_err(),
					"header predicate must reject U+{:04X}",
					forbidden as u32
				);
			}
		}
	}

	#[test]
	fn report_mail_rejects_oversized_complete_header_lines() {
		for (from, to, prefix) in [
			(Some("x".repeat(8185)), vec!["to".into()], None),
			(None, vec!["x".repeat(4093), "y".repeat(4093)], None),
			(None, vec!["to".into()], Some("x".repeat(8181))),
		] {
			let repo = repo_with_email(from, to, prefix).expect("admitted stored settings");
			assert!(
				render_message(&repo, &[report_finding()], DEFAULT_FROM).is_err(),
				"complete header lines over 8192 bytes must reject"
			);
		}
	}

	#[test]
	fn report_mail_rejects_a_message_over_sixteen_mib() {
		let repo = repo_with_email(None, vec!["to".into()], None).unwrap();
		let mut report = report_finding();
		report.finding.description = text(&"x".repeat(2 * 1024 * 1024));
		let findings = vec![report; 8];
		assert!(
			render_message(&repo, &findings, DEFAULT_FROM).is_err(),
			"headers and framing beyond sixteen MiB must reject the message"
		);
	}

	#[test]
	fn complete_header_limits_include_prefix_separator_and_crlf() {
		let subject_overhead = "Subject:  1 high finding(s) in acme/widget\r\n".len();
		for (from, to, prefix) in [
			(Some("é".repeat(4092)), vec!["to".into()], None),
			(None, vec!["x".repeat(4092), "y".repeat(4092)], None),
			(None, vec!["to".into()], Some("x".repeat(HEADER_LINE_MAX - subject_overhead))),
		] {
			let repo = repo_with_email(from, to, prefix).unwrap();
			let message = render_message(&repo, &[report_finding()], DEFAULT_FROM).unwrap();
			let (headers, _) = message.split_once("\r\n\r\n").unwrap();
			assert!(headers.split("\r\n").all(|line| line.len() + 2 <= HEADER_LINE_MAX));
			assert!(headers.split("\r\n").any(|line| line.len() + 2 == HEADER_LINE_MAX));
			assert_eq!(headers.split("\r\n").count(), 5);
		}
	}

	#[test]
	fn header_section_counter_rejects_overflow_and_aggregate_excess() {
		// The production five-line shape cannot reach 64 KiB under the
		// per-line cap. These are direct checked-counter boundary controls.
		let mut bytes = HEADER_SECTION_MAX - HEADER_LINE_MAX;
		count_header_line(&mut bytes, Some(HEADER_LINE_MAX)).unwrap();
		assert_eq!(bytes, HEADER_SECTION_MAX);
		assert!(count_header_line(&mut bytes, Some(1)).is_err());
		let mut overflow = usize::MAX;
		assert!(count_header_line(&mut overflow, Some(1)).is_err());
		assert!(count_header_line(&mut 0, None).is_err());
	}

	#[test]
	fn stored_headers_are_independent_of_every_finding_payload() {
		let repo = repo_with_email(
			Some("".into()),
			vec!["a".into(), "a".into(), " b ".into()],
			Some("".into()),
		)
		.unwrap();
		let first = report_finding();
		let mut changed = report_finding();
		changed.id = 9876;
		changed.reviewed_revision = Some(revision("new`revision"));
		changed.finding.scanner_id = text("new-scanner");
		changed.finding.title = text("subject [attack](target)");
		changed.finding.description = text("\r\nBcc: body-only\r\n\r\n```");
		changed.finding.file_path = Some(path("`new`path"));
		changed.finding.line_start = Some(9);
		changed.finding.line_end = Some(19);
		changed.finding.cwe = Some(text("new-cwe"));
		changed.finding.fingerprint = text("new-fingerprint");
		changed.finding.poc_unified = Some(text("new-poc"));
		changed.finding.patch_unified = Some(text("new-patch"));
		let left = render_message(&repo, &[first], DEFAULT_FROM).unwrap();
		let right = render_message(&repo, &[changed], DEFAULT_FROM).unwrap();
		let (left_headers, left_body) = left.split_once("\r\n\r\n").unwrap();
		let (right_headers, right_body) = right.split_once("\r\n\r\n").unwrap();
		assert_eq!(left_headers, right_headers);
		assert!(left_headers
			.starts_with("From: \r\nTo: a, a,  b \r\nSubject:  1 high finding(s) in acme/widget"));
		assert_ne!(left_body, right_body);
		assert!(right_body.contains("\r\nBcc: body-only\r\n\r\n```"));
		for omitted in ["new-scanner", "new-fingerprint", "new-poc", "new-patch"] {
			assert!(!right_body.contains(omitted));
		}
	}

	#[tokio::test]
	async fn sendmail_echo_cannot_enter_diagnostic_source_chain() {
		use std::os::unix::fs::PermissionsExt;
		let scratch = tempfile::tempdir().unwrap();
		let bin = scratch.path().join("echo-sendmail");
		std::fs::write(&bin, "#!/bin/sh\ncat >&2\nexit 1\n").unwrap();
		std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).unwrap();
		let repo = repo_with_email(None, vec!["to".into()], None).unwrap();
		let mut report = report_finding();
		let original = "agent-diagnostic-echo-7f5342 [payload](https://example.test)";
		report.finding.description = text(original);
		let batch = super::super::fixtures::prepared(&repo, &[report]);
		let error = EmailReporter::with_bin(bin).dispatch(&batch).await.unwrap_err();
		for source in error.chain() {
			assert!(
				!source.to_string().contains(original),
				"sendmail echoed original Agent content into the diagnostic source chain"
			);
		}
		assert_eq!(error.to_string(), "sendmail delivery failed");
		assert_eq!(error.chain().count(), 1, "closed category has no external source");
	}

	#[tokio::test]
	async fn complete_message_exact_limit_passes_and_plus_one_never_spawns() {
		let repo = repo_with_email(None, vec!["to".into()], None).unwrap();
		let mut reports = vec![report_finding(); 8];
		for report in &mut reports {
			report.finding.description = text("");
		}
		let framing = render_message(&repo, &reports, DEFAULT_FROM).unwrap().len();
		let max_field = loupe_core::text::policy::LEGACY_TEXT_MAX_BYTES;
		let last = MESSAGE_MAX - framing - 7 * max_field;
		for report in reports.iter_mut().take(7) {
			report.finding.description = text(&"x".repeat(max_field));
		}
		reports[7].finding.description = text(&"x".repeat(last));
		assert_eq!(render_message(&repo, &reports, DEFAULT_FROM).unwrap().len(), MESSAGE_MAX);
		reports[7].finding.description = text(&"x".repeat(last + 1));
		let batch = super::super::fixtures::prepared(&repo, &reports);
		let scratch = tempfile::tempdir().unwrap();
		let bin = scratch.path().join("must-not-spawn");
		let error = EmailReporter::with_bin(bin).dispatch(&batch).await.unwrap_err();
		assert!(
			error.to_string().contains("byte budget"),
			"admission must fail before process lookup: {error:#}"
		);
	}
}
