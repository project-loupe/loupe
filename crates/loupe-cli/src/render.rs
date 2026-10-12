//! Plain-text rendering of findings for human review.
//!
//! The output is the operator's primary review surface before they
//! click `loupectl finding approve`, so we lay it out top-down: title
//! and severity first, then the location, then the description, then
//! the **proof of concept** — the regression test the model emits to
//! show the bug is real and would still pass after a fix. The PoC is
//! rendered as a unified diff with `+`/`-` coloured the same way `git
//! diff` does it, so the eye can pick out the test it adds.
//!
//! Color is opt-in via TTY detection (`std::io::IsTerminal`) and
//! suppressed when `NO_COLOR` is set in the env, matching the de facto
//! convention. A non-TTY pipe (`loupectl finding show 42 | less`)
//! gets plain ASCII.

use std::fmt::Write as _;
use std::io::IsTerminal;

use loupe_core::{FindingState, Severity};
use loupe_provenance::{Agent, Server};
type FindingDetail = loupe_proto::FindingDetail<Agent, Server>;
type FindingSummary = loupe_proto::FindingSummary<Agent, Server>;

/// Preserve the CLI's historical kind spelling at its explicit terminal sink.
pub fn job_kind(kind: &loupe_core::JobKind<Server>) -> String {
	match kind {
		loupe_core::JobKind::Scan => "Scan".into(),
		loupe_core::JobKind::Verify => "Verify".into(),
		loupe_core::JobKind::Survey => "Survey".into(),
		loupe_core::JobKind::Drilldown => "Drilldown".into(),
		loupe_core::JobKind::Unknown(text) => format!("Unknown({:?})", text.expose()),
	}
}

/// Whether to emit ANSI escape sequences. Detected once per call by
/// [`Style::detect`], threaded through the renderer so callers can
/// force one mode or the other (e.g. in unit tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
	Plain,
	Color,
}

impl Style {
	/// Color when stdout is a TTY *and* `NO_COLOR` is unset. Treat any
	/// non-empty value of `NO_COLOR` as opt-out (the spec at
	/// no-color.org specifies "any non-empty string").
	pub fn detect() -> Self {
		if !std::io::stdout().is_terminal() {
			return Style::Plain;
		}
		match std::env::var_os("NO_COLOR") {
			Some(v) if !v.is_empty() => Style::Plain,
			_ => Style::Color,
		}
	}

	fn paint(self, code: &str, text: &str) -> String {
		let text = TerminalText(text);
		match self {
			Style::Plain => text.to_string(),
			Style::Color => format!("\x1b[{code}m{text}\x1b[0m"),
		}
	}
}

const BOLD: &str = "1";
const DIM: &str = "2";
const RED: &str = "31";
const GREEN: &str = "32";
const YELLOW: &str = "33";
const CYAN: &str = "36";

/// Escape before adding our own ANSI styling. Printable Unicode is preserved;
/// terminal commands and other C0/C1 controls remain visible as literal escapes.
pub struct TerminalText<'a>(pub &'a str);

impl std::fmt::Display for TerminalText<'_> {
	fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		for character in self.0.chars() {
			if character.is_control() {
				write!(out, "{}", character.escape_default())?;
			} else {
				out.write_char(character)?;
			}
		}
		Ok(())
	}
}

/// Render one human listing row; tabs belong to the layout, never to data.
pub fn finding_list_row(f: &FindingSummary) -> String {
	format!(
		"{:>5}\tjob={}\t{:?}\t{}\tstate={}\tverify={}\t{}\t{}",
		f.id,
		f.job_id,
		f.severity,
		TerminalText(f.scanner_id.expose()),
		f.state,
		f.verification_required,
		TerminalText(&summary_location(f)),
		TerminalText(f.title.expose())
	)
}

/// Render one search result using the same text boundary as finding details.
pub fn finding_search_row(f: &FindingSummary) -> String {
	format!(
		"{:>5}\t{:?}\t{}\tstate={}\t{}\t{}",
		f.id,
		f.severity,
		TerminalText(f.scanner_id.expose()),
		f.state,
		TerminalText(&summary_location(f)),
		TerminalText(f.title.expose())
	)
}

fn summary_location(f: &FindingSummary) -> String {
	match (f.file_path.as_ref().map(|path| path.expose()), f.line_start) {
		(Some(path), Some(line)) => format!("{path}:{line}"),
		(Some(path), None) => path.to_owned(),
		_ => "-".into(),
	}
}

/// Render a [`loupe_proto::FindingDetail`] as multi-line plain text.
pub fn finding(f: &FindingDetail, style: Style) -> String {
	let mut out = String::with_capacity(1024);
	header(&mut out, f, style);
	metadata(&mut out, f, style);
	if !f.description.expose().trim().is_empty() {
		section(&mut out, "Description", style);
		for line in f.description.expose().lines() {
			let _ = writeln!(out, "  {}", TerminalText(line));
		}
		out.push('\n');
	}
	poc(&mut out, f, style);
	patch(&mut out, f, style);
	audit(&mut out, f, style);
	out
}

fn header(out: &mut String, f: &FindingDetail, style: Style) {
	let sev_label = severity_label(f.severity);
	let sev_color = severity_color(f.severity);
	let _ = writeln!(
		out,
		"{} {} — {}",
		style.paint(BOLD, &format!("Finding #{}", f.id)),
		style.paint(sev_color, &format!("[{sev_label}]")),
		style.paint(BOLD, f.title.expose()),
	);
	let bar = "─".repeat(60);
	let _ = writeln!(out, "{}", style.paint(DIM, &bar));
}

fn metadata(out: &mut String, f: &FindingDetail, style: Style) {
	let location = match (f.file_path.as_ref().map(|path| path.expose()), f.line_start, f.line_end)
	{
		(Some(p), Some(start), Some(end)) if end > start => format!("{p}:{start}-{end}"),
		(Some(p), Some(start), _) => format!("{p}:{start}"),
		(Some(p), None, _) => p.to_string(),
		_ => "(unknown)".into(),
	};
	let _ = writeln!(out, "  {} {}", style.paint(DIM, "Location:"), TerminalText(&location));
	let _ = writeln!(out, "  {} {}", style.paint(DIM, "Repo:    "), f.repo_id);
	let _ = writeln!(out, "  {} {}", style.paint(DIM, "Job:     "), f.job_id);
	let _ = writeln!(
		out,
		"  {} {}",
		style.paint(DIM, "Scanner: "),
		TerminalText(f.scanner_id.expose())
	);
	let _ = writeln!(out, "  {} {}", style.paint(DIM, "State:   "), state_painted(&f.state, style));
	if let Some(cwe) = &f.cwe {
		let _ = writeln!(out, "  {} {}", style.paint(DIM, "CWE:     "), TerminalText(cwe.expose()));
	}
	let _ = writeln!(out, "  {} {}", style.paint(DIM, "Created: "), format_unix(f.created_at));
	let _ = writeln!(out, "  {} {}", style.paint(DIM, "Verify:  "), f.verification_required);
	let _ = writeln!(
		out,
		"  {} {}",
		style.paint(DIM, "FP:      "),
		style.paint(DIM, f.fingerprint.expose()),
	);
	out.push('\n');
}

fn poc(out: &mut String, f: &FindingDetail, style: Style) {
	let Some(diff) = &f.poc_unified else {
		section(out, "Proof of concept", style);
		out.push_str("  (none — scanner did not emit a regression-test diff)\n\n");
		return;
	};
	section(out, "Proof of concept (regression test, fails on HEAD)", style);
	render_unified_diff(out, diff.expose(), style);
	out.push('\n');
}

fn patch(out: &mut String, f: &FindingDetail, style: Style) {
	let Some(diff) = &f.patch_unified else {
		return;
	};
	section(out, "Suggested fix", style);
	render_unified_diff(out, diff.expose(), style);
	out.push('\n');
}

fn audit(out: &mut String, f: &FindingDetail, style: Style) {
	if f.approved_at.is_none() && f.rejected_at.is_none() {
		return;
	}
	section(out, "Audit", style);
	if let (Some(at), Some(by)) =
		(f.approved_at, f.approved_by_cn.as_ref().map(|text| text.expose()))
	{
		let _ = writeln!(
			out,
			"  {} {} by {}",
			style.paint(GREEN, "approved"),
			format_unix(at),
			TerminalText(by)
		);
	}
	if let (Some(at), Some(by)) =
		(f.rejected_at, f.rejected_by_cn.as_ref().map(|text| text.expose()))
	{
		let _ = writeln!(
			out,
			"  {} {} by {}",
			style.paint(RED, "rejected"),
			format_unix(at),
			TerminalText(by)
		);
	}
	out.push('\n');
}

fn section(out: &mut String, title: &str, style: Style) {
	let _ = writeln!(out, "{}", style.paint(BOLD, title));
	out.push('\n');
}

/// Render a unified diff with `+`/`-` lines tinted (when `Style::Color`)
/// the same way `git diff` does. Hunk headers get cyan; metadata
/// (`diff --git ...`, `index ...`, `+++`, `---`) gets dim.
fn render_unified_diff(out: &mut String, diff: &str, style: Style) {
	for line in diff.lines() {
		let painted = if line.starts_with("+++") || line.starts_with("---") {
			style.paint(DIM, line)
		} else if line.starts_with('+') {
			style.paint(GREEN, line)
		} else if line.starts_with('-') {
			style.paint(RED, line)
		} else if line.starts_with("@@") {
			style.paint(CYAN, line)
		} else if line.starts_with("diff ") || line.starts_with("index ") {
			style.paint(DIM, line)
		} else {
			TerminalText(line).to_string()
		};
		let _ = writeln!(out, "  {painted}");
	}
}

fn severity_label(sev: Severity) -> &'static str {
	match sev {
		Severity::Critical => "critical",
		Severity::High => "high",
		Severity::Medium => "medium",
		Severity::Low => "low",
		Severity::Info => "info",
	}
}

fn severity_color(sev: Severity) -> &'static str {
	match sev {
		Severity::Critical | Severity::High => RED,
		Severity::Medium => YELLOW,
		Severity::Low | Severity::Info => GREEN,
	}
}

fn state_painted(state: &FindingState, style: Style) -> String {
	let code = match state {
		FindingState::AwaitingApproval => YELLOW,
		FindingState::Confirmed => GREEN,
		FindingState::Reported => CYAN,
		FindingState::Dismissed => RED,
		FindingState::Validating | FindingState::Pending => DIM,
	};
	style.paint(code, state.as_str())
}

/// Format a unix timestamp as `YYYY-MM-DD HH:MM:SS UTC` without
/// pulling in a date crate. The civil-from-days math is the
/// classic Howard Hinnant algorithm; readable and exact for any
/// timestamp the system clock can produce.
pub fn format_unix(ts: i64) -> String {
	// Euclidean division floors negatives without negating i64::MIN or
	// multiplying a rounded-down day count beyond the timestamp range.
	let days = ts.div_euclid(86_400);
	let seconds_of_day = ts.rem_euclid(86_400);
	let hours = seconds_of_day / 3600;
	let minutes = (seconds_of_day % 3600) / 60;
	let secs = seconds_of_day % 60;
	let (year, month, day) = civil_from_days(days);
	format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{secs:02} UTC")
}

/// Howard Hinnant's `civil_from_days`: convert days-since-1970-01-01
/// to a (year, month, day) Gregorian date.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
	let z = z + 719_468;
	let era = if z >= 0 { z / 146_097 } else { (z - 146_096) / 146_097 };
	let doe = (z - era * 146_097) as u64;
	let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
	let y = yoe as i64 + era * 400;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
	let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
	let year = if m <= 2 { y + 1 } else { y };
	(year, m, d)
}

#[cfg(test)]
mod tests {
	use loupe_proto::PROTOCOL_VERSION;

	use super::*;
	use crate::legacy_responses::FindingDetail;

	// Rendering fixtures enter through the actual response owner. There is
	// no unchecked constructor capable of labelling invalid test strings.
	fn render(input: &FindingDetail, style: Style) -> anyhow::Result<String> {
		let raw = serde_json::to_vec(input).unwrap();
		tokio::runtime::Runtime::new().unwrap().block_on(async {
			let received = crate::ingress::test_support::received(&raw).await;
			let finding = crate::ingress::get_finding(received)?;
			Ok(super::finding(&finding, style))
		})
	}

	fn sample() -> FindingDetail {
		FindingDetail {
			protocol_version: PROTOCOL_VERSION,
			id: 42,
			repo_id: 1,
			job_id: 7,
			scanner_id: "regex-secrets".into(),
			severity: Severity::High,
			title: "AWS access key in source".into(),
			description: "An AKIA-prefixed AWS access key is hardcoded\nin the repo.".into(),
			file_path: Some("src/config.rs".into()),
			line_start: Some(14),
			line_end: Some(14),
			cwe: Some("CWE-798".into()),
			patch_unified: None,
			poc_unified: Some(
				"diff --git a/tests/no_keys.rs b/tests/no_keys.rs\n\
				 +++ b/tests/no_keys.rs\n\
				 @@ -0,0 +1,3 @@\n\
				 +#[test]\n\
				 +fn no_aws_keys() { panic!() }\n\
				 -unrelated\n"
					.into(),
			),
			fingerprint: "deadbeef".into(),
			state: FindingState::AwaitingApproval,
			verification_required: false,
			created_at: 1_756_000_000, // 2025-08-24 01:46:40 UTC
			approved_at: None,
			approved_by_cn: None,
			rejected_at: None,
			rejected_by_cn: None,
		}
	}

	#[test]
	fn invalid_controls_cannot_reach_typed_finding_renderers() {
		let payload: String = (0..=159)
			.filter_map(char::from_u32)
			.filter(|c| c.is_control() && !matches!(c, '\n' | '\r'))
			.collect();
		for field in 0..10 {
			let mut f = sample();
			match field {
				0 => f.title = payload.clone(),
				1 => f.description = payload.clone(),
				2 => f.file_path = Some(payload.clone()),
				3 => f.scanner_id = payload.clone(),
				4 => f.cwe = Some(payload.clone()),
				5 => f.fingerprint = payload.clone(),
				6 => f.poc_unified = Some(payload.clone()),
				7 => f.patch_unified = Some(payload.clone()),
				8 => {
					f.approved_at = Some(0);
					f.approved_by_cn = Some(payload.clone());
				},
				_ => {
					f.rejected_at = Some(0);
					f.rejected_by_cn = Some(payload.clone());
				},
			}
			for style in [Style::Plain, Style::Color] {
				assert!(render(&f, style).is_err(), "field {field} reached typed renderer");
			}
		}
	}

	#[test]
	fn terminal_data_controls_keep_their_visible_spelling() {
		let payload: String =
			(0..=159).filter_map(char::from_u32).filter(|c| c.is_control()).collect();
		for style in [Style::Plain, Style::Color] {
			let mut rendered = style.paint(BOLD, &payload);
			for code in ["0", BOLD] {
				rendered = rendered.replace(&format!("\x1b[{code}m"), "");
			}
			assert!(!rendered.chars().any(char::is_control));
			for c in payload.chars() {
				assert!(rendered.contains(&c.escape_default().to_string()), "lost {c:?}");
			}
		}
	}

	#[test]
	fn title_newlines_cannot_enter_the_typed_renderer() {
		let mut f = sample();
		f.title = "safe\r\nforged".into();
		assert!(render(&f, Style::Plain).is_err());
		assert_eq!(TerminalText("safe\r\nforged").to_string(), "safe\\r\\nforged");
	}

	#[test]
	fn format_unix_handles_extreme_timestamps() {
		for ts in [i64::MIN, i64::MIN + 86_400, i64::MAX] {
			let rendered = format_unix(ts);
			assert!(rendered.ends_with(" UTC"));
			assert!(!rendered.contains(":-"));
		}
	}

	#[test]
	fn plain_render_carries_all_review_critical_fields() {
		let out = render(&sample(), Style::Plain).unwrap();
		assert!(out.contains("Finding #42"));
		assert!(out.contains("[high]"));
		assert!(out.contains("AWS access key in source"));
		assert!(out.contains("Location: src/config.rs:14"));
		assert!(out.contains("CWE-798"));
		assert!(out.contains("hardcoded"));
		assert!(out.contains("Proof of concept"));
		assert!(out.contains("fn no_aws_keys()"));
		assert!(out.contains("awaiting_approval"));
		// Plain rendering must contain no ANSI escapes.
		assert!(!out.contains('\x1b'), "plain rendering must be ANSI-free, got: {out:?}");
	}

	#[test]
	fn color_render_emits_ansi_for_severity_and_diff_lines() {
		let out = render(&sample(), Style::Color).unwrap();
		// Header severity tag is colored.
		assert!(out.contains("\x1b[31m[high]\x1b[0m"), "expected red severity in: {out:?}");
		// `+` lines green, `-` lines red.
		assert!(out.contains("\x1b[32m+#[test]\x1b[0m"), "expected green addition: {out:?}");
		assert!(out.contains("\x1b[31m-unrelated\x1b[0m"), "expected red removal: {out:?}");
		// Hunk header cyan.
		assert!(out.contains("\x1b[36m@@ "));
	}

	#[test]
	fn missing_poc_renders_explicit_placeholder() {
		let mut f = sample();
		f.poc_unified = None;
		let out = render(&f, Style::Plain).unwrap();
		assert!(out.contains("Proof of concept"));
		assert!(out.contains("(none"));
	}

	#[test]
	fn audit_section_only_renders_when_a_decision_was_recorded() {
		let mut f = sample();
		assert!(!render(&f, Style::Plain).unwrap().contains("Audit"));
		f.approved_at = Some(1_756_000_001);
		f.approved_by_cn = Some("admin".into());
		assert!(render(&f, Style::Plain).unwrap().contains("approved"));
	}

	#[test]
	fn format_unix_known_timestamps() {
		// 1_756_000_000 = 2025-08-24 01:46:40 UTC.
		assert_eq!(format_unix(1_756_000_000), "2025-08-24 01:46:40 UTC");
		// Epoch.
		assert_eq!(format_unix(0), "1970-01-01 00:00:00 UTC");
		// One second before epoch — exercises the negative-days branch.
		assert_eq!(format_unix(-1), "1969-12-31 23:59:59 UTC");
		// 2000-02-29, leap day across a century divisible by 400.
		assert_eq!(format_unix(951_782_400), "2000-02-29 00:00:00 UTC");
	}
}
