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
use loupe_proto::FindingDetail;

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
		match self {
			Style::Plain => text.to_owned(),
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

/// Render a [`FindingDetail`] as multi-line plain text.
pub fn finding(f: &FindingDetail, style: Style) -> String {
	let mut out = String::with_capacity(1024);
	header(&mut out, f, style);
	metadata(&mut out, f, style);
	if !f.description.trim().is_empty() {
		section(&mut out, "Description", style);
		for line in f.description.lines() {
			let _ = writeln!(out, "  {line}");
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
		style.paint(BOLD, &f.title),
	);
	let bar = "─".repeat(60);
	let _ = writeln!(out, "{}", style.paint(DIM, &bar));
}

fn metadata(out: &mut String, f: &FindingDetail, style: Style) {
	let location = match (f.file_path.as_deref(), f.line_start, f.line_end) {
		(Some(p), Some(start), Some(end)) if end > start => format!("{p}:{start}-{end}"),
		(Some(p), Some(start), _) => format!("{p}:{start}"),
		(Some(p), None, _) => p.to_string(),
		_ => "(unknown)".into(),
	};
	let _ = writeln!(out, "  {} {location}", style.paint(DIM, "Location:"));
	let _ = writeln!(out, "  {} {}", style.paint(DIM, "Repo:    "), f.repo_id);
	let _ = writeln!(out, "  {} {}", style.paint(DIM, "Job:     "), f.job_id);
	let _ = writeln!(out, "  {} {}", style.paint(DIM, "Scanner: "), f.scanner_id);
	let _ = writeln!(out, "  {} {}", style.paint(DIM, "State:   "), state_painted(&f.state, style));
	if let Some(cwe) = &f.cwe {
		let _ = writeln!(out, "  {} {}", style.paint(DIM, "CWE:     "), cwe);
	}
	let _ = writeln!(out, "  {} {}", style.paint(DIM, "Created: "), format_unix(f.created_at));
	let _ = writeln!(out, "  {} {}", style.paint(DIM, "Verify:  "), f.verification_required);
	let _ =
		writeln!(out, "  {} {}", style.paint(DIM, "FP:      "), style.paint(DIM, &f.fingerprint),);
	out.push('\n');
}

fn poc(out: &mut String, f: &FindingDetail, style: Style) {
	let Some(diff) = &f.poc_unified else {
		section(out, "Proof of concept", style);
		out.push_str("  (none — scanner did not emit a regression-test diff)\n\n");
		return;
	};
	section(out, "Proof of concept (regression test, fails on HEAD)", style);
	render_unified_diff(out, diff, style);
	out.push('\n');
}

fn patch(out: &mut String, f: &FindingDetail, style: Style) {
	let Some(diff) = &f.patch_unified else {
		return;
	};
	section(out, "Suggested fix", style);
	render_unified_diff(out, diff, style);
	out.push('\n');
}

fn audit(out: &mut String, f: &FindingDetail, style: Style) {
	if f.approved_at.is_none() && f.rejected_at.is_none() {
		return;
	}
	section(out, "Audit", style);
	if let (Some(at), Some(by)) = (f.approved_at, f.approved_by_cn.as_deref()) {
		let _ = writeln!(out, "  {} {} by {}", style.paint(GREEN, "approved"), format_unix(at), by);
	}
	if let (Some(at), Some(by)) = (f.rejected_at, f.rejected_by_cn.as_deref()) {
		let _ = writeln!(out, "  {} {} by {}", style.paint(RED, "rejected"), format_unix(at), by);
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
			line.to_owned()
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
fn format_unix(ts: i64) -> String {
	let (days, seconds_of_day) = if ts >= 0 {
		(ts / 86_400, ts % 86_400)
	} else {
		// Floor-div so negatives go the right way.
		let d = -((-ts + 86_399) / 86_400);
		let s = ts - d * 86_400;
		(d, s)
	};
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
	fn plain_render_carries_all_review_critical_fields() {
		let out = finding(&sample(), Style::Plain);
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
		let out = finding(&sample(), Style::Color);
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
		let out = finding(&f, Style::Plain);
		assert!(out.contains("Proof of concept"));
		assert!(out.contains("(none"));
	}

	#[test]
	fn audit_section_only_renders_when_a_decision_was_recorded() {
		let mut f = sample();
		assert!(!finding(&f, Style::Plain).contains("Audit"));
		f.approved_at = Some(1_756_000_001);
		f.approved_by_cn = Some("admin".into());
		assert!(finding(&f, Style::Plain).contains("approved"));
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
