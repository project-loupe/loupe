//! Independent output parsing: these tests exercise the actual report sink.
use loupe_core::{Finding, Severity};

use super::fixtures::{path, revision, text, ReportFinding};
use super::github;

fn report() -> ReportFinding {
	ReportFinding {
		id: 73,
		finding: Finding {
			scanner_id: text("scanner"),
			severity: Severity::High,
			title: text("title sentinel [link](https://title.invalid)"),
			description: text("description sentinel\n## injected heading\n<a href='x'>html</a>"),
			file_path: None,
			line_start: None,
			line_end: None,
			cwe: Some(text("cwe sentinel [link](https://cwe.invalid)")),
			fingerprint: text("fingerprint sentinel `edge`"),
			poc_unified: None,
			patch_unified: None,
		},
		reviewed_revision: Some(revision("revision sentinel `edge`")),
	}
}

/// Parse fenced code intervals from lines. This deliberately does not call
/// the renderer's fence-sizing helper. It also requires an explicit closer.
fn closed_blocks(input: &str) -> Vec<std::ops::Range<usize>> {
	let mut blocks = Vec::new();
	let mut active = None;
	let mut offset = 0;
	for line in input.split_inclusive(['\r', '\n']) {
		let bare = line.trim_end_matches(['\r', '\n']);
		let indent = bare.bytes().take_while(|b| *b == b' ').count();
		let candidate = if indent <= 3 { &bare[indent..] } else { "" };
		let run = candidate.bytes().take_while(|b| *b == b'`').count();
		if let Some((width, start)) = active {
			if run >= width && candidate[run..].bytes().all(|b| b == b' ' || b == b'\t') {
				blocks.push(start..offset);
				active = None;
			}
		} else if run >= 3 && !candidate[run..].contains('`') {
			active = Some((run, offset + line.len()));
		}
		offset += line.len();
	}
	assert!(active.is_none(), "every literal block needs an explicit closer");
	blocks
}

fn assert_contained(body: &str, payload: &str) {
	let blocks = closed_blocks(body);
	let positions: Vec<_> = body.match_indices(payload).map(|(start, _)| start).collect();
	assert!(!positions.is_empty(), "original payload must be present");
	for start in positions {
		assert!(
			blocks.iter().any(|range| range.start <= start && start + payload.len() <= range.end),
			"payload must stay inside a closed literal block: {payload:?}"
		);
	}
}

#[test]
fn report_prose_is_contained_in_closed_literal_blocks() {
	let report = report();
	let repo = super::fixtures::repo(serde_json::json!({"kind":"manual"})).unwrap();
	let body = github::render_view(&repo, report.view()).unwrap().into_string();
	for payload in [
		report.finding.title.expose(),
		report.finding.description.expose(),
		report.finding.cwe.as_ref().unwrap().expose(),
		report.finding.fingerprint.expose(),
		report.reviewed_revision.as_ref().unwrap().expose(),
		repo.owner.expose(),
		repo.repo.expose(),
		repo.clone_url.expose(),
	] {
		assert_contained(&body, payload);
	}
}

#[test]
fn report_diff_cannot_close_its_literal_block() {
	let mut report = report();
	let repo = super::fixtures::repo(serde_json::json!({"kind":"manual"})).unwrap();
	for payload in [
		"",
		"\n\n",
		" a \t\r\n\r\n",
		"start\r```\t\r## breakout",
		"```\n## breakout\n",
		"```` \t\n<iframe>escape</iframe>",
		"start\n`````\nend",
		"trailing```",
	] {
		report.finding.poc_unified = Some(text(payload));
		report.finding.patch_unified = Some(text(payload));
		let rendered = github::render_view(&repo, report.view()).unwrap().into_string();
		let blocks = closed_blocks(&rendered);
		assert_eq!(
			blocks
				.iter()
				.filter(|block| rendered
					.get((*block).clone())
					.is_some_and(|text| text.strip_suffix('\n') == Some(payload)))
				.count(),
			2,
			"both exact diff payloads must have independent closed frames"
		);
		if payload.chars().any(|ch| !ch.is_whitespace()) {
			assert_contained(&rendered, payload);
		}
	}
}

/// Parse inline code according to delimiter equality and one-space edge
/// stripping. Text outside the sole code span is not permitted at this field.
fn location_code(body: &str) -> String {
	let line = body.lines().find_map(|line| line.strip_prefix("- location: ")).unwrap();
	let width = line.bytes().take_while(|b| *b == b'`').count();
	assert!(width > 0, "location must start with a code span");
	let mut cursor = width;
	while cursor < line.len() {
		if line.as_bytes()[cursor] != b'`' {
			cursor += 1;
			continue;
		}
		let run = line.as_bytes()[cursor..].iter().take_while(|b| **b == b'`').count();
		if run == width {
			assert_eq!(cursor + run, line.len(), "path emitted text outside its code span");
			let raw = &line[width..cursor];
			return if raw.starts_with(' ') && raw.ends_with(' ') && raw.bytes().any(|b| b != b' ') {
				raw[1..raw.len() - 1].to_owned()
			} else {
				raw.to_owned()
			};
		}
		cursor += run;
	}
	panic!("location needs a matching code-span closer")
}

#[test]
fn report_path_preserves_edges_without_markdown_siblings() {
	let mut report = report();
	let repo = super::fixtures::repo(serde_json::json!({"kind":"manual"})).unwrap();
	for value in ["a`[escape](evil)`b", "`edge", "edge`", " both ", "   ", "````", "é/e\u{301}"] {
		for suffix in [false, true] {
			report.finding.file_path = Some(path(value));
			report.finding.line_start = suffix.then_some(3);
			report.finding.line_end = suffix.then_some(8);
			let expected = if suffix { format!("{value}:3-8") } else { value.to_owned() };
			assert_eq!(
				location_code(github::render_view(&repo, report.view()).unwrap().as_str()),
				expected,
				"displayed path must preserve original bytes and scalar suffix"
			);
		}
	}
}
