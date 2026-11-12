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
fn report_metadata_stays_in_exact_code_spans() {
	let report = report();
	let repo = super::fixtures::repo(serde_json::json!({"kind":"manual"})).unwrap();
	let body = github::render_view(&repo, report.view()).unwrap().into_string();
	let literals = super::fixtures::literal_values(&body);
	for payload in [
		report.finding.cwe.as_ref().unwrap().expose(),
		report.finding.fingerprint.expose(),
		report.reviewed_revision.as_ref().unwrap().expose(),
		repo.owner.expose(),
		repo.repo.expose(),
		repo.clone_url.expose(),
	] {
		assert!(literals.iter().any(|value| value == payload), "not literal: {payload:?}");
	}
	assert_inert(&body, "metadata");
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
	let line = body
		.lines()
		.find_map(|line| line.strip_prefix("**Location:** "))
		.unwrap()
		.trim_end_matches(" ");
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

/// Independent readers of the rendered issue. GitHub links mentions, references
/// and commits in text nodes after Markdown parsing, so escaping is not enough:
/// agent text outside code must be unable to contain those tokens at all.
fn assert_inert(body: &str, payload: &str) {
	use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
	let mut links = Vec::new();
	let mut headings = 0;
	let mut in_host_link = false;
	let mut in_block = false;
	let parser = Parser::new_ext(body, Options::ENABLE_TABLES | Options::ENABLE_TASKLISTS);
	for event in parser {
		match event {
			Event::Start(Tag::Link { dest_url, .. }) => {
				links.push(dest_url.to_string());
				in_host_link = true;
			},
			Event::End(TagEnd::Link) => in_host_link = false,
			Event::Start(Tag::CodeBlock(_)) => in_block = true,
			Event::End(TagEnd::CodeBlock) => in_block = false,
			Event::Start(Tag::Heading { .. }) => headings += 1,
			Event::Start(
				Tag::Image { .. }
				| Tag::BlockQuote(_)
				| Tag::Table(_)
				| Tag::List(_)
				| Tag::HtmlBlock,
			)
			| Event::Rule
			| Event::Html(_)
			| Event::InlineHtml(_)
			| Event::TaskListMarker(_) => panic!("{payload:?} became active markup: {event:?}"),
			Event::Text(text) if !in_host_link && !in_block => {
				for word in text.split_whitespace().filter(|word| *word != "LUP-73") {
					let hex = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
					// GitHub links a commit prefix bounded by any non-alphanumeric, so
					// check each run between punctuation, not only the whole word.
					let commit_like = hex
						.split(|c: char| !c.is_ascii_alphanumeric())
						.any(|run| run.len() >= 7 && run.bytes().all(|b| b.is_ascii_hexdigit()));
					assert!(
						!word.contains(|c: char| c.is_ascii_digit()
							|| matches!(c, '@' | '#' | '/' | '<' | '>' | '[' | ']' | '\\' | '`'))
							&& !word.contains("://")
							&& !word.to_ascii_lowercase().starts_with("www.")
							&& !word.starts_with(':')
							&& !commit_like,
						"{payload:?} left a GitHub-active token outside code: {word:?}"
					);
				}
			},
			_ => {},
		}
	}
	assert_eq!(links, ["https://github.com/project-loupe/loupe"], "{payload:?} added a link");
	assert_eq!(headings, 3, "{payload:?} changed the trusted headings");
}

fn description_body(payload: &str) -> String {
	let mut report = report();
	report.finding.description = text(payload);
	let repo = super::fixtures::repo(serde_json::json!({"kind":"manual"})).unwrap();
	github::render_view(&repo, report.view()).unwrap().into_string()
}

#[test]
fn description_renders_as_readable_prose() {
	use pulldown_cmark::{Event, Parser, Tag, TagEnd};
	let body = description_body(
		"The `idx` helper in src/lib.rs indexes without checking bounds, so it panics.\n\nA second paragraph.\n- first item\n",
	);
	let events: Vec<_> = Parser::new(&body).collect();
	let description = events
		.iter()
		.position(|event| matches!(event, Event::Text(text) if &**text == "Description"))
		.unwrap();
	let mut paragraphs = 0;
	let mut text_seen = String::new();
	for event in &events[description..] {
		match event {
			Event::Start(Tag::CodeBlock(_)) => panic!("prose must not be a code block"),
			Event::Start(Tag::Paragraph) => paragraphs += 1,
			Event::End(TagEnd::Paragraph) if paragraphs == 2 => break,
			Event::Text(text) | Event::Code(text) => text_seen.push_str(text),
			Event::SoftBreak => text_seen.push(' '),
			_ => {},
		}
	}
	assert!(text_seen.contains("The idx helper in src/lib.rs indexes"), "{text_seen}");
	assert!(text_seen.contains("A second paragraph."), "{text_seen}");
	assert!(text_seen.contains("• first item"), "{text_seen}");
	assert!(!body.contains("- description"), "metadata bullets are gone: {body}");
}

#[test]
fn prose_keeps_agent_snippets_literal_and_contained() {
	let snippet = "fn main() {\n    // ```\n    # not a heading\n}";
	for payload in [
		format!("Before\n\n```rust\n{snippet}\n```\n\nAfter"),
		format!("Before\n\n~~~\n{snippet}\n~~~\n\nAfter"),
		"Before\n\n    # indented\n    @octocat\n\nAfter".to_owned(),
		format!("Unclosed\n\n```\n{snippet}"),
	] {
		let body = description_body(&payload);
		assert_inert(&body, &payload);
		let blocks = closed_blocks(&body);
		assert!(
			blocks.iter().any(|block| body[block.clone()].contains("# ")),
			"snippet must stay in a block: {body}"
		);
	}
}

#[test]
fn description_cannot_activate_markup_or_github_references() {
	for payload in [
		"hi @octocat there",
		"hi \\@octocat and &#64;octocat and ＠octocat",
		"see #1 owner/repo#1 GH-1 JIRA-123 (#1) #1, 1",
		"see 7fd1a60b01f91b314f59955a4e4d4e80d8edf11d 7fd1a60 abcdefa, deadbeef.",
		"deadbeef’s fix, cafebabe's patch and abcdefa-thing or thing-abcdefa",
		"https://evil.invalid/x www.evil.invalid http://evil.invalid someone@evil.invalid",
		"[click](https://evil.invalid) ![x](https://evil.invalid/p.png) [a]: https://evil.invalid",
		"<!-- hidden --> <img src=x> <script>bad</script> <details> &lt;b&gt;",
		"# injected\n## injected\ninjected\n===\ninjected\n---\n***\n___",
		"> quote\n- list\n* list\n+ list\n1. list\n1) list\n- [ ] task",
		"a | b\n--- | ---\nc | d",
		":rocket: *emphasis* **strong** _under_ ~~strike~~",
		"```\n# in a fence\n",
		"``` ` `` a`b ``unbalanced `@octocat `#1` @octocat",
		"line\\\n# after backslash",
		"tab\there\r\n# crlf\r# cr",
		"(@octocat), \"#1\" 'www.evil.invalid' —@octocat",
		"    # four spaces\n\t# tab\n   # three spaces",
		"",
		"\n\n",
	] {
		assert_inert(&description_body(payload), payload);
		let mut report = report();
		report.finding.title = text(&payload.replace(['\r', '\n', '\t'], " "));
		report.finding.scanner_id = text("fixture");
		let repo = super::fixtures::repo(serde_json::json!({"kind":"manual"})).unwrap();
		let body = github::render_view(&repo, report.view()).unwrap().into_string();
		assert_inert(&body, payload);
	}
}
