//! Literal report containment and destination admission over committed findings.
use loupe_core::Finding;
use loupe_provenance::Agent;
use loupe_server::reporters::github;

use crate::server_common;
use crate::utils::test_logger;

#[cfg(test)]
mod corpus_tests;

/// Find payload occurrences that are not wholly inside a backtick code fence.
/// A payload containing its own closing fence cannot be considered contained.
pub fn escapes_fences(body: &str, payload: &str) -> bool {
	if payload.is_empty() {
		return false;
	}
	let mut ranges = Vec::new();
	let mut opening = None;
	let mut offset = 0;
	for line in body.split_inclusive('\n') {
		let ticks = line.bytes().take_while(|b| *b == b'`').count();
		if let Some((width, start)) = opening {
			if ticks >= width && line.get(ticks..).is_some_and(|s| s.trim().is_empty()) {
				ranges.push(start..offset);
				opening = None;
			}
		} else if ticks >= 3 {
			opening = Some((ticks, offset + line.len()));
		}
		offset += line.len();
	}
	body.match_indices(payload).any(|(start, _)| {
		!ranges.iter().any(|range| start >= range.start && start + payload.len() <= range.end)
	})
}

/// Independent report oracle over pulldown-cmark, never the renderer's helpers.
/// Agent text outside code may only be words GitHub cannot link after parsing.
fn assert_inert(body: &str) {
	use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
	let mut links = 0;
	let mut in_link = false;
	let mut in_block = false;
	let mut headings = 0;
	for event in Parser::new_ext(body, Options::ENABLE_TABLES | Options::ENABLE_TASKLISTS) {
		match event {
			Event::Start(Tag::Link { dest_url, .. }) => {
				assert_eq!(&*dest_url, "https://github.com/project-loupe/loupe");
				links += 1;
				in_link = true;
			},
			Event::End(TagEnd::Link) => in_link = false,
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
			| Event::TaskListMarker(_) => panic!("agent text became active markup"),
			Event::Text(text) if !in_link && !in_block => {
				for word in text.split_whitespace().filter(|word| !word.starts_with("LUP-")) {
					let hex = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
					// GitHub links a commit prefix bounded by any non-alphanumeric, so
					// check each run between punctuation, not only the whole word.
					let commit_like = hex
						.split(|c: char| !c.is_ascii_alphanumeric())
						.any(|run| run.len() >= 7 && run.bytes().all(|b| b.is_ascii_hexdigit()));
					assert!(
						!word.contains(|c: char| c.is_ascii_digit()
							|| matches!(c, '@' | '#' | '/' | '<' | '>' | '[' | ']' | '\\' | '`'))
							&& !word.starts_with(':')
							&& !word.to_ascii_lowercase().starts_with("www.")
							&& !commit_like,
						"GitHub-active token outside code"
					);
				}
			},
			_ => {},
		}
	}
	assert_eq!(links, 1, "only the host footer may link");
	assert!((3..=5).contains(&headings), "only trusted headings may exist");
}

/// Code a diff attachment is guaranteed to render as, byte for byte.
fn contains_literal_diff(body: &str, diff: &str) -> bool {
	use pulldown_cmark::{Event, Parser, Tag, TagEnd};
	let mut block = None::<String>;
	for event in Parser::new(body) {
		match event {
			Event::Start(Tag::CodeBlock(_)) => block = Some(String::new()),
			Event::Text(text) => {
				if let Some(block) = &mut block {
					block.push_str(&text);
				}
			},
			Event::End(TagEnd::CodeBlock) => {
				let rendered = block.take().unwrap_or_default();
				let normalized = diff.replace("\r\n", "\n").replace('\r', "\n");
				if rendered.replace("\r\n", "\n").replace('\r', "\n") == format!("{normalized}\n") {
					return true;
				}
			},
			_ => {},
		}
	}
	false
}

fn rendered(finding: &Finding<Agent>) -> Result<String, String> {
	let (_db, batch) = server_common::prepared_report(
		serde_json::json!({"kind":"github_issue", "target_owner":"example", "target_repo":"repo"}),
		finding,
		false,
	)
	.unwrap_or_else(|error| panic!("report preparation: {error}"));
	github::fuzz_render_body(&batch, 0).map_err(|error| error.to_string())
}

pub fn do_test(data: &[u8]) {
	let Some(finding) = server_common::finding(data) else { return };
	let title = github::fuzz_render_title(&finding);
	assert!(title.chars().count() <= 100, "GitHub title exceeds its character cap");
	assert!(!title.contains(['\r', '\n']));
	assert!(!title.is_empty());
	let compact = finding.title.expose().split_whitespace().collect::<Vec<_>>().join(" ");
	if compact.is_empty() {
		assert_eq!(title, "Untitled finding");
	} else if compact.chars().count() <= 100 {
		assert_eq!(title, compact);
	} else {
		assert!(title.ends_with("..."));
		assert!(compact.starts_with(title.trim_end_matches('.')));
	}
	let raw_chars = [
		Some(finding.title.expose()),
		Some(finding.description.expose()),
		finding.cwe.as_ref().map(|value| value.expose()),
		finding.file_path.as_ref().map(|value| value.expose()),
		finding.poc_unified.as_ref().map(|value| value.expose()),
		finding.patch_unified.as_ref().map(|value| value.expose()),
		Some(finding.fingerprint.expose()),
	]
	.into_iter()
	.flatten()
	.map(|value| value.chars().count())
	.sum::<usize>();
	match rendered(&finding) {
		Ok(body) => {
			assert!(body.chars().count() <= 65_536 && body.len() <= 262_144);
			assert!(github::validate_body(&body).is_ok());
			assert_inert(&body);
			let poc = finding.poc_unified.as_ref().map(|value| value.expose());
			let patch = finding.patch_unified.as_ref().map(|value| value.expose());
			for diff in [poc, patch].into_iter().flatten() {
				assert!(contains_literal_diff(&body, diff), "diff must stay literal");
			}
		},
		Err(error) => {
			assert_eq!(error, "GitHub issue body exceeds 65536 characters or 262144 bytes including framing; shorten the report and retry");
			// Each char costs a bounded amount of framing, so small reports
			// are never rejected: a token is at worst a padded span of itself.
			assert!(
				raw_chars.saturating_mul(6).saturating_add(1024) > 65_536,
				"small report rejected"
			);
		},
	}
}

pub fn server_report_github_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn server_report_github_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller guarantees a valid readable input buffer.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn original_report_payloads_reach_the_renderer_with_admissible_titles() {
		for (original, companion, oversized) in [
			(
				include_bytes!("../test_cases/server_report_github/escape-closing-fence")
					.as_slice(),
				include_bytes!("../test_cases/server_report_github/escape-closing-fence-admitted")
					.as_slice(),
				false,
			),
			(
				include_bytes!("../test_cases/server_report_github/oversize-body").as_slice(),
				include_bytes!("../test_cases/server_report_github/oversize-body-admitted")
					.as_slice(),
				true,
			),
		] {
			let original_json: serde_json::Value =
				serde_json::from_slice(original).unwrap_or_else(|e| panic!("original seed: {e}"));
			let mut companion_json: serde_json::Value =
				serde_json::from_slice(companion).unwrap_or_else(|e| panic!("admitted seed: {e}"));
			assert_eq!(companion_json["title"], " title words ");
			companion_json["title"] = original_json["title"].clone();
			assert_eq!(companion_json, original_json, "only title may change");
			assert!(
				server_common::finding(original).is_none(),
				"original newline title must reject"
			);
			let finding = server_common::finding(companion)
				.unwrap_or_else(|| panic!("companion must reach the real renderer"));
			let body = rendered(&finding);
			if oversized {
				assert!(body.is_err(), "oversize input must not produce a partial report");
			} else {
				let body = body.unwrap_or_else(|error| panic!("admitted literal report: {error}"));
				let poc = finding
					.poc_unified
					.as_ref()
					.unwrap_or_else(|| panic!("closing-fence payload missing"));
				assert!(poc.expose().contains("```"));
				assert!(body.contains(poc.expose()), "closing-fence payload must reach the body");
				assert!(!escapes_fences(&body, poc.expose()), "saved escape must be contained");
			}
			do_test(companion);
		}
	}

	#[test]
	fn containment_distinguishes_plain_text_and_embedded_closing_fences() {
		assert!(!escapes_fences("```diff\nsafe\n```\n", "safe"));
		assert!(escapes_fences("description outside a fence", "outside"));
		assert!(escapes_fences("```diff\n```\nescape\n```\n", "```\nescape"));
	}
}
