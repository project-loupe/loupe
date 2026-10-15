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

/// Independent wire reference: split into backtick-only substrings rather than
/// using the renderer's scanner, accounting state or destination constructors.
pub(super) fn reference_field(label: &str, value: &str, language: &str) -> String {
	let longest = value.split(|ch| ch != '`').map(str::len).max().unwrap_or(0);
	let fence = "`".repeat(3.max(longest + 1));
	format!("- {label}:\n{fence}{language}\n{value}\n{fence}\n\n")
}

fn reference_body(finding: &Finding<Agent>) -> String {
	let mut pieces = vec!["## Finding LUP-1\n\n".to_owned()];
	for (label, value) in [
		("repository owner", "example"),
		("repository", "repo"),
		("clone URL", "https://github.com/example/repo.git"),
		("reviewed revision", "reviewed-sha"),
		("title", finding.title.expose()),
	] {
		pieces.push(reference_field(label, value, ""));
	}
	pieces.push(format!("- severity: {}\n", finding.severity));
	if let Some(path) = &finding.file_path {
		let mut value = path.expose().to_owned();
		if let Some(start) = finding.line_start {
			value.push_str(&format!(":{start}"));
			if let Some(end) = finding.line_end.filter(|end| *end != start) {
				value.push_str(&format!("-{end}"));
			}
		}
		let longest = value.split(|ch| ch != '`').map(str::len).max().unwrap_or(0);
		let fence = "`".repeat(3.max(longest + 1));
		// CommonMark removes one pair of surrounding spaces from nonblank code.
		let padded = value.starts_with('`')
			|| value.ends_with('`')
			|| (value.starts_with(' ') && value.ends_with(' ') && !value.trim().is_empty());
		let pad = if padded { " " } else { "" };
		pieces.push(format!("- location: {fence}{pad}{value}{pad}{fence}\n"));
	}
	if let Some(cwe) = &finding.cwe {
		pieces.push(reference_field("cwe", cwe.expose(), ""));
	}
	pieces.push(reference_field("fingerprint", finding.fingerprint.expose(), ""));
	pieces.push("## Description\n\n".into());
	pieces.push(reference_field("description", finding.description.expose(), ""));
	if let Some(poc) = &finding.poc_unified {
		pieces.push("## Proof of Concept\n\n".into());
		pieces.push(reference_field("proof of concept", poc.expose(), "diff"));
	}
	if let Some(patch) = &finding.patch_unified {
		pieces.push("## Suggested Fix\n\n".into());
		pieces.push(reference_field("suggested fix", patch.expose(), "diff"));
	}
	pieces.push("_This finding was discovered by [Project Loupe](https://github.com/project-loupe/loupe)._\n".into());
	pieces.concat()
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
	let expected = reference_body(&finding);
	let body = rendered(&finding);
	let admitted = expected.chars().count() <= 65_536 && expected.len() <= 262_144;
	assert_eq!(body.is_ok(), admitted, "complete GitHub body admission differs");
	assert_eq!(
		github::validate_body(&expected).is_ok(),
		expected.chars().count() <= 65_536,
		"GitHub body admission must count characters"
	);
	match body {
		Ok(body) => assert_eq!(body, expected, "original report data must stay in literal fields"),
		Err(error) => assert_eq!(error, "GitHub issue body exceeds 65536 characters or 262144 bytes including framing; shorten the report and retry"),
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
			let expected = reference_body(&finding);
			assert!(expected.contains(finding.description.expose()));
			let body = rendered(&finding);
			if oversized {
				assert!(
					expected.chars().count() > 65_536,
					"oversize payload must reach body admission"
				);
				assert!(body.is_err(), "oversize input must not produce a partial report");
				assert!(github::validate_body(&expected).is_err());
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
