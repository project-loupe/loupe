//! Legacy report admission; containment gaps are committed escape seeds for S3.
use loupe_server::reporters::{github, ReportFinding};

use crate::server_common;
use crate::utils::test_logger;

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
	let repo = server_common::repo();
	let report = ReportFinding { id: 1, finding, reviewed_revision: repo.last_scanned_sha.clone() };
	let body = github::fuzz_render_body(&repo, &report);
	assert_eq!(
		github::validate_body(&body).is_ok(),
		body.chars().count() <= 65_536,
		"GitHub body admission must count characters"
	);
	for payload in [
		Some(report.finding.title.expose()),
		Some(report.finding.description.expose()),
		report.finding.poc_unified.as_ref().map(|v| v.expose()),
		report.finding.patch_unified.as_ref().map(|v| v.expose()),
	]
	.into_iter()
	.flatten()
	{
		// Observe the deferred S3 property without writing to the source corpus.
		std::hint::black_box(escapes_fences(&body, payload));
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
			let repo = server_common::repo();
			let report =
				ReportFinding { id: 1, finding, reviewed_revision: repo.last_scanned_sha.clone() };
			let body = github::fuzz_render_body(&repo, &report);
			assert!(body.contains(report.finding.description.expose()));
			if oversized {
				assert!(
					body.chars().count() > 65_536,
					"oversize payload must reach body admission"
				);
				assert!(github::validate_body(&body).is_err());
			} else {
				let poc = report
					.finding
					.poc_unified
					.as_ref()
					.unwrap_or_else(|| panic!("closing-fence payload missing"));
				assert!(poc.expose().contains("```"));
				assert!(body.contains(poc.expose()), "closing-fence payload must reach the body");
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
