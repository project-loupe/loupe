//! An eight-byte little-endian timestamp, then arbitrary UTF-8 finding text.
//! Both styles exercise every externally supplied text field and both diffs.

use loupe_cli::fuzz_support::{observe_response, ResponseCase, ResponseValue};
use loupe_cli::render::{
	finding, finding_list_row, finding_search_row, format_unix, Style, TerminalText,
};
use loupe_proto::FindingSummary;

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	if data.len() > 16 * 1024 {
		return;
	}
	let Some((time, text)) = data.split_at_checked(8) else { return };
	let timestamp = i64::from_le_bytes(time.try_into().unwrap_or_else(|_| unreachable!()));
	let formatted = format_unix(timestamp);
	assert!(formatted.ends_with(" UTC"));
	assert!(!formatted.contains(":-"));
	let Ok(text) = std::str::from_utf8(text) else { return };
	// The terminal primitive sees every UTF-8 control, including those that
	// field policies prevent from becoming a finding.
	let mut visible = String::new();
	for character in text.chars() {
		if character.is_control() {
			visible.extend(character.escape_default());
		} else {
			visible.push(character);
		}
	}
	assert_eq!(TerminalText(text).to_string(), visible, "terminal boundary changed visible text");
	let mut wire = serde_json::json!({
		"protocol_version": 2, "id": 42, "repo_id": 1, "job_id": 7,
		"scanner_id": text, "severity": "high", "title": text,
		"description": text, "file_path": text, "line_start": 1, "line_end": 2,
		"cwe": text, "poc_unified": text, "patch_unified": text,
		"fingerprint": text, "state": "awaiting_approval",
		"verification_required": false, "created_at": timestamp,
		"approved_at": timestamp, "approved_by_cn": text,
		"rejected_at": timestamp, "rejected_by_cn": text
	});
	let bytes = serde_json::to_vec(&wire).unwrap_or_else(|e| panic!("render fixture: {e}"));
	let mut result = observe_response(ResponseCase::GetFinding, &bytes).result;
	assert_eq!(result.is_ok(), crate::cli_common::path(text), "render fixture admission");
	if result.is_err() {
		// A newline/path rejection must not hide admissible multiline finding
		// bodies from the real renderer. Keep their original bytes and use
		// fixed admissible metadata for this independent body fixture.
		for field in [
			"scanner_id",
			"title",
			"file_path",
			"cwe",
			"fingerprint",
			"approved_by_cn",
			"rejected_by_cn",
		] {
			wire[field] = serde_json::Value::String("fixture".into());
		}
		let bytes =
			serde_json::to_vec(&wire).unwrap_or_else(|e| panic!("multiline render fixture: {e}"));
		result = observe_response(ResponseCase::GetFinding, &bytes).result;
		assert_eq!(
			result.is_ok(),
			crate::cli_common::exact(text, true),
			"multiline fixture admission"
		);
		visible = "fixture".to_owned();
	}
	let Ok(ResponseValue::Finding(detail)) = result else { return };
	assert_eq!(detail.description.expose(), text);
	assert_eq!(detail.poc_unified.as_ref().map(|v| v.expose()), Some(text));
	assert_eq!(detail.patch_unified.as_ref().map(|v| v.expose()), Some(text));
	let plain = finding(&detail, Style::Plain);
	let colored = finding(&detail, Style::Color);
	let mut unstyled = String::new();
	let mut remaining = colored.as_str();
	while let Some((index, character)) = remaining.char_indices().next() {
		assert_eq!(index, 0);
		if character == '\x1b' {
			let code =
				["\x1b[0m", "\x1b[1m", "\x1b[2m", "\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[36m"]
					.into_iter()
					.find(|code| remaining.starts_with(code))
					.unwrap_or_else(|| panic!("renderer emitted a foreign escape sequence"));
			remaining = remaining.get(code.len()..).unwrap_or_else(|| unreachable!());
		} else {
			assert!(
				!character.is_control() || character == '\n',
				"renderer emitted a foreign control"
			);
			unstyled.push(character);
			remaining = remaining.get(character.len_utf8()..).unwrap_or_else(|| unreachable!());
		}
	}
	assert_eq!(unstyled, plain, "styling must not change visible content");
	assert!(!plain.chars().any(|c| c.is_control() && c != '\n'));
	// Title is single-line data: each input control has a literal spelling,
	// including CR and LF, even though description/diff lines are structural.
	assert!(plain.contains(&format!("[high] — {visible}\n")), "title lost or injected a row");
	assert!(colored.len() <= text.len().saturating_mul(120).saturating_add(4096));
	let summary = FindingSummary {
		id: 42,
		repo_id: 1,
		job_id: 7,
		scanner_id: detail.scanner_id,
		severity: detail.severity,
		title: detail.title,
		file_path: detail.file_path,
		line_start: Some(1),
		fingerprint: detail.fingerprint,
		state: detail.state,
		verification_required: false,
		created_at: timestamp,
		approved_at: None,
		approved_by_cn: None,
		rejected_at: None,
		rejected_by_cn: None,
	};
	for (row, tabs) in [(finding_list_row(&summary), 7), (finding_search_row(&summary), 5)] {
		assert_eq!(row.matches('\t').count(), tabs, "finding text injected a column");
		assert!(
			!row.chars().any(|c| c.is_control() && c != '\t'),
			"finding text injected a control"
		);
		assert!(row.ends_with(&format!("\t{visible}:1\t{visible}")), "location or title lost");
		assert!(row.contains(&format!("\t{visible}\tstate=")), "scanner identity lost");
	}
}

pub fn cli_render_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cli_render_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
