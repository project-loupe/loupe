//! Header injection checks for validated operator fields and arbitrary findings.
use loupe_server::reporters::{email, ReportFinding};
use serde::Deserialize;

use crate::server_common;
use crate::utils::test_logger;

#[derive(Deserialize)]
struct Input {
	from: String,
	to: Vec<String>,
	subject: String,
	finding: crate::cli_response_oracle::wire::Finding,
}

pub fn do_test(data: &[u8]) {
	let Ok(input) = serde_json::from_slice::<Input>(data) else { return };
	let mut accepted = true;
	for (name, value) in [("From", &input.from), ("Subject", &input.subject)]
		.into_iter()
		.chain(input.to.iter().map(|value| ("To", value)))
	{
		let valid = !value.contains(['\r', '\n']);
		assert_eq!(
			email::validate_header_value(name, value).is_ok(),
			valid,
			"email header admission differs"
		);
		accepted &= valid;
	}
	if !accepted {
		return;
	}
	let repo = server_common::repo_with_reporting(serde_json::json!({
		"kind":"email", "from":input.from, "to":input.to, "subject_prefix":input.subject
	}));
	let admitted = [&input.from, &input.subject]
		.into_iter()
		.chain(input.to.iter())
		.all(|value| crate::cli_common::exact(value, false));
	assert_eq!(repo.is_ok(), admitted, "stored header admission differs");
	let Ok(repo) = repo else { return };
	let bytes =
		serde_json::to_vec(&input.finding).unwrap_or_else(|e| panic!("finding fixture: {e}"));
	let Some(finding) = server_common::finding(&bytes) else { return };
	let subject = format!("{} 1 {} finding(s) in example/repo", input.subject, finding.severity);
	let report = ReportFinding { id: 1, finding, reviewed_revision: None };
	let message = email::fuzz_render_message(&repo, &[report])
		.unwrap_or_else(|e| panic!("admitted email renderer: {e}"));
	let Some((headers, body)) = message.split_once("\r\n\r\n") else {
		panic!("email header boundary missing")
	};
	let expected = format!("From: {}\r\nTo: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8",
		input.from, input.to.join(", "), subject);
	assert_eq!(headers, expected, "finding content escaped into email headers");
	// Main has no body cap. Keep a known oversize seed for S3 rather than
	// introducing a cap or dynamically modifying committed test cases here.
	std::hint::black_box(body.len() > 65_536);
}

pub fn server_report_email_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn server_report_email_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller guarantees a valid readable input buffer.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn original_oversize_payload_reaches_email_with_an_admissible_title() {
		let original = include_bytes!("../test_cases/server_report_email/escape-oversize-body");
		let companion =
			include_bytes!("../test_cases/server_report_email/escape-oversize-body-admitted");
		let original_json: serde_json::Value =
			serde_json::from_slice(original).unwrap_or_else(|e| panic!("original seed: {e}"));
		let mut companion_json: serde_json::Value =
			serde_json::from_slice(companion).unwrap_or_else(|e| panic!("admitted seed: {e}"));
		assert_eq!(companion_json["finding"]["title"], " title words ");
		companion_json["finding"]["title"] = original_json["finding"]["title"].clone();
		assert_eq!(companion_json, original_json, "only title may change");
		let input: Input =
			serde_json::from_slice(companion).unwrap_or_else(|e| panic!("admitted input: {e}"));
		let original_finding = serde_json::to_vec(&original_json["finding"])
			.unwrap_or_else(|e| panic!("original finding: {e}"));
		assert!(server_common::finding(&original_finding).is_none());
		let finding_bytes =
			serde_json::to_vec(&input.finding).unwrap_or_else(|e| panic!("admitted finding: {e}"));
		let finding = server_common::finding(&finding_bytes)
			.unwrap_or_else(|| panic!("companion must reach the real email renderer"));
		let repo = server_common::repo_with_reporting(serde_json::json!({
			"kind":"email", "from":input.from, "to":input.to, "subject_prefix":input.subject
		}))
		.unwrap_or_else(|e| panic!("admitted email fixture: {e}"));
		let report = ReportFinding { id: 1, finding, reviewed_revision: None };
		let message = email::fuzz_render_message(&repo, &[report])
			.unwrap_or_else(|e| panic!("actual email renderer: {e}"));
		let (_, body) = message
			.split_once("\r\n\r\n")
			.unwrap_or_else(|| panic!("email header boundary missing"));
		assert!(body.len() > 65_536, "oversize payload must reach the body");
		let description = original_json["finding"]["description"]
			.as_str()
			.unwrap_or_else(|| panic!("description payload missing"));
		assert!(body.contains(description));
		do_test(companion);
	}
}
