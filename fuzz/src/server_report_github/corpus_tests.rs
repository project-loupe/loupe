use super::*;

#[test]
fn canonical_injection_corpus_is_literal_in_both_report_destinations() {
	let directory =
		std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test_cases/worker_prompt_render");
	let mut admitted = 0;
	let mut rejected = 0;
	for entry in std::fs::read_dir(directory).unwrap_or_else(|error| panic!("corpus: {error}")) {
		let path = entry.unwrap_or_else(|error| panic!("corpus entry: {error}")).path();
		let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
		if !name.starts_with("injection-") {
			continue;
		}
		let raw = std::fs::read_to_string(&path)
			.unwrap_or_else(|error| panic!("corpus payload {name}: {error}"));
		let negative = matches!(
			name,
			"injection-bidi-isolate" | "injection-bidi-override" | "injection-forbidden-control"
		);
		let value = serde_json::json!({
			"scanner_id":"fixture", "severity":"high", "title":"corpus report",
			"fingerprint":"fixture", "description":raw,
			"poc_unified":raw, "patch_unified":raw
		});
		let bytes =
			serde_json::to_vec(&value).unwrap_or_else(|error| panic!("corpus wire: {error}"));
		let finding = server_common::finding(&bytes);
		if negative {
			assert!(finding.is_none(), "forbidden corpus control admitted: {name}");
			rejected += 1;
			continue;
		}
		let finding = finding.unwrap_or_else(|| panic!("admissible corpus rejected: {name}"));
		assert_eq!(finding.description.expose().as_bytes(), raw.as_bytes());
		let body =
			rendered(&finding).unwrap_or_else(|error| panic!("corpus renderer {name}: {error}"));
		assert!(body.contains(&raw), "original corpus bytes missing: {name}");
		assert!(!escapes_fences(&body, &raw), "corpus payload must be literal: {name}");
		do_test(&bytes);
		let email = serde_json::to_vec(&serde_json::json!({
			"from":"loupe@example.test", "to":["operator@example.test"],
			"subject":"corpus reports", "finding":value
		}))
		.unwrap_or_else(|error| panic!("email corpus wire: {error}"));
		crate::server_report_email::do_test(&email);
		admitted += 1;
	}
	assert_eq!((admitted, rejected), (37, 3), "all canonical payloads must run");
}
