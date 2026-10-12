//! Synthetic original Server fixture passed through the actual lease owner.
//! No production raw prompt constructor or source-selecting serializer exists.

use super::*;

pub fn render(
	raw: &[u8], mode: DataMode, projection: bool, candidates: [[u8; 16]; 3],
) -> Option<Result<Prompt, PromptError>> {
	if raw.len() > 2 * 1024 * 1024 {
		return None;
	}
	let description = std::str::from_utf8(raw).ok()?;
	let original = serde_json::to_vec(&serde_json::json!({
		"kind": "lease", "protocol_version": 1, "job_id": 42, "repo_id": 1,
		"job_capability": "test-capability", "scanner_config": null,
		"repo": {"host": "github.com", "owner": "a", "repo": "b", "clone_url": "https://github.com/a/b.git"},
		"lease_expires_at": 300,
		"payload": {"kind": "verify", "finding_id": 7, "finding": {
			"scanner_id": "llm-code-review", "severity": "high", "title": "OOB index",
			"description": description, "file_path": "src/lib.rs", "line_start": 1,
			"line_end": 2, "cwe": null, "patch_unified": null, "poc_unified": null, "fingerprint": "fp1"
		}}
	})).ok()?;
	let loupe_proto::LeaseResponse::Lease(env) =
		crate::client::fuzz_support::lease_response(&original)?
	else {
		return None;
	};
	let loupe_proto::LeasePayload::Verify { finding, .. } = env.payload else {
		return None;
	};
	assert_eq!(finding.description.expose().as_bytes(), raw);
	let mut builder = PromptBuilder::new(PREAMBLE).mode(mode);
	let added = if projection {
		builder.verification(7, &finding)
	} else {
		builder.data("description", &finding.description)
	};
	if let Err(error) = added {
		return Some(Err(error));
	}
	let mut draw = 0;
	Some(builder.render_with(|| {
		let candidate = candidates[draw];
		draw += 1;
		Ok(candidate)
	}))
}
