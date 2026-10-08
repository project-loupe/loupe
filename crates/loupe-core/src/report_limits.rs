//! Report content budget shared by the MCP broker and server. The final
//! GitHub body also includes metadata and Markdown, checked at dispatch.

pub const GITHUB_ISSUE_BODY_MAX_CHARS: usize = 65_536;
/// Leave room for metadata, headings, code fences, and the attribution.
pub const REPORT_CONTENT_MAX_CHARS: usize = 60_000;

pub fn validate_report_content(
	description: &str, poc_unified: Option<&str>, patch_unified: Option<&str>,
) -> Result<(), String> {
	let chars = [Some(description), poc_unified, patch_unified]
		.into_iter()
		.flatten()
		.map(|text| text.chars().count())
		.sum::<usize>();
	if chars > REPORT_CONTENT_MAX_CHARS {
		return Err(format!(
			"report content is too long: {chars} characters; maximum is \
			 {REPORT_CONTENT_MAX_CHARS} across description, poc_unified, and patch_unified \
			 combined (GitHub issue body maximum: {GITHUB_ISSUE_BODY_MAX_CHARS}). \
			 Shorten the description or diffs, preserve a complete applying diff, and retry \
			 the submission."
		));
	}
	Ok(())
}
