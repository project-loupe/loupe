//! Stable-ish fingerprints for findings.
//!
//! A finding's fingerprint is the dedup key for `(repo_id,
//! fingerprint)` on the `findings` table — two scans of the same
//! repo that emit the same fingerprint share a row, with `INSERT OR
//! IGNORE` quietly dropping the duplicate. So whatever we hash needs
//! to stay the same when we'd consider two emissions "the same
//! finding," and change when we'd consider them different.
//!
//! The shape we hash:
//!
//! ```text
//! blake3( scanner_id | "\0" | file_path | "\0" | normalized_window )
//! ```
//!
//! `normalized_window` is the source bytes immediately around the
//! bug, normalised so cosmetic-but-not-semantic edits don't shift
//! the hash:
//!
//! - lowercased
//! - each line trimmed
//! - runs of whitespace within a line collapsed to a single space
//! - blank lines dropped entirely
//!
//! Properties:
//!
//! - **Stable** across `cargo fmt` runs, license header additions,
//!   unrelated edits in the same file, capitalisation drift in
//!   model-emitted titles. The window doesn't include the line
//!   number or the title — both are unstable.
//! - **Stable** across `head_sha` changes — explicitly not part of
//!   the hash. Re-scanning the same content on a later commit
//!   produces the same fingerprint.
//! - **Unstable** when the bug *itself* is touched (which is what
//!   you want — a fix should produce a different fingerprint, so
//!   approval state from the original doesn't carry forward).
//! - **Unstable** across file renames — file path is in the hash.
//!   Tradeoff: the alternative (content-only) would conflate "same
//!   pattern in two different files," which is the more harmful
//!   collision.
//!
//! For paraphrase / refactor tolerance (function moved to a different
//! file, model phrased the description differently), the hash is the
//! deterministic floor; semantic dedup belongs above it as a separate
//! pass — see the MCP build-out / stage-2 dedup work in `LOUPE.md`.

/// Compute the fingerprint for a finding.
///
/// `content_window` is whatever bytes the scanner deems
/// representative of the bug — typically the lines around
/// `line_start..=line_end` from the worktree, plus a couple of lines
/// of context. For the regex secrets scanner, it's the matched
/// secret bytes themselves.
pub fn compute(scanner_id: &str, file_path: &str, content_window: &str) -> String {
	let normalized = normalize_window(content_window);
	let mut h = blake3::Hasher::new();
	h.update(scanner_id.as_bytes());
	h.update(b"\0");
	h.update(file_path.as_bytes());
	h.update(b"\0");
	h.update(normalized.as_bytes());
	h.finalize().to_hex().to_string()
}

/// Normalise a content window for fingerprinting.
///
/// The transformations are deliberately aggressive: a `cargo fmt`
/// run, an indentation change, a trailing-whitespace trim, or a
/// blank-line cleanup must not move the fingerprint. The cost is
/// false-merges only on inputs whose only meaningful difference is
/// whitespace and case — which for source code is essentially never
/// the case.
pub fn normalize_window(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for line in s.lines() {
		let trimmed = line.trim();
		if trimmed.is_empty() {
			continue;
		}
		let collapsed: String = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
		if !out.is_empty() {
			out.push('\n');
		}
		out.push_str(&collapsed.to_lowercase());
	}
	out
}

/// Pull a content window from `source` covering
/// `line_start..=line_end` (1-indexed) plus `context` lines on each
/// side, clamped to the file. Returns an empty string if the file
/// is empty or `line_start > line_end > line_count`.
///
/// Clamping makes the helper tolerant of model-emitted line numbers
/// that fall slightly outside the actual file (off-by-one, stale
/// against a re-fetched HEAD) — we still produce a representative
/// window rather than blowing up.
pub fn extract_window(source: &str, line_start: u32, line_end: u32, context: u32) -> String {
	let lines: Vec<&str> = source.lines().collect();
	if lines.is_empty() {
		return String::new();
	}
	let start = line_start.saturating_sub(context).saturating_sub(1) as usize;
	let end = (line_end.saturating_add(context) as usize).min(lines.len());
	if start >= end {
		return String::new();
	}
	lines[start..end].join("\n")
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn cosmetic_edits_do_not_shift_the_hash() {
		// Same logical content, different formatting.
		let a = "  let x = 1;\n  let y = 2;\n";
		let b = "let x = 1;\nlet y = 2;\n"; // unindented
		let c = "\nlet x = 1;\n\n\nlet y = 2;\n\n"; // extra blank lines
		let d = "let x  =  1;\nlet y\t=\t2;\n"; // weird whitespace runs / tabs
		let e = "LET X = 1;\nLET Y = 2;\n"; // capitalised

		let h_a = compute("scanner", "src/x.rs", a);
		assert_eq!(h_a, compute("scanner", "src/x.rs", b));
		assert_eq!(h_a, compute("scanner", "src/x.rs", c));
		assert_eq!(h_a, compute("scanner", "src/x.rs", d));
		assert_eq!(h_a, compute("scanner", "src/x.rs", e));
	}

	#[test]
	fn touching_the_bug_body_changes_the_hash() {
		// Substantive edit — different code, different fingerprint.
		let original = "let x = unsafe { *raw };\n";
		let fixed = "let x = unsafe { *raw }.unwrap_or(0);\n";
		assert_ne!(compute("scanner", "src/x.rs", original), compute("scanner", "src/x.rs", fixed),);
	}

	#[test]
	fn same_window_in_different_files_is_a_different_finding() {
		let window = "let x = unsafe { *raw };\n";
		assert_ne!(compute("scanner", "src/a.rs", window), compute("scanner", "src/b.rs", window),);
	}

	#[test]
	fn different_scanners_do_not_collide() {
		let window = "let x = unsafe { *raw };\n";
		assert_ne!(
			compute("regex-secrets", "src/x.rs", window),
			compute("llm-code-review", "src/x.rs", window),
		);
	}

	#[test]
	fn extract_window_clamps_to_file() {
		let source = "line1\nline2\nline3\nline4\nline5\n";
		// Normal extract: lines 2..=3 with 1 line context = lines 1..=4.
		assert_eq!(extract_window(source, 2, 3, 1), "line1\nline2\nline3\nline4");
		// Out-of-bounds end — clamped.
		assert_eq!(extract_window(source, 4, 99, 1), "line3\nline4\nline5");
		// Way out of bounds — empty string, not panic.
		assert_eq!(extract_window(source, 100, 200, 1), "");
		// Empty file.
		assert_eq!(extract_window("", 1, 1, 2), "");
	}

	#[test]
	fn extract_window_zero_context_is_just_the_bug_lines() {
		let source = "line1\nline2\nline3\nline4\n";
		assert_eq!(extract_window(source, 2, 3, 0), "line2\nline3");
	}

	#[test]
	fn normalize_drops_pure_whitespace_diffs() {
		assert_eq!(normalize_window("  foo  bar\n\n"), "foo bar");
		assert_eq!(normalize_window("FOO BAR"), "foo bar");
		assert_eq!(normalize_window(""), "");
		assert_eq!(normalize_window("\n\n\n"), "");
	}

	#[test]
	fn fingerprints_are_64_hex_chars() {
		let h = compute("s", "f", "w");
		assert_eq!(h.len(), 64);
		assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
	}
}
