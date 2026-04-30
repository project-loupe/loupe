//! Discovery and validation prompts for the LLM code-review scanner.
//!
//! Both prompts ask for **structured JSON** as the only output format.
//! The scanner's parser tolerates a JSON object embedded in surrounding
//! prose (the model often emits "Here's the result: { … }" before its
//! actual answer), but on parse failure the file's report is dropped
//! and a warning is logged. We do not attempt to extract findings from
//! free-form text.

/// Discovery prompt — runs once per source file.
///
/// `{file}` is replaced with the worktree-relative path of the file the
/// model should focus on. The file lives at `/workdir/{file}` inside
/// the sandbox (worktree is bind-mounted read-only at `/workdir`).
pub const DISCOVERY: &str = r##"
You are a security code reviewer playing in a CTF. Inspect the file
`{file}` (located at `/workdir/{file}`) for the single most serious
exploitable vulnerability you can find. Look for: memory-safety bugs,
auth/authorization flaws, injection (SQL, command, path traversal),
secret leaks, broken cryptography, insecure deserialisation, race
conditions with security impact, integer overflows reaching length
checks, anything that lets an adversary escalate privileges or
exfiltrate data.

Output **exactly one JSON object** and nothing else. No prose, no
markdown fences, no follow-up. The object must have these fields:

```
{
  "found": true | false,
  "severity": "info" | "low" | "medium" | "high" | "critical",
  "title": "<short title>",
  "file": "<the path you were given, verbatim>",
  "line_start": <1-based int>,
  "line_end": <1-based int>,
  "description": "<200 words max, mechanism + impact + reproduction sketch>",
  "cwe": "<optional CWE-NNN string>"
}
```

If you found nothing serious, return `{"found": false}`.

Before deciding `found: true`, you may use the `query_prior_findings`
MCP tool (when available) to check whether the same vulnerability has
already been reported on this repo in a previous scan. Search with
keywords from the bug — function name, vulnerability class, CWE if
known. If a prior finding clearly describes the same issue, the most
useful thing is usually to NOT re-emit it: return `{"found": false}`
so the run doesn't re-confirm a known bug. Only re-emit if you see
something materially different about the current state of the code
(e.g. the original was dismissed and the bug returned, or the
location moved). The tool is optional — if it's not available or
returns nothing, proceed with your usual judgment.
"##;

/// Validation prompt — runs once per discovered finding.
///
/// `{finding_json}` is replaced with the JSON object emitted by the
/// discovery pass. `{file}` is the worktree-relative path. The model
/// should re-read the file at `/workdir/{file}` (it can use whatever
/// tools the backend provides — `claude` reads files itself).
pub const VALIDATE: &str = r##"
You are validating a vulnerability report for a CTF. Re-read the file
`{file}` (located at `/workdir/{file}`) and decide whether the
following finding is real and exploitable, or whether it's a
false-positive.

Reported finding:
{finding_json}

If you confirm the finding, write a unified diff that adds a
**regression test** demonstrating the bug. The test must FAIL on the
current HEAD and would pass once the bug is fixed. Use any standard
test framework already present in the repo (`#[test]` for Rust,
`pytest` for Python, etc.). The diff must be applicable with
`git apply` against the worktree as it stands.

Output **exactly one JSON object** and nothing else:

```
{
  "verdict": "confirmed" | "rejected" | "inconclusive",
  "notes": "<one sentence on why>",
  "poc_unified": "<unified diff text, or null if not confirmed>"
}
```

When `verdict = "confirmed"`, `poc_unified` MUST be a non-empty unified
diff. When the verdict is anything else, `poc_unified` MUST be null.
"##;

/// Cross-model verification prompt — runs once per finding when the
/// server has enqueued a `kind=verify` job. Independent second
/// opinion: takes the original finding (rendered as JSON) and asks
/// the model whether it agrees with the diagnosis. No PoC requested
/// — the original validator already produced one (see `VALIDATE`).
///
/// `{file}` and `{finding_json}` placeholders match the validation
/// prompt's. We keep the phrase "validating a vulnerability report"
/// out of this template so a stub backend keying on prompt content
/// can tell the verify and validate paths apart.
pub const VERIFY: &str = r##"
You are providing an independent second opinion on a vulnerability
report from another security reviewer. Re-read the file `{file}`
(located at `/workdir/{file}`) and decide whether the report is real
and exploitable, or whether it's a false-positive.

Original report:
{finding_json}

Output **exactly one JSON object** and nothing else:

```
{
  "verdict": "confirmed" | "dismissed" | "inconclusive",
  "notes": "<one sentence on why>"
}
```

Use `"inconclusive"` only when the file's behaviour genuinely
depends on context outside the file itself (e.g. a downstream
caller's invariants). Prefer a definite verdict when you can.
"##;

/// Substitute `{key}` placeholders in a template. Simple sentinel-
/// based replacement — no escaping, no nested templates. Used for the
/// two prompts above.
pub fn render(template: &str, vars: &[(&str, &str)]) -> String {
	let mut out = template.to_owned();
	for (k, v) in vars {
		let needle = format!("{{{k}}}");
		out = out.replace(&needle, v);
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn render_substitutes_known_keys() {
		let s = render("hello {name}, file is {file}", &[("name", "world"), ("file", "x.rs")]);
		assert_eq!(s, "hello world, file is x.rs");
	}

	#[test]
	fn render_leaves_unknown_keys_alone() {
		// Unknown keys should NOT be silently dropped — leaving them
		// present makes a templating bug obvious in tests/logs.
		let s = render("a {known} b {unknown}", &[("known", "X")]);
		assert_eq!(s, "a X b {unknown}");
	}

	#[test]
	fn discovery_template_has_file_placeholder() {
		assert!(DISCOVERY.contains("{file}"), "discovery prompt must mention the file");
	}

	#[test]
	fn validate_template_has_required_placeholders() {
		assert!(VALIDATE.contains("{file}"));
		assert!(VALIDATE.contains("{finding_json}"));
	}

	#[test]
	fn verify_template_distinct_from_validate() {
		// A stub backend that keys on prompt content must be able to
		// tell a VERIFY call apart from a VALIDATE call. We rely on
		// the "validating a vulnerability report" phrase appearing in
		// VALIDATE only.
		assert!(VALIDATE.contains("validating a vulnerability report"));
		assert!(!VERIFY.contains("validating a vulnerability report"));
	}
}
