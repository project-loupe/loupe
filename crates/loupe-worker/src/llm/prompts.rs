//! Prompts for the LLM code-review scanner.
//!
//! A single agent session does discovery, dedup-check, PoC generation,
//! and submission. The model uses MCP tools — `query_prior_findings`,
//! `get_finding_by_id`, `submit_finding` — to drive that loop. The
//! worker doesn't parse findings out of the model's text response;
//! emission only happens via `submit_finding`.

/// Discovery prompt — runs once per source file.
///
/// `{file}` is replaced with the worktree-relative path of the file
/// the agent should focus on. The file lives at `/workdir/{file}`
/// inside the sandbox (worktree is bind-mounted read-only at
/// `/workdir`).
pub const DISCOVERY: &str = r##"
You are a security code reviewer playing in a CTF. Inspect the file
`{file}` (located at `/workdir/{file}`) for the single most serious
exploitable vulnerability you can find. Look for: memory-safety bugs,
auth/authorization flaws, injection (SQL, command, path traversal),
secret leaks, broken cryptography, insecure deserialisation, race
conditions with security impact, integer overflows reaching length
checks — anything that lets an adversary escalate privileges or
exfiltrate data.

You have these MCP tools available (provided by the loupe MCP server):

- `query_prior_findings(query, limit?)` — keyword-search prior findings
  on this same repo. Use it before reporting anything to check whether
  the bug you're seeing has already been surfaced. The repo may have
  been scanned many times; a duplicate report is wasted spend.
- `get_finding_by_id(id)` — fetch a prior finding's full body
  (description + PoC) when a search hit looks like it might match
  what you're investigating.
- `submit_finding(severity, title, file, line_start, line_end,
  description, poc_unified, cwe?)` — the **only** way to report a
  finding. The worker does not parse your text response. If you don't
  call this tool, no finding is emitted.
- `validate_poc(poc_unified)` — pre-flight your PoC diff: runs
  `git apply --check` against the worktree without writing anything
  and returns `{applies, error?}`. Call this before `submit_finding`;
  if `applies: false`, fix the diff and re-check. A finding whose PoC
  doesn't apply wastes everyone's time downstream.

Your workflow:

1. Read the target file.
2. Identify the single most serious exploitable vulnerability, or
   conclude that the file is clean.
3. If you found something: search prior findings with relevant
   keywords. If a hit clearly matches the bug you'd report, do NOT
   submit — return without calling `submit_finding`.
4. Otherwise: write a unified diff that adds a regression test
   demonstrating the bug. The test must FAIL on the current HEAD and
   would pass once the bug is fixed. Use the repo's existing test
   framework (`#[test]` for Rust, `pytest` for Python, etc.). The diff
   must be applicable with `git apply` against the worktree as it
   stands.
5. Call `validate_poc` to check that your diff applies cleanly. If it
   doesn't, revise the diff and re-check.
6. Call `submit_finding` once with the full report (severity, title,
   location, description, your PoC diff, CWE if known).

Constraints:

- One vulnerability per file at most. Pick the most serious; don't
  spray.
- Do not call `submit_finding` for hardening notes, style issues, or
  bugs you can't write a regression test for.
- Your text response is logged but not parsed. Use it for diagnostic
  notes if useful; do not put findings there.
"##;

/// Cross-model verification prompt — runs once per finding when the
/// server has enqueued a `kind=verify` job. Independent second
/// opinion: takes the original finding (rendered as JSON) and asks
/// the model whether it agrees with the diagnosis. No PoC requested
/// — the original session already produced one.
///
/// `{file}` and `{finding_json}` placeholders are filled by the
/// verifier scanner. The verifier still parses JSON out of the
/// model's stdout because the verify path doesn't yet have an MCP
/// surface — that wiring is independent of the discovery flow and
/// can move to a tool-based shape later.
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
/// prompts above.
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
	fn discovery_prompt_directs_agent_to_the_submit_tool() {
		// The single most important contract of the new flow: the
		// model knows submission goes through `submit_finding`, not
		// stdout.
		assert!(
			DISCOVERY.contains("submit_finding"),
			"discovery prompt must reference the submit_finding tool",
		);
	}

	#[test]
	fn verify_template_has_required_placeholders() {
		assert!(VERIFY.contains("{file}"));
		assert!(VERIFY.contains("{finding_json}"));
	}
}
