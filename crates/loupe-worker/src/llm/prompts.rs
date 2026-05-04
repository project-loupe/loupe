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
`{file}` (located at `/workdir/{file}`) for **every** real, exploitable
vulnerability you can find. Look for: memory-safety bugs, auth /
authorization flaws, injection (SQL, command, path traversal), secret
leaks, broken cryptography, insecure deserialisation, race conditions
with security impact, integer overflows reaching length checks —
anything that lets an adversary escalate privileges or exfiltrate
data.

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
  call this tool, no finding is emitted. You can call it multiple
  times in one session — once per distinct vulnerability you've
  confirmed.
- `validate_poc(poc_unified)` — pre-flight your PoC diff: runs
  `git apply --check` against the worktree without writing anything
  and returns `{applies, error?}`. Call this before `submit_finding`;
  if `applies: false`, fix the diff and re-check. A finding whose PoC
  doesn't apply wastes everyone's time downstream.

Your workflow:

1. Read the target file end-to-end.
2. Enumerate the real, exploitable vulnerabilities you can find,
   ordered by severity (critical → high → medium → low). If you
   genuinely see nothing exploitable, you're done; return.
3. For each candidate, in order:
   a. Search prior findings (`query_prior_findings`) with keywords
      from the bug — function name, vulnerability class, CWE if
      known. If a hit clearly matches, fetch its body via
      `get_finding_by_id` to confirm; if it really is the same bug,
      **skip this candidate and move on to the next one** — do not
      stop the session, and do not call `submit_finding`. A prior
      finding suppresses *that one* report, not the whole file.
   b. Otherwise, write a unified diff adding a regression test that
      FAILS on HEAD and would pass once the bug is fixed. Use the
      repo's existing test framework (`#[test]` for Rust, `pytest`
      for Python, etc.).
   c. Call `validate_poc` to confirm the diff applies cleanly. If it
      doesn't, revise the diff and re-check.
   d. Call `submit_finding` with the full report.
4. Continue step 3 until every candidate has been either submitted
   or skipped (as a duplicate). Then return.

Constraints:

- One `submit_finding` call per distinct vulnerability — don't bundle
  multiple bugs into one report, and don't double-submit the same bug
  under different titles.
- Do not call `submit_finding` for hardening notes, style issues, or
  bugs you can't write a regression test for. Quality over volume.
- Your text response is logged but not parsed. Use it for diagnostic
  notes if useful; do not put findings there.

Scope of knowledge — read carefully:

- Your only filesystem access is the worktree mounted at `/workdir`.
  You cannot read external repositories, dependency source from
  `cargo registry`, vendored crates outside this tree, system docs,
  the internet, or anything else off-tree. If `Cargo.toml` pins a
  dependency, you have access to the *name and version* of that
  pin — not its source code.
- Do not claim to have "verified against" or "checked" any
  out-of-tree source you cannot actually open through this
  worktree. If a determination depends on an invariant the
  *caller* of this code is supposed to uphold, on a downstream
  crate's behaviour, or on a pinned dependency's internals, treat
  that as **uncertainty**, not as a clearance to dismiss the bug.
  Note the dependency in the `description` and submit the finding
  anyway, flagging the assumption — a false positive a human can
  dismiss is better than a false negative dressed as a confident
  cross-reference check.
- If you find yourself writing "I verified against …" or "this
  matches upstream's convention" about code you have no path to
  read, stop and re-frame: either the bug stands without that
  external check, or you are uncertain, in which case submit and
  flag the uncertainty.
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
	fn discovery_prompt_tells_agent_to_keep_going_after_a_dup() {
		// Failure mode this test guards: under continuous scanning, if
		// the model finds the most-serious bug, sees it's already
		// reported, and exits, we never drill down to the second-most-
		// serious bug. The prompt must explicitly say "skip this one,
		// move on to the next" — not "you're done."
		//
		// Compare against a whitespace-collapsed copy so prose reflow
		// (which moves "multiple times" across a line break, etc.)
		// doesn't break the pin.
		let collapsed: String = DISCOVERY.split_whitespace().collect::<Vec<_>>().join(" ");
		assert!(
			collapsed.contains("call it multiple times"),
			"prompt must tell the agent submit_finding accepts multiple calls per session",
		);
		assert!(
			collapsed.contains("move on to the next"),
			"prompt must tell the agent a duplicate skips that finding, not the session",
		);
	}

	#[test]
	fn verify_template_has_required_placeholders() {
		assert!(VERIFY.contains("{file}"));
		assert!(VERIFY.contains("{finding_json}"));
	}

	#[test]
	fn discovery_prompt_forbids_claimed_external_verification() {
		// Failure mode this guards against: the agent claiming it
		// "verified against the pinned LDK rev" or similar, when the
		// bwrap sandbox grants it no path to that source — and then
		// using that confabulated check to dismiss real findings as
		// safe. The prompt must explicitly tell the agent its
		// filesystem access is /workdir-only and that absent
		// cross-references mean *uncertainty*, not clearance.
		//
		// Compare against a whitespace-collapsed copy so prose reflow
		// (which moves phrases across line breaks) doesn't break the
		// pin.
		let collapsed: String = DISCOVERY.split_whitespace().collect::<Vec<_>>().join(" ");
		assert!(
			collapsed.contains("filesystem access is the worktree"),
			"prompt must declare /workdir-only filesystem scope",
		);
		assert!(
			collapsed.contains("Do not claim to have")
				|| collapsed.contains("do not claim to have"),
			"prompt must forbid agent from claiming out-of-tree verification",
		);
		assert!(
			collapsed.contains("uncertainty"),
			"prompt must tell the agent that absent cross-refs map to uncertainty, not clearance",
		);
	}
}
