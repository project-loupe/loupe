//! New-API tests. The old public API remains covered by source_migration_baseline.
#![cfg(feature = "source-migration")]

use loupe_core::source_migration::text::{
	Anchor, BoundedJson, BoundedText, Identifier, RepoPath, SourceRef,
};
use loupe_core::source_migration::{
	Finding, RepoSpec, ReportingDestination, Verdict, VerdictPatch,
};
use loupe_core::text::policy::*;
use loupe_core::text::{AnchorPolicy, Error, IdentPolicy, JsonPolicy, Rule, TextPolicy};
use loupe_core::Severity;
use loupe_provenance::{
	Agent, Config, Db, Ingress, Mark, Repo, Source, Untrusted, Unvalidated, Validate,
};

struct Fixture<F>(F);
impl<S: Source, F, R> Validate<&str, S> for Fixture<F>
where
	F: for<'a> FnOnce(&'a str, &Mark<'a, S>) -> R,
{
	type Output = R;
	type Error = std::convert::Infallible;
	fn validate<'a>(self, u: Unvalidated<'a, &str>, mark: Mark<'a, S>) -> Result<R, Self::Error> {
		Ok((self.0)(u.get(), &mark))
	}
}

#[allow(unsafe_code)]
fn fixture<S: Source, R>(raw: &str, f: impl for<'a> FnOnce(&'a str, &Mark<'a, S>) -> R) -> R {
	// SAFETY: this integration fixture mints a source for input the test made up.
	let ingress = unsafe { Ingress::<S>::new() };
	Untrusted::new(raw, ingress).validate(Fixture(f)).unwrap()
}

fn text<P: TextPolicy>(raw: &str) -> Result<BoundedText<P, Agent>, Error> {
	fixture(raw, |raw, mark| BoundedText::new(mark, raw))
}

fn same<T: Clone + Eq>(value: &T) {
	assert!(*value == value.clone());
}

// These generic bodies, not just calls with current markers, pin the absence
// of accidental S/P Clone, Eq, Debug or Serialize bounds.
fn wrapper_traits<S: Source, P: TextPolicy, I: IdentPolicy, A: AnchorPolicy, J: JsonPolicy>(
	t: &BoundedText<P, S>, i: &Identifier<I, S>, a: &Anchor<A, S>, j: &BoundedJson<J, S>,
	p: &RepoPath<S>,
) {
	same(t);
	same(i);
	same(a);
	same(j);
	same(p);
	for value in [
		serde_json::to_string(t),
		serde_json::to_string(i),
		serde_json::to_string(a),
		serde_json::to_string(j),
		serde_json::to_string(p),
	] {
		assert!(value.is_ok());
	}
	assert!(format!("{t:?} {i:?} {a:?} {j:?} {p:?}").contains(S::NAME));
}

fn finding<S: Source>(mark: &Mark<'_, S>, raw: &str) -> Finding<S> {
	Finding {
		scanner_id: BoundedText::new(mark, "regex-secrets").unwrap(),
		severity: Severity::High,
		title: BoundedText::new(mark, "  cafe\u{301} title  ").unwrap(),
		description: BoundedText::new(mark, raw).unwrap(),
		file_path: Some(RepoPath::new(mark, "src/cafe\u{301}.rs").unwrap()),
		line_start: Some(1),
		line_end: Some(2),
		cwe: Some(BoundedText::new(mark, "").unwrap()),
		patch_unified: Some(BoundedText::new(mark, raw).unwrap()),
		poc_unified: Some(BoundedText::new(mark, "").unwrap()),
		fingerprint: BoundedText::new(mark, "legacy-fingerprint").unwrap(),
	}
}

fn container_traits<S: Source>(mark: &Mark<'_, S>, raw: &str) {
	let f = finding(mark, raw);
	same(&f);
	let reference = SourceRef { path: RepoPath::new(mark, "x").unwrap(), symbol: None };
	same(&reference);
	let patch = VerdictPatch {
		patch_unified: BoundedText::new(mark, raw).unwrap(),
		notes: BoundedText::new(mark, "").unwrap(),
	};
	same(&patch);
	let verdict = Verdict::Confirmed { notes: None, patch: Some(patch) };
	same(&verdict);
	let repo = RepoSpec {
		host: BoundedText::new(mark, "example.invalid").unwrap(),
		owner: BoundedText::new(mark, "owner").unwrap(),
		repo: BoundedText::new(mark, "repo").unwrap(),
		clone_url: BoundedText::new(mark, "https://example.invalid/a%40b/c=d.git").unwrap(),
		branch: Some(BoundedText::new(mark, "topic/cafe\u{301}").unwrap()),
	};
	same(&repo);
	let reporting = ReportingDestination::Email {
		to: vec![BoundedText::new(mark, "a@example.invalid").unwrap()],
		from: None,
		subject_prefix: None,
	};
	same(&reporting);
	assert!(serde_json::to_string(&f).is_ok());
	assert!(serde_json::to_string(&reference).is_ok());
	assert!(serde_json::to_string(&verdict).is_ok());
	assert!(serde_json::to_string(&repo).is_ok());
	assert!(serde_json::to_string(&reporting).is_ok());
	for diagnostic in [
		format!("{f:?}"),
		format!("{reference:?}"),
		format!("{verdict:?}"),
		format!("{repo:?}"),
		format!("{reporting:?}"),
	] {
		assert!(diagnostic.contains(S::NAME));
		assert!(diagnostic.contains("[redacted]"));
		assert!(!diagnostic.contains(raw));
	}
}

#[test]
fn source_and_policy_parameters_add_no_incidental_trait_bounds() {
	fixture::<Repo, _>("private-canary", |raw, mark| {
		wrapper_traits(
			&BoundedText::<Title, _>::new(mark, raw).unwrap(),
			&Identifier::<Family, _>::new(mark, "auth-bypass").unwrap(),
			&Anchor::<AnchorText, _>::new(mark, "Token Refresh").unwrap(),
			&BoundedJson::<Payload, _>::new(mark, r#"{"a":1}"#).unwrap(),
			&RepoPath::new(mark, "src/a.rs").unwrap(),
		);
		container_traits(mark, raw);
	});
	fixture::<Agent, _>("agent-canary", |raw, mark| container_traits(mark, raw));
	fixture::<Db, _>("db-canary", |raw, mark| container_traits(mark, raw));
	fixture::<Config, _>("config-canary", |raw, mark| container_traits(mark, raw));
}

#[test]
fn owned_output_outlives_the_validation_mark_and_debug_is_exact() {
	let owned = {
		let raw = String::from("private-canary");
		text::<FindingDescription>(&raw).unwrap()
	};
	assert_eq!(owned.expose(), "private-canary");
	assert_eq!(format!("{owned:?}"), "BoundedText<finding_description, agent>([redacted])");
	let cloned = owned.clone();
	drop(owned);
	assert_eq!(cloned.expose(), "private-canary");
}

#[test]
fn same_source_equality_compares_payloads_and_variant_state() {
	fixture::<Agent, _>("", |_, mark| {
		assert_ne!(
			BoundedText::<FindingTitle, _>::new(mark, "café").unwrap(),
			BoundedText::<FindingTitle, _>::new(mark, "cafe\u{301}").unwrap()
		);
		assert_eq!(
			BoundedText::<Title, _>::new(mark, "café").unwrap(),
			BoundedText::<Title, _>::new(mark, "cafe\u{301}").unwrap()
		);
		assert_ne!(
			RepoPath::new(mark, "café.rs").unwrap(),
			RepoPath::new(mark, "cafe\u{301}.rs").unwrap()
		);
		assert_ne!(
			BoundedJson::<Payload, _>::new(mark, "[1,2]").unwrap(),
			BoundedJson::<Payload, _>::new(mark, "[2,1]").unwrap()
		);
		let first = finding(mark, "first");
		let second = finding(mark, "second");
		assert_ne!(first, second);
		let mut changed = first.clone();
		changed.line_end = Some(3);
		assert_ne!(first, changed);
		let reason = BoundedText::new(mark, "reason").unwrap();
		assert_ne!(
			Verdict::Inconclusive { reason: reason.clone(), terminal: false },
			Verdict::Inconclusive { reason, terminal: true }
		);
		assert_ne!(
			Verdict::<Agent>::Confirmed { notes: None, patch: None },
			Verdict::<Agent>::Dismissed { notes: None }
		);
		assert_ne!(
			ReportingDestination::<Agent>::Manual,
			ReportingDestination::<Agent>::Email {
				to: Vec::new(),
				from: None,
				subject_prefix: None
			}
		);
	});
}

#[test]
fn each_exact_policy_preserves_its_admitted_bytes() {
	fn exact<P: TextPolicy>(raw: &str) {
		assert_eq!(P::MAX_BYTES, 2 * 1024 * 1024);
		assert_eq!(P::MAX_CHARS, 2 * 1024 * 1024);
		assert_eq!(text::<P>(raw).unwrap().expose().as_bytes(), raw.as_bytes());
		assert_eq!(text::<P>("").unwrap().expose(), "");
	}
	let quoted = "  cafe\u{301}\r\n\tcode  \r\n\r\n\r\n";
	exact::<FindingDescription>(quoted);
	exact::<PocUnified>(quoted);
	exact::<PatchUnified>(quoted);
	exact::<VerdictNotes>(quoted);
	exact::<VerdictReason>(quoted);
	exact::<PatchNotes>(quoted);
	let single = " cafe\u{301} %2F  ";
	exact::<FindingTitle>(single);
	exact::<ScannerIdText>(single);
	exact::<CweText>(single);
	exact::<FindingFingerprintText>(single);
	exact::<RepoHost>(single);
	exact::<RepoOwner>(single);
	exact::<RepoName>(single);
	exact::<CloneUrl>(single);
	exact::<GitBranch>(single);
	exact::<MailAddress>(single);
	exact::<MailSubjectPrefix>(single);
}

#[test]
fn exact_control_admission_rejects_without_rewriting() {
	for ch in [
		'\0', '\u{1b}', '\u{7f}', '\u{202e}', '\u{200d}', '\u{e000}', '\u{0378}', '\u{2028}',
		'\u{2029}', '\u{fdd0}',
	] {
		let raw = format!("private{ch}canary");
		for error in
			[text::<PatchUnified>(&raw).unwrap_err(), text::<FindingTitle>(&raw).unwrap_err()]
		{
			assert_eq!(error.rule, Rule::Character);
			assert!(!format!("{error:?}").contains("private"));
		}
	}
	for raw in ["a\nb", "a\tb", "a\rb"] {
		assert_eq!(text::<PatchUnified>(raw).unwrap().expose(), raw);
		assert_eq!(text::<FindingTitle>(raw).unwrap_err().rule, Rule::Character);
	}
}

#[test]
fn new_legacy_caps_are_exact_and_not_the_llm_poc_route_cap() {
	let cap = 2 * 1024 * 1024;
	for raw in ["x".repeat(cap), "é".repeat(cap / 2)] {
		assert_eq!(text::<PatchUnified>(&raw).unwrap().expose(), raw);
		assert_eq!(text::<FindingTitle>(&raw).unwrap().expose(), raw);
		assert!(text::<PatchUnified>(&format!("{raw}x")).is_err());
		assert!(text::<FindingTitle>(&format!("{raw}x")).is_err());
	}
	assert!(text::<PocUnified>(&"x".repeat(256 * 1024 + 1)).is_ok());
	// The strict LLM route still owns its smaller cap; D does not change it.
}

#[test]
fn staged_semantic_json_anchor_and_path_contracts_match_legacy() {
	fixture::<Agent, _>("", |_, mark| {
		for raw in ["cafe\u{301}\r\nnext", "", " x", "x ", "a\n\n\nb", "x\0y"] {
			assert_eq!(
				BoundedText::<Objective, _>::new(mark, raw).map(|v| v.expose().to_owned()),
				loupe_core::text::BoundedText::<Objective>::new(raw).map(|v| v.expose().to_owned())
			);
		}
		for raw in ["  CAFE\u{301}   handler  ", "job_9", "file.rs:9", "a\tb"] {
			assert_eq!(
				Anchor::<AnchorText, _>::new(mark, raw).map(|v| v.expose().to_owned()),
				loupe_core::text::Anchor::<AnchorText>::new(raw).map(|v| v.expose().to_owned())
			);
		}
		for raw in [r#"{"z":"cafe\u0301","a":1}"#, r#"{"a":1,"a":2}"#, r#"{"a":" trailing "}"#] {
			assert_eq!(
				BoundedJson::<Payload, _>::new(mark, raw)
					.map(|v| (v.expose().to_owned(), *v.digest())),
				loupe_core::text::BoundedJson::<Payload>::new(raw)
					.map(|v| (v.expose().to_owned(), *v.digest()))
			);
		}
		for raw in [
			"café.rs",
			"cafe\u{301}.rs",
			"dir/%2e%2e.rs",
			"",
			"a/../b",
			"a//b",
			"a\\b",
			&"x".repeat(513),
		] {
			assert_eq!(
				RepoPath::new(mark, raw).map(|v| v.expose().to_owned()),
				loupe_core::text::RepoPath::new(raw).map(|v| v.expose().to_owned())
			);
		}
		let reference = SourceRef {
			path: RepoPath::new(mark, "cafe\u{301}.rs").unwrap(),
			symbol: Some(BoundedText::new(mark, "cafe\u{301}").unwrap()),
		};
		assert_eq!(
			serde_json::to_value(reference).unwrap(),
			serde_json::json!({"path":"cafe\u{301}.rs","symbol":"café"})
		);
	});
}

#[test]
fn serialized_findings_and_all_verdict_variants_keep_the_legacy_wire_schema() {
	fixture::<Agent, _>("quote\r\n\t cafe\u{301} \n", |raw, mark| {
		let f = finding(mark, raw);
		let json = serde_json::to_value(&f).unwrap();
		let old: loupe_core::Finding = serde_json::from_value(json.clone()).unwrap();
		assert_eq!(old.title, f.title.expose());
		assert_eq!(old.description, raw);
		assert_eq!(old.patch_unified.as_deref(), Some(raw));
		assert_eq!(old.poc_unified.as_deref(), Some(""));
		assert_eq!(serde_json::to_value(old).unwrap(), json);
		for (verdict, expected) in [
			(
				Verdict::Confirmed { notes: None, patch: None },
				serde_json::json!({"outcome":"confirmed"}),
			),
			(
				Verdict::Confirmed {
					notes: Some(BoundedText::new(mark, "").unwrap()),
					patch: Some(VerdictPatch {
						patch_unified: BoundedText::new(mark, raw).unwrap(),
						notes: BoundedText::new(mark, raw).unwrap(),
					}),
				},
				serde_json::json!({"outcome":"confirmed","notes":"","patch":{"patch_unified":raw,"notes":raw}}),
			),
			(
				Verdict::Dismissed { notes: Some(BoundedText::new(mark, raw).unwrap()) },
				serde_json::json!({"outcome":"dismissed","notes":raw}),
			),
			(
				Verdict::Inconclusive {
					reason: BoundedText::new(mark, "").unwrap(),
					terminal: false,
				},
				serde_json::json!({"outcome":"inconclusive","reason":""}),
			),
			(
				Verdict::Inconclusive {
					reason: BoundedText::new(mark, raw).unwrap(),
					terminal: true,
				},
				serde_json::json!({"outcome":"inconclusive","reason":raw,"terminal":true}),
			),
		] {
			let value = serde_json::to_value(&verdict).unwrap();
			assert_eq!(value, expected);
			let old: loupe_core::Verdict = serde_json::from_value(value.clone()).unwrap();
			assert_eq!(serde_json::to_value(old).unwrap(), value);
			same(&verdict);
		}
	});
}

#[test]
fn repository_and_reporting_configuration_keep_the_exact_wire_schema() {
	fixture::<Config, _>("", |_, mark| {
		let repo = RepoSpec {
			host: BoundedText::new(mark, "example.invalid").unwrap(),
			owner: BoundedText::new(mark, "owner").unwrap(),
			repo: BoundedText::new(mark, "repo").unwrap(),
			clone_url: BoundedText::new(mark, "https://example.invalid/a%40b/c=d.git").unwrap(),
			branch: None,
		};
		assert_eq!(
			serde_json::to_value(&repo).unwrap(),
			serde_json::json!({"host":"example.invalid","owner":"owner","repo":"repo","clone_url":"https://example.invalid/a%40b/c=d.git"})
		);
		for (destination, expected) in [
			(
				ReportingDestination::GithubIssue {
					target_owner: BoundedText::new(mark, "acme").unwrap(),
					target_repo: BoundedText::new(mark, "repo").unwrap(),
					pat_secret_id: None,
				},
				serde_json::json!({"kind":"github_issue","target_owner":"acme","target_repo":"repo"}),
			),
			(
				ReportingDestination::GithubIssue {
					target_owner: BoundedText::new(mark, "acme").unwrap(),
					target_repo: BoundedText::new(mark, "repo").unwrap(),
					pat_secret_id: Some(7),
				},
				serde_json::json!({"kind":"github_issue","target_owner":"acme","target_repo":"repo","pat_secret_id":7}),
			),
			(
				ReportingDestination::Email {
					to: vec![BoundedText::new(mark, "a@example.invalid").unwrap()],
					from: Some(BoundedText::new(mark, "b@example.invalid").unwrap()),
					subject_prefix: Some(BoundedText::new(mark, "").unwrap()),
				},
				serde_json::json!({"kind":"email","to":["a@example.invalid"],"from":"b@example.invalid","subject_prefix":""}),
			),
			(ReportingDestination::Manual, serde_json::json!({"kind":"manual"})),
		] {
			assert_eq!(serde_json::to_value(&destination).unwrap(), expected);
			same(&destination);
			let old: loupe_core::ReportingDestination =
				serde_json::from_value(expected.clone()).unwrap();
			assert_eq!(serde_json::to_value(old).unwrap(), expected);
		}
	});
}

#[test]
fn exact_diff_bytes_still_apply_with_unicode_crlf_and_no_final_newline() {
	use std::io::Write;
	use std::process::{Command, Stdio};

	use unicode_normalization::UnicodeNormalization;
	let dir = tempfile::tempdir().unwrap();
	let git = |args: &[&str], input: &[u8]| {
		let mut command = Command::new("/usr/bin/git");
		command
			.env_clear()
			.env("PATH", "/usr/bin:/bin")
			.env("HOME", dir.path())
			.env("GIT_CONFIG_NOSYSTEM", "1")
			.env("GIT_CONFIG_GLOBAL", "/dev/null")
			.current_dir(dir.path())
			.args(["-c", "core.autocrlf=false"])
			.args(args)
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::piped());
		let mut child = command.spawn().unwrap();
		child.stdin.take().unwrap().write_all(input).unwrap();
		child.wait_with_output().unwrap()
	};
	assert!(git(&["init", "--quiet"], b"").status.success());
	std::fs::write(dir.path().join("cafe\u{301}.rs"), "let cafe\u{301} = 1;\r\n\told  \r\n\r\n")
		.unwrap();
	let patch = "--- a/cafe\u{301}.rs\n+++ b/cafe\u{301}.rs\n@@ -1,3 +1,3 @@\n let cafe\u{301} = 1;\r\n-\told  \r\n+\tnew  \r\n \r\n";
	let checked = text::<PatchUnified>(patch).unwrap();
	assert_eq!(checked.expose().as_bytes(), patch.as_bytes());
	assert!(git(&["apply", "--check", "--whitespace=nowarn", "-"], checked.expose().as_bytes())
		.status
		.success());
	assert!(!git(&["apply", "--check", "-"], patch.nfc().collect::<String>().as_bytes())
		.status
		.success());
	assert!(!git(&["apply", "--check", "-"], patch.replace("\r\n", "\n").as_bytes())
		.status
		.success());
	assert!(git(&["apply", "--whitespace=nowarn", "-"], checked.expose().as_bytes())
		.status
		.success());
	assert_eq!(
		std::fs::read(dir.path().join("cafe\u{301}.rs")).unwrap(),
		"let cafe\u{301} = 1;\r\n\tnew  \r\n\r\n".as_bytes()
	);
	std::fs::write(dir.path().join("no-lf"), b"old").unwrap();
	let no_lf = "--- a/no-lf\n+++ b/no-lf\n@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n";
	let checked = text::<PocUnified>(no_lf).unwrap();
	assert_eq!(checked.expose(), no_lf);
	assert!(git(&["apply", "-"], checked.expose().as_bytes()).status.success());
	assert_eq!(std::fs::read(dir.path().join("no-lf")).unwrap(), b"new");
}
