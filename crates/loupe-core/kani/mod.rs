//! Bounded proofs of domain decisions. Run through `ci/kani.sh`.

use crate::{initial_job_state, JobState, JobTransition};

// Bound: all nine transition variants; no input is omitted.
// ci: fast
#[kani::proof]
fn initial_job_state_requires_enqueue() {
	let choice: u8 = kani::any();
	kani::assume(choice < 9);
	let transition = match choice {
		0 => JobTransition::Enqueue,
		1 => JobTransition::Lease,
		2 => JobTransition::Heartbeat,
		3 => JobTransition::CompleteSucceeded,
		4 => JobTransition::CompleteFailed,
		5 => JobTransition::Cancel,
		6 => JobTransition::Retry,
		7 => JobTransition::ReapToQueued,
		_ => JobTransition::ReapToFailed,
	};
	let result = initial_job_state(transition);
	if choice == 0 {
		assert!(matches!(result, Ok(JobState::Queued)));
	} else {
		assert!(result.is_err());
	}
	kani::cover!(result.is_ok(), "initial enqueue is reachable");
	kani::cover!(result.is_err(), "noninitial transitions are rejected");
}

fn job_transition() -> crate::JobTransition {
	let choice: u8 = kani::any();
	kani::assume(choice < 9);
	match choice {
		0 => JobTransition::Enqueue,
		1 => JobTransition::Lease,
		2 => JobTransition::Heartbeat,
		3 => JobTransition::CompleteSucceeded,
		4 => JobTransition::CompleteFailed,
		5 => JobTransition::Cancel,
		6 => JobTransition::Retry,
		7 => JobTransition::ReapToQueued,
		_ => JobTransition::ReapToFailed,
	}
}

fn finding_state() -> crate::FindingState {
	use crate::FindingState::*;
	let choice: u8 = kani::any();
	kani::assume(choice < 6);
	match choice {
		0 => Pending,
		1 => Validating,
		2 => AwaitingApproval,
		3 => Confirmed,
		4 => Dismissed,
		_ => Reported,
	}
}

// Bound: All three terminal job states and all nine transitions;
// no is_terminal oracle, because Failed deliberately permits recovery.
// ci: fast
#[kani::proof]
fn terminal_job_states_exit_only_by_operator_recovery() {
	let choice: u8 = kani::any();
	kani::assume(choice < 3);
	let state = match choice {
		0 => JobState::Succeeded,
		1 => JobState::Cancelled,
		_ => JobState::Failed,
	};
	let original = state;
	let transition = job_transition();
	let result = state.apply(transition);
	if choice == 2 && transition == JobTransition::Retry {
		assert!(matches!(result, Ok(JobState::Queued)));
	} else {
		assert!(result.is_err());
	}
	assert_eq!(state, original);
	kani::cover!(choice == 0 && result.is_err(), "succeeded is sealed");
	kani::cover!(choice == 1 && result.is_err(), "cancelled is sealed");
	kani::cover!(choice == 2 && result.is_ok(), "failed can recover");
	kani::cover!(choice == 2 && result.is_err(), "failed rejects other transitions");
}

// Bound: Both terminal finding states and all twelve transitions.
// ci: fast
#[kani::proof]
fn terminal_finding_states_exit_only_by_operator_recovery() {
	use crate::{FindingState, FindingTransition};
	let dismissed: bool = kani::any();
	let state = if dismissed { FindingState::Dismissed } else { FindingState::Reported };
	let original = state;
	let choice: u8 = kani::any();
	kani::assume(choice < 12);
	let transition = match choice {
		0 => FindingTransition::ScanAccepted,
		1 => FindingTransition::ScanAutoConfirm,
		2 => FindingTransition::ScanAwaitApproval,
		3 => FindingTransition::ScanRequireVerification,
		4 => FindingTransition::VerdictConfirm,
		5 => FindingTransition::VerdictAwaitApproval,
		6 => FindingTransition::VerdictDismiss,
		7 => FindingTransition::DeadlineExpire,
		8 => FindingTransition::Approve,
		9 => FindingTransition::Reject,
		10 => FindingTransition::RetryVerification,
		_ => FindingTransition::MarkReported,
	};
	let result = state.apply(transition);
	if dismissed && choice == 10 {
		assert!(matches!(result, Ok(FindingState::Validating)));
	} else {
		assert!(result.is_err());
	}
	assert_eq!(state, original);
	kani::cover!(!dismissed && result.is_err(), "reported is sealed");
	kani::cover!(dismissed && result.is_ok(), "dismissed can recover");
	kani::cover!(dismissed && result.is_err(), "dismissed rejects other transitions");
}

// Bound: Six finding states times every combination of four booleans.
// The table is the specification, independent of transition implementation.
// ci: fast
#[kani::proof]
fn verdict_rollup_matches_the_precedence_table() {
	use crate::{roll_up_verdicts, FindingState, VerdictRollup};
	let state = finding_state();
	let rollup = VerdictRollup {
		has_confirmed: kani::any(),
		has_dismissed: kani::any(),
		terminal_inconclusive: kani::any(),
		require_approval: kani::any(),
	};
	let expected = match (
		state,
		rollup.has_dismissed,
		rollup.terminal_inconclusive,
		rollup.has_confirmed,
		rollup.require_approval,
	) {
		(FindingState::Validating, true, _, _, _) | (FindingState::Validating, _, true, _, _) => {
			Some(FindingState::Dismissed)
		},
		(FindingState::Validating, false, false, true, true) => {
			Some(FindingState::AwaitingApproval)
		},
		(FindingState::Validating, false, false, true, false) => Some(FindingState::Confirmed),
		_ => None,
	};
	let result = roll_up_verdicts(state, rollup);
	assert_eq!(result, Ok(expected));
	kani::cover!(expected == Some(FindingState::Dismissed), "dismissal precedence");
	kani::cover!(expected == Some(FindingState::AwaitingApproval), "approval required");
	kani::cover!(expected == Some(FindingState::Confirmed), "confirmation");
	kani::cover!(state == FindingState::Validating && expected.is_none(), "no verdict yet");
	kani::cover!(state != FindingState::Validating && expected.is_none(), "other states unchanged");
}

// Bound: Eight arbitrary bytes reach dot, parent, leading/trailing and
// repeated separators. Structural checks intentionally do not decode UTF-8.
#[kani::proof]
#[kani::unwind(10)]
fn repo_path_core_never_panics_and_rejects_dot_components() {
	let bytes: [u8; 8] = kani::any();
	let len: usize = kani::any();
	kani::assume(len <= bytes.len());
	let path = &bytes[..len];
	let accepted = crate::text::is_repo_path(path);
	let mut component_start = 0;
	let mut expected = len != 0;
	for index in 0..len {
		let byte = bytes[index];
		if byte == 0 || byte == b'\\' {
			expected = false;
		}
		if byte == b'/' {
			let count = index - component_start;
			if count == 0
				|| (count == 1 && bytes[component_start] == b'.')
				|| (count == 2
					&& bytes[component_start] == b'.'
					&& bytes[component_start + 1] == b'.')
			{
				expected = false;
			}
			component_start = index + 1;
		}
	}
	let count = len - component_start;
	if count == 0
		|| (count == 1 && bytes[component_start] == b'.')
		|| (count == 2 && bytes[component_start] == b'.' && bytes[component_start + 1] == b'.')
	{
		expected = false;
	}
	assert_eq!(accepted, expected);
	kani::cover!(accepted, "ordinary relative path");
	kani::cover!(path == b"a/../b" && !accepted, "parent component");
	kani::cover!(path == b"./a" && !accepted, "dot component");
	kani::cover!(path == b"a/" && !accepted, "trailing separator");
	kani::cover!(path == b"/a" && !accepted, "leading separator");
	kani::cover!(path == b"a//b" && !accepted, "empty component");
}

// Bound: All Unicode scalar values, including every forbidden category.
// The dependency's category table is used as an independent category oracle;
// noncharacters are specified separately by Unicode's code-point ranges.
#[kani::proof]
#[kani::unwind(20)]
fn code_point_filter_matches_categories() {
	use unicode_general_category::{get_general_category, GeneralCategory as G};
	let cp: u32 = kani::any();
	kani::assume(cp <= 0x10ffff && !(0xd800..=0xdfff).contains(&cp));
	let character = char::from_u32(cp).unwrap();
	let expected = matches!(
		get_general_category(character),
		G::Control
			| G::Format
			| G::Unassigned
			| G::PrivateUse
			| G::LineSeparator
			| G::ParagraphSeparator
	) || (0xfdd0..=0xfdef).contains(&cp)
		|| cp % 65536 == 65534
		|| cp % 65536 == 65535;
	let rejected = crate::text::rejects_code_point(cp);
	assert_eq!(rejected, expected);
	kani::cover!(cp == u32::from('a') && !rejected, "ASCII accepted");
	kani::cover!(cp == u32::from('é') && !rejected, "non-ASCII letter accepted");
	kani::cover!(cp == 0x1f600 && !rejected, "emoji accepted");
	kani::cover!(cp == 0 && rejected, "control rejected");
	kani::cover!(cp == 0x200d && rejected, "format rejected");
	kani::cover!(cp == 0xe000 && rejected, "private use rejected");
	kani::cover!(cp == 0xfdd0 && rejected, "noncharacter rejected");
}

struct TinyText;
impl crate::text::TextPolicy for TinyText {
	const FIELD: &'static str = "proof";
	const MAX_CHARS: usize = 1;
	const MAX_BYTES: usize = 2;
	const MULTILINE: bool = false;
}

fn normalization_must_not_run(_: &str) -> String {
	panic!("normalization entered before rejecting the oversized raw input")
}

// Bound: Lengths 9..=17 cover every over-cap input in this bounded
// buffer for a two-byte policy (raw cap eight). A panic stub detects any entry
// into normalization, even if a reordered constructor would still return Bytes.
#[kani::proof]
#[kani::unwind(19)]
#[kani::stub(crate::text::normalized, normalization_must_not_run)]
fn bounded_text_caps_raw_input_before_normalization() {
	let len: usize = kani::any();
	kani::assume((9..=17).contains(&len));
	let raw = &"aaaaaaaaaaaaaaaaa"[..len];
	let result = crate::text::checked::text::<TinyText>(raw);
	assert!(matches!(result, Err(error) if error.rule == crate::text::Rule::Bytes));
	kani::cover!(len == 9, "first byte beyond raw cap");
	kani::cover!(len == 17, "longer oversized input");
}

fn symbolic_normalized(_: &str) -> String {
	let choice: u8 = kani::any();
	kani::assume(choice < 5);
	match choice {
		0 => "a",
		1 => "é",
		2 => "😀",
		3 => "ab",
		_ => "",
	}
	.into()
}

// Bound: Five normalization outputs reach acceptance, Unicode byte
// expansion, the character cap and empty rejection. This proves the production field-check
// wiring; the arbitrary eight-byte proof below proves the shared limit core.
#[kani::proof]
#[kani::unwind(6)]
#[kani::stub(crate::text::normalized, symbolic_normalized)]
fn bounded_text_checks_normalized_output_caps() {
	let result = crate::text::checked::text::<TinyText>("a");
	if let Ok(text) = &result {
		let mut characters = 0;
		for _ in text.as_str().chars() {
			characters += 1;
		}
		assert!(characters <= 1);
		assert!(text.as_str().len() <= 2);
	}
	kani::cover!(result.as_ref().is_ok_and(|text| text.as_str() == "é"), "Unicode output accepted");
	kani::cover!(
		matches!(&result, Err(error) if error.rule == crate::text::Rule::Chars),
		"normalized character cap"
	);
	kani::cover!(
		matches!(&result, Err(error) if error.rule == crate::text::Rule::Bytes),
		"normalized byte cap"
	);
}

struct TinyIdentifier;
impl crate::text::IdentPolicy for TinyIdentifier {
	const FIELD: &'static str = "proof_identifier";
	const MAX_LEN: usize = 2;
	fn accepts(_: &str) -> bool {
		panic!("identifier predicate entered before byte cap")
	}
}

// Bound: Lengths three through nine exceed the exact two-byte cap;
// the panic predicate detects a validation callback before that cap.
#[kani::proof]
#[kani::unwind(11)]
fn identifier_checks_exact_cap_before_predicate() {
	let len: usize = kani::any();
	kani::assume((3..=9).contains(&len));
	let result = crate::text::checked::identifier::<TinyIdentifier>(&"aaaaaaaaa"[..len]);
	assert!(matches!(result, Err(error) if error.rule == crate::text::Rule::Bytes));
	kani::cover!(len == 3, "first byte beyond identifier cap");
	kani::cover!(len == 9, "larger identifier rejected");
}

// Bound: Up to eight bytes of valid UTF-8, arbitrary usize limits.
// The independent char iterator checks the byte-level production count core,
// called by both BoundedText and Anchor after their respective normalization.
#[kani::proof]
#[kani::unwind(10)]
fn normalized_text_caps_count_characters_and_bytes() {
	let bytes: [u8; 8] = kani::any();
	let len: usize = kani::any();
	kani::assume(len <= 8);
	let Ok(text) = std::str::from_utf8(&bytes[..len]) else {
		kani::assume(false);
		return;
	};
	let max_chars: usize = kani::any();
	let max_bytes: usize = kani::any();
	let result = crate::text::count_within(text.as_bytes(), max_chars, max_bytes);
	let mut characters = 0;
	for _ in text.chars() {
		characters += 1;
	}
	assert_eq!(result.is_ok(), characters <= max_chars && text.len() <= max_bytes);
	if characters > max_chars {
		assert_eq!(result, Err(crate::text::Rule::Chars));
	} else if text.len() > max_bytes {
		assert_eq!(result, Err(crate::text::Rule::Bytes));
	}
	kani::cover!(
		text == "é" && max_chars == 1 && max_bytes == 2 && result.is_ok(),
		"characters differ from bytes"
	);
	kani::cover!(result == Err(crate::text::Rule::Chars), "character cap rejects");
	kani::cover!(result == Err(crate::text::Rule::Bytes), "byte cap rejects");
}

// Bound: Full usize aggregate character count. The production caller
// sums description/PoC/patch .chars().count(); fuzz exercises those strings.
// ci: fast
#[kani::proof]
fn validate_report_content_matches_the_github_cap() {
	let characters: usize = kani::any();
	let accepted = crate::report_limits::report_content_within_cap(characters);
	assert_eq!(accepted, characters <= 60_000);
	assert!(
		crate::report_limits::REPORT_CONTENT_MAX_CHARS
			< crate::report_limits::GITHUB_ISSUE_BODY_MAX_CHARS
	);
	kani::cover!(characters == 60_000 && accepted, "exact aggregate character cap");
	kani::cover!(characters == 60_001 && !accepted, "first character beyond cap");
}

// Bound: Three distinct keys in every insertion permutation and three
// symbolic boolean values. This proves Ordered's actual sorting core preserves
// associations and sorts keys. JSON parsing/recursive round trips are fuzzed by
// core_canonical; those parser operations are outside this proof's bound.
// Four loop iterations cover three entries plus termination. Temporary maps
// are forgotten after checking them; collection destruction is outside this
// ordering property and otherwise dominates symbolic execution.
#[kani::proof]
#[kani::unwind(4)]
fn canonical_object_keys_are_sorted() {
	use serde_json::{Map, Value};
	let first: usize = kani::any();
	let second: usize = kani::any();
	kani::assume(first < 3 && second < 3 && first != second);
	let third = 3 - first - second;
	let keys = ["a", "m", "z"];
	let values: [bool; 3] = kani::any();
	let mut fields = Map::new();
	for index in [first, second, third] {
		fields.insert(keys[index].into(), Value::Bool(values[index]));
	}
	let ordered = crate::canonical::ordered_fields(&fields);
	let mut entries = ordered.iter();
	for index in 0..3 {
		let (key, value) = entries.next().unwrap();
		assert_eq!(*key, keys[index]);
		assert_eq!(*value, &Value::Bool(values[index]));
	}
	assert!(entries.next().is_none());
	kani::cover!(first == 2 && second == 1, "reverse insertion order");
	kani::cover!(first == 0 && second == 1, "already sorted insertion order");
	kani::cover!(values == [true, false, true], "distinct value associations");
	std::mem::forget(ordered);
	std::mem::forget(fields);
}

// Bound: Actual no-allocation JSON-string preflight on at most eight
// arbitrary valid UTF-8 bytes, with full usize byte/scalar caps. This bounded
// proof covers malformed/short escapes, admission/count boundaries and direct
// UTF-8 counts; it does not claim induction over longer tokens or serde parity.
// Longer/surrogate tokens and serde equivalence are independently tested/fuzzed.
#[kani::proof]
#[kani::unwind(12)]
fn json_string_preflight_counts_bounded_tokens() {
	use crate::text::json_string::preflight;
	let bytes: [u8; 8] = kani::any();
	let len: usize = kani::any();
	kani::assume(len <= bytes.len());
	let Ok(raw) = std::str::from_utf8(&bytes[..len]) else {
		kani::assume(false);
		return;
	};
	let max_bytes: usize = kani::any();
	let max_chars: usize = kani::any();
	let unlimited = preflight(raw, "proof", usize::MAX, usize::MAX);
	let bounded = preflight(raw, "proof", max_bytes, max_chars);
	if let Ok(size) = &unlimited {
		assert_eq!(bounded.is_ok(), size.bytes <= max_bytes && size.chars <= max_chars);
		if !raw.contains('\\') {
			let contents = &raw[1..raw.len() - 1];
			assert_eq!(size.bytes, contents.len());
			assert_eq!(size.chars, contents.chars().count());
		}
	}
	if let Ok(size) = &bounded {
		assert!(unlimited.is_ok());
		assert!(size.bytes <= max_bytes && size.chars <= max_chars);
	}
	kani::cover!(raw == r#""é""# && bounded.is_ok(), "borrowed Unicode token");
	kani::cover!(raw == r#""\n""# && bounded.is_ok(), "escaped scalar token");
	kani::cover!(
		matches!(bounded, Err(ref e) if e.rule == crate::text::Rule::Bytes),
		"byte cap rejects"
	);
	kani::cover!(
		matches!(bounded, Err(ref e) if e.rule == crate::text::Rule::Chars),
		"scalar cap rejects"
	);
}

// Bound: Every valid high/low surrogate pair, actual preflight, full
// usize caps. The 14-byte encoded token must decode to exactly four UTF-8 bytes
// and one scalar. This supplements, rather than shrinks, the arbitrary-token
// bound above. No allocation or external parser is stubbed.
#[kani::proof]
#[kani::unwind(16)]
fn json_string_preflight_accepts_surrogate_pairs() {
	use crate::text::json_string::preflight;
	let high: u16 = kani::any();
	let low: u16 = kani::any();
	kani::assume((0xd800..=0xdbff).contains(&high));
	kani::assume((0xdc00..=0xdfff).contains(&low));
	let hex = b"0123456789abcdef";
	let mut token = *br#""\u0000\u0000""#;
	for (offset, value) in [(3, high), (9, low)] {
		for index in 0..4 {
			token[offset + index] = hex[((value >> (12 - index * 4)) & 15) as usize];
		}
	}
	let raw = std::str::from_utf8(&token).unwrap();
	let max_bytes: usize = kani::any();
	let max_chars: usize = kani::any();
	let result = preflight(raw, "proof", max_bytes, max_chars);
	assert_eq!(result.is_ok(), max_bytes >= 4 && max_chars >= 1);
	if let Ok(size) = result {
		assert_eq!((size.bytes, size.chars), (4, 1));
	}
	kani::cover!(
		high == 0xd800 && low == 0xdc00 && max_bytes == 4 && max_chars == 1,
		"first supplementary scalar"
	);
	kani::cover!(high == 0xdbff && low == 0xdfff && max_bytes == 3, "last scalar exceeds byte cap");
}
