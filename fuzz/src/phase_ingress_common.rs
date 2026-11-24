//! Shared harness for the phase-catalog MCP decoders over original Sandbox
//! records: record construction and the invariants every phase holds.
use loupe_worker::mcp::fuzz_support::PhaseObservation;

pub const SENTINEL: &str = "zq9sentinel";
/// Errors whose text is a constant, so they cannot echo anything.
const FIXED_ERRORS: [&str; 2] = ["unknown argument for this tool", "unknown tool"];
/// Shorter tokens spell parts of fixed error text too often to tell apart.
const ECHO_MIN: usize = 12;
/// Swapped rewrites tried when filler takes another decode path.
const SWAPS: usize = 4;

/// Builds the record for `data`: a raw record, or a structured one in which
/// each three-byte chunk picks a field from `fields`, a sentinel text length
/// and a `value` shape. `None` when the record is out of scope.
pub fn record(
	data: &[u8], tools: &[&str], fields: &[&str], value: fn(&str, u8) -> String,
) -> Option<Vec<u8>> {
	if data.len() > 65_536 {
		return None;
	}
	let body = data.get(1..).unwrap_or_default();
	let record = match data.first().copied().unwrap_or(0) % 2 {
		0 => body.to_vec(),
		_ => structured(body, tools, fields, value),
	};
	(!record.contains(&b'\n')).then_some(record)
}

fn structured(
	data: &[u8], tools: &[&str], fields: &[&str], value: fn(&str, u8) -> String,
) -> Vec<u8> {
	let tool = tools[usize::from(data.first().copied().unwrap_or(0)) % tools.len()];
	let members: Vec<String> = data
		.get(1..)
		.unwrap_or_default()
		.chunks(3)
		.map(|chunk| {
			let field = fields[usize::from(chunk[0]) % fields.len()];
			let length = usize::from(chunk.get(1).copied().unwrap_or(0)) * 24;
			let text = format!("{SENTINEL}{}", "a".repeat(length));
			format!("{field:?}:{}", value(&text, chunk.get(2).copied().unwrap_or(0)))
		})
		.collect();
	format!(
		r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{tool}","arguments":{{{}}}}}}}"#,
		members.join(",")
	)
	.into_bytes()
}

/// The invariants of one decoded record: Agent carries stay inside it,
/// names outside the catalog never decode, and a rejected argument's error
/// never echoes Agent content.
pub fn check(record: &[u8], foreign: &[&str], observe: fn(&[u8]) -> PhaseObservation) {
	let observed = observe(record);
	for span in &observed.agent_spans {
		assert!(record.get(span.clone()).is_some(), "Agent carry escaped the original record");
	}
	let Some((tool, arguments)) = observed.decoded else { return };
	if tool == "unknown" || foreign.contains(&tool.as_str()) {
		assert!(arguments.is_err(), "a name outside the catalog decoded arguments");
	}
	let Err(error) = arguments else { return };
	assert!(!error.contains(SENTINEL), "argument error echoed Agent content: {error}");
	if FIXED_ERRORS.contains(&error.as_str()) {
		return;
	}
	for span in &observed.agent_spans {
		let inner = content(&record[span.clone()]);
		if inner.len() < ECHO_MIN || !error.contains(&*String::from_utf8_lossy(inner)) {
			continue;
		}
		// The token may spell part of the error's fixed text by chance, so
		// decode again with the token rewritten. The same error means the
		// token's content does not reach it; the rewritten content in the
		// error is an echo; any other outcome is another decode path, which
		// proves nothing, so the next rewrite is tried.
		for (rewritten, content) in rewrites(record, span) {
			let Some((_, Err(other))) = observe(&rewritten).decoded else { continue };
			if other == error {
				break;
			}
			assert!(!other.contains(&content), "argument error echoed an Agent token: {other}");
		}
	}
}

/// A token without its surrounding quotes, if it has them.
fn content(token: &[u8]) -> &[u8] {
	token.strip_prefix(b"\"").and_then(|t| t.strip_suffix(b"\"")).unwrap_or(token)
}

/// Copies of `record` with the content of the token at `span` rewritten,
/// each with its new content: first overwritten by filler, then with two
/// neighbouring bytes swapped, which usually leaves the token valid or
/// invalid for the same reason. A quoted token keeps its quotes and is filled
/// with letters; an unquoted one with digits, so a number stays a number.
fn rewrites(record: &[u8], span: &std::ops::Range<usize>) -> Vec<(Vec<u8>, String)> {
	let token = &record[span.clone()];
	let quoted = token.len() >= 2 && token[0] == b'"' && token[token.len() - 1] == b'"';
	let inner = if quoted { span.start + 1..span.end - 1 } else { span.clone() };
	let rewrite = |change: &dyn Fn(&mut [u8])| {
		let mut rewritten = record.to_vec();
		change(&mut rewritten[inner.clone()]);
		let content = String::from_utf8_lossy(&rewritten[inner.clone()]).into_owned();
		(rewritten, content)
	};
	let filler = if quoted { b'q' } else { b'7' };
	let plain = |byte: u8| byte.is_ascii() && byte != b'\\' && byte != b'"';
	let content = &record[inner.clone()];
	let swaps = (1..content.len())
		.filter(|&at| {
			content[at] != content[at - 1] && plain(content[at]) && plain(content[at - 1])
		})
		.take(SWAPS);
	std::iter::once(rewrite(&|content| content.fill(filler)))
		.chain(swaps.map(|at| rewrite(&|content| content.swap(at - 1, at))))
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	const TOKEN: &[u8] = b"\"agent-chosen-text\"";
	const NAME: &[u8] = b"\"identity_instance_key\"";

	fn observation(record: &[u8], arguments: Result<Vec<u8>, String>) -> PhaseObservation {
		PhaseObservation {
			decoded: Some(("submit_lead".to_owned(), arguments)),
			agent_spans: std::iter::once(0..record.len()).collect(),
		}
	}

	fn valid(record: &[u8]) -> bool {
		content(record).iter().all(|byte| byte.is_ascii_lowercase())
	}

	/// Rejects every token, quoting it.
	fn echoing(record: &[u8]) -> PhaseObservation {
		let error = format!("bad value {}", String::from_utf8_lossy(content(record)));
		observation(record, Err(error))
	}

	/// Quotes the tokens it rejects and accepts lowercase ones, so filler
	/// takes another decode path.
	fn echoing_unless_valid(record: &[u8]) -> PhaseObservation {
		if valid(record) {
			observation(record, Ok(Vec::new()))
		} else {
			echoing(record)
		}
	}

	/// Rejects with fixed wording that spells one possible token.
	fn fixed_unless_valid(record: &[u8]) -> PhaseObservation {
		let error = "`identity_instance_key` argument is required".to_owned();
		observation(record, if valid(record) { Ok(Vec::new()) } else { Err(error) })
	}

	#[test]
	#[should_panic(expected = "echoed an Agent token")]
	fn an_echo_is_caught_on_the_same_decode_path() {
		check(TOKEN, &[], echoing);
	}

	#[test]
	#[should_panic(expected = "echoed an Agent token")]
	fn an_echo_is_caught_when_filler_takes_another_decode_path() {
		check(TOKEN, &[], echoing_unless_valid);
	}

	#[test]
	fn a_token_spelling_fixed_wording_is_no_echo() {
		check(NAME, &[], fixed_unless_valid);
	}
}
