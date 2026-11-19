//! Shared harness for the phase-catalog MCP decoders over original Sandbox
//! records: record construction and the invariants every phase holds.
use loupe_worker::mcp::fuzz_support::PhaseObservation;

pub const SENTINEL: &str = "zq9sentinel";
/// Errors whose text is a constant, so they cannot echo anything.
const FIXED_ERRORS: [&str; 2] = ["unknown argument for this tool", "unknown tool"];
/// Shorter tokens spell parts of fixed error text too often to tell apart.
const ECHO_MIN: usize = 12;

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
		// The token may spell part of the error's fixed text by chance: decode
		// again with the token overwritten, and only filler in that error is
		// an echo. A masked token that takes another decode path proves
		// nothing either way.
		let (masked, filler) = mask(record, span);
		if let Some((_, Err(masked_error))) = observe(&masked).decoded {
			assert!(
				!masked_error.contains(&filler),
				"argument error echoed an Agent token: {masked_error}"
			);
		}
	}
}

/// A token without its surrounding quotes, if it has them.
fn content(token: &[u8]) -> &[u8] {
	token.strip_prefix(b"\"").and_then(|t| t.strip_suffix(b"\"")).unwrap_or(token)
}

/// `record` with the token at `span` overwritten by filler of the same
/// length, and that filler. A quoted token keeps its quotes and becomes
/// letters; an unquoted one becomes digits, so a number stays a number.
fn mask(record: &[u8], span: &std::ops::Range<usize>) -> (Vec<u8>, String) {
	let mut masked = record.to_vec();
	let token = &mut masked[span.clone()];
	let quoted = token.len() >= 2 && token[0] == b'"' && token[token.len() - 1] == b'"';
	let (inner, byte) = if quoted {
		let end = token.len() - 1;
		(&mut token[1..end], b'q')
	} else {
		(token, b'7')
	};
	inner.fill(byte);
	let filler = char::from(byte).to_string().repeat(inner.len());
	(masked, filler)
}
