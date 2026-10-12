//! Harness-local specification: legacy public schemas plus independent field rules.
//! No production text constructor, decoder, token-range helper or source mint.
use serde_json::Value;
use unicode_general_category::{get_general_category, GeneralCategory};

pub(crate) const TEXT_LIMIT: usize = 2 * 1024 * 1024;
pub(crate) const BODY_LIMIT: usize = 16 * 1024 * 1024;

/// Original text decoders have no diagnostic log egress. Keep this baseline
/// separate from sender-facing error/echo observations and runtime collectors.
pub(crate) fn without_logs<T>(action: impl FnOnce() -> T) -> T {
	#[derive(Clone, Default)]
	struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
	impl std::io::Write for Capture {
		fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
			let mut log = self.0.lock().unwrap_or_else(|e| e.into_inner());
			let keep = bytes.len().min(1024usize.saturating_sub(log.len()));
			log.extend_from_slice(&bytes[..keep]);
			Ok(bytes.len())
		}
		fn flush(&mut self) -> std::io::Result<()> {
			Ok(())
		}
	}
	let capture = Capture::default();
	let writer = capture.clone();
	let subscriber = tracing_subscriber::fmt()
		.with_max_level(tracing::Level::TRACE)
		.without_time()
		.with_ansi(false)
		.with_writer(move || writer.clone())
		.finish();
	let _guard = tracing::subscriber::set_default(subscriber);
	let result = action();
	assert!(
		capture.0.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
		"pure original decoder emitted diagnostic log content"
	);
	result
}

pub(crate) fn permitted(ch: char, multiline: bool) -> bool {
	if multiline && matches!(ch, '\r' | '\n' | '\t') {
		return true;
	}
	let point = ch as u32;
	!matches!(
		get_general_category(ch),
		GeneralCategory::Control
			| GeneralCategory::Format
			| GeneralCategory::Unassigned
			| GeneralCategory::PrivateUse
			| GeneralCategory::LineSeparator
			| GeneralCategory::ParagraphSeparator
	) && !(0xfdd0..=0xfdef).contains(&point)
		&& !matches!(point & 0xffff, 0xfffe | 0xffff)
}

pub(crate) fn text(value: &str, multiline: bool) -> bool {
	value.len() <= TEXT_LIMIT && value.chars().all(|ch| permitted(ch, multiline))
}

pub(crate) fn path(value: &str) -> bool {
	value.len() <= 512
		&& text(value, false)
		&& !value.contains('\\')
		&& !value.split('/').any(|part| matches!(part, "" | "." | ".."))
}

fn optional_text(value: Option<&Value>, multiline: bool) -> bool {
	value.and_then(Value::as_str).is_none_or(|value| text(value, multiline))
}

pub(crate) fn finding(value: &Value) -> bool {
	["scanner_id", "title", "cwe", "fingerprint", "approved_by_cn", "rejected_by_cn"]
		.into_iter()
		.all(|key| optional_text(value.get(key), false))
		&& ["description", "poc_unified", "patch_unified"]
			.into_iter()
			.all(|key| optional_text(value.get(key), true))
		&& value.get("file_path").and_then(Value::as_str).is_none_or(path)
}

pub(crate) fn scanner(value: &Value) -> bool {
	let lists = if let Some(fields) = value.as_object() {
		[fields.get("include_extensions"), fields.get("exclude_path_substrings")]
	} else if let Some(items) = value.as_array() {
		[items.get(3), items.get(4)]
	} else {
		[None, None]
	};
	lists
		.into_iter()
		.flatten()
		.filter_map(Value::as_array)
		.flatten()
		.filter_map(Value::as_str)
		.all(|value| text(value, false))
}

pub(crate) fn lease(value: &mut loupe_proto::LeaseResponse) -> bool {
	let loupe_proto::LeaseResponse::Lease(env) = value else { return true };
	let repo = &env.repo;
	if [&repo.host, &repo.owner, &repo.repo, &repo.clone_url].into_iter().any(|v| !text(v, false))
		|| repo.branch.as_deref().is_some_and(|v| !text(v, false))
		|| env.head_branch.as_deref().is_some_and(|v| !text(v, false))
		|| !scanner(&env.scanner_config)
	{
		return false;
	}
	match &mut env.payload {
		loupe_proto::LeasePayload::Scan { since_sha } => {
			since_sha.as_deref().is_none_or(|v| text(v, false))
		},
		loupe_proto::LeasePayload::Verify { finding: content, reviewed_sha, .. } => {
			if let Some(revision) = reviewed_sha {
				if revision.len() > TEXT_LIMIT {
					return false;
				}
				if revision.trim().is_empty() {
					*reviewed_sha = None;
				} else if !text(revision, false) {
					return false;
				}
			}
			finding(
				&serde_json::to_value(content)
					.unwrap_or_else(|error| panic!("fixture finding: {error}")),
			)
		},
	}
}

/// Canonical output is produced only from the unchanged public legacy schemas.
pub(crate) fn client(kind: u8, bytes: &[u8]) -> Option<Value> {
	if bytes.len() > BODY_LIMIT {
		return None;
	}
	match kind {
		0 => {
			let mut value = serde_json::from_slice::<loupe_proto::LeaseResponse>(bytes).ok()?;
			lease(&mut value).then(|| {
				serde_json::to_value(value).unwrap_or_else(|error| panic!("fixture lease: {error}"))
			})
		},
		1 => serde_json::from_slice::<loupe_proto::HeartbeatResponse>(bytes).ok().map(|v| {
			serde_json::to_value(v).unwrap_or_else(|error| panic!("fixture heartbeat: {error}"))
		}),
		2 => {
			let value = serde_json::from_slice::<loupe_proto::ListFindingsResponse>(bytes).ok()?;
			let value = serde_json::to_value(value)
				.unwrap_or_else(|error| panic!("fixture search: {error}"));
			value["findings"].as_array()?.iter().all(finding).then_some(value)
		},
		3 => {
			let value = serde_json::from_slice::<loupe_proto::FindingDetail>(bytes).ok()?;
			let value = serde_json::to_value(value)
				.unwrap_or_else(|error| panic!("fixture detail: {error}"));
			finding(&value).then_some(value)
		},
		4 => Some(Value::String(String::from_utf8_lossy(bytes).trim().to_owned())),
		5 => Some(Value::Null),
		_ => None,
	}
}

/// Append-time ledger: original encoded spans are recorded at construction.
/// Equal contents, keys and ignored/audit values cannot redirect a span.
#[derive(Default)]
pub(crate) struct Ledger {
	pub bytes: Vec<u8>,
	pub agent: Vec<std::ops::Range<usize>>,
}
impl Ledger {
	pub fn raw(&mut self, raw: &str) {
		self.bytes.extend_from_slice(raw.as_bytes());
	}
	pub fn token(&mut self, encoded: &str, agent: bool) {
		let start = self.bytes.len();
		self.raw(encoded);
		if agent {
			self.agent.push(start..self.bytes.len());
		}
	}
}
