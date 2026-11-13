//! Header: kind byte, limit byte, two little-endian i64 IDs (as u32 halves)
//! and a created-at u32; then u16-length-prefixed query, commit, family and
//! anchor strings, and an optional instance key in the rest. The query goes
//! through the shared bounded-text oracle; identifier rules and the
//! candidate limit range 1..=20 are restated here as closed formulas.

use loupe_core::review_candidates::{Candidate, CandidateKind, CandidateQuery, QueryPolicy};
use loupe_core::review_metadata::CommitPolicy;
use loupe_core::text::policy::{AnchorText, Family, InstanceKey};
use serde_json::{json, Value};

use crate::utils::input::ByteSource;
use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	let mut input = ByteSource::new(data);
	let (Some(kind), Some(limit), Some(id), Some(producer), Some(created_at)) =
		(input.u8(), input.u8(), i64_of(&mut input), i64_of(&mut input), input.u32())
	else {
		return;
	};
	let Some(query) = utf8(input.len_prefixed(2048)) else { return };
	crate::core_text_bounded::check::<QueryPolicy>(query);
	if let Ok(text) = crate::fixtures::text::<QueryPolicy>(query) {
		let candidate_query = CandidateQuery { query: text, limit };
		assert_eq!(candidate_query.validate().is_ok(), (1..=20).contains(&limit));
		assert_eq!(format!("{candidate_query:?}"), "CandidateQuery([redacted])");
		let wire = serde_json::to_value(&candidate_query)
			.unwrap_or_else(|_| panic!("candidate query must serialize"));
		assert_eq!(wire, json!({"query": candidate_query.query.expose(), "limit": limit}));
	}

	let (Some(commit), Some(family), Some(anchor)) = (
		utf8(input.len_prefixed(256)),
		utf8(input.len_prefixed(256)),
		utf8(input.len_prefixed(2048)),
	) else {
		return;
	};
	let instance = std::str::from_utf8(input.rest()).ok().filter(|rest| !rest.is_empty());
	let commit_ok = matches!(commit.len(), 40 | 64)
		&& commit.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
	let commit_sha = crate::fixtures::identifier::<CommitPolicy>(commit);
	assert_eq!(commit_sha.is_ok(), commit_ok, "commit acceptance disagrees with oracle");
	let (Ok(commit_sha), Ok(identity_family), Ok(identity_anchor)) = (
		commit_sha,
		crate::fixtures::identifier::<Family>(family),
		crate::fixtures::anchor::<AnchorText>(anchor),
	) else {
		return;
	};
	let identity_instance_key = match instance.map(crate::fixtures::anchor::<InstanceKey>) {
		None => None,
		Some(Ok(key)) => Some(key),
		Some(Err(_)) => return,
	};
	let kind = if kind & 1 == 0 { CandidateKind::Lead } else { CandidateKind::Finding };
	let candidate = Candidate {
		kind,
		id,
		producer_job_id: producer,
		commit_sha,
		created_at: i64::from(created_at),
		identity_family,
		identity_anchor,
		identity_instance_key,
	};
	assert_eq!(candidate.validate().is_ok(), id > 0 && producer > 0);
	assert_eq!(format!("{candidate:?}"), "Candidate([redacted])");
	assert_eq!(candidate.clone(), candidate);
	let expected = json!({
		"kind": if kind == CandidateKind::Lead { "lead" } else { "finding" },
		"id": id,
		"producer_job_id": producer,
		"commit_sha": commit,
		"created_at": created_at,
		"identity_family": candidate.identity_family.expose(),
		"identity_anchor": candidate.identity_anchor.expose(),
		"identity_instance_key": candidate
			.identity_instance_key
			.as_ref()
			.map_or(Value::Null, |key| Value::from(key.expose())),
	});
	let wire =
		serde_json::to_value(&candidate).unwrap_or_else(|_| panic!("candidate must serialize"));
	assert_eq!(wire, expected, "candidate wire disagrees with field rendering");
}

fn i64_of(input: &mut ByteSource<'_>) -> Option<i64> {
	let low = input.u32()?;
	let high = input.u32()?;
	Some(((u64::from(high) << 32) | u64::from(low)) as i64)
}

fn utf8(bytes: Option<&[u8]>) -> Option<&str> {
	std::str::from_utf8(bytes?).ok()
}

pub fn core_review_candidates_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn core_review_candidates_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
