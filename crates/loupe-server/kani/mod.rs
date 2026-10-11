use axum::http::HeaderValue;
use loupe_core::{JobKind, JobState};

use crate::job_capability::{capability_admits, legacy_kind, parse_capability_value, LeaseFacts};
use crate::request_budget::Budget;
use crate::routes::jobs::{route_admits_kind, Route};

fn hash_stub(_: &[u8]) -> blake3::Hash {
	[0x42; 32].into()
}

fn bounded_bytes_copy(data: &[u8]) -> axum::body::Bytes {
	assert!(data.len() <= 44);
	let mut copied = Box::new([0u8; 44]);
	copied[..data.len()].copy_from_slice(data);
	axum::body::Bytes::from_static(&Box::leak(copied)[..data.len()])
}

// invariant: I1. All header byte strings of lengths 0..=44, including HTAB.
// Hash cryptography is excluded: this proof checks acceptance and hash-result
// propagation. HeaderMap lookup and real hashing remain in unit/fuzz checks;
// proving through HeaderMap timed out while expanding header-name hashing.
// Bytes copying uses a same-byte, fixed-size allocation model: real BytesMut
// refcount/pointer machinery exhausted 12 GiB. HeaderValue's byte validation
// and to_str remain real; allocator internals are covered by ordinary fuzzing.
#[kani::proof]
#[kani::unwind(46)]
#[kani::stub(blake3::hash, hash_stub)]
#[kani::stub(axum::body::Bytes::copy_from_slice, bounded_bytes_copy)]
fn parse_capability_matches_header_text_length() {
	let bytes: [u8; 44] = kani::any();
	let len: usize = kani::any();
	kani::assume(len <= 44);
	let header = HeaderValue::from_bytes(&bytes[..len]);
	if let Ok(header) = &header {
		assert_eq!(header.as_bytes(), &bytes[..len]);
	}
	let accepted_text = header.as_ref().is_ok_and(|value| value.to_str().is_ok());
	let parsed = parse_capability_value(header.as_ref().ok());
	assert_eq!(parsed.is_some(), accepted_text && len == 43);
	if let Some(hash) = parsed {
		assert_eq!(hash, [0x42; 32]);
	}
	kani::cover!(parsed.is_some(), "accepted exact-length text");
	kani::cover!(parsed.is_none(), "rejected header");
	kani::cover!(parsed.is_some() && bytes[0] == b'\t', "horizontal tab accepted");
}

// invariant: I1. Full i64 worker/time domain, all state variants and 32-byte
// hashes. SQL tests separately establish that the returned row matches the
// query hash; JobRow itself does not retain the stored capability hash.
// ci: fast
#[kani::proof]
#[kani::unwind(34)]
fn capability_admits_is_sound() {
	let state: u8 = kani::any();
	kani::assume(state < 5);
	let state = match state {
		0 => JobState::Queued,
		1 => JobState::Leased,
		2 => JobState::Succeeded,
		3 => JobState::Failed,
		_ => JobState::Cancelled,
	};
	let facts = LeaseFacts {
		worker_id: kani::any(),
		capability_hash: kani::any(),
		lease_expires_at: kani::any(),
		state,
	};
	let caller: i64 = kani::any();
	let hash: [u8; 32] = kani::any();
	let now: i64 = kani::any();
	let admitted = capability_admits(&facts, caller, &hash, now);
	let expected = facts.worker_id == Some(caller)
		&& facts.capability_hash == hash
		&& facts.state == JobState::Leased
		&& facts.lease_expires_at.is_some_and(|expiry| expiry >= now);
	assert_eq!(admitted, expected);
	kani::cover!(admitted, "valid lease admitted");
	kani::cover!(admitted && facts.lease_expires_at == Some(now), "inclusive expiry admitted");
	kani::cover!(
		!admitted
			&& facts.worker_id == Some(caller)
			&& facts.capability_hash == hash
			&& facts.state == JobState::Leased
			&& facts.lease_expires_at.and_then(|expiry| expiry.checked_add(1)) == Some(now),
		"next instant refused"
	);
}

// invariant: I1. Every route-table row and every JobKind variant. The Unknown
// payload deliberately spells a known kind: the variant, not text, grants access.
// ci: fast
#[kani::proof]
fn route_kind_check_is_exhaustive() {
	let kind: u8 = kani::any();
	kani::assume(kind < 5);
	let kind = match kind {
		0 => JobKind::Scan,
		1 => JobKind::Verify,
		2 => JobKind::Survey,
		3 => JobKind::Drilldown,
		_ => JobKind::Unknown("scan".into()),
	};
	let route: u8 = kani::any();
	kani::assume(route < 3);
	let selected = match route {
		0 => Route::Findings,
		1 => Route::LlmFinding,
		_ => Route::Verdict,
	};
	let admitted = route_admits_kind(selected, &kind);
	assert_eq!(admitted, if route == 2 { kind == JobKind::Verify } else { kind == JobKind::Scan });
	assert_eq!(legacy_kind(&kind), matches!(kind, JobKind::Scan | JobKind::Verify));
	kani::cover!(admitted && route == 0, "findings accepts scan");
	kani::cover!(admitted && route == 1, "LLM findings accepts scan");
	kani::cover!(admitted && route == 2, "verdict accepts verify");
	kani::cover!(!admitted && kind == JobKind::Survey, "phase denied");
	kani::cover!(!admitted && matches!(kind, JobKind::Unknown(_)), "unknown denied");
}

// invariant: I6. One arbitrary transition over the full u64 domain. The
// independent conservation oracle partitions exact arithmetic: overflow of
// either checked operation means earned credit exceeds every u64 capacity.
// This avoids a second 128-bit multiplier (the first attempt timed out).
// Composition follows by summing successful charges; time never moves back.
#[kani::proof]
fn request_budget_is_monotone() {
	let capacity: u64 = kani::any();
	let remaining: u64 = kani::any();
	kani::assume(remaining <= capacity);
	let rate: u64 = kani::any();
	let last: u64 = kani::any();
	let now: u64 = kani::any();
	let cost: u64 = kani::any();
	let mut budget = Budget { capacity, remaining, refill_per_second: rate, last };
	let admitted = budget.admit(now, cost);
	let elapsed = if now >= last { now - last } else { 0 };
	let earned = elapsed.checked_mul(rate).and_then(|refill| remaining.checked_add(refill));
	let available = earned.map_or(capacity, |earned| earned.min(capacity));
	assert_eq!(admitted, cost <= available);
	assert_eq!(budget.remaining, if admitted { available - cost } else { available });
	assert!(budget.remaining <= capacity);
	assert!(budget.last >= last && budget.last >= now);
	if now < last {
		assert!(budget.remaining <= remaining);
	}
	kani::cover!(admitted && cost > 0, "positive charge admitted");
	kani::cover!(!admitted, "insufficient credit refused");
	kani::cover!(now < last && admitted, "backward clock creates no credit");
	kani::cover!(earned.is_none(), "refill overflow saturates");
}
