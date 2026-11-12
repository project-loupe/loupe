//! Header: u32 retry attempt, two u32 halves of a logical sequence, two u32
//! halves of a `now` timestamp and one priority selector byte, all little
//! endian; the rest is UTF-8 version-2 policy JSON admitted as BoundedJson.
//! The acceptance oracle reads the JSON as an untyped value, so duplicate
//! keys, unknown fields and wrong types are judged without the product's
//! derived decoder. Delays and capacity follow PR-B4-STORAGE-CONTRACT:
//! capped exponential delays and general = max - urgent - verification >= 1.

use loupe_core::review_priority::{Access, Impact, Reachability};
use loupe_core::text::policy::Payload;
use loupe_core::JobKind;
use loupe_storage::admission_policy::{classify_priority, CampaignPolicyV2};
use loupe_storage::scheduler::Band;
use serde::de::{Deserializer as _, MapAccess, Visitor};
use serde_json::{Map, Value};

use crate::utils::input::ByteSource;
use crate::utils::test_logger;

const I64_FIELDS: [&str; 12] = [
	"survey_units_per_job",
	"survey_deadline_seconds",
	"survey_submit_margin_seconds",
	"drilldown_deadline_seconds",
	"drilldown_submit_margin_seconds",
	"verify_deadline_seconds",
	"verify_submit_margin_seconds",
	"retry_backoff_base_seconds",
	"retry_backoff_cap_seconds",
	"campaign_deadline_seconds",
	"campaign_max_jobs",
	"campaign_urgent_reserve",
];
const LAST_I64_FIELD: &str = "campaign_verification_reserve";
const U32_FIELDS: [&str; 6] = [
	"version",
	"max_attempts",
	"max_units_per_survey",
	"max_leads_per_survey",
	"max_sibling_leads_per_drilldown",
	"priority_policy_version",
];
const BUDGET_FIELDS: [&str; 3] =
	["survey_token_budget", "drilldown_token_budget", "verify_token_budget"];

pub fn do_test(data: &[u8]) {
	let mut input = ByteSource::new(data);
	let (Some(attempt), Some(seq_lo), Some(seq_hi), Some(now_lo), Some(now_hi), Some(selector)) =
		(input.u32(), input.u32(), input.u32(), input.u32(), input.u32(), input.u8())
	else {
		return;
	};
	let sequence = (u64::from(seq_hi) << 32) | u64::from(seq_lo);
	let now = ((u64::from(now_hi) << 32) | u64::from(now_lo)) as i64;
	check_priority(selector);
	let Ok(raw) = std::str::from_utf8(input.rest()) else { return };
	let Ok(snapshot) = crate::fixtures::json::<Payload>(raw) else { return };

	let typed = typed_fields(snapshot.expose());
	let expected = typed.as_ref().is_some_and(|fields| fields.valid());
	let result = CampaignPolicyV2::from_snapshot(&snapshot);
	assert_eq!(
		CampaignPolicyV2::from_json(snapshot.expose()).is_ok(),
		result.is_ok(),
		"from_json and from_snapshot must agree"
	);
	assert_eq!(result.is_ok(), expected, "version-2 policy acceptance disagrees with oracle");
	let policy = match result {
		Ok(policy) => policy,
		Err(error) => {
			assert_eq!(error.to_string(), "conflict: CampaignPolicy");
			if let Some(fields) = typed {
				check_invalid_policy(&fields);
			}
			return;
		},
	};
	let Some(fields) = typed else { unreachable!("accepted policy without typed fields") };
	assert!(policy.validate().is_ok());

	let mut expected_bytes = Vec::new();
	crate::core_canonical::write_json(&fields.canonical_value(), &mut expected_bytes, false);
	let canonical =
		policy.canonical_bytes().unwrap_or_else(|_| panic!("accepted policy must canonicalize"));
	assert_eq!(canonical, expected_bytes, "canonical bytes disagree with sorted field rendering");
	let reparsed = std::str::from_utf8(&canonical)
		.ok()
		.and_then(|text| CampaignPolicyV2::from_json(text).ok())
		.unwrap_or_else(|| panic!("canonical bytes must decode"));
	assert_eq!(reparsed, policy, "canonical bytes must round-trip");

	let base = fields.i64("retry_backoff_base_seconds");
	let cap = fields.i64("retry_backoff_cap_seconds");
	for attempt in [attempt, 0, 1, 2, 31, 62, 63, 64, u32::MAX] {
		let exponent = attempt.saturating_sub(1);
		let expected = capped_exponential(base, cap, u64::from(exponent));
		assert_eq!(policy.retry_delay(attempt), expected, "retry delay disagrees with oracle");
	}
	for sequence in [sequence, 0, 1, 2, 63, 64, 65, u64::from(u32::MAX) + 2, u64::MAX] {
		check_logical(&policy, base, cap, sequence, now);
	}

	let general = fields.i64("campaign_max_jobs")
		- fields.i64("campaign_urgent_reserve")
		- fields.i64(LAST_I64_FIELD);
	assert!(general >= 1, "oracle accepted a policy without general capacity");
	assert_eq!(policy.general_capacity().ok(), Some(general), "general capacity disagrees");

	for (kind, prefix) in [
		(JobKind::<loupe_provenance::Agent>::Survey, "survey"),
		(JobKind::Drilldown, "drilldown"),
		(JobKind::Verify, "verify"),
	] {
		let phase = policy.phase(&kind).unwrap_or_else(|_| panic!("known phase must be accepted"));
		assert_eq!(
			(phase.deadline_seconds, phase.submit_margin_seconds, phase.token_budget),
			(
				fields.i64(&format!("{prefix}_deadline_seconds")),
				fields.i64(&format!("{prefix}_submit_margin_seconds")),
				fields.budget(&format!("{prefix}_token_budget")),
			)
		);
	}
	assert!(policy.phase(&JobKind::<loupe_provenance::Agent>::Scan).is_err());
}

/// base * 2^exponent capped at `cap`, computed without wrapping.
fn capped_exponential(base: i64, cap: i64, exponent: u64) -> i64 {
	if exponent >= 64 {
		return cap;
	}
	let product = (base as u128) * (1_u128 << exponent);
	product.min(cap as u128) as i64
}

fn check_logical(policy: &CampaignPolicyV2, base: i64, cap: i64, sequence: u64, now: i64) {
	let delay = policy.logical_delay(sequence);
	let not_before = policy.logical_not_before(now, sequence);
	if sequence == 0 {
		assert!(delay.is_err(), "logical sequence 0 has no delay");
		assert!(not_before.is_err());
		return;
	}
	let expected = capped_exponential(base, cap, sequence - 1);
	assert_eq!(delay.ok(), Some(expected), "logical delay disagrees with oracle");
	assert!((1..=cap).contains(&expected));
	if let Some(next) = sequence.checked_add(1) {
		let following = policy.logical_delay(next).unwrap_or_else(|_| panic!("positive sequence"));
		assert!(following >= expected, "logical delay must be non-decreasing");
	}
	let sum = i128::from(now) + i128::from(expected);
	let expected_not_before = i64::try_from(sum).ok();
	assert_eq!(not_before.ok(), expected_not_before, "logical not-before must not wrap");
}

fn check_invalid_policy(fields: &Typed) {
	let Ok(policy) = serde_json::from_value::<CampaignPolicyV2>(Value::Object(fields.0.clone()))
	else {
		panic!("well-typed fields must build a policy value");
	};
	assert!(policy.validate().is_err());
	assert!(policy.canonical_bytes().is_err());
	assert!(policy.general_capacity().is_err());
	assert!(policy.logical_delay(1).is_err());
	assert!(policy.logical_not_before(0, 1).is_err());
}

/// The policy's fields, present exactly once each with their wire types.
struct Typed(Map<String, Value>);

impl Typed {
	fn i64(&self, name: &str) -> i64 {
		self.0.get(name).and_then(Value::as_i64).unwrap_or_else(|| panic!("typed i64 field"))
	}
	fn u32(&self, name: &str) -> u32 {
		self.0
			.get(name)
			.and_then(Value::as_u64)
			.and_then(|value| u32::try_from(value).ok())
			.unwrap_or_else(|| panic!("typed u32 field"))
	}
	fn budget(&self, name: &str) -> Option<u64> {
		self.0.get(name).and_then(Value::as_u64)
	}

	fn valid(&self) -> bool {
		let units = self.i64("survey_units_per_job");
		let base = self.i64("retry_backoff_base_seconds");
		let cap = self.i64("retry_backoff_cap_seconds");
		let deadline = self.i64("campaign_deadline_seconds");
		let max_jobs = self.i64("campaign_max_jobs");
		let urgent = i128::from(self.i64("campaign_urgent_reserve"));
		let verification = i128::from(self.i64(LAST_I64_FIELD));
		let scalar = self.u32("version") == 2
			&& self.u32("priority_policy_version") == 1
			&& (1..=32).contains(&units)
			&& self.u32("max_attempts") >= 1
			&& self.u32("max_units_per_survey") >= 1
			&& self.u32("max_leads_per_survey") >= 1
			&& self.u32("max_sibling_leads_per_drilldown") >= 1
			&& max_jobs >= 1
			&& base >= 1
			&& cap >= base
			&& urgent >= 0
			&& verification >= 0
			&& i128::from(max_jobs) - urgent - verification >= 1;
		scalar
			&& ["survey", "drilldown", "verify"].into_iter().all(|phase| {
				let phase_deadline = self.i64(&format!("{phase}_deadline_seconds"));
				let margin = self.i64(&format!("{phase}_submit_margin_seconds"));
				let budget = self.budget(&format!("{phase}_token_budget"));
				phase_deadline >= 1
					&& margin >= 0
					&& margin < phase_deadline
					&& phase_deadline <= deadline
					&& budget.is_none_or(|value| (1..=i64::MAX as u64).contains(&value))
			})
	}

	fn canonical_value(&self) -> Value {
		let mut map = Map::new();
		for name in I64_FIELDS.into_iter().chain([LAST_I64_FIELD]) {
			map.insert(name.into(), Value::from(self.i64(name)));
		}
		for name in U32_FIELDS {
			map.insert(name.into(), Value::from(self.u32(name)));
		}
		for name in BUDGET_FIELDS {
			map.insert(name.into(), self.budget(name).map_or(Value::Null, Value::from));
		}
		Value::Object(map)
	}
}

/// Accepts exactly a top-level object holding every field once with its
/// wire type: i64 and u32 integers, and u64-or-null budgets.
fn typed_fields(raw: &str) -> Option<Typed> {
	let keys = top_level_keys(raw)?;
	let Ok(Value::Object(map)) = serde_json::from_str::<Value>(raw) else { return None };
	let mut expected: Vec<&str> =
		I64_FIELDS.iter().chain(&U32_FIELDS).chain(&BUDGET_FIELDS).copied().collect();
	expected.push(LAST_I64_FIELD);
	let mut seen = keys.clone();
	seen.sort_unstable();
	seen.dedup();
	if seen.len() != keys.len() || keys.len() != expected.len() {
		return None;
	}
	if !expected.iter().all(|name| keys.iter().any(|key| key == name)) {
		return None;
	}
	let integer = |value: &Value| value.as_i64().is_some() && !value.is_f64();
	let unsigned = |value: &Value| value.as_u64().is_some() && !value.is_f64();
	for name in I64_FIELDS.into_iter().chain([LAST_I64_FIELD]) {
		if !map.get(name).is_some_and(integer) {
			return None;
		}
	}
	for name in U32_FIELDS {
		if !map.get(name).is_some_and(|value| {
			unsigned(value) && value.as_u64().is_some_and(|v| u32::try_from(v).is_ok())
		}) {
			return None;
		}
	}
	for name in BUDGET_FIELDS {
		if !map.get(name).is_some_and(|value| value.is_null() || unsigned(value)) {
			return None;
		}
	}
	Some(Typed(map))
}

/// Every key of the top-level object in document order, duplicates included.
fn top_level_keys(raw: &str) -> Option<Vec<String>> {
	struct Keys;
	impl<'de> Visitor<'de> for Keys {
		type Value = Vec<String>;
		fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			f.write_str("an object")
		}
		fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Vec<String>, A::Error> {
			let mut keys = Vec::new();
			while let Some(key) = map.next_key::<String>()? {
				map.next_value::<serde::de::IgnoredAny>()?;
				keys.push(key);
			}
			Ok(keys)
		}
	}
	let mut deserializer = serde_json::Deserializer::from_str(raw);
	let keys = (&mut deserializer).deserialize_map(Keys).ok()?;
	deserializer.end().ok()?;
	Some(keys)
}

/// Priority policy 1 as written in PR-B4-STORAGE-CONTRACT.
fn check_priority(selector: u8) {
	let impact =
		[Impact::Low, Impact::Medium, Impact::High, Impact::Critical][usize::from(selector & 3)];
	let access = [Access::Privileged, Access::Local, Access::Remote, Access::Remote]
		[usize::from((selector >> 2) & 3)];
	let reachability =
		if selector & 0x10 != 0 { Reachability::Traced } else { Reachability::Plausible };
	let boundary = selector & 0x20 != 0;
	let supported = selector & 0x40 != 0;
	let (band, score) = expected_priority(impact, access, reachability, boundary, supported);
	let actual = classify_priority(impact, access, reachability, boundary, supported);
	assert_eq!((actual.band, actual.score), (band, score), "priority disagrees with contract");
	assert!(actual.score <= 550);
}

fn expected_priority(
	impact: Impact, access: Access, reachability: Reachability, boundary: bool, supported: bool,
) -> (Band, u32) {
	if !supported {
		return (Band::Normal, 0);
	}
	let impact_score = match impact {
		Impact::Low => 0,
		Impact::Medium => 100,
		Impact::High => 200,
		Impact::Critical => 300,
	};
	let access_score = match access {
		Access::Privileged => 0,
		Access::Local => 50,
		Access::Remote => 100,
	};
	let traced = reachability == Reachability::Traced;
	let severe = impact_score >= 200;
	let band = match (severe, access == Access::Remote, traced, boundary, impact_score) {
		(true, true, true, true, _) => Band::Urgent,
		(true, _, true, _, _) => Band::High,
		(_, _, _, _, 0) => Band::Background,
		_ => Band::Normal,
	};
	let score =
		impact_score + access_score + if traced { 100 } else { 0 } + if boundary { 50 } else { 0 };
	(band, score)
}

pub fn storage_admission_policy_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn storage_admission_policy_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	#[test]
	fn every_priority_input_matches_the_contract() {
		for selector in 0..=u8::MAX {
			super::check_priority(selector);
		}
	}
}
