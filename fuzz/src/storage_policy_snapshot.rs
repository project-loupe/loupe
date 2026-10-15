//! A little-endian u32 attempt count followed by UTF-8 policy JSON. Raw JSON is
//! admitted by BoundedJson before CampaignPolicy; only validated policies size
//! retry delays. Additional fixed attempts pin every overflow boundary.

use loupe_core::text::policy::Payload;
use loupe_core::JobKind;
use loupe_storage::scheduler::CampaignPolicy;

use crate::utils::input::ByteSource;
use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	let mut input = ByteSource::new(data);
	let Some(attempts) = input.u32() else { return };
	let Ok(raw) = std::str::from_utf8(input.rest()) else { return };
	let Ok(snapshot) = crate::fixtures::json::<Payload>(raw) else { return };
	let decoded = serde_json::from_str::<CampaignPolicy>(snapshot.expose());
	let expected = decoded.as_ref().is_ok_and(valid_policy);
	let result = CampaignPolicy::from_snapshot(&snapshot);
	assert_eq!(result.is_ok(), expected, "campaign policy acceptance disagrees with oracle");
	let policy = match result {
		Ok(policy) => policy,
		Err(error) => {
			assert_eq!(error.to_string(), "conflict: CampaignPolicy");
			assert_eq!(format!("{error:?}"), "Conflict(CampaignPolicy)");
			return;
		},
	};
	assert_eq!(decoded.ok().as_ref(), Some(&policy), "accepted policy values must be preserved");
	for attempt in [attempts, 0, 1, 2, 31, 62, 63, 64, u32::MAX] {
		let expected = if attempt >= 64 {
			policy.retry_backoff_cap_seconds
		} else {
			let exponent = if attempt == 0 { 0 } else { attempt - 1 };
			let product = (policy.retry_backoff_base_seconds as u128) * (1_u128 << exponent);
			product.min(policy.retry_backoff_cap_seconds as u128) as i64
		};
		let actual = policy.retry_delay(attempt);
		assert_eq!(actual, expected, "retry delay disagrees with capped mathematical exponential");
		assert!((1..=policy.retry_backoff_cap_seconds).contains(&actual));
	}
	for (kind, deadline, margin, tokens) in [
		(
			JobKind::<loupe_provenance::Agent>::Survey,
			policy.survey_deadline_seconds,
			policy.survey_submit_margin_seconds,
			policy.survey_token_budget,
		),
		(
			JobKind::Drilldown,
			policy.drilldown_deadline_seconds,
			policy.drilldown_submit_margin_seconds,
			policy.drilldown_token_budget,
		),
		(
			JobKind::Verify,
			policy.verify_deadline_seconds,
			policy.verify_submit_margin_seconds,
			policy.verify_token_budget,
		),
	] {
		let phase = policy.phase(&kind).unwrap_or_else(|_| panic!("known phase must be accepted"));
		assert_eq!(
			(phase.deadline_seconds, phase.submit_margin_seconds, phase.token_budget),
			(deadline, margin, tokens)
		);
	}
	for kind in [
		JobKind::Scan,
		JobKind::Unknown(crate::fixtures::text("future").unwrap_or_else(|_| panic!("fixed kind"))),
		JobKind::Unknown(crate::fixtures::text("survey").unwrap_or_else(|_| panic!("fixed kind"))),
	] {
		assert!(policy.phase(&kind).is_err(), "non-phase job must not acquire phase policy");
	}
}

fn valid_policy(policy: &CampaignPolicy) -> bool {
	if policy.version != 1
		|| policy.survey_units_per_job < 1
		|| policy.survey_units_per_job > 32
		|| policy.max_attempts == 0
		|| policy.campaign_max_jobs < 1
		|| policy.campaign_handoff_reserve < 0
		|| policy.campaign_handoff_reserve >= policy.campaign_max_jobs
		|| policy.retry_backoff_base_seconds < 1
		|| policy.retry_backoff_cap_seconds < policy.retry_backoff_base_seconds
	{
		return false;
	}
	for (deadline, margin, token) in [
		(
			policy.survey_deadline_seconds,
			policy.survey_submit_margin_seconds,
			policy.survey_token_budget,
		),
		(
			policy.drilldown_deadline_seconds,
			policy.drilldown_submit_margin_seconds,
			policy.drilldown_token_budget,
		),
		(
			policy.verify_deadline_seconds,
			policy.verify_submit_margin_seconds,
			policy.verify_token_budget,
		),
	] {
		if deadline < 1
			|| margin < 0
			|| margin >= deadline
			|| deadline > policy.campaign_deadline_seconds
		{
			return false;
		}
		if token.is_some_and(|value| !(1..=i64::MAX as u64).contains(&value)) {
			return false;
		}
	}
	true
}

pub fn storage_policy_snapshot_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn storage_policy_snapshot_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
