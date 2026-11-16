//! How long one survey invocation may run.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use loupe_proto::review_lease::ReviewLimits;

/// Time left before the hard deadline for the host to stop the agent and
/// report the attempt.
pub const KILL_MARGIN: Duration = Duration::from_secs(30);

/// The invocation timeout for a survey launched at `now`, or `None` when
/// the attempt must not launch.
pub fn survey_timeout(limits: &ReviewLimits, now: SystemTime) -> Option<Duration> {
	invocation_timeout(now.duration_since(UNIX_EPOCH).ok()?, limits.hard_deadline_at)
}

/// `hard_deadline_at − now − KILL_MARGIN`, with `now` since the Unix epoch.
pub(crate) fn invocation_timeout(now: Duration, hard_deadline_at: i64) -> Option<Duration> {
	let hard_deadline = Duration::from_secs(u64::try_from(hard_deadline_at).ok()?);
	hard_deadline.checked_sub(now)?.checked_sub(KILL_MARGIN).filter(|left| !left.is_zero())
}

#[cfg(test)]
mod tests {
	use super::*;

	const S: fn(u64) -> Duration = Duration::from_secs;

	#[test]
	fn leaves_the_kill_margin_before_the_hard_deadline() {
		assert_eq!(invocation_timeout(S(1_000), 1_100), Some(S(70)));
		assert_eq!(
			invocation_timeout(S(1_000) + Duration::from_millis(250), 1_100),
			Some(S(70) - Duration::from_millis(250))
		);
		assert_eq!(invocation_timeout(S(1_000), 1_031), Some(S(1)));
	}

	#[test]
	fn does_not_launch_without_time_past_the_margin() {
		assert_eq!(invocation_timeout(S(1_000), 1_030), None);
		assert_eq!(invocation_timeout(S(1_000), 1_010), None);
		assert_eq!(invocation_timeout(S(1_000), 1_000), None);
		assert_eq!(invocation_timeout(S(1_000), 900), None);
		assert_eq!(invocation_timeout(S(0), -1), None);
		assert_eq!(invocation_timeout(S(0), i64::MIN), None);
		assert_eq!(invocation_timeout(Duration::MAX, i64::MAX), None);
	}

	#[test]
	fn far_deadlines_do_not_overflow() {
		assert_eq!(invocation_timeout(S(0), i64::MAX), Some(S(i64::MAX as u64) - KILL_MARGIN));
	}

	#[test]
	fn reads_the_lease_hard_deadline() {
		let limits = ReviewLimits {
			soft_deadline_at: 0,
			submit_by: 0,
			hard_deadline_at: 2_000,
			token_budget: None,
			new_unit_limit: 1,
			lead_limit: 1,
			sibling_limit: 1,
		};
		assert_eq!(survey_timeout(&limits, UNIX_EPOCH + S(1_000)), Some(S(970)));
		assert_eq!(survey_timeout(&limits, UNIX_EPOCH + S(1_980)), None);
	}
}
