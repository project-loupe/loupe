//! Retry classification for phase requests. Every phase write replays by
//! key or digest, so a lost response is re-sent with identical bytes.

use std::time::Duration;

/// Total tries of one request, including the first.
pub(crate) const MAX_TRIES: u8 = 3;
/// Pause before the second and the third try.
pub(crate) const PAUSES: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(4)];

/// How one try of a phase request failed.
// debug-ok: numeric status and closed transport classes only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
	Timeout,
	Connection,
	Status(u16),
}

// debug-ok: a pause length only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
	/// Pause this long, then send the same bytes again.
	Retry(Duration),
	Final,
}

/// Decide after try number `tries` (1-based) failed with `failure`. `now`
/// and `deadline` are on one clock; no try is scheduled to start at or past
/// `deadline`.
pub(crate) fn classify(failure: Failure, tries: u8, now: Duration, deadline: Duration) -> Decision {
	let retryable = match failure {
		Failure::Timeout | Failure::Connection => true,
		Failure::Status(status) => status == 429 || (500..=599).contains(&status),
	};
	let Some(&pause) = tries.checked_sub(1).and_then(|index| PAUSES.get(usize::from(index))) else {
		return Decision::Final;
	};
	match now.checked_add(pause) {
		Some(start) if retryable && start < deadline => Decision::Retry(pause),
		_ => Decision::Final,
	}
}
const _: () = assert!(PAUSES.len() + 1 == MAX_TRIES as usize);

#[cfg(test)]
mod tests {
	use super::*;

	const NOW: Duration = Duration::from_secs(1_000);
	const FAR: Duration = Duration::from_secs(10_000);

	#[test]
	fn retries_transport_failures_429_and_5xx_with_fixed_pauses() {
		for failure in [
			Failure::Timeout,
			Failure::Connection,
			Failure::Status(429),
			Failure::Status(500),
			Failure::Status(503),
			Failure::Status(599),
		] {
			assert_eq!(classify(failure, 1, NOW, FAR), Decision::Retry(PAUSES[0]), "{failure:?}");
			assert_eq!(classify(failure, 2, NOW, FAR), Decision::Retry(PAUSES[1]), "{failure:?}");
			assert_eq!(classify(failure, 3, NOW, FAR), Decision::Final, "{failure:?}");
		}
	}

	#[test]
	fn never_retries_other_statuses() {
		for status in [200, 204, 301, 400, 401, 403, 404, 409, 413, 415, 422, 428, 430, 499, 600] {
			assert_eq!(classify(Failure::Status(status), 1, NOW, FAR), Decision::Final, "{status}");
		}
	}

	#[test]
	fn never_schedules_a_try_at_or_past_the_deadline() {
		let at = NOW + PAUSES[0];
		assert_eq!(classify(Failure::Timeout, 1, NOW, at), Decision::Final);
		assert_eq!(
			classify(Failure::Timeout, 1, NOW, at + Duration::from_nanos(1)),
			Decision::Retry(PAUSES[0])
		);
		assert_eq!(classify(Failure::Timeout, 2, NOW, NOW + PAUSES[1]), Decision::Final);
		assert_eq!(classify(Failure::Timeout, 1, Duration::MAX, Duration::MAX), Decision::Final);
		assert_eq!(classify(Failure::Timeout, 1, FAR, NOW), Decision::Final);
	}
}
