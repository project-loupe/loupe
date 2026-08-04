//! Adaptive concurrency + backoff for LLM provider rate limits.
//!
//! Codex (and other CLIs) surface upstream 429s as process failures after
//! their own internal retries are exhausted, typically:
//!
//!   ERROR: exceeded retry limit, last status: 429 Too Many Requests
//!
//! The discovery scanner fans out one agent session per source file. Without
//! coordination, N concurrent sessions all thrash the same quota, burn the
//! retry budget, and fail every file. This module:
//!
//! 1. Classifies rate-limit / retry-limit errors from CLI stderr/stdout.
//! 2. Provides a dynamic permit pool ([`AdaptiveConcurrency`]) that shrinks
//!    on rate limits, sleeps with exponential backoff, and slowly recovers
//!    on success.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// Base backoff after the first rate-limit hit. Doubles per consecutive hit
/// up to [`MAX_BACKOFF`].
const BASE_BACKOFF: Duration = Duration::from_secs(20);
/// Cap so a stuck provider doesn't park the worker for an hour.
const MAX_BACKOFF: Duration = Duration::from_secs(5 * 60);
/// Consecutive rate-limit hits used for the exponential shift (2^n).
const MAX_BACKOFF_EXPONENT: u32 = 5;

/// Return true when an LLM backend error looks like an upstream rate limit
/// or exhausted provider retry budget. Matching is intentionally loose —
/// codex, claude, and OpenAI-compatible proxies phrase the same condition
/// slightly differently, and the actionable text often sits at the tail of
/// a long CLI banner (see [`super::summarize_cli_stream_for_error`]).
pub fn is_rate_limit_error(err: &anyhow::Error) -> bool {
	is_rate_limit_message(&format!("{err:#}"))
}

/// String-level classifier used by [`is_rate_limit_error`] and unit tests.
pub fn is_rate_limit_message(msg: &str) -> bool {
	let lower = msg.to_ascii_lowercase();
	// Order: cheap specific markers first, then broader phrases.
	lower.contains("429")
		|| lower.contains("too many requests")
		|| lower.contains("exceeded retry limit")
		|| lower.contains("retry limit")
		|| lower.contains("rate limit")
		|| lower.contains("rate-limit")
		|| lower.contains("rate_limit")
		|| lower.contains("ratelimit")
		|| lower.contains("quota exceeded")
		|| lower.contains("resource has been exhausted")
		|| lower.contains("tokens per day")
		|| lower.contains("tokens per minute")
		|| lower.contains("requests per minute")
}

#[derive(Debug)]
struct BackoffState {
	/// Consecutive rate-limit observations since the last success.
	consecutive: u32,
	/// When set and in the future, [`AdaptiveConcurrency::acquire`] sleeps
	/// until this instant before handing out a new permit.
	cooldown_until: Option<Instant>,
}

/// Dynamic concurrency limiter shared across the per-file agent fan-out.
///
/// - Starts at `max` concurrent permits (the configured
///   `max_concurrent_files`).
/// - On rate limit: halves the limit (floor 1), records exponential
///   cooldown, wakes waiters so they observe the new ceiling.
/// - On success: clears the consecutive counter and nudges the limit up
///   by 1 (capped at `max`) once any cooldown has elapsed.
/// - [`Ticket`] RAII releases the in-flight slot on drop.
pub struct AdaptiveConcurrency {
	max: usize,
	limit: AtomicUsize,
	in_flight: AtomicUsize,
	notify: Notify,
	state: Mutex<BackoffState>,
}

/// RAII permit. Dropping it decrements `in_flight` and wakes a waiter.
pub struct Ticket {
	parent: Arc<AdaptiveConcurrency>,
}

impl Drop for Ticket {
	fn drop(&mut self) {
		self.parent.in_flight.fetch_sub(1, Ordering::AcqRel);
		self.parent.notify.notify_waiters();
	}
}

impl AdaptiveConcurrency {
	pub fn new(max: usize) -> Arc<Self> {
		let max = max.max(1);
		Arc::new(Self {
			max,
			limit: AtomicUsize::new(max),
			in_flight: AtomicUsize::new(0),
			notify: Notify::new(),
			state: Mutex::new(BackoffState { consecutive: 0, cooldown_until: None }),
		})
	}

	/// Current concurrency ceiling (1..=max). Exposed for logs/tests.
	pub fn current_limit(&self) -> usize {
		self.limit.load(Ordering::Acquire).clamp(1, self.max)
	}

	pub fn max(&self) -> usize {
		self.max
	}

	/// Wait until a permit is available and any cooldown has elapsed.
	pub async fn acquire(self: &Arc<Self>) -> Ticket {
		loop {
			// Honour cooldown first so we don't spin-acquire during backoff.
			let sleep_for = {
				let st = self.state.lock().expect("rate-limit state lock");
				st.cooldown_until.and_then(|until| {
					let now = Instant::now();
					if until > now {
						Some(until - now)
					} else {
						None
					}
				})
			};
			if let Some(delay) = sleep_for {
				tokio::time::sleep(delay).await;
				// Clear expired cooldown so success recovery can run.
				let mut st = self.state.lock().expect("rate-limit state lock");
				if st.cooldown_until.is_some_and(|u| u <= Instant::now()) {
					st.cooldown_until = None;
				}
				continue;
			}

			// Register the waiter BEFORE re-checking so a release between
			// the check and the await can't be missed (`notify_waiters`
			// only wakes registered waiters; without `enable` we'd risk a
			// lost wakeup and a stalled scan).
			let notified = self.notify.notified();
			tokio::pin!(notified);
			notified.as_mut().enable();

			let limit = self.current_limit();
			let prev = self.in_flight.fetch_add(1, Ordering::AcqRel);
			if prev < limit {
				return Ticket { parent: Arc::clone(self) };
			}
			// Lost the race — roll back and wait for a release / limit change.
			self.in_flight.fetch_sub(1, Ordering::AcqRel);
			notified.await;
		}
	}

	/// A session completed cleanly. Reset consecutive rate-limit count and
	/// slowly restore concurrency once we're outside a cooldown window.
	pub fn record_success(&self) {
		let mut st = self.state.lock().expect("rate-limit state lock");
		st.consecutive = 0;
		let cooling = st.cooldown_until.is_some_and(|u| u > Instant::now());
		if cooling {
			return;
		}
		st.cooldown_until = None;
		let cur = self.current_limit();
		if cur < self.max {
			let next = (cur + 1).min(self.max);
			self.limit.store(next, Ordering::Release);
			tracing::info!(
				previous = cur,
				limit = next,
				max = self.max,
				"llm rate-limit: restored concurrency after success"
			);
			self.notify.notify_waiters();
		}
	}

	/// A session hit a provider rate limit. Shrink concurrency and arm
	/// exponential backoff so the rest of the fan-out slows down.
	pub fn record_rate_limit(&self, detail: &str) {
		let mut st = self.state.lock().expect("rate-limit state lock");
		st.consecutive = st.consecutive.saturating_add(1).min(MAX_BACKOFF_EXPONENT + 1);
		let exponent = st.consecutive.saturating_sub(1).min(MAX_BACKOFF_EXPONENT);
		let mut delay = BASE_BACKOFF.saturating_mul(1u32 << exponent);
		if delay > MAX_BACKOFF {
			delay = MAX_BACKOFF;
		}
		let until = Instant::now() + delay;
		st.cooldown_until = Some(match st.cooldown_until {
			Some(existing) if existing > until => existing,
			_ => until,
		});

		let cur = self.current_limit();
		// Floor at 1 so we keep making progress, just slowly.
		let next = (cur / 2).max(1);
		self.limit.store(next, Ordering::Release);

		tracing::warn!(
			previous = cur,
			limit = next,
			max = self.max,
			consecutive = st.consecutive,
			backoff_secs = delay.as_secs(),
			detail = %truncate_for_log(detail, 240),
			"llm rate-limit: slowing fan-out (reduced concurrency + backoff)"
		);
		// Wake acquire() waiters so they re-check cooldown/limit instead of
		// sitting on a stale notified edge.
		self.notify.notify_waiters();
	}

	/// Non-rate-limit failure: leave concurrency alone. (Auth errors, MCP
	/// crashes, etc. aren't fixed by going slower.)
	pub fn record_other_error(&self) {
		// Intentionally empty — kept as an explicit hook so call sites
		// document the three-way outcome (success / rate-limit / other).
	}
}

fn truncate_for_log(s: &str, max_chars: usize) -> String {
	let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
	if collapsed.chars().count() <= max_chars {
		return collapsed;
	}
	let mut out: String = collapsed.chars().take(max_chars.saturating_sub(3)).collect();
	out.push_str("...");
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn classifies_codex_retry_limit_429() {
		let msg = "codex CLI exited with exit status: 1: stderr(chars=200)=\
			`ERROR: exceeded retry limit, last status: 429 Too Many Requests`";
		assert!(is_rate_limit_message(msg));
	}

	#[test]
	fn classifies_plain_rate_limit_phrases() {
		assert!(is_rate_limit_message("Rate limit exceeded, please retry later"));
		assert!(is_rate_limit_message("resource_exhausted: quota exceeded"));
		assert!(is_rate_limit_message("TPM: tokens per minute limit hit"));
	}

	#[test]
	fn ignores_unrelated_errors() {
		assert!(!is_rate_limit_message("codex CLI exited with exit status: 1: auth failed"));
		assert!(!is_rate_limit_message("mcp startup: failed: loupe handshaking failed"));
		assert!(!is_rate_limit_message("timed out after 30s"));
	}

	#[test]
	fn rate_limit_halves_concurrency_and_sets_cooldown() {
		let c = AdaptiveConcurrency::new(8);
		assert_eq!(c.current_limit(), 8);
		c.record_rate_limit("429 Too Many Requests");
		assert_eq!(c.current_limit(), 4);
		c.record_rate_limit("exceeded retry limit");
		assert_eq!(c.current_limit(), 2);
		c.record_rate_limit("429");
		assert_eq!(c.current_limit(), 1);
		// Floor stays at 1.
		c.record_rate_limit("429");
		assert_eq!(c.current_limit(), 1);

		let st = c.state.lock().unwrap();
		assert!(st.consecutive >= 4);
		assert!(st.cooldown_until.is_some_and(|u| u > Instant::now()));
	}

	#[test]
	fn success_restores_concurrency_after_cooldown_clears() {
		let c = AdaptiveConcurrency::new(4);
		c.record_rate_limit("429");
		assert_eq!(c.current_limit(), 2);
		// Simulate cooldown already elapsed.
		{
			let mut st = c.state.lock().unwrap();
			st.cooldown_until = Some(Instant::now() - Duration::from_secs(1));
		}
		c.record_success();
		assert_eq!(c.current_limit(), 3);
		c.record_success();
		assert_eq!(c.current_limit(), 4);
		// Capped at max.
		c.record_success();
		assert_eq!(c.current_limit(), 4);
	}

	#[test]
	fn success_does_not_restore_during_active_cooldown() {
		let c = AdaptiveConcurrency::new(4);
		c.record_rate_limit("429");
		assert_eq!(c.current_limit(), 2);
		c.record_success();
		// Still cooling down — limit stays put.
		assert_eq!(c.current_limit(), 2);
	}

	#[tokio::test]
	async fn acquire_respects_limit() {
		let c = AdaptiveConcurrency::new(2);
		let t1 = c.acquire().await;
		let t2 = c.acquire().await;
		assert_eq!(c.in_flight.load(Ordering::Acquire), 2);

		// Third acquire should not complete until a ticket drops.
		let c3 = Arc::clone(&c);
		let third = tokio::spawn(async move { c3.acquire().await });
		tokio::time::sleep(Duration::from_millis(30)).await;
		assert!(!third.is_finished());

		drop(t1);
		let t3 = tokio::time::timeout(Duration::from_secs(1), third)
			.await
			.expect("join")
			.expect("third acquire");
		assert_eq!(c.in_flight.load(Ordering::Acquire), 2);
		drop(t2);
		drop(t3);
	}

	#[tokio::test]
	async fn acquire_waits_out_cooldown() {
		let c = AdaptiveConcurrency::new(2);
		{
			let mut st = c.state.lock().unwrap();
			st.cooldown_until = Some(Instant::now() + Duration::from_millis(80));
			st.consecutive = 1;
		}
		let started = Instant::now();
		let _t = c.acquire().await;
		assert!(
			started.elapsed() >= Duration::from_millis(60),
			"acquire returned before cooldown elapsed: {:?}",
			started.elapsed()
		);
	}
}
