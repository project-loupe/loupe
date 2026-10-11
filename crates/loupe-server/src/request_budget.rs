//! Per-worker token buckets shared by every authenticated route.
//!
//! Refill uses whole monotonic seconds. Defaults allow a burst of 600
//! requests, 16 MiB of input, and 60 lease attempts, then 10 requests,
//! 256 KiB, and one lease attempt per second. These are token-bucket
//! limits, not strict sliding-window totals. Operators can override
//! `[worker_budgets]` and its `requests`, `bytes`, and `leases` tables.
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{Method, StatusCode};
use futures_util::StreamExt;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BucketConfig {
	pub capacity: u64,
	pub refill_per_second: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkerBudgetConfig {
	pub requests: BucketConfig,
	pub bytes: BucketConfig,
	pub leases: BucketConfig,
	pub max_workers: usize,
	pub idle_seconds: u64,
}

impl Default for WorkerBudgetConfig {
	fn default() -> Self {
		Self {
			requests: BucketConfig { capacity: 600, refill_per_second: 10 },
			bytes: BucketConfig { capacity: 16 * 1024 * 1024, refill_per_second: 256 * 1024 },
			leases: BucketConfig { capacity: 60, refill_per_second: 1 },
			max_workers: 4096,
			idle_seconds: 120,
		}
	}
}

impl WorkerBudgetConfig {
	pub fn validate(&self) -> anyhow::Result<()> {
		anyhow::ensure!(self.max_workers > 0, "worker_budgets.max_workers must be positive");
		anyhow::ensure!(self.idle_seconds > 0, "worker_budgets.idle_seconds must be positive");
		for (name, bucket) in
			[("requests", &self.requests), ("bytes", &self.bytes), ("leases", &self.leases)]
		{
			anyhow::ensure!(
				bucket.capacity > 0 && bucket.refill_per_second > 0,
				"worker_budgets.{name} capacity and refill_per_second must be positive"
			);
		}
		Ok(())
	}
}

/// Arithmetic decision only; no clock or shared state access.
#[derive(Clone, Debug)]
pub(crate) struct Budget {
	pub(crate) capacity: u64,
	pub(crate) remaining: u64,
	pub(crate) refill_per_second: u64,
	pub(crate) last: u64,
}

impl Budget {
	fn new(config: &BucketConfig, now: u64) -> Self {
		Self {
			capacity: config.capacity,
			remaining: config.capacity,
			refill_per_second: config.refill_per_second,
			last: now,
		}
	}

	pub(crate) fn admit(&mut self, now: u64, cost: u64) -> bool {
		let elapsed = now.saturating_sub(self.last);
		self.remaining = self
			.remaining
			.saturating_add(elapsed.saturating_mul(self.refill_per_second))
			.min(self.capacity);
		// A backward clock neither refills nor moves the refill origin backward.
		self.last = self.last.max(now);
		if cost > self.remaining {
			return false;
		}
		self.remaining -= cost;
		true
	}
}

struct Entry {
	requests: Budget,
	bytes: Budget,
	leases: Budget,
	last_seen: u64,
}

impl Entry {
	fn full(&mut self, now: u64) -> bool {
		[&mut self.requests, &mut self.bytes, &mut self.leases].into_iter().all(|bucket| {
			bucket.admit(now, 0);
			bucket.remaining == bucket.capacity
		})
	}
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Charge {
	Request,
	Bytes(u64),
	Lease,
}

impl Charge {
	fn category(self) -> &'static str {
		match self {
			Self::Request => "requests",
			Self::Bytes(_) => "bytes",
			Self::Lease => "leases",
		}
	}
}

pub struct WorkerBudgets {
	config: WorkerBudgetConfig,
	started: Instant,
	entries: Mutex<HashMap<i64, Entry>>,
}

impl WorkerBudgets {
	pub fn new(config: WorkerBudgetConfig) -> anyhow::Result<Self> {
		config.validate()?;
		Ok(Self { config, started: Instant::now(), entries: Mutex::new(HashMap::new()) })
	}

	fn charge_at(&self, worker: i64, now: u64, charge: Charge) -> Result<(), &'static str> {
		let mut entries = self.entries.lock().map_err(|_| "unavailable")?;
		if !entries.contains_key(&worker) {
			// Reclaim only naturally full idle buckets. Evicting indebted workers
			// would give them fresh burst credit on their next request.
			entries.retain(|_, entry| {
				!(now.saturating_sub(entry.last_seen) >= self.config.idle_seconds
					&& entry.full(now))
			});
			if entries.len() >= self.config.max_workers {
				return Err("workers");
			}
			entries.insert(
				worker,
				Entry {
					requests: Budget::new(&self.config.requests, now),
					bytes: Budget::new(&self.config.bytes, now),
					leases: Budget::new(&self.config.leases, now),
					last_seen: now,
				},
			);
		}
		let entry = entries.get_mut(&worker).expect("entry was inserted under the same lock");
		entry.last_seen = entry.last_seen.max(now);
		let (bucket, cost) = match charge {
			Charge::Request => (&mut entry.requests, 1),
			Charge::Bytes(bytes) => (&mut entry.bytes, bytes),
			Charge::Lease => (&mut entry.leases, 1),
		};
		if bucket.admit(now, cost) {
			Ok(())
		} else {
			Err(charge.category())
		}
	}

	fn charge(&self, worker: i64, charge: Charge) -> Result<(), StatusCode> {
		self.charge_at(worker, self.started.elapsed().as_secs(), charge).map_err(|category| {
			tracing::warn!(
				event = "worker_budget_exhausted",
				category,
				worker_id = worker,
				"worker budget exhausted"
			);
			StatusCode::TOO_MANY_REQUESTS
		})
	}

	pub(crate) async fn enforce(
		&self, worker: i64, request: &mut Request,
	) -> Result<(), StatusCode> {
		self.charge(worker, Charge::Request)?;
		if request.method() == Method::POST && request.uri().path() == "/v1/jobs/lease" {
			self.charge(worker, Charge::Lease)?;
		}
		// Axum's existing JSON/Bytes extractor cap is 2 MiB. Keep that cap
		// while charging actual chunks even for handlers that ignore the body.
		const BODY_CAP: usize = 2 * 1024 * 1024;
		let body = std::mem::replace(request.body_mut(), Body::empty());
		let mut stream = body.into_data_stream();
		let mut buffered = Vec::new();
		while let Some(chunk) = stream.next().await {
			let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
			self.charge(worker, Charge::Bytes(chunk.len() as u64))?;
			if chunk.len() > BODY_CAP - buffered.len() {
				return Err(StatusCode::PAYLOAD_TOO_LARGE);
			}
			buffered.extend_from_slice(&chunk);
		}
		*request.body_mut() = Body::from(buffered);
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn backward_clock_and_overflow_never_mint_extra_credit() {
		let mut bucket = Budget { capacity: 10, remaining: 4, refill_per_second: 2, last: 10 };
		assert!(!bucket.admit(5, 5));
		assert_eq!((bucket.remaining, bucket.last), (4, 10));
		assert!(bucket.admit(11, 6));
		assert_eq!(bucket.remaining, 0);
		bucket.refill_per_second = u64::MAX;
		assert!(bucket.admit(u64::MAX, 10));
		assert_eq!(bucket.remaining, 0);
		assert!(!bucket.admit(0, 1));
	}

	#[test]
	fn concurrent_charges_share_one_atomic_balance() {
		let mut config = WorkerBudgetConfig::default();
		config.requests.capacity = 20;
		let budgets = std::sync::Arc::new(WorkerBudgets::new(config).unwrap());
		let threads: Vec<_> = (0..8)
			.map(|_| {
				let budgets = budgets.clone();
				std::thread::spawn(move || {
					(0..10).filter(|_| budgets.charge_at(7, 0, Charge::Request).is_ok()).count()
				})
			})
			.collect();
		let admitted: usize = threads.into_iter().map(|thread| thread.join().unwrap()).sum();
		assert_eq!(admitted, 20);
		assert!(budgets.charge_at(7, 0, Charge::Request).is_err());
		assert!(budgets.charge_at(7, 1, Charge::Request).is_ok());
	}

	#[test]
	fn retention_is_bounded_and_debt_cannot_be_reset_by_eviction() {
		let mut config =
			WorkerBudgetConfig { max_workers: 1, idle_seconds: 1, ..WorkerBudgetConfig::default() };
		config.bytes = BucketConfig { capacity: 1000, refill_per_second: 1 };
		let budgets = WorkerBudgets::new(config).unwrap();
		assert!(budgets.charge_at(1, 0, Charge::Bytes(1000)).is_ok());
		assert_eq!(budgets.charge_at(2, 1, Charge::Request), Err("workers"));
		assert_eq!(budgets.charge_at(1, 1, Charge::Bytes(2)), Err("bytes"));
		assert_eq!(budgets.entries.lock().unwrap().len(), 1);
		assert!(budgets.charge_at(2, 1001, Charge::Request).is_ok());
		assert_eq!(budgets.charge_at(1, 1001, Charge::Request), Err("workers"));
		assert_eq!(budgets.entries.lock().unwrap().len(), 1);
	}

	#[test]
	fn configuration_rejects_disabled_budgets_and_unknown_fields() {
		assert!(toml::from_str::<WorkerBudgetConfig>("unexpected = 1").is_err());
		let config: WorkerBudgetConfig =
			toml::from_str("max_workers = 2\n[requests]\ncapacity = 3\nrefill_per_second = 1")
				.unwrap();
		config.validate().unwrap();
		assert_eq!(config.requests.capacity, 3);
		for field in 0..8 {
			let mut config = WorkerBudgetConfig::default();
			match field {
				0 => config.max_workers = 0,
				1 => config.idle_seconds = 0,
				2 => config.requests.capacity = 0,
				3 => config.requests.refill_per_second = 0,
				4 => config.bytes.capacity = 0,
				5 => config.bytes.refill_per_second = 0,
				6 => config.leases.capacity = 0,
				_ => config.leases.refill_per_second = 0,
			}
			assert!(config.validate().is_err());
		}
	}
}
