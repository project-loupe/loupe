//! LLM token-usage accounting for funding / capacity planning.
//!
//! Codex `exec --json` emits `event_msg.token_count` events with
//! cumulative `total_token_usage` for the session. We parse those,
//! attach them to [`LlmResponse`], and append durable JSONL rows under
//! the worker cache so operators can answer "how many tokens did we
//! burn this week?" without scraping provider dashboards.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Token counters for one agent session (one file scan / one verify).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsage {
	pub input_tokens: u64,
	pub cached_input_tokens: u64,
	pub output_tokens: u64,
	pub reasoning_output_tokens: u64,
	pub total_tokens: u64,
}

impl TokenUsage {
	pub fn is_zero(&self) -> bool {
		self.total_tokens == 0
			&& self.input_tokens == 0
			&& self.output_tokens == 0
			&& self.cached_input_tokens == 0
			&& self.reasoning_output_tokens == 0
	}

	/// Prefer the richer cumulative snapshot when multiple token_count
	/// events arrive in one session (Codex reports running totals).
	pub fn prefer_richer(self, other: Self) -> Self {
		if other.total_tokens >= self.total_tokens {
			other
		} else {
			self
		}
	}
}

/// One append-only row written under `usage/llm-usage.jsonl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageEvent {
	pub ts_unix_ms: u64,
	pub backend: String,
	pub model: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub provider: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub repo_id: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub job_id: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub finding_id: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub file: Option<String>,
	pub ok: bool,
	pub elapsed_ms: u64,
	#[serde(flatten)]
	pub usage: TokenUsage,
	/// Best-effort USD estimate when unit prices are configured.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub estimated_usd: Option<f64>,
}

/// Process-wide recorder. Appends JSONL and keeps running totals for logs.
pub struct UsageRecorder {
	jsonl_path: PathBuf,
	summary_path: PathBuf,
	write_lock: Mutex<()>,
	sessions: AtomicU64,
	total_tokens: AtomicU64,
	input_tokens: AtomicU64,
	output_tokens: AtomicU64,
	/// Optional default USD / 1M tokens used when no per-model price matches.
	default_input_usd_per_mtok: Option<f64>,
	default_output_usd_per_mtok: Option<f64>,
}

impl UsageRecorder {
	pub fn open(cache_dir: &Path) -> anyhow::Result<Arc<Self>> {
		let dir = cache_dir.join("usage");
		std::fs::create_dir_all(&dir)?;
		let jsonl_path = dir.join("llm-usage.jsonl");
		let summary_path = dir.join("llm-usage-summary.json");
		// Optional crude pricing via env so funding estimates work without a
		// config-schema bump. Values are USD per 1M tokens.
		let default_input_usd_per_mtok =
			std::env::var("LOUPE_USAGE_INPUT_USD_PER_MTOK").ok().and_then(|s| s.parse().ok());
		let default_output_usd_per_mtok =
			std::env::var("LOUPE_USAGE_OUTPUT_USD_PER_MTOK").ok().and_then(|s| s.parse().ok());
		let me = Arc::new(Self {
			jsonl_path,
			summary_path,
			write_lock: Mutex::new(()),
			sessions: AtomicU64::new(0),
			total_tokens: AtomicU64::new(0),
			input_tokens: AtomicU64::new(0),
			output_tokens: AtomicU64::new(0),
			default_input_usd_per_mtok,
			default_output_usd_per_mtok,
		});
		// Seed in-memory totals from any existing JSONL so restarts don't
		// zero the funding counters operators already paid for.
		if let Err(e) = me.hydrate_from_disk() {
			tracing::warn!(error = %e, path = %me.jsonl_path.display(), "usage: could not hydrate prior totals");
		}
		tracing::info!(
			path = %me.jsonl_path.display(),
			sessions = me.sessions.load(Ordering::Relaxed),
			total_tokens = me.total_tokens.load(Ordering::Relaxed),
			"usage: recorder ready (JSONL + summary)"
		);
		Ok(me)
	}

	pub fn jsonl_path(&self) -> &Path {
		&self.jsonl_path
	}

	fn hydrate_from_disk(&self) -> anyhow::Result<()> {
		if !self.jsonl_path.exists() {
			return Ok(());
		}
		let text = std::fs::read_to_string(&self.jsonl_path)?;
		let mut sessions = 0u64;
		let mut input_tokens = 0u64;
		let mut output_tokens = 0u64;
		let mut total_tokens = 0u64;
		for line in text.lines() {
			let line = line.trim();
			if line.is_empty() {
				continue;
			}
			let ev: UsageEvent = match serde_json::from_str(line) {
				Ok(v) => v,
				Err(_) => continue,
			};
			sessions += 1;
			input_tokens = input_tokens.saturating_add(ev.usage.input_tokens);
			output_tokens = output_tokens
				.saturating_add(ev.usage.output_tokens)
				.saturating_add(ev.usage.reasoning_output_tokens);
			total_tokens = total_tokens.saturating_add(ev.usage.total_tokens);
		}
		self.sessions.store(sessions, Ordering::Relaxed);
		self.total_tokens.store(total_tokens, Ordering::Relaxed);
		self.input_tokens.store(input_tokens, Ordering::Relaxed);
		self.output_tokens.store(output_tokens, Ordering::Relaxed);
		Ok(())
	}

	pub fn estimate_usd(&self, usage: &TokenUsage) -> Option<f64> {
		let (Some(inp), Some(out)) =
			(self.default_input_usd_per_mtok, self.default_output_usd_per_mtok)
		else {
			return None;
		};
		// Bill uncached input + all output (incl. reasoning) at the output rate
		// when we lack a separate reasoning price. Cached input is treated as
		// free/cheap (0) unless operators set a dedicated price later.
		let uncached_input = usage.input_tokens.saturating_sub(usage.cached_input_tokens);
		let billable_output = usage.output_tokens.saturating_add(usage.reasoning_output_tokens);
		let usd = (uncached_input as f64) / 1_000_000.0 * inp
			+ (billable_output as f64) / 1_000_000.0 * out;
		Some(usd)
	}

	pub fn record(&self, mut event: UsageEvent) {
		if event.estimated_usd.is_none() {
			event.estimated_usd = self.estimate_usd(&event.usage);
		}
		self.sessions.fetch_add(1, Ordering::Relaxed);
		self.total_tokens.fetch_add(event.usage.total_tokens, Ordering::Relaxed);
		self.input_tokens.fetch_add(event.usage.input_tokens, Ordering::Relaxed);
		self.output_tokens.fetch_add(
			event.usage.output_tokens.saturating_add(event.usage.reasoning_output_tokens),
			Ordering::Relaxed,
		);

		let line = match serde_json::to_string(&event) {
			Ok(s) => s,
			Err(e) => {
				tracing::warn!(error = %e, "usage: failed to serialise event");
				return;
			},
		};

		let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
		if let Err(e) = (|| -> anyhow::Result<()> {
			let mut f = OpenOptions::new().create(true).append(true).open(&self.jsonl_path)?;
			f.write_all(line.as_bytes())?;
			f.write_all(b"\n")?;
			f.flush()?;
			// Rewrite a small summary snapshot for humans / funding decks.
			let summary = serde_json::json!({
				"updated_ts_unix_ms": now_ms(),
				"sessions": self.sessions.load(Ordering::Relaxed),
				"input_tokens": self.input_tokens.load(Ordering::Relaxed),
				"output_tokens": self.output_tokens.load(Ordering::Relaxed),
				"total_tokens": self.total_tokens.load(Ordering::Relaxed),
				"jsonl_path": self.jsonl_path.display().to_string(),
				"note": "Totals are cumulative across worker restarts (hydrated from JSONL). Set LOUPE_USAGE_INPUT_USD_PER_MTOK / LOUPE_USAGE_OUTPUT_USD_PER_MTOK for USD estimates.",
			});
			let tmp = self.summary_path.with_extension("json.tmp");
			let mut sf = File::create(&tmp)?;
			sf.write_all(serde_json::to_string_pretty(&summary)?.as_bytes())?;
			sf.write_all(b"\n")?;
			sf.flush()?;
			std::fs::rename(&tmp, &self.summary_path)?;
			Ok(())
		})() {
			tracing::warn!(error = %e, path = %self.jsonl_path.display(), "usage: failed to persist event");
		}

		tracing::info!(
			backend = %event.backend,
			model = %event.model,
			provider = ?event.provider,
			repo_id = ?event.repo_id,
			job_id = ?event.job_id,
			file = ?event.file,
			ok = event.ok,
			input_tokens = event.usage.input_tokens,
			cached_input_tokens = event.usage.cached_input_tokens,
			output_tokens = event.usage.output_tokens,
			reasoning_output_tokens = event.usage.reasoning_output_tokens,
			total_tokens = event.usage.total_tokens,
			estimated_usd = ?event.estimated_usd,
			cumulative_total_tokens = self.total_tokens.load(Ordering::Relaxed),
			cumulative_sessions = self.sessions.load(Ordering::Relaxed),
			"usage: session recorded"
		);
	}
}

pub fn now_ms() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Parse Codex `exec --json` JSONL stdout into (final text, token usage).
///
/// Usage: take the richest `payload.info.total_token_usage` across all
/// `token_count` events (Codex emits running session totals).
/// Text: last `agent_message` (prefer `phase == "final"` when present),
/// falling back to `task_complete.last_agent_message`.
pub fn parse_codex_jsonl(stdout: &str) -> (String, Option<TokenUsage>) {
	let mut usage = TokenUsage::default();
	let mut saw_usage = false;
	let mut last_msg: Option<String> = None;
	let mut last_final: Option<String> = None;
	let mut task_complete_msg: Option<String> = None;

	for line in stdout.lines() {
		let line = line.trim();
		if line.is_empty() {
			continue;
		}
		let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
			continue;
		};
		let typ = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
		if typ != "event_msg" {
			continue;
		}
		let Some(payload) = v.get("payload") else { continue };
		let ptype = payload.get("type").and_then(|t| t.as_str()).unwrap_or("");
		match ptype {
			"token_count" => {
				if let Some(u) = extract_total_token_usage(payload) {
					usage = if saw_usage { usage.prefer_richer(u) } else { u };
					saw_usage = true;
				}
			},
			"agent_message" => {
				if let Some(msg) = payload.get("message").and_then(|m| m.as_str()) {
					let phase = payload.get("phase").and_then(|p| p.as_str()).unwrap_or("");
					if phase == "final" {
						last_final = Some(msg.to_owned());
					}
					last_msg = Some(msg.to_owned());
				}
			},
			"task_complete" => {
				if let Some(msg) = payload.get("last_agent_message").and_then(|m| m.as_str()) {
					task_complete_msg = Some(msg.to_owned());
				}
			},
			_ => {},
		}
	}

	let text = last_final.or(last_msg).or(task_complete_msg).unwrap_or_default();
	(text, if saw_usage { Some(usage) } else { None })
}

fn extract_total_token_usage(payload: &serde_json::Value) -> Option<TokenUsage> {
	let info = payload.get("info")?;
	// Prefer cumulative total_token_usage; fall back to last_token_usage.
	let u = info
		.get("total_token_usage")
		.or_else(|| info.get("last_token_usage"))
		.or_else(|| payload.get("total_token_usage"))?;
	Some(TokenUsage {
		input_tokens: u.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
		cached_input_tokens: u.get("cached_input_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
		output_tokens: u.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
		reasoning_output_tokens: u
			.get("reasoning_output_tokens")
			.and_then(|v| v.as_u64())
			.unwrap_or(0),
		total_tokens: u.get("total_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
	})
}

/// Best-effort parse of ` usage={input:N,...}` notes we embed in codex
/// CLI error strings so failed sessions can still be attributed.
pub fn parse_usage_note_from_error(msg: &str) -> Option<TokenUsage> {
	let start = msg.find("usage={")?;
	let rest = &msg[start + "usage={".len()..];
	let end = rest.find('}')?;
	let body = &rest[..end];
	let mut u = TokenUsage::default();
	for part in body.split(',') {
		let mut kv = part.splitn(2, ':');
		let key = kv.next()?.trim();
		let val: u64 = kv.next()?.trim().parse().ok()?;
		match key {
			"input" => u.input_tokens = val,
			"cached_input" => u.cached_input_tokens = val,
			"output" => u.output_tokens = val,
			"reasoning_output" => u.reasoning_output_tokens = val,
			"total" => u.total_tokens = val,
			_ => {},
		}
	}
	if u.is_zero() {
		None
	} else {
		Some(u)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_token_count_and_prefers_richest_total() {
		let stdout = r#"
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100,"cached_input_tokens":10,"output_tokens":5,"reasoning_output_tokens":2,"total_tokens":105}}}}
{"type":"event_msg","payload":{"type":"agent_message","message":"working...","phase":"commentary"}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":500,"cached_input_tokens":200,"output_tokens":40,"reasoning_output_tokens":10,"total_tokens":540}}}}
{"type":"event_msg","payload":{"type":"agent_message","message":"done","phase":"final"}}
{"type":"event_msg","payload":{"type":"task_complete","last_agent_message":"done"}}
"#;
		let (text, usage) = parse_codex_jsonl(stdout);
		assert_eq!(text, "done");
		let u = usage.expect("usage");
		assert_eq!(u.total_tokens, 540);
		assert_eq!(u.input_tokens, 500);
		assert_eq!(u.cached_input_tokens, 200);
		assert_eq!(u.output_tokens, 40);
		assert_eq!(u.reasoning_output_tokens, 10);
	}

	#[test]
	fn ignores_non_json_noise() {
		let (text, usage) = parse_codex_jsonl("not json\n{\"type\":\"other\"}\n");
		assert!(text.is_empty());
		assert!(usage.is_none());
	}

	#[test]
	fn parses_usage_note_from_error() {
		let msg = "codex CLI exited with exit status: 1: blah usage={input:10,cached_input:2,output:3,reasoning_output:1,total:14}";
		let u = parse_usage_note_from_error(msg).unwrap();
		assert_eq!(u.total_tokens, 14);
		assert_eq!(u.input_tokens, 10);
	}

	#[test]
	fn recorder_persists_and_hydrates() {
		let dir = tempfile::tempdir().unwrap();
		let rec = UsageRecorder::open(dir.path()).unwrap();
		rec.record(UsageEvent {
			ts_unix_ms: 1,
			backend: "codex-cli".into(),
			model: "glm-5.2".into(),
			provider: Some("zai".into()),
			repo_id: Some(1),
			job_id: Some(2),
			finding_id: None,
			file: Some("src/lib.rs".into()),
			ok: true,
			elapsed_ms: 10,
			usage: TokenUsage {
				input_tokens: 1000,
				cached_input_tokens: 100,
				output_tokens: 50,
				reasoning_output_tokens: 10,
				total_tokens: 1050,
			},
			estimated_usd: None,
		});
		assert_eq!(rec.total_tokens.load(Ordering::Relaxed), 1050);
		assert!(rec.jsonl_path().exists());
		// New recorder hydrates.
		let rec2 = UsageRecorder::open(dir.path()).unwrap();
		assert_eq!(rec2.total_tokens.load(Ordering::Relaxed), 1050);
		assert_eq!(rec2.sessions.load(Ordering::Relaxed), 1);
	}
}
