//! Raw JSON/SSE provider bytes, bounded by the default 32 MiB output ceiling.
//! Accounting uses an iterative independent walk; serde's recursion limit stays
//! enabled. The pure accounting/header paths have an empty log baseline.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use loupe_worker::llm::model_broker::fuzzing;
use serde_json::Value;

use crate::utils::test_logger;
use crate::worker_broker_policy::{connection_names, headers, hop_by_hop};

#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);
impl Write for LogCapture {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		let mut log = self.0.lock().unwrap_or_else(|_| panic!("log capture poisoned"));
		// A log emitted by these pure paths already violates the empty baseline;
		// retain a bounded prefix rather than permitting a diagnostic memory flood.
		let retain = bytes.len().min(1024_usize.saturating_sub(log.len()));
		log.extend_from_slice(&bytes[..retain]);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

pub fn do_test(data: &[u8]) {
	if data.len() > 32 * 1024 * 1024 {
		return;
	}
	let log = LogCapture::default();
	let writer = log.clone();
	let subscriber = tracing_subscriber::fmt()
		.with_max_level(tracing::Level::TRACE)
		.without_time()
		.with_ansi(false)
		.with_writer(move || writer.clone())
		.finish();
	let _guard = tracing::subscriber::set_default(subscriber);
	let chunk_size =
		(usize::from(data.first().copied().unwrap_or(0)) + 1).max(data.len() / 1024 + 1);
	let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
	for (initial, ceiling) in [
		(0, 0),
		(0, data.len() as u64 / 2),
		(0, data.len() as u64),
		(17, data.len() as u64 + 18),
		(u64::MAX, u64::MAX),
	] {
		check_chunks(&chunks, initial, ceiling);
	}
	check_chunks(&[data], 0, u64::MAX);
	// A zero reservation ends the stream, even for an empty transport chunk.
	check_chunks(&[b"", data], 0, u64::MAX);
	let headers = headers(data);
	let connection = connection_names(&headers);
	let actual = fuzzing::response_headers(&headers);
	let mut expected = hyper::HeaderMap::new();
	for (name, value) in &headers {
		if name.as_str() != "content-length"
			&& !hop_by_hop(name.as_str())
			&& !connection.contains(name)
		{
			expected.append(name.clone(), value.clone());
		}
	}
	assert_eq!(actual, expected, "response header filtering differs from oracle");
	assert!(
		log.0.lock().unwrap_or_else(|_| panic!("log capture poisoned")).is_empty(),
		"pure provider-byte parsing emitted a log"
	);
}

fn check_chunks(chunks: &[&[u8]], initial: u64, ceiling: u64) {
	let actual = fuzzing::provider_chunks(chunks, initial, ceiling);
	let mut total = u128::from(initial);
	let mut expected = Vec::new();
	let mut overflow = false;
	for chunk in chunks {
		let remaining = u128::from(ceiling).saturating_sub(total);
		let admitted = remaining.min(chunk.len() as u128) as usize;
		expected.extend_from_slice(&chunk[..admitted]);
		total += admitted as u128;
		if admitted == 0 || admitted < chunk.len() {
			overflow = true;
			break;
		}
	}
	assert_eq!(actual.forwarded, expected, "Provider forwarding differs from reservation prefix");
	assert_eq!(
		actual.captured, expected,
		"Provider capture included discarded bytes or lost admitted bytes"
	);
	assert_eq!(actual.output_total as u128, total, "Provider counter differs from admitted bytes");
	assert_eq!(actual.overflow, overflow, "Provider overflow decision differs");
	assert_eq!(
		actual.tokens,
		oracle(&expected),
		"Provider usage was not computed on the exact capture"
	);
}

fn oracle(data: &[u8]) -> u64 {
	let mut maxima = [0_u64; 3];
	if let Ok(value) = serde_json::from_slice::<Value>(data) {
		observe(&value, &mut maxima);
	} else if let Ok(text) = std::str::from_utf8(data) {
		for line in text.lines().filter(|line| line.starts_with("data:")) {
			if let Some(raw) = line.get(5..)
				&& let Ok(value) = serde_json::from_str::<Value>(raw.trim())
			{
				observe(&value, &mut maxima);
			}
		}
	}
	u64::try_from((u128::from(maxima[0]) + u128::from(maxima[1])).max(u128::from(maxima[2])))
		.unwrap_or(u64::MAX)
}

fn observe(root: &Value, maxima: &mut [u64; 3]) {
	let mut pending = vec![root];
	while let Some(value) = pending.pop() {
		match value {
			Value::Array(items) => pending.extend(items),
			Value::Object(fields) => {
				for (name, child) in fields {
					if name == "usage"
						&& let Some(usage) = child.as_object()
					{
						for (index, key) in ["input_tokens", "output_tokens", "total_tokens"]
							.into_iter()
							.enumerate()
						{
							if let Some(number) = usage.get(key).and_then(Value::as_u64) {
								maxima[index] = maxima[index].max(number);
							}
						}
					}
					pending.push(child);
				}
			},
			_ => {},
		}
	}
}

pub fn worker_broker_usage_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_broker_usage_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	#[test]
	fn original_provider_chunks_reserve_before_capture_and_usage() {
		for body in [
			b"".as_slice(),
			b"abc",
			br#"{"usage":{"input_tokens":3,"output_tokens":7}}"#,
			b"data: {\"usage\":{\"total_tokens\":11}}\n\ndata: [DONE]\n",
			br#"{"usage":{"input_tokens":18446744073709551615,"output_tokens":1}}"#,
		] {
			super::do_test(body);
		}
		let body = br#"{"usage":{"total_tokens":17}}"#;
		for split in 1..body.len() {
			for limit in [0, 1, body.len() - 1, body.len(), body.len() + 1] {
				super::check_chunks(&[&body[..split], &body[split..]], 3, limit as u64 + 3);
			}
		}
	}
}
