//! Harness-only target for the byte cursor, runner and corpus replay.
//! It also serves as the template for additional targets.
//!
//! It fuzzes the harness's own [`ByteSource`] cursor: every field read
//! must either succeed within bounds or return `None`, never panic,
//! and `rest()` must hand back exactly what was not consumed.

use crate::utils::input::ByteSource;
use crate::utils::test_logger;

#[inline]
pub fn do_test(data: &[u8]) {
	let mut src = ByteSource::new(data);
	let mut consumed = 0usize;
	while let Some(op) = src.u8() {
		consumed += 1;
		match op % 4 {
			0 => {
				if src.u16().is_some() {
					consumed += 2;
				}
			},
			1 => {
				if src.u32().is_some() {
					consumed += 4;
				}
			},
			2 => {
				let before = src.remaining();
				if let Some(s) = src.len_prefixed(64) {
					assert!(s.len() <= 64);
					consumed += before - src.remaining();
				} else if before >= 2 {
					// The length prefix was read but the body was short.
					consumed += 2;
				}
			},
			_ => {
				let n = usize::from(op);
				let before = src.remaining();
				if let Some(s) = src.take(n) {
					assert_eq!(s.len(), n);
					consumed += n;
				} else {
					assert!(before < n);
				}
			},
		}
		assert_eq!(src.remaining(), data.len() - consumed);
	}
	assert_eq!(src.rest(), &data[consumed..]);
	assert!(src.is_empty());
}

pub fn smoke_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// Entry point for external fuzzers driving the static library through
/// `targets.h`.
///
/// # Safety
///
/// `data` must point to `datalen` readable bytes that stay alive for
/// the duration of the call.
#[allow(unsafe_code)] // the C entry point takes a raw pointer from the fuzzer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn smoke_run(data: *const u8, datalen: usize) {
	// SAFETY: guaranteed by the caller, see the function's contract.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
