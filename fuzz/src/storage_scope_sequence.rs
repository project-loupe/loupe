//! Bounded operation sequences over the actual storage authority/receipt APIs.
//! The storage-owned driver exports only a byte-slice exercise entry point.
use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	loupe_storage::scope_sequence_fuzz::exercise(data);
}

pub fn storage_scope_sequence_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn storage_scope_sequence_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
