//! Inventory chunking over admissible entry sizes: every batch stays within
//! the entry, canonical-byte and body limits, the batches cover the input
//! once and in order, and the split is deterministic.

use loupe_core::inventory_manifest::{MAX_CHUNK_BYTES, MAX_CHUNK_ENTRIES, MAX_PATH_BYTES};
use loupe_worker::inventory_fuzz::{chunks, EntrySize, BODY_CAP, FRAME_BYTES};

use crate::utils::test_logger;

const MAX_INPUT_ENTRIES: usize = 20_000;

/// Each 4-byte record is a path length, a mode and object-id choice, and a
/// repeat count, so a short input reaches several full batches.
fn sizes(data: &[u8]) -> Vec<EntrySize> {
	let mut sizes = Vec::new();
	for record in data.as_chunks::<4>().0 {
		let path = u64::from(u16::from_le_bytes([record[0], record[1]])) + 1;
		let path = path.min(MAX_PATH_BYTES as u64);
		let mode = [0o100644, 0o100755, 0o120000, 0o160000][usize::from(record[2] & 3)];
		let oid = if record[2] & 4 == 0 { 40 } else { 64 };
		let size = EntrySize::new(path, mode, oid);
		for _ in 0..=record[3] {
			if sizes.len() == MAX_INPUT_ENTRIES {
				return sizes;
			}
			sizes.push(size);
		}
	}
	sizes
}

pub fn do_test(data: &[u8]) {
	let sizes = sizes(data);
	let ranges = chunks(&sizes);
	assert_eq!(ranges, chunks(&sizes), "chunking is not deterministic");
	assert!(!ranges.is_empty(), "every inventory uploads at least one batch");
	let mut next = 0;
	for range in &ranges {
		assert_eq!(range.start, next, "batches must cover the entries in order");
		assert!(range.end >= range.start);
		assert!(range.end > range.start || sizes.is_empty(), "only an empty inventory is empty");
		let batch = &sizes[range.clone()];
		assert!(batch.len() <= MAX_CHUNK_ENTRIES);
		let canonical: u64 = batch.iter().map(|size| size.canonical).sum();
		assert!(canonical <= MAX_CHUNK_BYTES);
		let body: u64 = FRAME_BYTES
			+ batch.iter().map(|size| size.encoded).sum::<u64>()
			+ batch.len().saturating_sub(1) as u64;
		assert!(body < BODY_CAP);
		next = range.end;
	}
	assert_eq!(next, sizes.len(), "batches must cover every entry");
}

pub fn worker_inventory_chunks_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_inventory_chunks_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	#[test]
	fn seeds_hold_the_invariants() {
		super::do_test(&[]);
		super::do_test(&[0xff, 0xff, 7, 0xff]);
		super::do_test(&[0, 0, 0, 0xff].repeat(40));
	}
}
