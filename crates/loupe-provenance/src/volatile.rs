//! The one place in the crate that uses `unsafe`: overwriting bytes
//! through volatile stores so the optimiser cannot drop them as dead
//! writes to memory that is about to be freed.
//!
//! Why `unsafe` is needed at all: a plain `b = 0` loop before a
//! deallocation is a dead store and LLVM removes it. The documented
//! way to keep it is `core::ptr::write_volatile`, which is `unsafe`
//! because it takes a raw pointer. The pointer here comes from a
//! `&mut u8` inside a `&mut [u8]`, so it is valid, aligned, exclusive
//! and initialised by construction; the `unsafe` block adds no
//! obligation the borrow checker has not already discharged. The
//! `compiler_fence` afterwards keeps later memory operations from
//! being reordered before the stores.
//!
//! This is the one memory-unsafe exception to the workspace's "no
//! unsafe" rule. The module is kept to this one function so it can be read in full
//! in a review
//! and run under Miri (`cargo miri test -p loupe-provenance`).
#![allow(unsafe_code)]

use core::sync::atomic::{compiler_fence, Ordering};

/// Overwrite every byte of `bytes` with zero through volatile writes.
/// Never panics; an empty slice is a no-op.
pub(crate) fn zero_bytes(bytes: &mut [u8]) {
	for byte in bytes.iter_mut() {
		// SAFETY: `byte` is a `&mut u8` obtained from iterating a
		// `&mut [u8]`, so the pointer derived from it is non-null,
		// aligned for `u8`, points to initialised memory, and is not
		// aliased for the duration of the write. `write_volatile`
		// requires exactly these; no uninitialised memory and no
		// other reference is involved.
		unsafe { core::ptr::write_volatile(byte, 0) };
	}
	compiler_fence(Ordering::SeqCst);
}
