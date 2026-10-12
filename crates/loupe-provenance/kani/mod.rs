//! Kani harnesses. Included from lib.rs as `#[cfg(kani)] mod kani;`
//! with `#[path = "../kani/mod.rs"]`. Each harness states its bound
//! and why that bound reaches the property. Run only through
//! `ci/kani.sh -p loupe-provenance`, never `cargo kani` directly.
//!
//! Slices and arrays are bounded at 32 bytes; allocation-bearing
//! operations use lengths/capacities through 8. Ranges, split positions
//! and discard counts remain unconstrained `usize`s, covering reversed
//! and out-of-bounds ranges as well as valid boundaries. These are
//! bounded verdicts, not an induction over arbitrary allocation sizes.
//! Covers witness empty and nonempty inputs and the relevant branches.
//! Zeroise assertions observe resulting bytes; the Vec harness observes
//! emptiness and retained capacity, not freed memory or optimiser output.

use alloc::vec::Vec;

use crate::{Agent, Secret, Untrusted, Unvalidated, ValidateCarrying, Worker, Zeroise};

/// Largest slice length proven. See the module doc for why.
const MAX_LEN: usize = 32;

/// Largest `Vec` capacity proven.
const MAX_CAP: usize = 8;

/// A symbolic slice of `buf` with any length from 0 to `MAX_LEN`.
fn any_prefix(buf: &[u8; MAX_LEN]) -> &[u8] {
	let len: usize = kani::any();
	kani::assume(len <= MAX_LEN);
	// `get` rather than indexing so the harness itself cannot be the
	// thing that panics; the assume above makes `None` unreachable.
	buf.get(..len).unwrap_or(&[])
}

#[kani::proof]
#[kani::unwind(34)]
fn len_and_is_empty_never_panic() {
	let buf: [u8; MAX_LEN] = kani::any();
	let slice = any_prefix(&buf);
	let u = Untrusted::new(slice, minted_ingress::<Worker>());
	assert_eq!(u.len(), slice.len());
	assert_eq!(u.is_empty(), slice.is_empty());
	kani::cover!(slice.is_empty());
	kani::cover!(slice.len() == MAX_LEN);
}

#[kani::proof]
#[kani::unwind(34)]
fn map_ref_never_panics_and_preserves_length() {
	let buf: [u8; MAX_LEN] = kani::any();
	let slice = any_prefix(&buf);
	let u = Untrusted::new(slice, minted_ingress::<Worker>());

	// Identity projection keeps the length.
	let same = u.map_ref(|s| *s);
	assert_eq!(same.len(), u.len());

	// A symbolic sub-range, taken with `get` as every parser must,
	// yields exactly that many bytes when it is in range and an empty
	// view otherwise, never a panic. Both branches are reachable: the
	// range is unconstrained.
	let start: usize = kani::any();
	let end: usize = kani::any();
	let sub = u.map_ref(|s| s.get(start..end).unwrap_or(&[]));
	let expected = match end.checked_sub(start) {
		Some(n) if end <= slice.len() => n,
		_ => 0,
	};
	assert_eq!(sub.len(), expected);
	kani::cover!(slice.len() == MAX_LEN && start == 1 && end == MAX_LEN);
	kani::cover!(slice.is_empty() && start == 0 && end == 0);
	kani::cover!(start > end);
	kani::cover!(end > slice.len());
}

#[kani::proof]
#[kani::unwind(34)]
fn split_at_never_panics_and_partitions_the_slice() {
	let buf: [u8; MAX_LEN] = kani::any();
	let slice = any_prefix(&buf);
	let u = Untrusted::new(slice, minted_ingress::<Worker>());
	// `mid` is unconstrained: in range it partitions, out of range it
	// is `None`; neither panics.
	let mid: usize = kani::any();
	match u.split_at(mid) {
		Some((head, tail)) => {
			assert!(mid <= slice.len());
			assert_eq!(head.len(), mid);
			assert_eq!(head.len().saturating_add(tail.len()), slice.len());
			kani::cover!(mid == 0 && slice.is_empty());
			kani::cover!(mid > 0 && mid < slice.len());
			kani::cover!(mid == MAX_LEN);
		},
		None => {
			assert!(mid > slice.len());
			kani::cover!(mid == usize::MAX);
		},
	}
}

#[kani::proof]
#[kani::unwind(34)]
fn zeroise_writes_every_byte_of_an_array() {
	let mut arr: [u8; MAX_LEN] = kani::any();
	let had_nonzero = arr.iter().any(|byte| *byte != 0);
	arr.zeroise();
	assert!(arr.iter().all(|b| *b == 0));
	kani::cover!(had_nonzero);
}

#[kani::proof]
#[kani::unwind(34)]
fn zeroise_writes_every_byte_of_a_slice() {
	let mut buf: [u8; MAX_LEN] = kani::any();
	let len: usize = kani::any();
	kani::assume(len <= MAX_LEN);
	let slice: &mut [u8] = buf.get_mut(..len).unwrap_or(&mut []);
	let had_nonzero = slice.iter().any(|byte| *byte != 0);
	slice.zeroise();
	assert!(slice.iter().all(|b| *b == 0));
	kani::cover!(len == 0);
	kani::cover!(len == MAX_LEN && had_nonzero);
}

/// Dropping a `Secret` runs the zeroiser over the bytes it holds.
/// Observed through a borrowing wrapper, as in the unit tests, because
/// memory an owned value frees cannot be read back afterwards.
#[kani::proof]
#[kani::unwind(34)]
fn secret_drop_zeroises_the_borrowed_bytes() {
	struct Borrowed<'a>(&'a mut [u8]);
	impl Zeroise for Borrowed<'_> {
		fn zeroise(&mut self) {
			self.0.zeroise();
		}
	}

	let mut buf: [u8; MAX_LEN] = kani::any();
	let len: usize = kani::any();
	kani::assume(len <= MAX_LEN);
	let had_nonzero = buf.iter().take(len).any(|byte| *byte != 0);
	{
		let slice: &mut [u8] = buf.get_mut(..len).unwrap_or(&mut []);
		drop(Secret::new(Borrowed(slice)));
	}
	assert!(buf.iter().take(len).all(|b| *b == 0));
	kani::cover!(len == 0);
	kani::cover!(len == MAX_LEN && had_nonzero);
}

#[kani::proof]
#[kani::unwind(10)]
fn zeroise_of_a_vec_empties_it_and_keeps_capacity() {
	let cap: usize = kani::any();
	kani::assume(cap <= MAX_CAP);
	let len: usize = kani::any();
	kani::assume(len <= cap);
	let mut v: Vec<u8> = Vec::with_capacity(cap);
	for _ in 0..len {
		v.push(kani::any());
	}
	let capacity = v.capacity();
	v.zeroise();
	assert!(v.is_empty());
	assert_eq!(v.capacity(), capacity);
	kani::cover!(cap == 0);
	kani::cover!(cap == MAX_CAP && len == MAX_CAP);
	kani::cover!(cap == MAX_CAP && len > 0 && len < cap);
}

/// Carries a symbolic range of its input on as `Agent`.
struct CarryRange {
	start: usize,
	end: usize,
}

impl<'a> ValidateCarrying<&'a [u8], Worker> for CarryRange {
	type Output = Option<Untrusted<&'a [u8], Agent>>;
	type Error = ();

	fn validate(self, u: Unvalidated<'_, &'a [u8], Worker>) -> Result<Self::Output, ()> {
		Ok(u.carry::<Agent>(self.start..self.end))
	}
}

#[kani::proof]
#[kani::unwind(34)]
fn carry_and_to_vec_never_panic() {
	let buf: [u8; MAX_LEN] = kani::any();
	let slice = any_prefix(&buf);
	let u = Untrusted::new(slice, minted_ingress::<Worker>());
	// The range is unconstrained: in range it yields exactly that many
	// bytes, reversed or past the end it is `None`; neither panics.
	let start: usize = kani::any();
	let end: usize = kani::any();
	match u.validate_carrying(CarryRange { start, end }) {
		Ok(Some(c)) => {
			assert!(start <= end && end <= slice.len());
			assert_eq!(c.len(), end.wrapping_sub(start));
			kani::cover!(slice.len() == MAX_LEN && start == 1 && end == MAX_LEN);
			kani::cover!(slice.is_empty() && start == 0 && end == 0);
		},
		Ok(None) => {
			assert!(start > end || end > slice.len());
			kani::cover!(start > end);
			kani::cover!(end > slice.len());
		},
		// The validator never fails.
		Err(()) => {},
	}
}

#[kani::proof]
#[kani::unwind(10)]
fn to_vec_keeps_the_length() {
	let buf: [u8; MAX_CAP] = kani::any();
	let len: usize = kani::any();
	kani::assume(len <= MAX_CAP);
	let slice = buf.get(..len).unwrap_or(&[]);
	let u = Untrusted::new(slice, minted_ingress::<Worker>());
	assert_eq!(u.to_vec().len(), len);
	kani::cover!(len == 0);
	kani::cover!(len == MAX_CAP);
}

#[kani::proof]
#[kani::unwind(10)]
fn receive_buffer_operations_never_panic() {
	let buf: [u8; MAX_CAP] = kani::any();
	let len: usize = kani::any();
	kani::assume(len <= MAX_CAP);
	let slice = buf.get(..len).unwrap_or(&[]);
	let mut b = Untrusted::new(Vec::new(), minted_ingress::<Worker>());
	b.extend(Untrusted::new(slice, minted_ingress::<Worker>()));
	let at: usize = kani::any();
	match b.split_off(at) {
		Some(t) => {
			assert_eq!(b.len().wrapping_add(t.len()), len);
			kani::cover!(len == 0 && at == 0);
			kani::cover!(len == MAX_CAP && at > 0 && at < len);
		},
		None => {
			assert!(at > len && b.len() == len);
			kani::cover!(at == usize::MAX);
		},
	}
	let n: usize = kani::any();
	let before = b.len();
	b.discard_front(n);
	assert_eq!(b.len(), before.saturating_sub(n));
	kani::cover!(before > 1 && n > 0 && n < before);
	kani::cover!(before == MAX_CAP && n == usize::MAX);
}

/// Labelled input for this harness. Only synthetic fixture bytes may be minted.
#[allow(unsafe_code)]
fn minted_ingress<S: crate::Source>() -> crate::Ingress<S> {
	// SAFETY: test fixture: the label marks bytes this test made up; no production
	// path receives them.
	unsafe { crate::Ingress::new() }
}
