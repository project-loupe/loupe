//! `Secret<T>`: a value that must not be printed and is wiped on drop.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::{volatile, Source, Untrusted};

/// A value whose bytes can be overwritten with zero in place.
///
/// Implemented for the byte-shaped types credentials are kept in. Implement it for a struct by zeroising each field. The
/// contract: after `zeroise` returns, every byte the value owns is
/// zero, including, for growable containers, the spare capacity.
/// `Vec` and `String` are left empty with their capacity intact.
pub trait Zeroise {
	/// Overwrite every byte this value owns with zero, through writes
	/// the optimiser cannot elide.
	fn zeroise(&mut self);
}

impl Zeroise for [u8] {
	fn zeroise(&mut self) {
		volatile::zero_bytes(self);
	}
}

impl<const N: usize> Zeroise for [u8; N] {
	fn zeroise(&mut self) {
		volatile::zero_bytes(self);
	}
}

impl Zeroise for Box<[u8]> {
	fn zeroise(&mut self) {
		volatile::zero_bytes(self);
	}
}

impl Zeroise for Vec<u8> {
	/// Wipes the whole capacity, not only the initialised prefix:
	/// `clear` and `truncate` leave old bytes in the spare part. The
	/// buffer is first extended to its capacity (no reallocation,
	/// since `len <= capacity`) so the volatile pass covers it
	/// entirely with safe code, then emptied.
	fn zeroise(&mut self) {
		self.resize(self.capacity(), 0);
		volatile::zero_bytes(self.as_mut_slice());
		self.clear();
	}
}

/// An untrusted value can be a secret too (a provider's token response
/// is both hostile and confidential). Zeroising writes and never
/// reads, so this exposes nothing; `Secret<Untrusted<Vec<u8>,
/// Provider>>` then wipes on drop and still has to be validated to be
/// read.
impl<T: Zeroise, S: Source> Zeroise for Untrusted<T, S> {
	fn zeroise(&mut self) {
		self.value_mut().zeroise();
	}
}

impl Zeroise for String {
	/// Wipes through the byte vector, which is the whole allocation.
	/// The (now empty) buffer is put back so the capacity is kept,
	/// like `Vec`.
	fn zeroise(&mut self) {
		let mut bytes = core::mem::take(self).into_bytes();
		bytes.zeroise();
		// An empty vector is valid UTF-8; `from_utf8` cannot fail on it,
		// and if it ever did the fallback is an empty string, which is
		// the same observable state minus the retained capacity.
		*self = String::from_utf8(bytes).unwrap_or_default();
	}
}

/// A secret: a credential, a token, key material, a capability.
///
/// `Debug` and `Display` print `[redacted]`. [`expose`](Self::expose)
/// is the only way to the value and its name is meant to be grepped
/// for. `Drop` zeroises the value through [`Zeroise`].
///
/// What the wipe promises: at drop, the bytes the wrapped value owns
/// at that moment are overwritten with zero, including a `Vec`'s or
/// `String`'s spare capacity. What it does not promise: copies the
/// compiler made (a move of a by-value secret, a register spill) or a
/// reallocation `Vec` performed before the value was wrapped. A
/// `Secret` that is never dropped (`mem::forget`, `ManuallyDrop`,
/// `Box::leak`) is never wiped. A container of by-value secrets
/// (`Vec<Secret<[u8; N]>>`) that grows copies them with `memcpy` and
/// leaves the old buffer unwiped. Keep large or long-lived secrets in
/// `Secret<Vec<u8>>` or `Secret<Box<[u8]>>` so that moving the wrapper
/// moves a pointer and not the bytes, and wrap as early as possible.
///
/// ```
/// use loupe_provenance::Secret;
///
/// let password = Secret::new(String::from("hunter2"));
/// assert_eq!(format!("{password:?}"), "[redacted]");
/// assert_eq!(format!("{password}"), "[redacted]");
/// assert_eq!(password.expose(), "hunter2");
/// ```
///
/// There is no `Deref`, `AsRef`, `Clone` or `PartialEq`, and no public
/// field; the compile-fail tests in `src/compile_fail.rs` prove each.
pub struct Secret<T: Zeroise> {
	value: T,
}

impl<T: Zeroise> Secret<T> {
	/// Wrap a secret. Do this as early as possible after the bytes
	/// exist, so no unwrapped copy is left behind.
	#[must_use]
	pub const fn new(value: T) -> Self {
		Secret { value }
	}

	/// The only accessor. Every call site is a place where the secret
	/// is used, and the name is chosen so they can be listed.
	pub const fn expose(&self) -> &T {
		&self.value
	}
}

impl<T: Zeroise> Drop for Secret<T> {
	fn drop(&mut self) {
		self.value.zeroise();
	}
}

impl<T: Zeroise> fmt::Debug for Secret<T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("[redacted]")
	}
}

impl<T: Zeroise> fmt::Display for Secret<T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("[redacted]")
	}
}
