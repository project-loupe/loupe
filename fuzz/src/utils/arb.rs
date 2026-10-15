//! Structure-aware input for typed, stateful targets.
//!
//! A byte-cursor target ([`super::input::ByteSource`]) is right for
//! parsers: the attacker controls bytes. A target over Loupe's own
//! types (a sequence of state transitions, a policy snapshot, a tool
//! call) mutates far better when the fuzzer sees the structure, which
//! `arbitrary` gives it. Both read the same raw bytes, so corpus files
//! stay plain files and the stdin runner replays them unchanged.

use arbitrary::{Arbitrary, Unstructured};

/// A cursor over the fuzzer's bytes for `Arbitrary` types.
pub fn unstructured(data: &[u8]) -> Unstructured<'_> {
	Unstructured::new(data)
}

/// Draw one value, or `None` when the input is exhausted. A target
/// returns cleanly on `None`; a short input is not a finding.
///
/// `arbitrary` itself never fails on short input: it pads with zero
/// bytes and returns a value. The emptiness check is what gives a
/// stateful target a stopping condition tied to the input.
pub fn draw<'a, T: Arbitrary<'a>>(u: &mut Unstructured<'a>) -> Option<T> {
	if u.is_empty() {
		return None;
	}
	T::arbitrary(u).ok()
}

/// Draw up to `max` values, stopping when the input is exhausted, so a
/// stateful target never loops past its input.
pub fn draw_up_to<'a, T: Arbitrary<'a>>(u: &mut Unstructured<'a>, max: usize) -> Vec<T> {
	let mut out = Vec::with_capacity(max.min(64));
	while out.len() < max {
		match draw(u) {
			Some(v) => out.push(v),
			None => break,
		}
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn draws_stop_at_the_end_of_the_input() {
		let data = [1u8, 2, 3];
		let mut u = unstructured(&data);
		let values: Vec<u8> = draw_up_to(&mut u, 10);
		assert_eq!(values.len(), 3);
		assert!(draw::<u64>(&mut u).is_none(), "exhausted input yields None");
	}
}
