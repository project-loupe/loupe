//! A cursor over the fuzzer's input for stateful targets.
//!
//! Single-shot targets (decode one DTO, one tool call) take the
//! whole input as the thing to parse. Stateful targets (a session with
//! a server, a sync loop) need to draw several values from one input:
//! "which command next", "how many bytes of server reply", and the
//! bytes themselves. [`ByteSource`] gives them that in a form every
//! fuzzer backend can mutate well: fixed-width little-endian fields
//! and length-prefixed slices, consumed in order, with `None` when the
//! input runs out so a target can stop cleanly instead of panicking.

pub struct ByteSource<'a> {
	data: &'a [u8],
	pos: usize,
}

impl<'a> ByteSource<'a> {
	pub fn new(data: &'a [u8]) -> Self {
		ByteSource { data, pos: 0 }
	}

	pub fn remaining(&self) -> usize {
		self.data.len() - self.pos
	}

	pub fn is_empty(&self) -> bool {
		self.remaining() == 0
	}

	/// The next `len` bytes, or `None` if fewer remain.
	pub fn take(&mut self, len: usize) -> Option<&'a [u8]> {
		if self.remaining() < len {
			return None;
		}
		let s = &self.data[self.pos..self.pos + len];
		self.pos += len;
		Some(s)
	}

	pub fn u8(&mut self) -> Option<u8> {
		self.take(1).map(|s| s[0])
	}

	pub fn u16(&mut self) -> Option<u16> {
		self.take(2).map(|s| u16::from_le_bytes([s[0], s[1]]))
	}

	pub fn u32(&mut self) -> Option<u32> {
		self.take(4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
	}

	/// A slice whose length is given by a leading u16, capped at `max`
	/// so a target cannot be asked to allocate the whole input at once.
	pub fn len_prefixed(&mut self, max: usize) -> Option<&'a [u8]> {
		let len = usize::from(self.u16()?).min(max);
		self.take(len)
	}

	/// Everything that is left. Consumes the source.
	pub fn rest(&mut self) -> &'a [u8] {
		let s = &self.data[self.pos..];
		self.pos = self.data.len();
		s
	}
}

#[cfg(test)]
mod tests {
	use super::ByteSource;

	#[test]
	fn fields_are_consumed_in_order_and_bounded() {
		let mut s = ByteSource::new(&[1, 2, 0, 3, 0, 9, 9, 9, 7]);
		assert_eq!(s.u8(), Some(1));
		assert_eq!(s.u16(), Some(2));
		assert_eq!(s.len_prefixed(2), Some(&[9, 9][..]));
		assert_eq!(s.rest(), &[9, 7]);
		assert!(s.is_empty());
		assert_eq!(s.u8(), None);
	}
}
