//! Output sinks for fuzz targets. Fuzzing runs write nowhere; corpus
//! replay under `cargo test` captures output per case so a failing case
//! prints only its own log; the stdin runner writes to stdout.

use std::io::Write;
use std::sync::{Arc, Mutex};

pub trait Output: Clone + 'static {
	fn locked_write(&self, data: &[u8]);
}

#[derive(Clone)]
pub struct DevNull {}
impl Output for DevNull {
	fn locked_write(&self, _data: &[u8]) {}
}

#[derive(Clone)]
pub struct Stdout {}
impl Output for Stdout {
	fn locked_write(&self, data: &[u8]) {
		// Diagnostics only: a closed stdout must not turn into a crash
		// that the fuzzer would then report as a finding.
		let _ = std::io::stdout().write_all(data);
	}
}

#[derive(Clone, Default)]
pub struct StringBuffer(Arc<Mutex<String>>);
impl Output for StringBuffer {
	fn locked_write(&self, data: &[u8]) {
		// A poisoned lock still holds the text written so far.
		let mut buf = self.0.lock().unwrap_or_else(|e| e.into_inner());
		buf.push_str(&String::from_utf8_lossy(data));
	}
}
impl StringBuffer {
	pub fn new() -> Self {
		Self::default()
	}

	/// The captured text. Works whether or not other clones still exist
	/// and whether or not the lock was poisoned by a panicking target.
	pub fn into_string(self) -> String {
		match Arc::try_unwrap(self.0) {
			Ok(m) => m.into_inner().unwrap_or_else(|e| e.into_inner()),
			Err(arc) => arc.lock().unwrap_or_else(|e| e.into_inner()).clone(),
		}
	}
}

/// A `std::io::Write` adapter over an [`Output`], for targets that want
/// to `writeln!` diagnostics.
pub struct WriteAdapter<'a, Out: Output>(pub &'a Out);
impl<Out: Output> Write for WriteAdapter<'_, Out> {
	fn write(&mut self, data: &[u8]) -> Result<usize, std::io::Error> {
		self.0.locked_write(data);
		Ok(data.len())
	}
	fn flush(&mut self) -> Result<(), std::io::Error> {
		Ok(())
	}
}
