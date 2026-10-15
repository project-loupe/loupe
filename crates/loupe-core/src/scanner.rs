//! Opaque scanner configuration forwarded through its named domain endpoints.
//!
//! This document admits arbitrary JSON with last-key-wins behavior.
//! It is not semantic Payload and supplies no general Value extraction. Worker
//! operational settings are a separate, explicitly validated projection.

use std::marker::PhantomData;

use loupe_provenance::{Config, Db, Mark, Operator, Server, Source};
use serde::{Serialize, Serializer};
use serde_json::Value;

pub struct ScannerDocument<S: Source> {
	value: Value,
	source: PhantomData<S>,
}

// Only the four actual decoder owners can construct this forwarding document.
// Each call moves the already decoded field under its enclosing validation
// mark; the enclosing decoder retains the original JSON recursion budget.
macro_rules! decoded {
	($source:ty, $method:ident) => {
		impl ScannerDocument<$source> {
			pub fn $method(_: &Mark<'_, $source>, value: Value) -> Self {
				Self { value, source: PhantomData }
			}
		}
	};
}
decoded!(Config, configured);
decoded!(Operator, registered);
decoded!(Db, stored);
decoded!(Server, leased);

impl<S: Source> ScannerDocument<S> {
	/// The registration wire format omits only a null document.
	pub fn is_null(&self) -> bool {
		self.value.is_null()
	}
}
impl<S: Source> Clone for ScannerDocument<S> {
	fn clone(&self) -> Self {
		Self { value: self.value.clone(), source: PhantomData }
	}
}
impl<S: Source> PartialEq for ScannerDocument<S> {
	fn eq(&self, other: &Self) -> bool {
		self.value == other.value
	}
}
impl<S: Source> Eq for ScannerDocument<S> {}
impl<S: Source> std::fmt::Debug for ScannerDocument<S> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "ScannerDocument<{}>([redacted])", S::NAME)
	}
}
impl<S: Source> Serialize for ScannerDocument<S> {
	fn serialize<T: Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
		self.value.serialize(serializer)
	}
}
