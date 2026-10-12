//! Synthetic labelled values for wire serialization tests, never a wire decoder.

use loupe_core::text::{BoundedText, RepoPath, TextPolicy};
use loupe_core::ScannerDocument;
use loupe_provenance::{Ingress, Mark, Server, Untrusted, Unvalidated, Validate};

struct Fixture<F>(F);
impl<F, T> Validate<&str, Server> for Fixture<F>
where
	F: for<'a> FnOnce(&'a str, &Mark<'a, Server>) -> T,
{
	type Output = T;
	type Error = std::convert::Infallible;
	fn validate<'a>(
		self, raw: Unvalidated<'a, &str>, mark: Mark<'a, Server>,
	) -> Result<T, Self::Error> {
		Ok((self.0)(raw.get(), &mark))
	}
}

#[allow(unsafe_code)]
fn fixture<T>(raw: &str, f: impl for<'a> FnOnce(&'a str, &Mark<'a, Server>) -> T) -> T {
	// SAFETY: this module exists only in test binaries and labels their synthetic
	// fixtures. It is not exported by the library or used for input admission.
	Untrusted::new(raw, unsafe { Ingress::<Server>::new() }).validate(Fixture(f)).unwrap()
}

pub fn text<P: TextPolicy>(raw: &str) -> BoundedText<P, Server> {
	fixture(raw, |raw, mark| BoundedText::new(mark, raw).unwrap())
}

pub fn path(raw: &str) -> RepoPath<Server> {
	fixture(raw, |raw, mark| RepoPath::new(mark, raw).unwrap())
}

pub fn scanner(value: serde_json::Value) -> ScannerDocument<Server> {
	fixture("synthetic scanner fixture", |_, mark| ScannerDocument::leased(mark, value))
}
