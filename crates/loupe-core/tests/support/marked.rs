//! Explicit synthetic-source fixture shared only by integration tests.
use loupe_provenance::{Ingress, Mark, Source, Untrusted, Unvalidated, Validate};

struct Fixture<F>(F);
impl<S: Source, F, R> Validate<&str, S> for Fixture<F>
where
	F: for<'a> FnOnce(&'a str, &Mark<'a, S>) -> R,
{
	type Output = R;
	type Error = std::convert::Infallible;
	fn validate<'a>(self, u: Unvalidated<'a, &str>, mark: Mark<'a, S>) -> Result<R, Self::Error> {
		Ok((self.0)(u.get(), &mark))
	}
}

#[allow(unsafe_code)]
pub fn fixture<S: Source, R>(raw: &str, f: impl for<'a> FnOnce(&'a str, &Mark<'a, S>) -> R) -> R {
	// SAFETY: this integration fixture mints a source for input the test made up.
	let ingress = unsafe { Ingress::<S>::new() };
	Untrusted::new(raw, ingress).validate(Fixture(f)).unwrap()
}
