//! Synthetic Agent fixtures for core policy and wire-shape tests only.
use loupe_provenance::{Agent, Ingress, Mark, Untrusted, Unvalidated, Validate};

use crate::text::{
	Anchor, AnchorPolicy, BoundedJson, BoundedText, Error, IdentPolicy, Identifier, JsonPolicy,
	RepoPath, TextPolicy,
};

struct Fixture<F>(F);
impl<F, T> Validate<&str, Agent> for Fixture<F>
where
	F: for<'a> FnOnce(&'a str, &Mark<'a, Agent>) -> T,
{
	type Output = T;
	type Error = std::convert::Infallible;
	fn validate<'a>(
		self, input: Unvalidated<'a, &str>, mark: Mark<'a, Agent>,
	) -> Result<T, Self::Error> {
		Ok((self.0)(input.get(), &mark))
	}
}

#[allow(unsafe_code)]
fn fixture<T>(raw: &str, f: impl for<'a> FnOnce(&'a str, &Mark<'a, Agent>) -> T) -> T {
	// SAFETY: only synthetic input constructed by this crate's tests, never a
	// runtime source reconstruction or exported decoder.
	Untrusted::new(raw, unsafe { Ingress::<Agent>::new() }).validate(Fixture(f)).unwrap()
}

pub(crate) fn text<P: TextPolicy>(raw: &str) -> Result<BoundedText<P, Agent>, Error> {
	fixture(raw, |raw, mark| BoundedText::new(mark, raw))
}
pub(crate) fn identifier<P: IdentPolicy>(raw: &str) -> Result<Identifier<P, Agent>, Error> {
	fixture(raw, |raw, mark| Identifier::new(mark, raw))
}
pub(crate) fn anchor<P: AnchorPolicy>(raw: &str) -> Result<Anchor<P, Agent>, Error> {
	fixture(raw, |raw, mark| Anchor::new(mark, raw))
}
pub(crate) fn path(raw: &str) -> Result<RepoPath<Agent>, Error> {
	fixture(raw, |raw, mark| RepoPath::new(mark, raw))
}
pub(crate) fn json<P: JsonPolicy>(raw: &str) -> Result<BoundedJson<P, Agent>, Error> {
	fixture(raw, |raw, mark| BoundedJson::new(mark, raw))
}

/// Decode a synthetic JSON string, then exercise marked field validation.
pub(crate) fn json_text<P: TextPolicy>(raw: &str) -> Result<BoundedText<P, Agent>, Error> {
	let value: String = serde_json::from_str(raw)
		.map_err(|_| Error::new(P::FIELD, crate::text::Rule::JsonSyntax))?;
	text(&value)
}
