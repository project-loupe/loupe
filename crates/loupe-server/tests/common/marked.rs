//! Fixed-source synthetic fixtures for direct typed APIs, never HTTP decoders.
//!
//! HTTP test requests use historical wire shapes and real server ingress.
//! Config inputs use the actual parser/read helpers in the parent module.
use loupe_core::text::{BoundedJson, BoundedText, JsonPolicy, TextPolicy};
use loupe_provenance::{Ingress, Mark, Untrusted, Unvalidated, Validate};

macro_rules! source_fixture {
	($module:ident, $source:ty) => {
		pub mod $module {
			use super::*;
			struct Fixture<F>(F);
			impl<F, T> Validate<&str, $source> for Fixture<F>
			where
				F: for<'a> FnOnce(&'a str, &Mark<'a, $source>) -> T,
			{
				type Output = T;
				type Error = std::convert::Infallible;
				fn validate<'a>(
					self, input: Unvalidated<'a, &str>, mark: Mark<'a, $source>,
				) -> Result<T, Self::Error> {
					Ok((self.0)(input.get(), &mark))
				}
			}
			#[allow(unsafe_code)]
			fn fixture<T>(
				raw: &str, f: impl for<'a> FnOnce(&'a str, &Mark<'a, $source>) -> T,
			) -> T {
				// SAFETY: private integration-test synthetic bytes of this fixed source.
				// No runtime data/source lookup or production decoder uses this helper.
				Untrusted::new(raw, unsafe { Ingress::<$source>::new() })
					.validate(Fixture(f))
					.unwrap()
			}
			pub fn text<P: TextPolicy>(raw: &str) -> BoundedText<P, $source> {
				fixture(raw, |raw, mark| BoundedText::new(mark, raw).unwrap())
			}
			pub fn json<P: JsonPolicy>(raw: &str) -> BoundedJson<P, $source> {
				fixture(raw, |raw, mark| BoundedJson::new(mark, raw).unwrap())
			}
			pub fn empty_refs<const MAX: usize>(
			) -> loupe_storage::source_refs::SourceRefs<MAX, $source> {
				fixture("[]", |_, mark| {
					loupe_storage::source_refs::SourceRefs::new(mark, vec![]).unwrap()
				})
			}
			pub fn try_text<P: TextPolicy>(
				raw: &str,
			) -> Result<BoundedText<P, $source>, loupe_core::text::Error> {
				fixture(raw, |raw, mark| BoundedText::new(mark, raw))
			}
		}
	};
}
source_fixture!(agent, loupe_provenance::Agent);
source_fixture!(repo, loupe_provenance::Repo);
source_fixture!(operator, loupe_provenance::Operator);
