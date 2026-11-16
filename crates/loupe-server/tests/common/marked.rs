//! Fixed-source synthetic fixtures for direct typed APIs, never HTTP decoders.
//!
//! HTTP test requests use independent wire fixtures and real server ingress.
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
			pub(super) fn fixture<T>(
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
			pub fn identifier<P: loupe_core::text::IdentPolicy>(
				raw: &str,
			) -> loupe_core::text::Identifier<P, $source> {
				fixture(raw, |raw, mark| loupe_core::text::Identifier::new(mark, raw).unwrap())
			}
			pub fn anchor<P: loupe_core::text::AnchorPolicy>(
				raw: &str,
			) -> loupe_core::text::Anchor<P, $source> {
				fixture(raw, |raw, mark| loupe_core::text::Anchor::new(mark, raw).unwrap())
			}
			pub fn empty_refs<const MAX: usize>(
			) -> loupe_storage::source_refs::SourceRefs<MAX, $source> {
				fixture("[]", |_, mark| {
					loupe_storage::source_refs::SourceRefs::new(mark, vec![]).unwrap()
				})
			}
			pub fn single_ref<const MAX: usize>(
				path: &str,
			) -> loupe_storage::source_refs::SourceRefs<MAX, $source> {
				fixture(path, |raw, mark| {
					loupe_storage::source_refs::SourceRefs::new(
						mark,
						vec![loupe_core::text::SourceRef {
							path: loupe_core::text::RepoPath::new(mark, raw).unwrap(),
							symbol: None,
						}],
					)
					.unwrap()
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

/// Fixed Agent evidence for comparing a typed stored row with authored fixtures.
pub fn lead_evidence(
	raw: &str,
) -> loupe_core::review_payload::LeadEvidenceV1<loupe_provenance::Agent> {
	agent::fixture(raw, |raw, mark| {
		loupe_core::review_payload::LeadEvidenceV1::from_json(mark, raw).unwrap()
	})
}

/// Fixed Agent terminal evidence for typed assertions against authored fixtures.
pub fn drilldown_terminal(
	raw: &str,
) -> loupe_core::review_payload::DrilldownTerminalV1<loupe_provenance::Agent> {
	agent::fixture(raw, |raw, mark| {
		loupe_core::review_payload::DrilldownTerminalV1::from_json(mark, raw).unwrap()
	})
}

/// Fixed Agent verification evidence for assertions against authored fixtures.
pub fn verification_terminal(
	raw: &str,
) -> loupe_core::review_payload::VerificationTerminalV1<loupe_provenance::Agent> {
	agent::fixture(raw, |raw, mark| {
		loupe_core::review_payload::VerificationTerminalV1::from_json(mark, raw).unwrap()
	})
}

/// Synthetic authenticated Operator authority for direct integration fixtures.
#[allow(unsafe_code)]
pub fn operator_ingress() -> Ingress<loupe_provenance::Operator> {
	// SAFETY: test-only authority for authored fixture setup and stored assertions.
	unsafe { Ingress::new() }
}

pub fn scanner_config(raw: &str) -> loupe_core::ScannerDocument<loupe_provenance::Operator> {
	operator::fixture(raw, |raw, mark| {
		loupe_core::ScannerDocument::registered(mark, serde_json::from_str(raw).unwrap()).unwrap()
	})
}

/// The router's own response bytes as the worker receives them, for checking
/// the worker's response decoders against actual server output.
#[allow(unsafe_code)]
pub fn server_response(bytes: &[u8]) -> Untrusted<&[u8], loupe_provenance::Server> {
	// SAFETY: integration tests only; the bytes come from the in-process router.
	Untrusted::new(bytes, unsafe { Ingress::<loupe_provenance::Server>::new() })
}

/// Authored request bytes as Worker input, for building typed requests the
/// worker's phase client then sends to the actual router.
#[allow(unsafe_code)]
pub fn worker_request(bytes: &[u8]) -> Untrusted<&[u8], loupe_provenance::Worker> {
	// SAFETY: integration tests only; the bytes are authored fixtures.
	Untrusted::new(bytes, unsafe { Ingress::<loupe_provenance::Worker>::new() })
}
