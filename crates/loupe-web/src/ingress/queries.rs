//! Concrete Browser query fields. Form decoding stays with pinned Axum/serde;
//! a streaming preflight counts lossy UTF-8 before any known field is owned.
use axum::extract::{FromRequestParts, Query};
use axum::http::request::Parts;
use axum::http::Uri;
use loupe_core::text::{policy, BoundedText, Normalization, TextPolicy, Whitespace};
use loupe_provenance::{Browser, Mark, Untrusted, Unvalidated, Validate};

use super::{BrowserRequest, Failure};
use crate::WebState;

#[derive(serde::Deserialize)]
struct JobsQuery {
	#[serde(default)]
	limit: Option<i64>,
	#[serde(default)]
	state: Option<String>,
	#[serde(default)]
	kind: Option<String>,
}
#[derive(serde::Deserialize)]
struct SearchQuery {
	q: String,
	#[serde(default)]
	limit: Option<i64>,
}

macro_rules! policy {
	($name:ident, $field:literal, $multi:literal) => {
		struct $name;
		impl TextPolicy for $name {
			const FIELD: &'static str = $field;
			const MAX_BYTES: usize = policy::LEGACY_TEXT_MAX_BYTES;
			const MAX_CHARS: usize = policy::LEGACY_TEXT_MAX_BYTES;
			const MULTILINE: bool = $multi;
			const ALLOW_EMPTY: bool = true;
			const NORMALIZATION: Normalization = Normalization::Exact;
			const WHITESPACE: Whitespace = Whitespace::Significant;
			const ALLOW_CR: bool = $multi;
		}
	};
}
policy!(BrowserSearchQuery, "search_query", true);
policy!(BrowserJobFilter, "job_filter", false);

fn decoded_budget(encoded: &str) -> Result<(), Failure> {
	let mut pending = [0u8; 4];
	let mut used = 0;
	let mut bytes = 0usize;
	// Literal '+' becomes ASCII space in form decoding. It has identical UTF-8
	// length/error behavior here; percent-decoded '+' must remain literal later.
	for byte in percent_encoding::percent_decode_str(encoded) {
		pending[used] = byte;
		used += 1;
		loop {
			match std::str::from_utf8(&pending[..used]) {
				Ok(_) => {
					bytes += used;
					used = 0;
					break;
				},
				Err(error) => match error.error_len() {
					None => break,
					Some(length) => {
						let consumed = error.valid_up_to() + length;
						bytes += error.valid_up_to() + 3;
						pending.copy_within(consumed..used, 0);
						used -= consumed;
						if used == 0 {
							break;
						}
					},
				},
			}
		}
		if bytes > policy::LEGACY_TEXT_MAX_BYTES {
			return Err(Failure::Query);
		}
	}
	if used > 0 {
		bytes += 3;
	}
	if bytes > policy::LEGACY_TEXT_MAX_BYTES {
		Err(Failure::Query)
	} else {
		Ok(())
	}
}
fn preflight(uri: &Uri, names: &[&str]) -> Result<(), Failure> {
	for pair in uri.query().unwrap_or("").split('&').filter(|s| !s.is_empty()) {
		let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
		// None of the closed ASCII names contains '+', so a literal form '+'
		// cannot match one; all other escapes use the pinned percent iterator.
		if names
			.iter()
			.any(|expected| percent_encoding::percent_decode_str(name).eq(expected.bytes()))
		{
			decoded_budget(value)?;
		}
	}
	Ok(())
}
pub(crate) struct BrowserJobs {
	limit: Option<i64>,
	state: Option<BoundedText<BrowserJobFilter, Browser>>,
	kind: Option<BoundedText<BrowserJobFilter, Browser>>,
}
struct JobsDecoder;
impl Validate<&Uri, Browser> for JobsDecoder {
	type Output = BrowserJobs;
	type Error = Failure;
	fn validate<'v>(
		self, u: Unvalidated<'v, &Uri>, mark: Mark<'v, Browser>,
	) -> Result<Self::Output, Failure> {
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::Jobs);
		preflight(u.get(), &["state", "kind"])?;
		let raw = Query::<JobsQuery>::try_from_uri(u.get()).map_err(|_| Failure::Query)?.0;
		Ok(BrowserJobs {
			limit: raw.limit,
			state: raw
				.state
				.map(|s| BoundedText::new(&mark, &s).map_err(|_| Failure::Query))
				.transpose()?,
			kind: raw
				.kind
				.map(|s| BoundedText::new(&mark, &s).map_err(|_| Failure::Query))
				.transpose()?,
		})
	}
}
impl BrowserJobs {
	pub(crate) async fn send(
		self, mut request: reqwest::RequestBuilder,
	) -> Result<reqwest::Response, reqwest::Error> {
		#[cfg(fuzzing)]
		{
			if let Some(text) = &self.state {
				crate::fuzz_support::browser_text(crate::fuzz_support::BrowserField::State, text);
			}
			if let Some(text) = &self.kind {
				crate::fuzz_support::browser_text(crate::fuzz_support::BrowserField::Kind, text);
			}
		}
		if let Some(limit) = self.limit {
			request = request.query(&[("limit", limit)]);
		}
		if let Some(state) = self.state.as_ref().filter(|s| !s.expose().is_empty()) {
			request = request.query(&[("state", state.expose())]);
		}
		if let Some(kind) = self.kind.as_ref().filter(|s| !s.expose().is_empty()) {
			request = request.query(&[("kind", kind.expose())]);
		}
		#[allow(
			clippy::disallowed_methods,
			reason = "dashboard jobs query egress sends only the fields admitted by BrowserJobs"
		)]
		let response = request.send().await;
		response
	}
}
pub(crate) struct BrowserSearch {
	query: BoundedText<BrowserSearchQuery, Browser>,
	limit: Option<i64>,
}
struct SearchDecoder;
impl Validate<&Uri, Browser> for SearchDecoder {
	type Output = BrowserSearch;
	type Error = Failure;
	fn validate<'v>(
		self, u: Unvalidated<'v, &Uri>, mark: Mark<'v, Browser>,
	) -> Result<Self::Output, Failure> {
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::Search);
		preflight(u.get(), &["q"])?;
		let raw = Query::<SearchQuery>::try_from_uri(u.get()).map_err(|_| Failure::Query)?.0;
		Ok(BrowserSearch {
			query: BoundedText::new(&mark, &raw.q).map_err(|_| Failure::Query)?,
			limit: raw.limit,
		})
	}
}
impl BrowserSearch {
	pub(crate) async fn send(
		self, request: reqwest::RequestBuilder,
	) -> Result<reqwest::Response, reqwest::Error> {
		#[cfg(fuzzing)]
		crate::fuzz_support::browser_text(crate::fuzz_support::BrowserField::Search, &self.query);
		let mut request = request.query(&[("q", self.query.expose())]);
		if let Some(limit) = self.limit {
			request = request.query(&[("limit", limit)]);
		}
		#[allow(
			clippy::disallowed_methods,
			reason = "dashboard search egress sends only the bounded Browser search query and numeric limit"
		)]
		let response = request.send().await;
		response
	}
}
macro_rules! extractor {
	($ty:ident, $decoder:ident) => {
		impl FromRequestParts<WebState> for $ty {
			type Rejection = Failure;
			async fn from_request_parts(parts: &mut Parts, _: &WebState) -> Result<Self, Failure> {
				let context = BrowserRequest::from_parts(parts)?;
				Untrusted::new(&parts.uri, context.token).validate($decoder)
			}
		}
	};
}
extractor!(BrowserJobs, JobsDecoder);
extractor!(BrowserSearch, SearchDecoder);

#[cfg(fuzzing)]
pub(crate) fn fuzz_budget(encoded: &str) -> bool {
	decoded_budget(encoded).is_ok()
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn preflight_matches_lossy_form_budget_without_allocating_the_decoded_field() {
		let cap = policy::LEGACY_TEXT_MAX_BYTES;
		for encoded in [
			"%FF",
			"%E2%82",
			"%E2%28%A1",
			"%F0%90%80%80",
			"%F0%80%80%80",
			"%ED%A0%80",
			"%C2%A0",
			"+%2B",
			"%",
			"%GG",
		] {
			let bytes = percent_encoding::percent_decode_str(encoded).collect::<Vec<_>>();
			let output = String::from_utf8_lossy(&bytes);
			let exact = format!("{}{encoded}", "a".repeat(cap - output.len()));
			assert!(decoded_budget(&exact).is_ok(), "{encoded}");
			assert!(decoded_budget(&format!("a{exact}")).is_err(), "{encoded}");
		}
		let over = "a".repeat(cap + 1);
		// The pinned HTTP Uri has a smaller encoded-size ceiling. Exercise the
		// policy boundary directly above, and retain that transport admission.
		assert!(format!("/search?%71={over}").parse::<Uri>().is_err());
		let unknown: Uri =
			format!("/search?%71=okay&unknown={}", "a".repeat(32 * 1024)).parse().unwrap();
		assert!(preflight(&unknown, &["q"]).is_ok());
	}
}
