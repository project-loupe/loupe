//! Concrete query owners. Authority selects one actual source before form
//! decoding; query parsing never mints a token or manufactures Agent content.
use axum::extract::{FromRequestParts, Query};
use axum::http::request::Parts;
use axum::http::{StatusCode, Uri};
use loupe_core::source_migration::text::BoundedText;
use loupe_core::text::{policy, Normalization, TextPolicy, Whitespace};
use loupe_provenance::{Mark, Operator, Source, Untrusted, Unvalidated, Validate, Worker};
use serde::Deserialize;

use crate::auth::AuthedWorker;

struct SearchText;
impl TextPolicy for SearchText {
	const FIELD: &'static str = "finding_search";
	const MAX_BYTES: usize = policy::LEGACY_TEXT_MAX_BYTES;
	const MAX_CHARS: usize = policy::LEGACY_TEXT_MAX_BYTES;
	const MULTILINE: bool = true;
	const ALLOW_CR: bool = true;
	const ALLOW_EMPTY: bool = true;
	const NORMALIZATION: Normalization = Normalization::Exact;
	const WHITESPACE: Whitespace = Whitespace::Significant;
}
#[derive(Deserialize)]
struct RawSearch {
	q: String,
	#[serde(default)]
	limit: Option<i64>,
}
struct SearchInput<S: Source> {
	q: BoundedText<SearchText, S>,
	limit: Option<i64>,
}
struct SearchQueryDecoder;
pub struct SearchQuery {
	pub(crate) q: String,
	pub(crate) limit: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
enum QueryError {
	#[error("Failed to deserialize query string: invalid query")]
	Shape,
	#[error("{0}")]
	Grammar(&'static str),
	#[error(transparent)]
	Text(#[from] loupe_core::text::Error),
}
impl QueryError {
	fn response(self) -> (StatusCode, String) {
		(StatusCode::BAD_REQUEST, self.to_string())
	}
}
macro_rules! search_source {
	($source:ty, $exit:ident) => {
		impl Validate<&Uri, $source> for SearchQueryDecoder {
			type Output = SearchInput<$source>;
			type Error = QueryError;
			fn validate<'view>(
				self, input: Unvalidated<'view, &Uri>, mark: Mark<'view, $source>,
			) -> Result<Self::Output, Self::Error> {
				let Query(raw) =
					Query::<RawSearch>::try_from_uri(input.get()).map_err(|_| QueryError::Shape)?;
				Ok(SearchInput { q: BoundedText::new(&mark, &raw.q)?, limit: raw.limit })
			}
		}
		impl SearchQueryDecoder {
			fn $exit(input: Untrusted<&Uri, $source>) -> Result<SearchQuery, QueryError> {
				let input = input.validate(Self)?;
				Ok(SearchQuery { q: input.q.expose().to_owned(), limit: input.limit })
			}
		}
	};
}
search_source!(Worker, worker_legacy);
search_source!(Operator, operator_legacy);
impl<S: Send + Sync> FromRequestParts<S> for SearchQuery {
	type Rejection = (StatusCode, String);
	async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
		let authed = parts
			.extensions
			.get::<AuthedWorker>()
			.ok_or_else(|| (StatusCode::UNAUTHORIZED, "authentication required".into()))?;
		if let Some(token) = authed.worker_ingress() {
			SearchQueryDecoder::worker_legacy(Untrusted::new(&parts.uri, token))
		} else if let Some(token) = authed.operator_ingress() {
			SearchQueryDecoder::operator_legacy(Untrusted::new(&parts.uri, token))
		} else {
			unreachable!("authenticated authority has exactly one role")
		}
		.map_err(QueryError::response)
	}
}

pub struct OperatorJobQuery(pub(crate) loupe_storage::jobs::JobFilter);
struct JobListQueryDecoder;
impl Validate<&Uri, Operator> for JobListQueryDecoder {
	type Output = loupe_storage::jobs::JobFilter;
	type Error = QueryError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &Uri>, _: Mark<'view, Operator>,
	) -> Result<Self::Output, Self::Error> {
		let Query(raw) = Query::<crate::routes::jobs::ListQuery>::try_from_uri(input.get())
			.map_err(|_| QueryError::Shape)?;
		let states =
			crate::routes::jobs::parse_states(raw.state.as_deref()).map_err(|(_, reason)| {
				QueryError::Grammar(if reason.starts_with("state must") {
					"state must name at least one job state"
				} else {
					"unknown job state; expected any of queued, leased, succeeded, failed, cancelled"
				})
			})?;
		let kind = crate::routes::jobs::parse_kind(raw.kind.as_deref()).map_err(|_| {
			QueryError::Grammar("unknown job kind; expected scan, verify, survey or drilldown")
		})?;
		if raw.limit.is_some_and(|limit| limit <= 0) {
			return Err(QueryError::Grammar("limit must be positive"));
		}
		Ok(loupe_storage::jobs::JobFilter { states, kind, limit: raw.limit })
	}
}
impl<S: Send + Sync> FromRequestParts<S> for OperatorJobQuery {
	type Rejection = (StatusCode, String);
	async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
		let token = parts
			.extensions
			.get::<AuthedWorker>()
			.and_then(AuthedWorker::operator_ingress)
			.ok_or_else(|| (StatusCode::FORBIDDEN, "operator role required".into()))?;
		Untrusted::new(&parts.uri, token)
			.validate(JobListQueryDecoder)
			.map(Self)
			.map_err(QueryError::response)
	}
}
