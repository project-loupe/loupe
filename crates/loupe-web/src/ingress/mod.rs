//! Private actual request owners. Browser validation grants no Operator role.
use axum::extract::{FromRequestParts, Query, RawPathParams};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use loupe_provenance::{Browser, Ingress, Mark, Untrusted, Unvalidated, Validate};

use crate::state::WebState;
use crate::token::Token;
pub(crate) mod bodies;
pub(crate) mod json;
pub(crate) mod queries;
pub(crate) mod server;

#[derive(Clone)]
pub(crate) struct BrowserRequest {
	token: Ingress<Browser>,
}
impl BrowserRequest {
	// Only browser_guard constructs this private request extension after its
	// actual incoming-request mint. No token getter or source selector exists.
	pub(crate) fn captured(token: Ingress<Browser>) -> Self {
		Self { token }
	}
	pub(crate) fn guard(
		&self, req: &axum::extract::Request, state: &WebState,
	) -> Result<(), crate::guard::GuardFailure> {
		Untrusted::new((req.headers(), req.method()), self.token)
			.validate(crate::guard::BrowserGuard(state))
	}
	pub(crate) fn check_token(&self, headers: &HeaderMap, token: &Token) -> Result<(), Failure> {
		Untrusted::new(headers, self.token).validate(DashboardTokenCheck(token))
	}
	fn from_parts(parts: &Parts) -> Result<Self, Failure> {
		parts.extensions.get::<Self>().cloned().ok_or(Failure::Context)
	}
}

#[derive(Debug)]
pub(crate) enum Failure {
	Context,
	Path,
	Query,
	Token,
	Media,
	Json,
	TooLarge,
	BodyRead,
}
impl IntoResponse for Failure {
	fn into_response(self) -> Response {
		let (status, message) = match self {
			Self::Context => (StatusCode::INTERNAL_SERVER_ERROR, "request context unavailable"),
			Self::Path => (StatusCode::BAD_REQUEST, "invalid request path identifier"),
			Self::Query => (StatusCode::BAD_REQUEST, "invalid request query"),
			Self::Media => (StatusCode::UNSUPPORTED_MEDIA_TYPE, "expected JSON Content-Type"),
			Self::Json => (StatusCode::BAD_REQUEST, "invalid JSON request"),
			Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "request body exceeds 2097152 bytes"),
			Self::BodyRead => (StatusCode::BAD_REQUEST, "reading request body failed"),
			Self::Token => {
				return (
					StatusCode::UNAUTHORIZED,
					"missing or invalid dashboard capability; reopen the URL printed at startup\n",
				)
					.into_response()
			},
		};
		(status, axum::Json(serde_json::json!({"error":message}))).into_response()
	}
}
struct DashboardTokenCheck<'a>(&'a Token);
impl Validate<&HeaderMap, Browser> for DashboardTokenCheck<'_> {
	type Output = ();
	type Error = Failure;
	fn validate<'v>(
		self, u: Unvalidated<'v, &HeaderMap>, _: Mark<'v, Browser>,
	) -> Result<(), Failure> {
		let presented = u.get().get(crate::token::HEADER_NAME).and_then(|h| h.to_str().ok());
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::Token);
		if presented.is_some_and(|s| self.0.matches(s)) {
			Ok(())
		} else {
			Err(Failure::Token)
		}
	}
}
struct BrowserPath;
impl Validate<&str, Browser> for BrowserPath {
	type Output = i64;
	type Error = Failure;
	fn validate<'v>(self, u: Unvalidated<'v, &str>, _: Mark<'v, Browser>) -> Result<i64, Failure> {
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::Path);
		u.get().parse().map_err(|_| Failure::Path)
	}
}
pub(crate) struct BrowserId(pub(crate) i64);
impl FromRequestParts<WebState> for BrowserId {
	type Rejection = Failure;
	async fn from_request_parts(parts: &mut Parts, state: &WebState) -> Result<Self, Failure> {
		let context = BrowserRequest::from_parts(parts)?;
		let params =
			RawPathParams::from_request_parts(parts, state).await.map_err(|_| Failure::Path)?;
		let (_, raw) = params.iter().next().ok_or(Failure::Context)?;
		Untrusted::new(raw, context.token).validate(BrowserPath).map(Self)
	}
}
struct LimitDecoder;
impl Validate<&Uri, Browser> for LimitDecoder {
	type Output = Option<i64>;
	type Error = Failure;
	fn validate<'v>(
		self, u: Unvalidated<'v, &Uri>, _: Mark<'v, Browser>,
	) -> Result<Self::Output, Failure> {
		#[cfg(fuzzing)]
		crate::fuzz_support::hit(crate::fuzz_support::Entry::Limit);
		Query::<crate::routes::api::LimitQuery>::try_from_uri(u.get())
			.map(|q| q.limit)
			.map_err(|_| Failure::Query)
	}
}
pub(crate) struct BrowserLimit(pub(crate) Option<i64>);
impl BrowserLimit {
	pub(crate) fn pairs(&self) -> Vec<(&'static str, String)> {
		crate::routes::api::LimitQuery { limit: self.0 }.pairs()
	}
}
impl FromRequestParts<WebState> for BrowserLimit {
	type Rejection = Failure;
	async fn from_request_parts(parts: &mut Parts, _: &WebState) -> Result<Self, Failure> {
		let context = BrowserRequest::from_parts(parts)?;
		Untrusted::new(&parts.uri, context.token).validate(LimitDecoder).map(Self)
	}
}
