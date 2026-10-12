//! Request guards for a loopback HTTP listener.
//!
//! Binding to loopback is not by itself a security boundary for a browser
//! endpoint. Any page the operator visits can issue cross-origin requests
//! to `127.0.0.1`, and while the browser blocks *reading* the response, a
//! state-changing request still executes. `evil.com` could therefore
//! trigger a scan, add a repo, or approve a finding. Three layers stop
//! that, and each closes a hole the others do not:
//!
//! 1. **Host allowlist** — a request whose `Host` is not one of ours is
//!    refused, so `evil.com` resolving to `127.0.0.1` (DNS rebinding)
//!    cannot become same-origin.
//! 2. **Site/Origin check** — mutating requests must be same-origin.
//! 3. **Required custom header** — a mutating request must carry
//!    `X-Loupe-Dashboard`. A cross-origin caller cannot set a custom
//!    header without a CORS preflight, which we never approve. This is
//!    what stops a form-style "simple request" that carries no `Origin`.
//!
//! On top of those, every `/api` request must present the capability
//! token in an origin-scoped header, which is what keeps another local
//! uid out. A cookie cannot do this job because cookies are shared across
//! every port on a host.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use loupe_provenance::{Browser, Ingress, Mark, Unvalidated, Validate};

use crate::ingress::BrowserRequest;
use crate::state::WebState;

/// Header a mutating request must carry. The value is irrelevant; its
/// presence is what forces a preflight for cross-origin callers.
pub const REQUEST_HEADER: &str = "X-Loupe-Dashboard";

/// Reject requests addressed to a host that isn't this listener.
fn host_is_allowed(headers: &HeaderMap, state: &WebState) -> bool {
	let Some(host) = headers.get(axum::http::header::HOST).and_then(|h| h.to_str().ok()) else {
		// HTTP/1.1 requires Host. Absent means malformed, not trusted.
		return false;
	};
	state.allowed_hosts.iter().any(|allowed| allowed == host)
}

/// Whether a request is state-changing, and so subject to the CSRF checks.
fn is_mutating(method: &Method) -> bool {
	!matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Same-origin check for mutating requests.
///
/// Prefers `Sec-Fetch-Site`, which modern browsers always send and which
/// cannot be forged by page script. Falls back to comparing `Origin`
/// against our own origins. A request with neither is refused: a browser
/// would have sent at least one, so its absence means we cannot establish
/// the request is same-origin.
fn same_origin(headers: &HeaderMap, state: &WebState) -> bool {
	if let Some(site) = headers.get("sec-fetch-site").and_then(|h| h.to_str().ok()) {
		return site == "same-origin";
	}
	match headers.get(axum::http::header::ORIGIN).and_then(|h| h.to_str().ok()) {
		Some(origin) => state.allowed_origins.iter().any(|allowed| allowed == origin),
		None => false,
	}
}

fn forbidden(reason: &'static str) -> Response {
	(StatusCode::FORBIDDEN, format!("{reason}\n")).into_response()
}

/// Applies the Host allowlist and, for mutating requests, the CSRF pair.
/// Mounted on every route including the document, so DNS rebinding cannot
/// even fetch the page.
#[allow(unsafe_code)]
pub async fn browser_guard(
	State(state): State<WebState>, mut req: Request, next: Next,
) -> Response {
	// SAFETY: this is the actual incoming Browser request, before application
	// interpretation. Every private decoder reuses this one request token.
	let context = BrowserRequest::captured(unsafe { Ingress::new() });
	if let Err(error) = context.guard(&req, &state) {
		return error.into_response();
	}
	req.extensions_mut().insert(context);
	next.run(req).await
}

pub(crate) struct BrowserGuard<'a>(pub(crate) &'a WebState);
pub(crate) enum GuardFailure {
	Host,
	Origin,
	Header,
}
impl IntoResponse for GuardFailure {
	fn into_response(self) -> Response {
		forbidden(match self {
		Self::Host=>"unexpected Host header; loupe-web only answers on its own loopback address",
		Self::Origin=>"cross-origin request refused",
		Self::Header=>"missing X-Loupe-Dashboard header; mutating requests must come from the dashboard itself",
	})
	}
}
impl Validate<(&HeaderMap, &Method), Browser> for BrowserGuard<'_> {
	type Output = ();
	type Error = GuardFailure;
	fn validate<'v>(
		self, u: Unvalidated<'v, (&HeaderMap, &Method)>, _: Mark<'v, Browser>,
	) -> Result<(), GuardFailure> {
		let (headers, method) = *u.get();
		if !host_is_allowed(headers, self.0) {
			return Err(GuardFailure::Host);
		}
		if is_mutating(method) {
			if !same_origin(headers, self.0) {
				return Err(GuardFailure::Origin);
			}
			if headers.get(REQUEST_HEADER).is_none() {
				return Err(GuardFailure::Header);
			}
		}
		Ok(())
	}
}

/// Requires a valid origin-scoped capability header. Mounted on `/api`
/// only so the document and assets can load before the page recovers the
/// token from its URL fragment.
pub async fn require_token(State(state): State<WebState>, req: Request, next: Next) -> Response {
	let Some(context) = req.extensions().get::<BrowserRequest>() else {
		return crate::ingress::Failure::Context.into_response();
	};
	if let Err(error) = context.check_token(req.headers(), &state.token) {
		return error.into_response();
	}
	next.run(req).await
}

#[cfg(test)]
mod tests {
	use super::*;

	fn state() -> WebState {
		WebState::for_tests("127.0.0.1:8455")
	}

	fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
		let mut headers = HeaderMap::new();
		for (name, value) in pairs {
			headers.insert(
				axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
				value.parse().unwrap(),
			);
		}
		headers
	}

	#[test]
	fn our_own_hosts_are_allowed() {
		let state = state();
		for host in ["127.0.0.1:8455", "localhost:8455"] {
			assert!(
				host_is_allowed(&headers(&[("host", host)]), &state),
				"{host} should be allowed"
			);
		}
	}

	#[test]
	fn a_rebound_host_is_refused() {
		let state = state();
		// The DNS-rebinding case: resolves to 127.0.0.1, but the Host
		// header gives the attacker's name away.
		for host in ["evil.com", "evil.com:8455", "127.0.0.1:9999", "127.0.0.1"] {
			assert!(
				!host_is_allowed(&headers(&[("host", host)]), &state),
				"{host} should be refused"
			);
		}
	}

	#[test]
	fn a_missing_host_is_refused() {
		assert!(!host_is_allowed(&HeaderMap::new(), &state()));
	}

	#[test]
	fn only_unsafe_methods_are_treated_as_mutating() {
		for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
			assert!(!is_mutating(&method), "{method} is safe");
		}
		for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
			assert!(is_mutating(&method), "{method} mutates");
		}
	}

	#[test]
	fn sec_fetch_site_decides_when_present() {
		let state = state();
		assert!(same_origin(&headers(&[("sec-fetch-site", "same-origin")]), &state));
		for site in ["cross-site", "same-site", "none"] {
			assert!(
				!same_origin(&headers(&[("sec-fetch-site", site)]), &state),
				"sec-fetch-site: {site} must not pass"
			);
		}
	}

	#[test]
	fn sec_fetch_site_wins_over_a_forged_origin() {
		// A cross-site request cannot launder itself by also setting an
		// Origin we happen to trust.
		let state = state();
		let h = headers(&[("sec-fetch-site", "cross-site"), ("origin", "http://127.0.0.1:8455")]);
		assert!(!same_origin(&h, &state));
	}

	#[test]
	fn origin_is_the_fallback_when_sec_fetch_site_is_absent() {
		let state = state();
		assert!(same_origin(&headers(&[("origin", "http://127.0.0.1:8455")]), &state));
		assert!(same_origin(&headers(&[("origin", "http://localhost:8455")]), &state));
		assert!(!same_origin(&headers(&[("origin", "http://evil.com")]), &state));
	}

	#[test]
	fn a_request_with_neither_signal_is_refused() {
		// This is the form-POST shape: no Origin, no Sec-Fetch-Site. The
		// required custom header is the backstop, but this check should
		// refuse it on its own too.
		assert!(!same_origin(&HeaderMap::new(), &state()));
	}
}
