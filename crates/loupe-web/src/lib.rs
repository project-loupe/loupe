// Keep production safety lints separate from test-only assertions.
#![cfg_attr(
	not(test),
	deny(
		clippy::unwrap_used,
		clippy::expect_used,
		clippy::string_slice,
		clippy::mem_forget,
		clippy::dbg_macro,
		clippy::todo,
		clippy::unimplemented,
		clippy::disallowed_methods
	)
)]
#![deny(unsafe_code)]
//! `loupe-web` — a local operator dashboard for `loupe-server`.
//!
//! # Shape
//!
//! This is an ordinary admin client, like `loupectl`: it talks to
//! `loupe-server` over mTLS using the same admin certificate and the same
//! `/v1/*` routes, and never opens the SQLCipher database. The difference
//! is only that it renders a browser UI instead of terminal output.
//!
//! # Why loopback-only
//!
//! The daemon holds the admin certificate, and its own listener has no
//! transport authentication. That is a deliberate trade: the browser needs
//! no client certificate, so there is nothing to import and no second
//! certificate to manage, and the trust boundary matches the one that
//! already exists — whoever can run `loupectl` on this machine can drive
//! this dashboard. Binding anywhere routable would break that equivalence,
//! so [`config::ensure_loopback`] refuses to.
//!
//! Two things follow, and both are implemented rather than assumed:
//!
//! * Loopback is reachable by *any* local process, including one that
//!   cannot read the admin key. The origin-scoped capability token in
//!   [`token`] closes that gap.
//! * Loopback is reachable by *any page the operator visits*. The guards
//!   in [`guard`] close that one.
//!
//! Exposed as a library so integration tests can drive the router.
//!
//! The actual Browser request context has no public construction path:
//!
//! ```compile_fail,E0603
//! use loupe_web::ingress::BrowserRequest;
//! ```
//!
//! Fuzz observations do not provide a normal-build decoder or mint API:
//! ```compile_fail,E0432
//! use loupe_web::fuzz_support;
//! ```
//!
//! Browser query text has no ordinary public serde admission bypass:
//! ```compile_fail,E0432
//! use loupe_web::routes::api::{JobsQuery, SearchQuery, LimitQuery};
//! ```

pub mod client;
pub mod config;
#[cfg(fuzzing)]
pub mod fuzz_support;
pub mod guard;
mod ingress;
pub mod routes;
pub mod state;
pub mod token;

use std::net::SocketAddr;

use anyhow::{Context, Result};
use axum::routing::{get, patch, post, put};
use axum::Router;
pub use client::AdminClient;
pub use config::{Cli, ConnArgs};
pub use state::WebState;
pub use token::Token;
use tokio::net::TcpListener;

/// Build the router. Pure function so tests can mount it directly.
///
/// Layer order matters. `browser_guard` is outermost so it covers the
/// document too — otherwise a rebound host could still fetch the page.
/// `require_token` wraps only `/api`, because the document and assets have
/// to load before the page can recover the token from its URL fragment.
pub fn router(state: WebState) -> Router {
	let api = Router::new()
		.route("/api/config", get(routes::assets::client_config))
		.route("/api/health", get(routes::api::health))
		.route("/api/whoami", get(routes::api::whoami))
		.route("/api/github-app", get(routes::api::github_app))
		.route("/api/repos", get(routes::api::list_repos).post(routes::api::create_repo))
		.route("/api/repos/{id}", patch(routes::api::update_repo).delete(routes::api::delete_repo))
		.route("/api/repos/{id}/scan", post(routes::api::enqueue_scan))
		.route("/api/repos/{id}/reporting/github-pat", post(routes::api::rotate_repo_pat))
		.route("/api/repos/{id}/reporting/github", put(routes::api::set_github_reporting))
		.route("/api/repos/{id}/findings", get(routes::api::list_findings))
		.route("/api/repos/{id}/findings/search", get(routes::api::search_findings))
		.route("/api/jobs", get(routes::api::list_jobs))
		.route("/api/jobs/{id}", get(routes::api::get_job))
		.route("/api/jobs/{id}/retry", post(routes::api::retry_job))
		.route("/api/jobs/{id}/cancel", post(routes::api::cancel_job))
		.route("/api/findings/retry-verify", post(routes::api::retry_verify))
		.route("/api/findings/{id}", get(routes::api::get_finding))
		.route("/api/findings/{id}/approve", post(routes::api::approve_finding))
		.route("/api/findings/{id}/reject", post(routes::api::reject_finding))
		.route("/api/findings/{id}/retry-report", post(routes::api::retry_report_finding))
		.route_layer(axum::middleware::from_fn_with_state(state.clone(), guard::require_token))
		.layer(axum::middleware::map_response(routes::api::enclose_bad_request));

	Router::new()
		.route("/", get(routes::assets::index))
		.route("/app.css", get(routes::assets::stylesheet))
		.route("/app.js", get(routes::assets::script))
		.merge(api)
		.layer(axum::middleware::from_fn_with_state(state.clone(), guard::browser_guard))
		.with_state(state)
}

/// Handle for a running dashboard.
// debug-ok: listener address and task handle contain no request/response data.
#[derive(Debug)]
pub struct ServeHandle {
	pub local_addr: SocketAddr,
	join: tokio::task::JoinHandle<()>,
}

impl ServeHandle {
	/// Stop serving. Aborts the listener task; there is no in-flight work
	/// worth draining because every request is a proxied round-trip.
	pub async fn shutdown(self) {
		self.join.abort();
		let _ = self.join.await;
	}
}

/// Bind and serve. Returns once bound so callers can read `local_addr`.
///
/// Uses `axum::serve` rather than a hand-rolled accept loop: the server's
/// loop exists only to lift the peer certificate off the TLS session, and
/// this listener has no TLS.
pub async fn serve(bind: SocketAddr, state: WebState) -> Result<ServeHandle> {
	config::ensure_loopback(bind)?;
	let listener = TcpListener::bind(bind).await.with_context(|| format!("binding {bind}"))?;
	let local_addr = listener.local_addr().context("local_addr on bound listener")?;
	let app = router(state);
	let join = tokio::spawn(async move {
		if let Err(e) = axum::serve(listener, app).await {
			tracing::error!(error = %e, "loupe-web listener stopped");
		}
	});
	Ok(ServeHandle { local_addr, join })
}

#[cfg(test)]
mod test_support;
