//! Shared handler state.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::client::AdminClient;
use crate::token::Token;

/// Everything the handlers need. Cheap to clone — axum clones it per
/// request.
#[derive(Clone)]
pub struct WebState {
	pub client: Arc<AdminClient>,
	pub token: Arc<Token>,
	/// Exact `Host` header values this listener answers to.
	pub allowed_hosts: Arc<Vec<String>>,
	/// Exact `Origin` values treated as same-origin.
	pub allowed_origins: Arc<Vec<String>>,
	/// Poll interval handed to the browser, in seconds.
	pub poll_seconds: u32,
}

impl WebState {
	pub fn new(client: AdminClient, token: Token, bind: SocketAddr, poll_seconds: u32) -> Self {
		let hosts = allowed_hosts(bind);
		let origins = hosts.iter().map(|h| format!("http://{h}")).collect();
		Self {
			client: Arc::new(client),
			token: Arc::new(token),
			allowed_hosts: Arc::new(hosts),
			allowed_origins: Arc::new(origins),
			poll_seconds,
		}
	}

	/// State with a throwaway client, for unit-testing the guards.
	#[cfg(test)]
	pub fn for_tests(bind: &str) -> Self {
		let base = "https://127.0.0.1:8443";
		let client = crate::test_support::client(reqwest::Client::new(), base);
		Self::new(client, Token::generate(), bind.parse().unwrap(), 5)
	}
}

/// `Host` values that mean "this listener".
///
/// A browser sends the authority exactly as it appeared in the URL, so we
/// accept both the numeric address the operator was given and `localhost`,
/// which is what most people type. Both are port-qualified: accepting a
/// bare hostname would let a request aimed at port 80 through.
fn allowed_hosts(bind: SocketAddr) -> Vec<String> {
	let port = bind.port();
	let mut hosts = vec![bind.to_string()];
	if bind.ip().is_ipv4() {
		hosts.push(format!("127.0.0.1:{port}"));
		hosts.push(format!("localhost:{port}"));
	} else {
		hosts.push(format!("[::1]:{port}"));
		hosts.push(format!("localhost:{port}"));
	}
	hosts.sort();
	hosts.dedup();
	hosts
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn ipv4_bind_accepts_numeric_and_localhost_with_port() {
		let hosts = allowed_hosts("127.0.0.1:8455".parse().unwrap());
		assert!(hosts.contains(&"127.0.0.1:8455".to_owned()));
		assert!(hosts.contains(&"localhost:8455".to_owned()));
		// Never a bare host: that would match a request aimed at port 80.
		assert!(!hosts.contains(&"localhost".to_owned()));
		assert!(!hosts.contains(&"127.0.0.1".to_owned()));
	}

	#[test]
	fn ipv6_bind_accepts_the_bracketed_form() {
		let hosts = allowed_hosts("[::1]:8455".parse().unwrap());
		assert!(hosts.contains(&"[::1]:8455".to_owned()));
		assert!(hosts.contains(&"localhost:8455".to_owned()));
	}

	#[test]
	fn a_nondefault_loopback_ip_is_still_accepted_verbatim() {
		let hosts = allowed_hosts("127.0.0.2:9000".parse().unwrap());
		assert!(hosts.contains(&"127.0.0.2:9000".to_owned()), "{hosts:?}");
	}

	#[test]
	fn origins_are_derived_from_hosts_over_plain_http() {
		let state = WebState::for_tests("127.0.0.1:8455");
		assert!(state.allowed_origins.contains(&"http://127.0.0.1:8455".to_owned()));
		assert!(state.allowed_origins.contains(&"http://localhost:8455".to_owned()));
		assert!(
			!state.allowed_origins.iter().any(|o| o.starts_with("https://")),
			"this listener is plain HTTP: {:?}",
			state.allowed_origins
		);
	}
}
