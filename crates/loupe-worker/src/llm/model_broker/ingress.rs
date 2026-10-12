//! Fixed model boundary owners. Provider bytes reach the sandbox only through
//! `ToSandbox`; the destination does not change their provenance.

use bytes::Bytes;
use loupe_provenance::{Mark, Provider, Sandbox, Untrusted, Unvalidated, Validate};

use super::{
	enforce_request_policy, token_usage_from_response, ModelBrokerBackend, RequestPolicyError,
	UsageCounters,
};

pub(super) struct UpstreamRequest(Bytes);
struct RequestPolicy<'a>(&'a ModelBrokerBackend);
impl Validate<Bytes, Sandbox> for RequestPolicy<'_> {
	type Output = UpstreamRequest;
	type Error = RequestPolicyError;
	fn validate<'view>(
		self, u: Unvalidated<'view, Bytes>, _: Mark<'view, Sandbox>,
	) -> Result<Self::Output, Self::Error> {
		enforce_request_policy(u.get(), self.0).map(UpstreamRequest)
	}
}
impl UpstreamRequest {
	pub(super) fn admit(
		body: Untrusted<Bytes, Sandbox>, backend: &ModelBrokerBackend,
	) -> Result<Self, RequestPolicyError> {
		body.validate(RequestPolicy(backend))
	}
	/// The sole original/repaired request-byte egress to the configured provider.
	pub(super) async fn send(
		self, request: reqwest::RequestBuilder,
	) -> reqwest::Result<reqwest::Response> {
		request.body(self.0).send().await
	}
}

/// An initially empty capture receives bytes only from `ToSandbox`'s Provider
/// mark scope. It retains the same output-budget accounting and allocation as
/// the existing capture, and exposes only the concrete usage interpretation.
#[derive(Default)]
pub(super) struct ProviderCapture(Vec<u8>);
impl ProviderCapture {
	pub(super) fn token_usage(&self) -> u64 {
		ProviderTokenUsage::decode(self)
	}
}
struct ProviderTokenUsage;
impl ProviderTokenUsage {
	fn decode(capture: &ProviderCapture) -> u64 {
		token_usage_from_response(&capture.0)
	}
}

pub(super) struct ToSandbox<'a> {
	pub(super) capture: &'a mut ProviderCapture,
	pub(super) usage: &'a UsageCounters,
	pub(super) output_ceiling: u64,
}
pub(super) struct ForwardedChunk {
	pub(super) bytes: Option<Bytes>,
	pub(super) overflowed: bool,
}
impl Validate<Bytes, Provider> for ToSandbox<'_> {
	type Output = ForwardedChunk;
	type Error = std::convert::Infallible;
	fn validate<'view>(
		self, u: Unvalidated<'view, Bytes>, _: Mark<'view, Provider>,
	) -> Result<Self::Output, Self::Error> {
		let chunk = u.get();
		let allowed = self.usage.reserve_output(chunk.len(), self.output_ceiling);
		if allowed == 0 {
			return Ok(ForwardedChunk { bytes: None, overflowed: true });
		}
		let overflowed = allowed < chunk.len();
		let chunk = chunk.slice(..allowed);
		self.capture.0.extend_from_slice(&chunk);
		Ok(ForwardedChunk { bytes: Some(chunk), overflowed })
	}
}
