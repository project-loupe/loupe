//! Concrete Server response validators. Original owner-backed Bytes stay live
//! through all nested carries; legacy DTO exits are private and removed at M.

use bytes::Bytes;
use loupe_provenance::{Mark, Server, Untrusted, Unvalidated, Validate, ValidateCarrying};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::ingress_text::DecodeError;

mod finding;
#[cfg(fuzzing)]
pub mod fuzz_support;
mod lease;
mod scanner;

struct LeaseResponseDecoder;
impl ValidateCarrying<&[u8], Server> for LeaseResponseDecoder {
	type Output = lease::DecodedLeaseResponse;
	type Error = DecodeError;
	fn validate(self, u: Unvalidated<'_, &[u8], Server>) -> Result<Self::Output, DecodeError> {
		lease::decode(&u)
	}
}
pub(super) fn lease(body: &Untrusted<Bytes, Server>) -> Result<super::LeaseReceipt, DecodeError> {
	Ok(body.as_bytes().validate_carrying(LeaseResponseDecoder)?.into_receipt())
}

struct HeartbeatResponseDecoder;
impl Validate<&[u8], Server> for HeartbeatResponseDecoder {
	type Output = loupe_proto::HeartbeatResponse;
	type Error = DecodeError;
	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, _: Mark<'view, Server>,
	) -> Result<Self::Output, DecodeError> {
		Ok(serde_json::from_slice(u.get())?)
	}
}
pub(super) fn heartbeat(
	body: &Untrusted<Bytes, Server>,
) -> Result<loupe_proto::HeartbeatResponse, DecodeError> {
	body.as_bytes().validate(HeartbeatResponseDecoder)
}

struct FindingDetailResponseDecoder;
impl ValidateCarrying<&[u8], Server> for FindingDetailResponseDecoder {
	type Output = finding::DecodedFindingDetail;
	type Error = DecodeError;
	fn validate(self, u: Unvalidated<'_, &[u8], Server>) -> Result<Self::Output, DecodeError> {
		finding::detail(&u)
	}
}
pub(super) fn detail(
	body: &Untrusted<Bytes, Server>,
) -> Result<loupe_proto::FindingDetail, DecodeError> {
	Ok(body.as_bytes().validate_carrying(FindingDetailResponseDecoder)?.into_legacy())
}

#[derive(Deserialize)]
struct RawSearch<'a> {
	protocol_version: u16,
	#[serde(borrow)]
	findings: Vec<&'a RawValue>,
}
struct DecodedSearchResponse {
	protocol_version: u16,
	findings: Vec<finding::DecodedSummary>,
}
impl DecodedSearchResponse {
	fn into_legacy(self) -> loupe_proto::ListFindingsResponse {
		loupe_proto::ListFindingsResponse {
			protocol_version: self.protocol_version,
			findings: self.findings.into_iter().map(finding::DecodedSummary::into_legacy).collect(),
		}
	}
}
struct SearchFindingsResponseDecoder;
impl ValidateCarrying<&[u8], Server> for SearchFindingsResponseDecoder {
	type Output = DecodedSearchResponse;
	type Error = DecodeError;
	fn validate(self, u: Unvalidated<'_, &[u8], Server>) -> Result<Self::Output, DecodeError> {
		let raw: RawSearch<'_> = serde_json::from_slice(u.get())?;
		let findings =
			raw.findings.into_iter().map(|t| finding::summary(&u, t)).collect::<Result<_, _>>()?;
		Ok(DecodedSearchResponse { protocol_version: raw.protocol_version, findings })
	}
}
pub(super) fn search(
	body: &Untrusted<Bytes, Server>,
) -> Result<loupe_proto::ListFindingsResponse, DecodeError> {
	Ok(body.as_bytes().validate_carrying(SearchFindingsResponseDecoder)?.into_legacy())
}

/// Temporary legacy diagnostic exit, not a general byte extraction adapter.
struct ServerErrorResponse;
impl Validate<&[u8], Server> for ServerErrorResponse {
	type Output = String;
	type Error = std::convert::Infallible;
	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, _: Mark<'view, Server>,
	) -> Result<String, Self::Error> {
		Ok(String::from_utf8_lossy(u.get()).trim().to_owned())
	}
}
pub(super) fn error(body: &Untrusted<Bytes, Server>) -> String {
	match body.as_bytes().validate(ServerErrorResponse) {
		Ok(value) => value,
		Err(never) => match never {},
	}
}

/// This endpoint's successful body is intentionally ignored, including 204.
/// Keep that protocol disposal as a named endpoint operation.
struct SubmissionResponse;
impl Validate<&[u8], Server> for SubmissionResponse {
	type Output = ();
	type Error = std::convert::Infallible;
	fn validate<'view>(
		self, _: Unvalidated<'view, &[u8]>, _: Mark<'view, Server>,
	) -> Result<(), Self::Error> {
		Ok(())
	}
}
pub(super) fn submission(body: Untrusted<Bytes, Server>) {
	match body.as_bytes().validate(SubmissionResponse) {
		Ok(()) => (),
		Err(never) => match never {},
	}
}
