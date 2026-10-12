//! Actual GitHub response capture, with fixed concrete Reporter schemas.
//! Ordinary responses use the existing guarded 16 MiB HTTP collector; the
//! confidential token endpoint keeps its separate 256 KiB collector.
use bytes::Bytes;
use loupe_core::source_migration::text::BoundedText;
use loupe_core::text::policy::GithubAppSlug;
use loupe_provenance::{Ingress, Mark, Reporter, Untrusted, Unvalidated, Validate};
use serde::Deserialize;
use serde_json::value::RawValue;

pub(super) async fn read(
	response: reqwest::Response,
) -> anyhow::Result<Untrusted<Bytes, Reporter>> {
	let bytes = loupe_http::read_response_bytes(response).await.map_err(|error| match error {
		loupe_http::ResponseBodyError::TooLarge => {
			anyhow::anyhow!("GitHub response body exceeds 16777216 bytes")
		},
		loupe_http::ResponseBodyError::Transport(_) => {
			anyhow::anyhow!("reading GitHub response body")
		},
	})?;
	// SAFETY: this allocation is the actual just-collected GitHub HTTP response,
	// before any schema parse, with its guarded owner retained by Bytes.
	#[allow(unsafe_code)]
	let token = unsafe { Ingress::<Reporter>::new() };
	Ok(Untrusted::new(bytes, token))
}

#[derive(Debug, thiserror::Error)]
#[error("{0}: invalid response body")]
pub(super) struct ReporterDecodeError(pub(super) &'static str);

#[derive(Deserialize)]
struct RawApp<'a> {
	id: u64,
	#[serde(borrow)]
	slug: &'a RawValue,
}
pub(super) struct AppMetadata {
	id: u64,
	slug: BoundedText<GithubAppSlug, Reporter>,
}
pub(super) struct AppMetadataDecoder;
impl Validate<&[u8], Reporter> for AppMetadataDecoder {
	type Output = AppMetadata;
	type Error = ReporterDecodeError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &[u8]>, mark: Mark<'view, Reporter>,
	) -> Result<Self::Output, Self::Error> {
		let raw: RawApp<'_> = serde_json::from_slice(input.get())
			.map_err(|_| ReporterDecodeError("parsing GitHub App metadata"))?;
		let slug = crate::ingress::text::json_text(&mark, raw.slug)
			.map_err(|_| ReporterDecodeError("parsing GitHub App metadata"))?;
		Ok(AppMetadata { id: raw.id, slug })
	}
}
impl AppMetadataDecoder {
	/// Named temporary I exit; M retains Reporter slug through the API owner.
	pub(super) fn decode_legacy(
		body: Untrusted<Bytes, Reporter>,
	) -> anyhow::Result<super::github_app::GithubAppInfo> {
		let value = body.as_bytes().validate(Self)?;
		Ok(super::github_app::GithubAppInfo { id: value.id, slug: value.slug.expose().to_owned() })
	}
}

#[derive(Deserialize)]
struct RawInstallation {
	id: u64,
}
pub(super) struct InstallationDecoder;
impl Validate<&[u8], Reporter> for InstallationDecoder {
	type Output = u64;
	type Error = ReporterDecodeError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &[u8]>, _: Mark<'view, Reporter>,
	) -> Result<Self::Output, Self::Error> {
		serde_json::from_slice::<RawInstallation>(input.get())
			.map(|body| body.id)
			.map_err(|_| ReporterDecodeError("parsing installation response"))
	}
}

pub(super) struct IssueReceiptDecoder;
impl Validate<&[u8], Reporter> for IssueReceiptDecoder {
	type Output = Option<i64>;
	type Error = ReporterDecodeError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &[u8]>, _: Mark<'view, Reporter>,
	) -> Result<Self::Output, Self::Error> {
		// Retain the legacy Value grammar and missing/noninteger -> None behavior.
		// Its bounded dependency-owned scratch is discarded inside this decoder.
		let body: serde_json::Value = serde_json::from_slice(input.get())
			.map_err(|_| ReporterDecodeError("parsing issue response"))?;
		Ok(body.get("number").and_then(serde_json::Value::as_i64))
	}
}

pub(super) struct LabelResponseDecoder;
impl Validate<&[u8], Reporter> for LabelResponseDecoder {
	type Output = bool;
	type Error = ReporterDecodeError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &[u8]>, _: Mark<'view, Reporter>,
	) -> Result<Self::Output, Self::Error> {
		// ASCII substring admission is identical to reqwest's lossy UTF-8 text
		// path for this marker, including malformed UTF-8/non-JSON responses.
		Ok(input.get().windows(b"already_exists".len()).any(|window| window == b"already_exists"))
	}
}

/// Pure fixtures exercise the same named decoders as HTTP. Status, actual
/// bounded collection, cancellation and authentication need transport tests.
#[cfg(fuzzing)]
pub(crate) mod fuzz_support {
	use super::*;

	#[allow(unsafe_code)]
	pub(in crate::reporters) fn original(body: &[u8]) -> Untrusted<&[u8], Reporter> {
		// SAFETY: the fuzzer supplied this synthetic Reporter response body.
		Untrusted::new(body, unsafe { Ingress::<Reporter>::new() })
	}

	pub(in crate::reporters) fn diagnostic(error: ReporterDecodeError) -> String {
		assert!(std::error::Error::source(&error).is_none());
		assert_eq!(format!("{error:?}"), format!("ReporterDecodeError({:?})", error.0));
		error.to_string()
	}

	pub fn app(body: &[u8]) -> Result<(u64, String), String> {
		let app = original(body).validate(AppMetadataDecoder).map_err(diagnostic)?;
		let slug: &BoundedText<GithubAppSlug, Reporter> = &app.slug;
		Ok((app.id, slug.expose().to_owned()))
	}

	pub fn installation(body: &[u8]) -> Result<u64, String> {
		original(body).validate(InstallationDecoder).map_err(diagnostic)
	}

	pub fn issue(body: &[u8]) -> Result<Option<i64>, String> {
		original(body).validate(IssueReceiptDecoder).map_err(diagnostic)
	}

	pub fn label(body: &[u8]) -> Result<bool, String> {
		original(body).validate(LabelResponseDecoder).map_err(diagnostic)
	}
}
