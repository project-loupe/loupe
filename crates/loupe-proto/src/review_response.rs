//! Shared admission rules for review phase responses read from Server bytes.
//! Responses that carry no Agent content must re-serialize to exactly the
//! received JSON, which also refuses sequence-form objects, map-form enums
//! and integer tags.

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::value::RawValue;
use serde_json::Value;

use crate::review_lease::ReviewLeaseDecodeError;

/// A bounded, content-free response admission failure.
// debug-ok: parser errors retain only static classifications and policy errors.
#[derive(Debug, thiserror::Error)]
pub enum ReviewResponseDecodeError {
	#[error("invalid review response JSON")]
	Json,
	#[error("invalid review response: {0}")]
	Invalid(&'static str),
	#[error(transparent)]
	Text(#[from] loupe_core::text::Error),
	#[error(transparent)]
	Payload(#[from] loupe_core::review_payload::Error),
}
impl From<serde_json::Error> for ReviewResponseDecodeError {
	fn from(_: serde_json::Error) -> Self {
		Self::Json
	}
}
impl From<ReviewLeaseDecodeError> for ReviewResponseDecodeError {
	fn from(error: ReviewLeaseDecodeError) -> Self {
		match error {
			ReviewLeaseDecodeError::Json => Self::Json,
			ReviewLeaseDecodeError::Invalid(rule) => Self::Invalid(rule),
			ReviewLeaseDecodeError::Text(error) => Self::Text(error),
			ReviewLeaseDecodeError::Payload(error) => Self::Payload(error),
		}
	}
}
type Error = ReviewResponseDecodeError;

/// Admits `value` only if it serializes to exactly the received document.
pub(crate) fn exact<T: Serialize>(raw: &[u8], value: T) -> Result<T, Error> {
	let received: Value = serde_json::from_slice(raw)?;
	if serde_json::to_value(&value)? != received {
		return Err(Error::Invalid("response not in its serialized form"));
	}
	Ok(value)
}

/// Decodes a metadata-only response type that serde may construct directly.
pub(crate) fn exact_response<T: Serialize + DeserializeOwned>(raw: &[u8]) -> Result<T, Error> {
	let value: T = serde_json::from_slice(raw)?;
	exact(raw, value)
}

/// A closed vocabulary value spelled only as a JSON string.
pub(crate) fn closed<T: DeserializeOwned>(raw: &RawValue) -> Result<T, Error> {
	if !raw.get().starts_with('"') {
		return Err(Error::Invalid("closed value is not a string"));
	}
	Ok(serde_json::from_str(raw.get())?)
}

/// An optional field the server always spells, as a value or `null`.
pub(crate) fn present<'de, D: serde::Deserializer<'de>>(
	deserializer: D,
) -> Result<Option<&'de RawValue>, D::Error> {
	serde::Deserialize::deserialize(deserializer)
}

/// A `Validate<&[u8], Server>` for a metadata-only response type.
macro_rules! exact_response_decoder {
	($(#[$doc:meta])* $decoder:ident => $response:ty) => {
		$(#[$doc])*
		pub struct $decoder;
		impl loupe_provenance::Validate<&[u8], loupe_provenance::Server> for $decoder {
			type Output = $response;
			type Error = $crate::review_response::ReviewResponseDecodeError;
			fn validate<'v>(
				self, u: loupe_provenance::Unvalidated<'v, &[u8]>,
				_: loupe_provenance::Mark<'v, loupe_provenance::Server>,
			) -> Result<Self::Output, Self::Error> {
				$crate::review_response::exact_response(u.get())
			}
		}
	};
}

/// Server-labelled metadata from a JSON string token of the response.
pub(crate) fn metadata<P: loupe_core::text::IdentPolicy>(
	mark: &loupe_provenance::Mark<'_, loupe_provenance::Server>, raw: &RawValue,
) -> Result<loupe_core::text::Identifier<P, loupe_provenance::Server>, Error> {
	let value =
		loupe_core::text::decode_json_string_bounded(raw.get(), P::FIELD, P::MAX_LEN, P::MAX_LEN)?;
	Ok(loupe_core::text::Identifier::new(mark, &value)?)
}
