//! Authenticated credential egress retains its wiping serialization owner.

use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use loupe_proto::{LeaseResponse, RegisterWorkerResponse};
use loupe_provenance::Secret;

struct CredentialBody(Secret<Vec<u8>>);

impl AsRef<[u8]> for CredentialBody {
	fn as_ref(&self) -> &[u8] {
		self.0.expose()
	}
}

pub(super) fn lease(value: &LeaseResponse) -> Result<Response, (StatusCode, String)> {
	response(value.credential_json(), StatusCode::OK)
}

pub(super) fn worker(value: &RegisterWorkerResponse) -> Result<Response, (StatusCode, String)> {
	response(value.credential_json(), StatusCode::CREATED)
}

fn response(
	encoded: serde_json::Result<Secret<Vec<u8>>>, status: StatusCode,
) -> Result<Response, (StatusCode, String)> {
	let encoded = encoded.map_err(|_| {
		(StatusCode::INTERNAL_SERVER_ERROR, "credential response encoding failed".to_owned())
	})?;
	Ok((status, [(CONTENT_TYPE, "application/json")], Bytes::from_owner(CredentialBody(encoded)))
		.into_response())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn response_retains_the_encoded_allocation() {
		let encoded = Secret::new(b"synthetic-response-secret".to_vec());
		let pointer = encoded.expose().as_ptr();
		let response = response(Ok(encoded), StatusCode::CREATED).unwrap();
		assert_eq!(response.status(), StatusCode::CREATED);
		assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
		let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
		assert_eq!(body.as_ptr(), pointer);
		let clone = body.clone();
		drop(body);
		assert_eq!(clone.as_ptr(), pointer);
		assert_eq!(&clone[..], b"synthetic-response-secret");
	}

	#[test]
	fn serializer_error_does_not_retain_secret_diagnostics() {
		let error = serde_json::Error::io(std::io::Error::other("synthetic-secret-error"));
		let (status, message) = response(Err(error), StatusCode::OK).unwrap_err();
		assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
		assert_eq!(message, "credential response encoding failed");
	}
}
