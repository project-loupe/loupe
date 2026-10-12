//! Deliberate credential delivery keeps the encoded owner through HTTP.

use bytes::Bytes;
use loupe_provenance::Secret;
use reqwest::header::CONTENT_TYPE;
use reqwest::RequestBuilder;

struct CredentialBody(Secret<Vec<u8>>);

impl AsRef<[u8]> for CredentialBody {
	fn as_ref(&self) -> &[u8] {
		self.0.expose()
	}
}

pub(super) fn with_body(request: RequestBuilder, encoded: Secret<Vec<u8>>) -> RequestBuilder {
	request
		.header(CONTENT_TYPE, "application/json")
		.body(Bytes::from_owner(CredentialBody(encoded)))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn request_and_clones_retain_the_encoded_allocation() {
		let encoded = Secret::new(b"synthetic-request-secret".to_vec());
		let pointer = encoded.expose().as_ptr();
		let request =
			with_body(reqwest::Client::new().post("http://127.0.0.1/"), encoded).build().unwrap();
		assert_eq!(request.headers()[CONTENT_TYPE], "application/json");
		assert_eq!(request.body().unwrap().as_bytes().unwrap().as_ptr(), pointer);
		let clone = request.try_clone().unwrap();
		drop(request);
		let retained = clone.body().unwrap().as_bytes().unwrap();
		assert_eq!(retained.as_ptr(), pointer);
		assert_eq!(retained, b"synthetic-request-secret");
	}
}
