//! Actual authenticated request owners and their closed, temporary I decoders.
//! The named `decode_legacy` exits are removed at atomic source adoption (M).
//! Transport chunks and serde scratch remain dependency-owned; collected
//! request storage is guarded through validation and all failure exits.

use axum::extract::{FromRequest, Request};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use bytes::Bytes;
use futures_util::StreamExt;
use loupe_provenance::{Ingress, Operator, Untrusted, Worker, Zeroise};

use crate::auth::AuthedWorker;

pub(crate) mod error;
pub(crate) mod jobs;
pub(crate) mod query;
pub(crate) mod registry;
#[cfg(test)]
mod tests;
pub(crate) mod text;
pub(crate) use error::DecodeError;

pub(crate) const BODY_CAP: usize = 2 * 1024 * 1024;
#[cfg(test)]
type CleanupAudit = std::sync::Arc<std::sync::Mutex<Vec<(usize, bool)>>>;

#[derive(Default)]
pub(crate) struct RequestBuffer {
	allocation: Box<[u8]>,
	used: usize,
	#[cfg(test)]
	audit: Option<CleanupAudit>,
}

/// Numeric admission used before allocating or copying an incoming chunk.
/// Also reject overflow and invalid starting lengths without subtraction.
pub(crate) fn request_body_next_len(used: usize, incoming: usize) -> Option<usize> {
	used.checked_add(incoming).filter(|required| *required <= BODY_CAP)
}

impl RequestBuffer {
	pub(crate) fn append(&mut self, chunk: &[u8]) -> Result<(), StatusCode> {
		let required =
			request_body_next_len(self.used, chunk.len()).ok_or(StatusCode::PAYLOAD_TOO_LARGE)?;
		if required > self.allocation.len() {
			let mut replacement = Self {
				allocation: vec![0; required.next_power_of_two().min(BODY_CAP)].into_boxed_slice(),
				used: self.used,
				#[cfg(test)]
				audit: self.audit.clone(),
			};
			replacement.allocation[..self.used].copy_from_slice(self.as_ref());
			*self = replacement;
		}
		self.allocation[self.used..required].copy_from_slice(chunk);
		self.used = required;
		Ok(())
	}
}
impl AsRef<[u8]> for RequestBuffer {
	fn as_ref(&self) -> &[u8] {
		&self.allocation[..self.used]
	}
}
impl Drop for RequestBuffer {
	fn drop(&mut self) {
		self.allocation.zeroise();
		#[cfg(test)]
		if let Some(audit) = &self.audit
			&& !self.allocation.is_empty()
		{
			audit
				.lock()
				.unwrap()
				.push((self.allocation.len(), self.allocation.iter().all(|byte| *byte == 0)));
		}
	}
}

// Clone shares Bytes' final guarded allocation; no plaintext replay Body.
#[derive(Clone)]
pub(crate) struct CapturedWorkerBody(Untrusted<Bytes, Worker>);
impl CapturedWorkerBody {
	pub(crate) fn new(buffer: RequestBuffer, token: Ingress<Worker>) -> Self {
		Self(Untrusted::new(Bytes::from_owner(buffer), token))
	}
}

pub struct WorkerBody(pub(super) Untrusted<Bytes, Worker>);
pub struct WorkerJson(pub(super) Untrusted<Bytes, Worker>);
pub struct OperatorJson(pub(super) Untrusted<Bytes, Operator>);

fn json_media(request: &Request) -> Result<(), (StatusCode, String)> {
	// Axum's Json admits application/json and any application/*+json, with
	// parameters. Reuse the MIME grammar without collecting the body again.
	let valid = request
		.headers()
		.get(CONTENT_TYPE)
		.and_then(|value| value.to_str().ok())
		.and_then(|value| value.parse::<mime::Mime>().ok())
		.is_some_and(|mime| {
			mime.type_() == mime::APPLICATION
				&& (mime.subtype() == mime::JSON || mime.suffix() == Some(mime::JSON))
		});
	if valid {
		Ok(())
	} else {
		Err((
			StatusCode::UNSUPPORTED_MEDIA_TYPE,
			"Expected request with Content-Type: application/json".into(),
		))
	}
}

impl<S: Send + Sync> FromRequest<S> for WorkerBody {
	type Rejection = (StatusCode, String);
	async fn from_request(mut req: Request, _: &S) -> Result<Self, Self::Rejection> {
		if req.extensions().get::<AuthedWorker>().and_then(AuthedWorker::worker_ingress).is_none() {
			return Err((StatusCode::FORBIDDEN, "worker role required".into()));
		}
		req.extensions_mut().remove::<CapturedWorkerBody>().map(|body| Self(body.0)).ok_or_else(
			|| (StatusCode::INTERNAL_SERVER_ERROR, "missing captured worker body".into()),
		)
	}
}
impl<S: Send + Sync> FromRequest<S> for WorkerJson {
	type Rejection = (StatusCode, String);
	async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
		json_media(&req)?;
		WorkerBody::from_request(req, state).await.map(|body| Self(body.0))
	}
}
impl<S: Send + Sync> FromRequest<S> for OperatorJson {
	type Rejection = (StatusCode, String);
	async fn from_request(req: Request, _: &S) -> Result<Self, Self::Rejection> {
		json_media(&req)?;
		let token = req
			.extensions()
			.get::<AuthedWorker>()
			.and_then(AuthedWorker::operator_ingress)
			.ok_or_else(|| (StatusCode::FORBIDDEN, "operator role required".into()))?;
		let bytes = collect_operator_body(req.into_body(), RequestBuffer::default()).await?;
		Ok(Self(Untrusted::new(bytes, token)))
	}
}

async fn collect_operator_body(
	body: axum::body::Body, mut buffered: RequestBuffer,
) -> Result<Bytes, (StatusCode, String)> {
	let mut stream = body.into_data_stream();
	while let Some(chunk) = stream.next().await {
		let chunk = chunk.map_err(|_| (StatusCode::BAD_REQUEST, "reading request body".into()))?;
		buffered
			.append(&chunk)
			.map_err(|status| (status, "request body exceeds 2097152 bytes".into()))?;
	}
	Ok(Bytes::from_owner(buffered))
}
