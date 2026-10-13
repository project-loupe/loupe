//! Collector ownership checks observe live storage after zeroisation,
//! before its allocation is freed.

use std::sync::{Arc, Mutex};

use futures_util::{stream, StreamExt};

use super::*;

pub(super) type DropAudit = Arc<Mutex<Vec<(usize, bool)>>>;

fn observed() -> (ResponseBuffer, DropAudit) {
	let audit = DropAudit::default();
	(ResponseBuffer { allocation: Box::default(), used: 0, audit: Some(Arc::clone(&audit)) }, audit)
}

fn drops(audit: &DropAudit) -> Vec<usize> {
	let observations = audit.lock().unwrap();
	assert!(observations.iter().all(|(_, zeroed)| *zeroed), "released storage was not wiped");
	observations.iter().map(|(capacity, _)| *capacity).filter(|capacity| *capacity > 0).collect()
}

#[test]
fn growth_wipes_replaced_storage_and_last_slice_retains_the_owner() {
	let (mut body, audit) = observed();
	body.append(b"key").unwrap();
	assert_eq!(body.allocation.len(), 4);
	body.append(b"12").unwrap();
	assert_eq!(body.allocation.len(), 8);
	assert_eq!(drops(&audit), vec![4]);
	let bytes = Bytes::from_owner(body);
	let shared = bytes.clone();
	let slice = bytes.slice(1..4);
	assert_eq!(bytes.as_ptr(), shared.as_ptr());
	drop(bytes);
	drop(shared);
	assert_eq!(&slice[..], b"ey1");
	assert_eq!(drops(&audit), vec![4]);
	drop(slice);
	assert_eq!(drops(&audit), vec![4, 8]);
}

#[test]
fn irregular_chunks_bound_every_allocation_and_fill_the_exact_budget() {
	let (mut body, audit) = observed();
	let chunk = [b'x'; 31_337];
	while body.used < MAX_RESPONSE_BYTES {
		let size = chunk.len().min(MAX_RESPONSE_BYTES - body.used);
		body.append(&chunk[..size]).unwrap();
		assert!(body.allocation.len() <= MAX_RESPONSE_BYTES);
		assert!(body.allocation.len() < body.used.saturating_mul(2));
	}
	assert_eq!(body.used, MAX_RESPONSE_BYTES);
	assert!(body.as_ref().iter().all(|byte| *byte == b'x'));
	assert!(matches!(body.append(b"x"), Err(ResponseBodyError::TooLarge)));
	assert_eq!(body.used, MAX_RESPONSE_BYTES);
	drop(body);
	assert_eq!(drops(&audit).last(), Some(&MAX_RESPONSE_BYTES));
}

#[tokio::test]
async fn oversize_and_transport_failure_wipe_the_collected_prefix() {
	let (body, audit) = observed();
	let chunks = stream::iter([
		Ok(Bytes::from_static(b"key")),
		Ok(Bytes::from(vec![b'x'; MAX_RESPONSE_BYTES])),
	]);
	assert!(matches!(collect(chunks, body).await, Err(ResponseBodyError::TooLarge)));
	assert_eq!(drops(&audit), vec![4]);

	let (body, audit) = observed();
	let error = reqwest::get("http://[").await.unwrap_err();
	let chunks = stream::iter([Ok(Bytes::from_static(b"key")), Err(error)]);
	assert!(matches!(collect(chunks, body).await, Err(ResponseBodyError::Transport(_))));
	assert_eq!(drops(&audit), vec![4]);
}

#[tokio::test]
async fn cancellation_wipes_the_collected_prefix() {
	let (body, audit) = observed();
	let chunks = stream::iter([Ok(Bytes::from_static(b"key"))]).chain(stream::pending());
	let mut pending = Box::pin(collect(chunks, body));
	assert!(futures_util::poll!(&mut pending).is_pending());
	assert!(drops(&audit).is_empty());
	drop(pending);
	assert_eq!(drops(&audit), vec![4]);
}

#[tokio::test]
async fn transport_error_formatting_and_source_do_not_disclose_response_urls() {
	let error = reqwest::get("http://[").await.unwrap_err().with_url(
		reqwest::Url::parse("https://untrusted-response-sentinel.example/path?token=secret")
			.unwrap(),
	);
	let error = collect(stream::iter([Err(error)]), ResponseBuffer::default()).await.unwrap_err();
	assert_eq!(
		(format!("{error:?}"), error.to_string(), std::error::Error::source(&error).is_some()),
		("Transport([redacted])".to_owned(), "reading response body failed".to_owned(), false),
		"response transport diagnostics must disclose only the error category"
	);
	assert_eq!(ResponseBodyError::TooLarge.to_string(), "response body exceeds 16777216 bytes");
}
