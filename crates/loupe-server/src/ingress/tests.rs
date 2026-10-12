//! Ownership checks observe zeroed allocations while they are still live,
//! never by reading freed memory. Router
//! tests separately prove body charging, cap precedence and stream rejection.
use std::sync::{Arc, Mutex};

use axum::body::Body;
use futures_util::{stream, StreamExt};

use super::*;

type Audit = Arc<Mutex<Vec<(usize, bool)>>>;
fn observed() -> (RequestBuffer, Audit) {
	let audit = Arc::new(Mutex::new(Vec::new()));
	(RequestBuffer { allocation: Box::default(), used: 0, audit: Some(audit.clone()) }, audit)
}

#[test]
fn growth_wipes_old_capacity_and_bytes_clones_retain_final_owner() {
	let (mut buffer, audit) = observed();
	buffer.append(b"ABC").unwrap();
	buffer.append(b"DEFGHI").unwrap();
	assert_eq!(*audit.lock().unwrap(), [(4, true)]);
	let bytes = Bytes::from_owner(buffer);
	let shared = bytes.clone();
	assert_eq!(bytes.as_ptr(), shared.as_ptr());
	assert_eq!(shared.as_ref(), b"ABCDEFGHI");
	drop(bytes);
	assert_eq!(*audit.lock().unwrap(), [(4, true)]);
	drop(shared);
	assert_eq!(*audit.lock().unwrap(), [(4, true), (16, true)]);
}

#[tokio::test]
async fn stream_error_and_over_cap_wipe_collected_storage() {
	for cap_error in [false, true] {
		let (buffer, audit) = observed();
		let tail = if cap_error {
			Ok(Bytes::from(vec![b'X'; BODY_CAP]))
		} else {
			Err(std::io::Error::other("FAKE_REQUEST_STREAM_ERROR"))
		};
		let body = Body::from_stream(stream::iter([Ok(Bytes::from_static(b"ABC")), tail]));
		let error = collect_operator_body(body, buffer).await.unwrap_err();
		assert_eq!(
			error.0,
			if cap_error { StatusCode::PAYLOAD_TOO_LARGE } else { StatusCode::BAD_REQUEST }
		);
		assert!(!error.1.contains("FAKE_REQUEST_STREAM_ERROR"));
		assert_eq!(*audit.lock().unwrap(), [(4, true)]);
	}
}

#[tokio::test]
async fn cancelled_collection_wipes_partial_body() {
	let (buffer, audit) = observed();
	let stream = stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(b"ABC"))])
		.chain(stream::pending());
	let mut collecting = Box::pin(collect_operator_body(Body::from_stream(stream), buffer));
	assert!(futures_util::poll!(&mut collecting).is_pending());
	assert!(audit.lock().unwrap().is_empty());
	drop(collecting);
	assert_eq!(*audit.lock().unwrap(), [(4, true)]);
}

#[tokio::test]
async fn completed_collection_keeps_bytes_until_last_owner() {
	let (buffer, audit) = observed();
	let bytes = collect_operator_body(Body::from("ABC"), buffer).await.unwrap();
	assert_eq!(bytes.as_ref(), b"ABC");
	assert!(audit.lock().unwrap().is_empty());
	drop(bytes);
	assert_eq!(*audit.lock().unwrap(), [(4, true)]);
}
