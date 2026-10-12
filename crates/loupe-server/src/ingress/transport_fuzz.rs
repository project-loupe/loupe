//! Observe actual collection and still-live cleanup without minting a source.
use std::sync::{Arc, Mutex};

use axum::body::Body;
use futures_util::{stream, StreamExt};

use super::{collect_operator_body, Bytes, RequestBuffer, BODY_CAP};

pub struct Collection {
	pub result: Result<(usize, [u8; 32]), (u16, String)>,
	pub wipes: Vec<(usize, bool)>,
	pub shared_owner_retained: bool,
}

/// `finish`: 0 completes, 1 fails after emitted bytes, 2 becomes pending.
/// A compact padding count reaches the real cap without a second large owner.
pub async fn collect_operator(
	prefix: &[u8], padding: usize, chunk_size: usize, finish: u8, schedule: u8,
) -> Collection {
	assert!(prefix.len() <= 64 * 1024 && padding <= BODY_CAP + 1);
	assert!((1..=8192).contains(&chunk_size));
	assert!(schedule < 3);
	// Large compact recipes have bounded work even when the schedule byte
	// would otherwise select one-byte chunks.
	let chunk_size = if padding > 64 * 1024 { chunk_size.max(4096) } else { chunk_size };
	let audit = Arc::new(Mutex::new(Vec::new()));
	let buffer = RequestBuffer { allocation: Box::default(), used: 0, audit: Some(audit.clone()) };
	let prefix = prefix.to_vec();
	let length = prefix.len() + padding;
	let data = stream::unfold((prefix, 0, 0usize), move |(prefix, offset, tick)| async move {
		if offset == length {
			return None;
		}
		let count = match (schedule, tick % 3) {
			(1, 0) => 0,
			(2, 0) => 1,
			(2, 1) => chunk_size / 2 + 1,
			_ => chunk_size,
		};
		let count = if padding > 64 * 1024 && count != 0 { count.max(4096) } else { count };
		let end = (offset + count).min(length);
		let mut chunk = vec![b' '; end - offset];
		if offset < prefix.len() {
			let copied = (prefix.len() - offset).min(chunk.len());
			chunk[..copied].copy_from_slice(&prefix[offset..offset + copied]);
		}
		Some((Ok::<_, std::io::Error>(Bytes::from(chunk)), (prefix, end, tick + 1)))
	});
	let tail = stream::once(async move {
		if finish == 2 {
			std::future::pending::<()>().await;
		}
		if finish == 1 {
			Err(std::io::Error::other("private_stream_sentinel"))
		} else {
			Ok(Bytes::new())
		}
	});
	let mut collecting =
		Box::pin(collect_operator_body(Body::from_stream(data.chain(tail)), buffer));
	let output = if finish == 2 {
		match futures_util::poll!(&mut collecting) {
			std::task::Poll::Ready(result) => Some(result),
			std::task::Poll::Pending => None,
		}
	} else {
		Some(collecting.as_mut().await)
	};
	drop(collecting);
	let mut shared_owner_retained = true;
	let result = match output {
		Some(Ok(bytes)) => {
			let count = bytes.len();
			let digest = *blake3::hash(&bytes).as_bytes();
			let before = audit.lock().expect("audit lock").len();
			let shared = bytes.clone();
			shared_owner_retained = bytes.as_ptr() == shared.as_ptr();
			drop(bytes);
			shared_owner_retained &= audit.lock().expect("audit lock").len() == before;
			drop(shared);
			Ok((count, digest))
		},
		Some(Err((status, text))) => Err((status.as_u16(), text)),
		None => Err((0, "fixture cancelled pending collection".into())),
	};
	let wipes = audit.lock().expect("audit lock").clone();
	Collection { result, wipes, shared_owner_retained }
}
