//! Actual worker HTTP decode paths under chunked and oversized responses.
//!
//! Byte 0 selects lease, heartbeat, search, finding detail, or an error.
//! Byte 1 controls the chunk size. Byte 2 selects an ordinary response,
//! padding to the 16 MiB budget (254), or one byte over (255). Remaining
//! bytes are the server body. Padding is streamed, never materialized.

use std::sync::OnceLock;
use std::time::Duration;

use loupe_http::MAX_RESPONSE_BYTES;
use loupe_proto::{JobCapability, PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use loupe_worker::ServerClient;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

use crate::utils::test_logger;

#[cfg(test)]
static LISTENER_BINDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub fn do_test(data: &[u8]) {
	let Some((&kind, rest)) = data.split_first() else { return };
	let Some((&chunk_control, rest)) = rest.split_first() else { return };
	let Some((&padding_control, bytes)) = rest.split_first() else { return };
	let kind = kind % 5;
	let bytes = &bytes[..bytes.len().min(MAX_RESPONSE_BYTES + 1)];
	let length = match padding_control {
		255 => (MAX_RESPONSE_BYTES + 1).max(bytes.len()),
		254 => MAX_RESPONSE_BYTES.max(bytes.len()),
		_ => bytes.len(),
	};
	let expected = (kind < 4 && length <= MAX_RESPONSE_BYTES)
		.then(|| crate::worker_client_ingress::oracle::client(kind, bytes))
		.flatten();
	// A new listening port per input exhausts the ephemeral range with
	// TIME_WAIT sockets during sustained campaigns. Keep the endpoint and
	// its owning reactor together for the lifetime of this target.
	static FIXTURE: OnceLock<(tokio::runtime::Runtime, tokio::net::TcpListener)> = OnceLock::new();
	let (runtime, listener) = FIXTURE.get_or_init(|| {
		let runtime = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.unwrap_or_else(|error| panic!("response fuzz runtime: {error}"));
		let listener = runtime
			.block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
			.unwrap_or_else(|error| panic!("response fuzz listener: {error}"));
		#[cfg(test)]
		LISTENER_BINDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
		(runtime, listener)
	});
	runtime.block_on(async {
		let address = listener.local_addr()
			.unwrap_or_else(|error| panic!("response fuzz address: {error}"));
		let payload = bytes.to_vec();
		let mut server = tokio::spawn(async move {
			let (mut socket, _) = listener.accept().await?;
			read_request(&mut socket).await?;
			let status = if kind == 4 { "409 Conflict" } else { "200 OK" };
			let headers = format!("HTTP/1.1 {status}\r\n{PROTOCOL_VERSION_HEADER}: {PROTOCOL_VERSION}\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n");
			socket.write_all(headers.as_bytes()).await?;
			for chunk in payload.chunks(usize::from(chunk_control) * 16 + 1) {
				write_chunk(&mut socket, chunk).await?;
			}
			let spaces = [b' '; 8192];
			let mut remaining = length - payload.len();
			while remaining > 0 {
				let size = remaining.min(spaces.len());
				write_chunk(&mut socket, &spaces[..size]).await?;
				remaining -= size;
			}
			socket.write_all(b"0\r\n\r\n").await
		});
		let result = tokio::time::timeout(Duration::from_secs(5), async {
			let base = reqwest::Url::parse(&format!("http://{address}/"))
				.unwrap_or_else(|error| panic!("response fuzz URL: {error}"));
			let client = ServerClient::from_parts(reqwest::Client::new(), base);
			let capability = JobCapability::from_secret("fuzz-capability");
			let result = match kind {
				0 => client.lease(Vec::new(), 0).await.map(serde_json::to_value),
				1 | 4 => client.heartbeat(1, &capability).await.map(serde_json::to_value),
				2 => client.search_findings(1, &capability, &crate::fixtures::text("").unwrap_or_else(|_| panic!("empty query")), 100).await.map(serde_json::to_value),
				_ => client.get_finding(1, &capability).await.map(serde_json::to_value),
			};
			// Rejecting an oversized body can close the socket before the
			// sender finishes. Join failures, unlike write failures, are bugs.
			let _ = (&mut server).await.unwrap_or_else(|error| panic!("response fuzz server: {error}"));
			if length > MAX_RESPONSE_BYTES {
				let error = result.err().unwrap_or_else(|| panic!("accepted oversized response"));
				let message = format!("{error:#}");
				assert!(message.contains("response body exceeds"));
				assert!(message.len() < 512);
			} else {
				assert_eq!(result.is_ok(), expected.is_some(), "worker response decoder disagrees");
				if let Ok(actual) = &result {
					assert_eq!(actual.as_ref().ok(), expected.as_ref(), "actual HTTP decoder changed admitted field values");
				}
				if kind == 4 {
					let error = result.err().unwrap_or_else(|| panic!("accepted server error"));
					assert!(format!("{error:#}").contains("409 Conflict"));
				}
			}
		}).await;
		if result.is_err() {
			server.abort();
			let _ = server.await;
		}
		assert!(result.is_ok(), "response fuzz transport timed out");
	});
}

async fn write_chunk(socket: &mut tokio::net::TcpStream, bytes: &[u8]) -> std::io::Result<()> {
	socket.write_all(format!("{:x}\r\n", bytes.len()).as_bytes()).await?;
	socket.write_all(bytes).await?;
	socket.write_all(b"\r\n").await
}

/// Drain the worker's small request before responding, including a POST body.
/// Otherwise closing a socket with unread request bytes can cause a reset.
async fn read_request(socket: &mut tokio::net::TcpStream) -> std::io::Result<()> {
	let mut reader = tokio::io::BufReader::new(socket);
	let mut length = 0;
	loop {
		let mut line = String::new();
		if reader.read_line(&mut line).await? == 0 || line == "\r\n" {
			break;
		}
		if let Some((name, value)) = line.split_once(':')
			&& name.eq_ignore_ascii_case("content-length")
		{
			length = value.trim().parse::<usize>().unwrap_or_default();
		}
	}
	assert!(length <= 4096, "worker fuzz request unexpectedly large");
	let mut body = vec![0; length];
	reader.read_exact(&mut body).await?;
	Ok(())
}

pub fn worker_server_response_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of the call.
#[allow(unsafe_code)] // The C entry point takes a raw pointer from the fuzzer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_server_response_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller guarantees the readable slice in the contract above.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	#[test]
	fn repeated_responses_bound_listener_allocation() {
		let before = super::LISTENER_BINDS.load(std::sync::atomic::Ordering::Relaxed);
		let response = include_bytes!("../test_cases/worker_server_response/heartbeat");
		super::do_test(response);
		super::do_test(response);
		let allocated = super::LISTENER_BINDS.load(std::sync::atomic::Ordering::Relaxed) - before;
		assert!(allocated <= 1, "repeated responses allocated {allocated} TCP listeners");
	}
}
