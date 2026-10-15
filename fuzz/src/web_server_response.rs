//! Actual router -> private AdminClient::call_forward -> named Server owners.
//! One persistent listener; compact recipes stream bounded 8192-byte blocks.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderValue, StatusCode};
use loupe_web::fuzz_support::{Entry, Observation, Session};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

use crate::utils::test_logger;
use crate::web_support::{self as support, Fixture, RAW_CAP, SERVER_CAP};

struct Case {
	status: StatusCode,
	header: Option<Vec<u8>>,
	body: Vec<u8>,
	padding: usize,
	fill: u8,
	chunked: bool,
	truncated: bool,
	cancel: bool,
}
impl Case {
	fn new(mode: u8, bytes: &[u8]) -> Self {
		let mut case = Self {
			status: StatusCode::OK,
			header: Some(b"2".to_vec()),
			body: bytes.to_vec(),
			padding: 0,
			fill: b' ',
			chunked: true,
			truncated: false,
			cancel: false,
		};
		match mode {
			1 => {
				case.status = StatusCode::CONFLICT;
				case.header = Some(b"wrong".to_vec());
			},
			2 => case.header = None,
			3 => {
				case.header = HeaderValue::from_bytes(&bytes[..bytes.len().min(128)])
					.ok()
					.map(|h| h.as_bytes().to_vec());
				case.body = b"{}".to_vec();
			},
			4 => {
				case.status = [
					StatusCode::CREATED,
					StatusCode::ACCEPTED,
					StatusCode::from_u16(299).unwrap_or_else(|_| unreachable!()),
				][usize::from(bytes.first().copied().unwrap_or(0)) % 3];
				case.header = Some(b"+2".to_vec());
			},
			5 => {
				case.status = StatusCode::NO_CONTENT;
				case.body.clear();
				case.chunked = false;
			},
			6..=8 => {
				case.body = b"{}".to_vec();
				case.padding = SERVER_CAP - 2 + usize::from(mode - 6) - 1;
			},
			9 => {
				case.truncated = true;
				case.chunked = false;
			},
			10 => case.status = StatusCode::UNAUTHORIZED,
			11 => case.status = StatusCode::FORBIDDEN,
			12 => {
				case.status = [
					StatusCode::BAD_REQUEST,
					StatusCode::NOT_FOUND,
					StatusCode::CONFLICT,
					StatusCode::TOO_MANY_REQUESTS,
					StatusCode::INTERNAL_SERVER_ERROR,
					StatusCode::SEE_OTHER,
				][usize::from(bytes.first().copied().unwrap_or(0)) % 6];
				case.header = None;
			},
			13 => {
				case.status = StatusCode::CONFLICT;
				case.body.clear();
				case.padding = SERVER_CAP;
				case.fill = 0xff;
			},
			14 => {
				case.body = b"FAKE_CANCELLED_SERVER_BODY".to_vec();
				case.cancel = true;
			},
			15 => {
				case.header = Some(b"65535".to_vec());
				case.body = b"[".to_vec();
			},
			16 | 17 => {
				case.body = b"{}".to_vec();
				case.padding = SERVER_CAP - 1;
				case.chunked = false;
				if mode == 17 {
					case.header = None;
				}
			},
			18 | 19 => {
				case.status =
					if mode == 18 { StatusCode::CONFLICT } else { StatusCode::UNAUTHORIZED };
				case.body.clear();
				case.padding = SERVER_CAP + 1;
			},
			20 => {
				case.body = bytes.get(1..).unwrap_or_default().to_vec();
			},
			_ => {},
		}
		case
	}
	fn logical_body(&self) -> Vec<u8> {
		let mut raw = self.body.clone();
		raw.resize(raw.len() + self.padding, self.fill);
		raw
	}
	fn protocol_error(&self) -> Option<String> {
		if !self.status.is_success() {
			return None;
		}
		let Some(raw) = &self.header else {
			return Some("server response missing X-Loupe-Protocol".into());
		};
		// HTTP parsing strips surrounding SP/HTAB before HeaderValue::to_str.
		let raw = raw.trim_ascii();
		let header = HeaderValue::from_bytes(raw).unwrap_or_else(|_| unreachable!());
		let Ok(text) = header.to_str() else {
			return Some("server protocol header is not ASCII".into());
		};
		let Ok(version) = text.parse::<u16>() else {
			return Some("server protocol header is not a u16".into());
		};
		(version != loupe_proto::PROTOCOL_VERSION).then(|| format!("server speaks protocol {version}, this loupe-web build speaks 2 — rebuild loupe-web against the running server"))
	}
	fn expected(&self) -> (StatusCode, Option<Value>) {
		if let Some(message) = self.protocol_error() {
			return (StatusCode::BAD_GATEWAY, Some(json!({"error":message})));
		}
		let mapped = if self.status.is_success()
			|| matches!(self.status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
		{
			StatusCode::BAD_GATEWAY
		} else {
			self.status
		};
		if self.body.len() + self.padding > SERVER_CAP {
			return (
				mapped,
				Some(
					json!({"error":"reading upstream body: response body exceeds 16777216 bytes"}),
				),
			);
		}
		if self.truncated {
			return (mapped, Some(json!({"error":"reading upstream body failed"})));
		}
		let raw = self.logical_body();
		let text = String::from_utf8_lossy(&raw);
		if self.status.is_success() {
			if text.trim().is_empty() {
				return (self.status, None);
			}
			match serde_json::from_str::<Value>(&text) {
				Ok(value) => (self.status, Some(value)),
				Err(_) => {
					(StatusCode::BAD_GATEWAY, Some(json!({"error":"upstream sent invalid JSON"})))
				},
			}
		} else {
			let message = if text.trim().is_empty() {
				format!("server returned {}", self.status)
			} else {
				text.trim().to_owned()
			};
			(mapped, Some(json!({"error":message})))
		}
	}
}
async fn chunk(socket: &mut tokio::net::TcpStream, bytes: &[u8]) -> std::io::Result<()> {
	if !bytes.is_empty() {
		socket.write_all(format!("{:x}\r\n", bytes.len()).as_bytes()).await?;
		socket.write_all(bytes).await?;
		socket.write_all(b"\r\n").await?;
	}
	Ok(())
}
async fn respond(
	listener: tokio::net::TcpListener, case: Arc<Case>, calls: Arc<AtomicUsize>, chunk_size: usize,
) -> std::io::Result<()> {
	let (mut socket, _) = listener.accept().await?;
	let mut request = Vec::new();
	while !request.ends_with(b"\r\n\r\n") {
		let mut byte = [0];
		socket.read_exact(&mut byte).await?;
		request.push(byte[0]);
		assert!(request.len() < 8192, "unexpected upstream request size");
	}
	let request =
		String::from_utf8(request).unwrap_or_else(|_| panic!("non-UTF8 upstream request"));
	assert!(request.starts_with("GET /v1/health HTTP/1.1\r\n"));
	assert!(request.to_ascii_lowercase().contains("x-loupe-protocol: 2\r\n"));
	assert!(!request.to_ascii_lowercase().contains("x-loupe-capability"));
	calls.fetch_add(1, Ordering::SeqCst);
	let mut headers = format!("HTTP/1.1 {}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nSet-Cookie: upstream=must-not-forward\r\n", case.status).into_bytes();
	if let Some(header) = &case.header {
		headers.extend_from_slice(b"X-Loupe-Protocol: ");
		headers.extend_from_slice(header);
		headers.extend_from_slice(b"\r\n");
	}
	if case.chunked {
		headers.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
	} else {
		headers.extend_from_slice(
			format!(
				"Content-Length: {}\r\n\r\n",
				case.body.len() + case.padding + usize::from(case.truncated)
			)
			.as_bytes(),
		);
	}
	socket.write_all(&headers).await?;
	if case.chunked {
		for bytes in case.body.chunks(chunk_size) {
			chunk(&mut socket, bytes).await?;
		}
		if case.cancel {
			return std::future::pending().await;
		}
		let block = [case.fill; 8192];
		let mut remaining = case.padding;
		while remaining != 0 {
			let count = remaining.min(block.len());
			chunk(&mut socket, &block[..count]).await?;
			remaining -= count;
		}
		chunk(&mut socket, &[]).await?;
		socket.write_all(b"0\r\n\r\n").await?;
	} else {
		socket.write_all(&case.body).await?;
	}
	socket.shutdown().await
}
pub fn do_test(data: &[u8]) {
	if data.len() > RAW_CAP {
		return;
	}
	let Some((&mode, bytes)) = data.split_first() else {
		return;
	};
	let case = Arc::new(Case::new(mode % 21, bytes));
	static FIXTURE: OnceLock<Mutex<Fixture>> = OnceLock::new();
	let fixture = FIXTURE
		.get_or_init(Fixture::new)
		.lock()
		.unwrap_or_else(|_| panic!("web response fixture poisoned"));
	fixture.runtime.block_on(async {
		let session = Session::start();
		let calls = Arc::new(AtomicUsize::new(0));
		let mut server = tokio::spawn(respond(
			fixture.listener(),
			case.clone(),
			calls.clone(),
			1 + usize::from(bytes.first().copied().unwrap_or(255))
				* if mode % 21 == 20 { 1 } else { 32 },
		));
		let (app, secret) = fixture.app();
		let future = app.oneshot(support::request("GET", "/api/health", &secret, Body::empty()));
		let deadline =
			if case.cancel { Duration::from_millis(30) } else { Duration::from_secs(10) };
		let response = tokio::time::timeout(deadline, future).await;
		if case.cancel {
			server.abort();
			let _ = server.await;
			assert!(response.is_err(), "stream cancellation fixture completed unexpectedly");
			let (trace, drops) = session.finish();
			support::assert_wiped(&drops);
			assert_eq!(calls.load(Ordering::SeqCst), 1);
			assert!(trace.entries.contains(&Entry::ServerCollect));
			assert!(!trace.entries.contains(&Entry::ServerJson));
			return;
		}
		let outcome = match response {
			Ok(Ok(response)) => {
				let status = response.status();
				let headers = response.headers().clone();
				let body = to_bytes(response.into_body(), 6 * SERVER_CAP + 1024).await;
				Some((status, headers, body))
			},
			_ => None,
		};
		match tokio::time::timeout(Duration::from_secs(2), &mut server).await {
			Ok(join) => {
				let _io = join.unwrap_or_else(|e| panic!("web sender task: {e}"));
			},
			Err(_) => {
				server.abort();
				let _ = server.await;
				panic!("web response sender failed to finish");
			},
		}
		let (status, headers, body) = outcome.unwrap_or_else(|| panic!("web response timed out"));
		let body = body.unwrap_or_else(|e| panic!("web encoded response collection: {e}"));
		let actual = if body.is_empty() {
			None
		} else {
			Some(
				serde_json::from_slice::<Value>(&body)
					.unwrap_or_else(|e| panic!("web response outside JSON envelope: {e}")),
			)
		};
		drop(body);
		let (trace, drops) = session.finish();
		support::assert_wiped(&drops);
		assert_eq!(
			(status, actual),
			case.expected(),
			"actual forward response changed status/body semantics"
		);
		assert_eq!(calls.load(Ordering::SeqCst), 1);
		assert!(headers.get("set-cookie").is_none());
		assert!(headers.get(loupe_proto::PROTOCOL_VERSION_HEADER).is_none());
		assert_eq!(trace.entries.contains(&Entry::ServerHeader), case.status.is_success());
		assert_eq!(
			trace.entries.contains(&Entry::ServerCollect),
			case.protocol_error().is_none(),
			"protocol validation must precede body collection"
		);
		let admitted = case.protocol_error().is_none()
			&& !case.truncated
			&& case.body.len() + case.padding <= SERVER_CAP;
		assert_eq!(
			trace.entries.contains(&Entry::ServerJson),
			admitted && case.status.is_success()
		);
		assert_eq!(
			trace.entries.contains(&Entry::ServerDiagnostic),
			admitted && !case.status.is_success()
		);
		let text_records: Vec<_> = trace
			.values
			.iter()
			.filter_map(|v| {
				if let Observation::ServerText {
					original_len,
					original_hash,
					shared_pointer,
					replacement_len,
					text_len,
				} = v
				{
					Some((
						*original_len,
						*original_hash,
						*shared_pointer,
						*replacement_len,
						*text_len,
					))
				} else {
					None
				}
			})
			.collect();
		assert_eq!(text_records.len(), usize::from(admitted));
		if admitted {
			let raw = case.logical_body();
			let lossy = String::from_utf8_lossy(&raw);
			assert_eq!(
				text_records[0],
				(
					raw.len(),
					*blake3::hash(&raw).as_bytes(),
					true,
					std::str::from_utf8(&raw).is_err().then_some(lossy.len()),
					lossy.len()
				)
			);
			for value in &trace.values {
				if let Observation::ServerJsonDebug(text) = value {
					assert_eq!(text, "ServerJson([redacted])");
				}
			}
			if std::str::from_utf8(&raw).is_err() {
				assert!(
					drops
						.iter()
						.any(|(capacity, used, _)| *capacity == lossy.len() && *used == lossy.len()),
					"lossy view's live owner was not observed dropping"
				);
			}
		}
	});
}
pub fn web_server_response_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}
/// # Safety
/// `data` must point to `datalen` readable bytes throughout this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_server_response_run(data: *const u8, datalen: usize) {
	// SAFETY: the fuzzer supplies a readable input for this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn actual_forward_matrix() {
		for input in [
			b"\0{}".as_slice(),
			b"\x01  FAKE_SERVER_DIAGNOSTIC \"<script>\"\n",
			b"\x02{}",
			b"\x03+2",
			b"\x03\xff",
			b"\x03wrong",
			b"\x04[1,true]",
			b"\x05",
			b"\x09truncated",
			b"\x0a denied ",
			b"\x0b denied ",
			b"\x0c",
			b"\x0e",
			b"\x0f",
			b"\0\"\xff\xe2\x82\"",
			b"\0{\"x\":1,\"x\":2}",
			b"\0[",
			b"\0 \r\n",
		] {
			do_test(input);
		}
	}
	#[test]
	fn streamed_budget_and_lossy_expansion() {
		for mode in [6, 7, 8, 13] {
			do_test(&[mode]);
		}
	}
}
