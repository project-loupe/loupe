//! The ordinary Reporter ceiling is independent of the token endpoint's 256 KiB cap.
mod common;
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use axum::Router;
use loupe_core::{Finding, Severity};
use loupe_provenance::Secret;
use loupe_server::reporters::github_app::GithubAppKey;
use loupe_server::reporters::{GithubReporter, ReportFinding, Reporter, ReporterCredential};
use loupe_storage::repos::RepoRow;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIMIT: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
enum Stage {
	Metadata,
	Installation,
	Issue,
	Label,
}

impl Stage {
	fn selected(self, path: &str) -> bool {
		match self {
			Self::Metadata => path == "/app",
			Self::Installation => path.ends_with("/installation"),
			Self::Issue => path.ends_with("/issues"),
			Self::Label => path.ends_with("/labels"),
		}
	}

	fn payload(self, size: usize) -> Vec<u8> {
		let prefix: &[u8] = match self {
			Self::Metadata => br#"{"id":1,"slug":"boundary-app"}"#,
			Self::Installation => br#"{"id":1}"#,
			Self::Issue => br#"{"number":7}"#,
			// Retain the existing non-JSON, lossy-UTF8 substring admission.
			Self::Label => b"\xff malformed already_exists response",
		};
		let mut payload = prefix.to_vec();
		payload.resize(size, b' ');
		payload
	}
}

#[derive(Clone, Copy, Debug)]
enum Wire {
	KnownLength,
	Chunked,
}

fn key() -> GithubAppKey {
	GithubAppKey::from_pem(1, loupe_server::reporters::github_app::testing::APP_PRIVATE_KEY_PEM)
		.unwrap()
}

fn repo() -> RepoRow {
	common::reporter_repo()
}

fn finding() -> ReportFinding {
	ReportFinding {
		id: 1,
		reviewed_revision: None,
		finding: Finding {
			scanner_id: common::marked::agent::text("fixture"),
			severity: Severity::High,
			title: common::marked::agent::text("title"),
			description: common::marked::agent::text("description"),
			file_path: None,
			line_start: None,
			line_end: None,
			cwe: None,
			patch_unified: None,
			poc_unified: None,
			fingerprint: common::marked::agent::text("fixture"),
		},
	}
}

async fn response_for(stage: Stage, wire: Wire, payload: Vec<u8>) -> anyhow::Result<String> {
	let body = match wire {
		Wire::KnownLength => Body::from(payload),
		Wire::Chunked => {
			let bytes = Bytes::from(payload);
			let chunks = (0..bytes.len())
				.step_by(64 * 1024)
				.map(|start| {
					Ok::<_, std::io::Error>(
						bytes.slice(start..(start + 64 * 1024).min(bytes.len())),
					)
				})
				.collect::<Vec<_>>();
			Body::from_stream(futures_util::stream::iter(chunks))
		},
	};
	let selected = Arc::new(Mutex::new(Some(
		Response::builder()
			.status(if matches!(stage, Stage::Label) {
				StatusCode::UNPROCESSABLE_ENTITY
			} else {
				StatusCode::OK
			})
			.body(body)
			.unwrap(),
	)));
	let app = Router::new().fallback(move |request: Request| {
		let selected = selected.clone();
		async move {
			let path = request.uri().path();
			if stage.selected(path) {
				return selected.lock().unwrap().take().expect("selected response consumed once");
			}
			let body = if path.ends_with("/installation") {
				"{\"id\":1}"
			} else if path.ends_with("/access_tokens") {
				"{\"token\":\"fake-test-token\"}"
			} else if path.ends_with("/issues") {
				"{\"number\":7}"
			} else {
				"{}"
			};
			Response::new(Body::from(body))
		}
	});
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = listener.local_addr().unwrap();
	let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	let reporter = GithubReporter::with_base(&format!("http://{address}")).unwrap();
	let result = if matches!(stage, Stage::Metadata) {
		reporter.verify_app(&key()).await.map(|app| format!("{}:{}", app.id, app.slug.expose()))
	} else {
		let credential = if matches!(stage, Stage::Installation) {
			ReporterCredential::GithubApp(Box::new(key()))
		} else {
			ReporterCredential::GithubPat(Secret::new(b"fake-test-pat".to_vec()))
		};
		reporter.dispatch(&repo(), &[finding()], &credential).await.map(|receipt| {
			assert_eq!(receipt.kind, "github_issue");
			receipt.external_id.expect("the issue response has a numeric receipt")
		})
	};
	server.abort();
	let _ = server.await;
	result
}

#[tokio::test]
async fn ordinary_reporter_response_at_limit_is_accepted() {
	for stage in [Stage::Metadata, Stage::Installation, Stage::Issue, Stage::Label] {
		for wire in [Wire::KnownLength, Wire::Chunked] {
			let result = response_for(stage, wire, stage.payload(LIMIT)).await.unwrap();
			assert_eq!(
				result,
				if matches!(stage, Stage::Metadata) { "1:boundary-app" } else { "7" }
			);
		}
	}
}

async fn rejects_over_limit(stage: Stage) {
	let mut accepted = Vec::new();
	for wire in [Wire::KnownLength, Wire::Chunked] {
		if response_for(stage, wire, stage.payload(LIMIT + 1)).await.is_ok() {
			accepted.push(format!("{stage:?}/{wire:?}"));
		}
	}
	assert!(accepted.is_empty(), "Reporter accepted oversized responses: {accepted:?}");
}

#[tokio::test]
async fn metadata_response_rejects_over_limit() {
	rejects_over_limit(Stage::Metadata).await;
}

#[tokio::test]
async fn installation_response_rejects_over_limit() {
	rejects_over_limit(Stage::Installation).await;
}

#[tokio::test]
async fn issue_response_rejects_over_limit() {
	rejects_over_limit(Stage::Issue).await;
}

#[tokio::test]
async fn label_response_rejects_over_limit() {
	rejects_over_limit(Stage::Label).await;
}

#[tokio::test]
async fn oversized_reporter_body_is_rejected_before_json_parsing() {
	let mut missing_cap = Vec::new();
	for stage in [Stage::Metadata, Stage::Installation, Stage::Issue] {
		let mut malformed = vec![b' '; LIMIT + 1];
		malformed[0] = b'{';
		let error = response_for(stage, Wire::Chunked, malformed).await.unwrap_err();
		if !format!("{error:#}").contains("exceeds") {
			missing_cap.push(format!("{stage:?}: {error:#}"));
		}
	}
	assert!(missing_cap.is_empty(), "oversized body reached JSON parsing: {missing_cap:?}");
}

// A raw peer makes the actual transfer encoding and misleading length explicit.
async fn metadata_from_raw_response(payload_size: usize, truncate: bool) -> anyhow::Result<String> {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = listener.local_addr().unwrap();
	let server = tokio::spawn(async move {
		let (mut socket, _) = listener.accept().await.unwrap();
		let mut headers = Vec::new();
		let mut byte = [0];
		while !headers.ends_with(b"\r\n\r\n") {
			socket.read_exact(&mut byte).await.unwrap();
			headers.push(byte[0]);
			assert!(headers.len() < 64 * 1024);
		}
		let payload = Stage::Metadata.payload(payload_size);
		if truncate {
			socket
				.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{}")
				.await?;
		} else {
			socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await?;
			for chunk in payload.chunks(64 * 1024) {
				socket.write_all(format!("{:x}\r\n", chunk.len()).as_bytes()).await?;
				socket.write_all(chunk).await?;
				socket.write_all(b"\r\n").await?;
			}
			socket.write_all(b"0\r\n\r\n").await?;
		}
		Ok::<_, std::io::Error>(())
	});
	let reporter = GithubReporter::with_base(&format!("http://{address}")).unwrap();
	let result =
		reporter.verify_app(&key()).await.map(|app| format!("{}:{}", app.id, app.slug.expose()));
	server.abort();
	let _ = server.await;
	result
}

#[tokio::test]
async fn chunked_body_at_limit_ignores_misleading_content_length() {
	assert_eq!(metadata_from_raw_response(LIMIT, false).await.unwrap(), "1:boundary-app");
}

#[tokio::test]
async fn misleading_content_length_cannot_bypass_reporter_cap() {
	let result = metadata_from_raw_response(LIMIT + 1, false).await;
	assert!(result.is_err(), "Reporter accepted oversized chunked body with Content-Length: 1");
}

#[tokio::test]
async fn incomplete_reporter_stream_is_rejected() {
	let error = metadata_from_raw_response(32, true).await.unwrap_err();
	assert!(
		format!("{error:#}").contains("reading"),
		"expected response collection failure: {error:#}"
	);
}
