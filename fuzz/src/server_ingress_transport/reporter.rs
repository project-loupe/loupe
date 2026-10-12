//! Bounded real HTTP recipes for each Reporter response consumer.
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use loupe_core::{Finding, ReportingDestination, Severity};
use loupe_provenance::Secret;
use loupe_server::reporters::github_app::{GithubAppKey, InstallationTokens};
use loupe_server::reporters::{GithubReporter, ReportFinding, Reporter, ReporterCredential};
use loupe_storage::repos::RepoRow;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

const ORDINARY: usize = 16 * 1024 * 1024;
const TOKEN: usize = 256 * 1024;

fn key() -> GithubAppKey {
	GithubAppKey::from_pem(1, loupe_server::reporters::github_app::testing::APP_PRIVATE_KEY_PEM)
		.unwrap_or_else(|error| panic!("fixture app key: {error}"))
}

fn report() -> (RepoRow, ReportFinding) {
	let repo = RepoRow {
		id: 1,
		clone_url: "https://github.com/example/repo.git".into(),
		host: "github.com".into(),
		owner: "example".into(),
		repo: "repo".into(),
		default_branch: None,
		scan_interval_seconds: None,
		scanner_config: serde_json::Value::Null,
		reporting: ReportingDestination::GithubIssue {
			target_owner: "example".into(),
			target_repo: "repo".into(),
			pat_secret_id: None,
		},
		verification_enabled: false,
		require_approval: None,
		last_scanned_sha: None,
		last_scanned_at: None,
		created_at: 0,
		disabled_at: None,
	};
	let finding = ReportFinding {
		id: 1,
		reviewed_revision: None,
		finding: Finding {
			scanner_id: "fixture".into(),
			severity: Severity::High,
			title: "title".into(),
			description: "description".into(),
			file_path: None,
			line_start: None,
			line_end: None,
			cwe: None,
			patch_unified: None,
			poc_unified: None,
			fingerprint: "fixture".into(),
		},
	};
	(repo, finding)
}

fn prefix(stage: usize, body: u8) -> &'static [u8] {
	match body {
		1 => b"{private_reporter_sentinel",
		2 => b"\xff private_reporter_sentinel",
		3 => b"{}",
		_ => match stage {
			0 => br#"{"id":1,"slug":"fixture"}"#,
			1 => br#"{"id":1}"#,
			2 => br#"{"token":"private_reporter_sentinel"}"#,
			3 => b"\xff malformed already_exists response",
			_ => br#"{"number":7}"#,
		},
	}
}

async fn request(socket: &mut tokio::net::TcpStream) -> std::io::Result<usize> {
	let mut reader = tokio::io::BufReader::new(socket);
	let mut first = String::new();
	reader.read_line(&mut first).await?;
	let path = first.split_whitespace().nth(1).unwrap_or("");
	let stage = if path == "/app" {
		0
	} else if path.ends_with("/installation") {
		1
	} else if path.ends_with("/access_tokens") {
		2
	} else if path.ends_with("/labels") {
		3
	} else {
		assert!(path.ends_with("/issues"), "unexpected Reporter request path");
		4
	};
	let mut length = 0;
	let mut total = first.len();
	loop {
		let mut line = String::new();
		if reader.read_line(&mut line).await? == 0 || line == "\r\n" {
			break;
		}
		total += line.len();
		assert!(total < 16 * 1024, "fixture request header limit");
		if let Some((name, value)) = line.split_once(':')
			&& name.eq_ignore_ascii_case("content-length")
		{
			length = value
				.trim()
				.parse::<usize>()
				.unwrap_or_else(|error| panic!("request length: {error}"));
		}
	}
	assert!(length <= 8192, "fixture request body limit");
	let mut bytes = [0; 8192];
	reader.read_exact(&mut bytes[..length]).await?;
	Ok(stage)
}

async fn response(
	socket: &mut tokio::net::TcpStream, stage: usize, status: u16, body: u8, boundary: u8,
	wire: u8, chunk: usize,
) -> std::io::Result<()> {
	let bytes = prefix(stage, body);
	let cap = if stage == 2 { TOKEN } else { ORDINARY };
	let length = match boundary {
		1 => cap - 1,
		2 => cap,
		3 => cap + 1,
		_ => bytes.len(),
	};
	let framing = match wire {
		0 => format!("Content-Length: {length}\r\n"),
		1 => "Transfer-Encoding: chunked\r\n".into(),
		2 => "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n".into(),
		3 => format!("Content-Length: {}\r\n", bytes.len() + 10),
		4 => format!("Content-Length: {}\r\n", cap + 1),
		_ => String::new(),
	};
	socket
		.write_all(
			format!("HTTP/1.1 {status} Fixture\r\n{framing}Connection: close\r\n\r\n").as_bytes(),
		)
		.await?;
	let length = if matches!(wire, 3 | 4) { bytes.len() } else { length };
	let chunk = if boundary != 0 { chunk.max(4096) } else { chunk };
	let mut offset = 0;
	let mut buffer = [b' '; 8192];
	while offset < length {
		let count = chunk.min(length - offset);
		buffer[..count].fill(b' ');
		if offset < bytes.len() {
			let copied = count.min(bytes.len() - offset);
			buffer[..copied].copy_from_slice(&bytes[offset..offset + copied]);
		}
		if matches!(wire, 1 | 2) {
			socket.write_all(format!("{count:x}\r\n").as_bytes()).await?;
		}
		socket.write_all(&buffer[..count]).await?;
		if matches!(wire, 1 | 2) {
			socket.write_all(b"\r\n").await?;
		}
		offset += count;
	}
	if matches!(wire, 1 | 2) {
		socket.write_all(b"0\r\n\r\n").await?;
	}
	socket.shutdown().await
}

pub(super) fn run(data: &[u8]) {
	let [stage, status, body, boundary, wire, chunk, app, ..] = data else { return };
	let stage = usize::from(stage % 5);
	let status = [200, 422, 500, 401][usize::from(status % 4)];
	let (body, boundary, wire) = (body % 4, boundary % 4, wire % 6);
	let chunk = 1 + usize::from(*chunk) * 31;
	let app = app & 1 != 0 && stage >= 3;
	// Serialize complete iterations around one listener/reactor. Each iteration
	// has a fresh reporter/cache, joined server task and checked request counts.
	static FIXTURE: OnceLock<(tokio::runtime::Runtime, tokio::net::TcpListener, Mutex<()>)> =
		OnceLock::new();
	let (runtime, listener, lock) = FIXTURE.get_or_init(|| {
		let runtime = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.unwrap_or_else(|error| panic!("reporter runtime: {error}"));
		let listener = runtime
			.block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
			.unwrap_or_else(|error| panic!("reporter listener: {error}"));
		(runtime, listener, Mutex::new(()))
	});
	let _guard = lock.lock().unwrap_or_else(|error| panic!("reporter iteration lock: {error}"));
	runtime.block_on(async {
		let counts = Arc::new(Mutex::new([0usize; 5]));
		let seen = counts.clone();
		let (shutdown, mut stopping) = tokio::sync::oneshot::channel::<()>();
		let server = tokio::spawn(async move {
			let mut connections = tokio::task::JoinSet::new();
			let mut accepted_connections = 0;
			loop {
				tokio::select! {
					_ = &mut stopping => break,
					Some(joined) = connections.join_next() => {
						joined.unwrap_or_else(|error| panic!("Reporter connection task: {error}"));
					},
					accepted = listener.accept() => {
						let (mut socket, _) = accepted.unwrap_or_else(|error| panic!("accept: {error}"));
						accepted_connections += 1;
						assert!(accepted_connections <= 8, "unexpected request retry loop");
						let seen = seen.clone();
						connections.spawn(async move {
							let endpoint = request(&mut socket).await.unwrap_or_else(|error| panic!("fixture request: {error}"));
							let attempt = {
								let mut counts = seen.lock().unwrap_or_else(|error| panic!("counts: {error}"));
								counts[endpoint] += 1;
								counts[endpoint]
							};
							// Refresh may run while the first unread 401 body still
							// owns its socket. Independent bounded tasks allow it.
							let selected = endpoint == stage && !(app && status == 401 && attempt == 2);
							let _ = if selected {
								response(&mut socket, endpoint, status, body, boundary, wire, chunk).await
							} else {
								response(&mut socket, endpoint, 200, 0, 0, 0, 8192).await
							};
							// Early close is expected for ignored/rejected bodies.
						});
					},
				}
			}
			connections.abort_all();
			while let Some(joined) = connections.join_next().await {
				if let Err(error) = joined {
					assert!(error.is_cancelled(), "Reporter connection task panicked: {error}");
				}
			}
		});
		let address =
			listener.local_addr().unwrap_or_else(|error| panic!("reporter address: {error}"));
		let base = format!("http://{address}");
		let result = tokio::time::timeout(Duration::from_secs(5), async {
			let reporter = GithubReporter::with_base(&base)
				.unwrap_or_else(|error| panic!("reporter: {error}"));
			if stage == 0 {
				reporter
					.verify_app(&key())
					.await
					.map(|value| format!("{}:{}", value.id, value.slug))
			} else if stage <= 2 {
				let cache = InstallationTokens::default();
				let base = reqwest::Url::parse(&base)
					.unwrap_or_else(|error| panic!("reporter URL: {error}"));
				cache
					.token_for(&reqwest::Client::new(), &base, &key(), "example", "repo")
					.await
					.map(|token| {
						assert_eq!(format!("{token:?}"), "[redacted]");
						token.expose().to_owned()
					})
			} else {
				let credential = if app {
					ReporterCredential::GithubApp(Box::new(key()))
				} else {
					ReporterCredential::GithubPat(Secret::new(b"fake-test-pat".to_vec()))
				};
				let (repo, finding) = report();
				reporter.dispatch(&repo, &[finding], &credential).await.map(|receipt| {
					assert_eq!(receipt.kind, "github_issue");
					receipt.external_id.unwrap_or_default()
				})
			}
		})
		.await;
		let _ = shutdown.send(());
		server.await.unwrap_or_else(|error| panic!("Reporter server task: {error}"));
		let result = result.unwrap_or_else(|_| panic!("Reporter fixture deadline"));
		let retry = app && status == 401;
		let ignored = stage == 3 && status == 200;
		let oversized = !ignored && !retry && (wire == 4 || (wire != 3 && boundary == 3));
		let truncated = !ignored && !retry && wire == 3;
		let valid_status = status == 200 || (stage == 3 && status == 422 && body == 0);
		let valid_body = body == 0 || ignored || (stage == 4 && body == 3);
		let accepted = retry || (!oversized && !truncated && valid_status && valid_body);
		assert_eq!(result.is_ok(), accepted, "actual Reporter admission: {result:?}");
		if oversized || truncated {
			let error = result.as_ref().err().unwrap_or_else(|| unreachable!());
			let message = format!("{error:#}");
			assert!(
				message.contains(if oversized { "exceeds" } else { "reading" }),
				"collector did not precede parser/status: {message}"
			);
		}
		if let Err(error) = &result {
			assert!(!format!("{error:#} {error:?}").contains("private_reporter_sentinel"));
		}
		if let Ok(value) = &result {
			let expected = match stage {
				0 => "1:fixture",
				1 | 2 => "private_reporter_sentinel",
				4 if body == 3 && !retry => "",
				_ => "7",
			};
			assert_eq!(value, expected, "actual Reporter decoded result");
		}
		let mut expected = [0; 5];
		match stage {
			0 => expected[0] = 1,
			1 => {
				expected[1] = 1;
				expected[2] = usize::from(accepted);
			},
			2 => {
				expected[1] = 1;
				expected[2] = 1;
			},
			_ => {
				if app {
					expected[1] = 1 + usize::from(retry);
					expected[2] = 1 + usize::from(retry);
				}
				expected[3] = 1 + usize::from(stage == 3 && retry);
				expected[4] =
					if stage == 4 { 1 + usize::from(retry) } else { usize::from(accepted) };
			},
		}
		assert_eq!(
			*counts.lock().unwrap_or_else(|error| panic!("counts: {error}")),
			expected,
			"actual endpoint counts/cache/retry"
		);
	});
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn endpoints_count_real_reads_and_preserve_caps_status_and_retry() {
		for stage in 0..5 {
			for boundary in 0..4 {
				for wire in 0..6 {
					run(&[stage, u8::from(stage == 3), 0, boundary, wire, 255, 0]);
				}
			}
			for body in 0..4 {
				for status in 0..4 {
					run(&[stage, status, body, 0, 1, 1, 0]);
				}
			}
			// Over-cap malformed bytes must be rejected before parser/status.
			run(&[stage, 2, 1, 3, 2, 255, 0]);
			if stage >= 3 {
				run(&[stage, 3, 1, 3, 2, 255, 1]);
			}
		}
		// Successful labels ignore malformed, truncated and overlimit bodies.
		for wire in 0..6 {
			run(&[3, 0, 2, 3, wire, 255, 0]);
		}
	}
}
