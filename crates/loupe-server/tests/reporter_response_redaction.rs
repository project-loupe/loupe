//! Provider errors must not turn a reflected credential into diagnostics.
mod common;
use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use axum::Router;
use loupe_core::{Finding, Severity};
use loupe_server::reporters::github_app::GithubAppKey;
use loupe_server::reporters::{GithubReporter, ReportFinding, Reporter, ReporterCredential};

const SECRET: &str = "ghs_private_marker_37a0849d";

async fn error_for(stage: &'static str) -> anyhow::Error {
	let app = Router::new().fallback(move |request: Request| async move {
		let path = request.uri().path();
		let selected = match stage {
			"metadata" | "decode" => path == "/app",
			"installation" => path.ends_with("/installation"),
			"token" => path.ends_with("/access_tokens"),
			"label" => path.ends_with("/labels"),
			"issue" => path.ends_with("/issues"),
			_ => unreachable!(),
		};
		let (status, body) = if selected {
			if stage == "decode" {
				(StatusCode::OK, format!("{{\"id\":\"{SECRET}\",\"slug\":\"test\"}}"))
			} else {
				(StatusCode::BAD_REQUEST, SECRET.to_owned())
			}
		} else if path.ends_with("/installation") {
			(StatusCode::OK, "{\"id\":1}".to_owned())
		} else if path.ends_with("/access_tokens") {
			(StatusCode::OK, format!("{{\"token\":\"{SECRET}\"}}"))
		} else {
			(StatusCode::OK, "{}".to_owned())
		};
		Response::builder().status(status).body(Body::from(body)).unwrap()
	});
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = listener.local_addr().unwrap();
	let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	let reporter = GithubReporter::with_base(&format!("http://{address}")).unwrap();
	let key = GithubAppKey::from_pem(
		1,
		loupe_server::reporters::github_app::testing::APP_PRIVATE_KEY_PEM,
	)
	.unwrap();
	let error = if matches!(stage, "metadata" | "decode") {
		reporter.verify_app(&key).await.unwrap_err()
	} else {
		let repo = common::reporter_repo();
		let finding = ReportFinding {
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
		};
		reporter
			.dispatch(&repo, &[finding], &ReporterCredential::GithubApp(Box::new(key)))
			.await
			.unwrap_err()
	};
	server.abort();
	let _ = server.await;
	error
}

#[tokio::test]
async fn provider_error_bodies_do_not_disclose_credentials() {
	for stage in ["metadata", "installation", "token", "label", "issue"] {
		let error = error_for(stage).await;
		assert!(!format!("{error:#}").contains(SECRET), "{stage} error disclosed provider content");
		assert!(error.to_string().contains("400"), "{stage} error lost HTTP status");
	}
}

#[tokio::test]
async fn response_decode_errors_do_not_disclose_credentials() {
	let error = error_for("decode").await;
	assert!(!format!("{error:#}").contains(SECRET), "decode error disclosed provider content");
}
