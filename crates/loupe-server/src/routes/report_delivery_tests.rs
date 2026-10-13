//! Actual prepared dispatch, network ordering and exact receipt completion.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use axum::Router;
use loupe_core::{Finding, Severity};

use super::*;
use crate::reporters::fixtures::{self, text, ReportFinding};
use crate::reporters::GithubReporter;

fn finding(id: i64) -> ReportFinding {
	ReportFinding {
		id,
		reviewed_revision: None,
		finding: Finding {
			scanner_id: text("scanner"),
			severity: Severity::High,
			title: text("title"),
			description: text("description"),
			file_path: None,
			line_start: None,
			line_end: None,
			cwe: None,
			patch_unified: None,
			poc_unified: None,
			fingerprint: text("fingerprint"),
		},
	}
}
fn states(db: &loupe_storage::Db) -> Vec<String> {
	loupe_storage::scope::with_operator_repository(
		db,
		&crate::test_support::operator(),
		loupe_storage::scope::OperatorTarget::Repository(1),
		|scope| {
			let mut rows = loupe_storage::findings::list_for_repo(scope, 100)?;
			rows.sort_by_key(|row| row.id);
			Ok(rows.into_iter().map(|row| row.state.as_str().to_owned()).collect())
		},
	)
	.unwrap()
}
fn app(db: Arc<loupe_storage::Db>, github: GithubReporter) -> AppState {
	AppState::new(db, Arc::new(loupe_tls::Ca::new("report-test").unwrap()), Arc::new(github))
}

#[tokio::test]
async fn github_keeps_first_completion_before_late_http_or_render_failure() {
	for render_failure in [false, true] {
		let (_guard, events) = crate::test_support::capture_security_events();
		let repo=fixtures::repo(serde_json::json!({"kind":"github_issue","target_owner":"o","target_repo":"r","pat_secret_id":7})).unwrap();
		let mut second = finding(2);
		if render_failure {
			second.finding.description = text(&"x".repeat(65_536));
		}
		let (db, batch, _fixture) = fixtures::prepared_with_db(&repo, &[finding(1), second]);
		let calls = Arc::new(AtomicUsize::new(0));
		let handler_db = db.clone();
		let handler_calls = calls.clone();
		let server = Router::new().fallback(move |request: Request| {
			let db = handler_db.clone();
			let calls = handler_calls.clone();
			async move {
				// This real read during I/O also exercises release of the Db mutex.
				let current = states(&db);
				if request.uri().path().ends_with("/issues") {
					let n = calls.fetch_add(1, Ordering::SeqCst);
					if n == 1 {
						assert_eq!(current, vec!["reported", "confirmed"]);
						return Response::builder()
							.status(StatusCode::BAD_GATEWAY)
							.body(Body::from("failure"))
							.unwrap();
					}
					assert_eq!(current, vec!["confirmed", "confirmed"]);
					return Response::new(Body::from("{\"number\":1}"));
				}
				Response::new(Body::from("{}"))
			}
		});
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let address = listener.local_addr().unwrap();
		let task = tokio::spawn(async move { axum::serve(listener, server).await.unwrap() });
		let state =
			app(db.clone(), GithubReporter::with_base(&format!("http://{address}")).unwrap());
		let error = dispatch_prepared(
			&state,
			reports::Preparation::Ready(Box::new(batch)),
			DispatchScope::Job(1),
			2,
		)
		.await
		.unwrap_err();
		assert!(
			error.to_string().contains(if render_failure { "65536" } else { "502" }),
			"{error:#}"
		);
		assert_eq!(states(&db), vec!["reported", "confirmed"]);
		assert_eq!(calls.load(Ordering::SeqCst), if render_failure { 1 } else { 2 });
		task.abort();
		let _ = task.await;
		let events = events.lock().unwrap();
		assert_eq!(
			events.len(),
			usize::from(render_failure),
			"only destination size rejection emits a report budget event"
		);
		if render_failure {
			assert_eq!(events[0]["resource"], "report_output");
			assert_eq!(events[0]["repo_id"], "1");
			assert_eq!(events[0]["job_id"], "1");
		}
	}
}

#[tokio::test]
async fn email_budget_event_excludes_invalid_destination_and_transport_failures() {
	for (recipients, budget) in
		[(vec![], false), (vec!["to@example.com"; 700], true), (vec!["to@example.com"], false)]
	{
		let (_guard, events) = crate::test_support::capture_security_events();
		let repo = fixtures::repo(serde_json::json!({"kind":"email","to":recipients})).unwrap();
		let (db, batch, _fixture) = fixtures::prepared_with_db(&repo, &[finding(1)]);
		let scratch = tempfile::tempdir().unwrap();
		let state = app(db.clone(), GithubReporter::new().unwrap()).with_email_reporter(
			crate::reporters::EmailReporter::with_bin(scratch.path().join("absent-sendmail")),
		);
		let error = dispatch_prepared(
			&state,
			reports::Preparation::Ready(Box::new(batch)),
			DispatchScope::Job(1),
			2,
		)
		.await
		.unwrap_err();
		assert_eq!(states(&db), vec!["confirmed"]);
		let events = events.lock().unwrap();
		assert_eq!(
			events.len(),
			usize::from(budget),
			"only a genuine header size limit is a budget event: {error}"
		);
		if budget {
			assert_eq!(events[0]["resource"], "report_output");
			assert_eq!(events[0]["repo_id"], "1");
			assert_eq!(events[0]["job_id"], "1");
		}
	}
}

#[tokio::test]
async fn email_failure_marks_none_and_success_marks_the_whole_batch() {
	for success in [false, true] {
		let repo = fixtures::repo(serde_json::json!({"kind":"email","to":["to"]})).unwrap();
		let (db, batch, _fixture) = fixtures::prepared_with_db(&repo, &[finding(1), finding(2)]);
		let scratch = tempfile::tempdir().unwrap();
		let binary = scratch.path().join("sendmail");
		std::fs::write(
			&binary,
			format!("#!/bin/sh\ncat >/dev/null\nexit {}\n", if success { 0 } else { 1 }),
		)
		.unwrap();
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
		}
		let state = app(db.clone(), GithubReporter::new().unwrap())
			.with_email_reporter(crate::reporters::EmailReporter::with_bin(&binary));
		let result = dispatch_prepared(
			&state,
			reports::Preparation::Ready(Box::new(batch)),
			DispatchScope::Job(1),
			2,
		)
		.await;
		assert_eq!(result.is_ok(), success);
		assert_eq!(
			states(&db),
			if success { vec!["reported", "reported"] } else { vec!["confirmed", "confirmed"] }
		);
	}
}
