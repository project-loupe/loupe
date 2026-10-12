//! Current host-verdict compatibility through the runner and HTTP serializer.

use super::*;

#[tokio::test]
async fn missing_or_unavailable_revision_emits_terminal_verdict_then_successful_completion() {
	use axum::extract::{Json, Path as RoutePath};
	use axum::http::{HeaderMap, StatusCode};
	use axum::routing::post;
	use loupe_proto::{JOB_CAPABILITY_HEADER, PROTOCOL_VERSION_HEADER};

	let remote = tempfile::tempdir().unwrap();
	init_git_repo(remote.path());
	commit_file(remote.path(), "original\n", "Original");
	let clone_url = reqwest::Url::from_directory_path(remote.path()).unwrap().to_string();
	let cache_dir = tempfile::tempdir().unwrap();
	let cache =
		Arc::new(RepoCache::new(cache_dir.path().to_path_buf(), 1024 * 1024, None).unwrap());
	let (send, mut received) = tokio::sync::mpsc::unbounded_channel();
	let leased = Arc::new(std::sync::Mutex::new(None::<serde_json::Value>));
	let response_lease = leased.clone();
	let app = axum::Router::new()
		.route(
			"/v1/jobs/lease",
			post(move || {
				let response_lease = response_lease.clone();
				async move {
					(
						[(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string())],
						Json(response_lease.lock().unwrap().take().unwrap()),
					)
				}
			}),
		)
		.route(
			"/v1/jobs/7/{operation}",
			post(
				move |RoutePath(operation): RoutePath<String>,
				      headers: HeaderMap,
				      Json(body): Json<serde_json::Value>| {
					let send = send.clone();
					async move {
						assert_eq!(headers[JOB_CAPABILITY_HEADER], "fixture-capability");
						assert_eq!(headers[PROTOCOL_VERSION_HEADER], PROTOCOL_VERSION.to_string());
						send.send((operation, body)).unwrap();
						(
							[(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string())],
							StatusCode::NO_CONTENT,
						)
					}
				},
			),
		);
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = listener.local_addr().unwrap();
	let stop = CancellationToken::new();
	let shutdown = stop.clone();
	let server = tokio::spawn(async move {
		axum::serve(listener, app)
			.with_graceful_shutdown(shutdown.cancelled_owned())
			.await
			.unwrap();
	});
	let client = Arc::new(ServerClient::from_parts(
		reqwest::Client::new(),
		format!("http://{address}").parse().unwrap(),
	));
	// Reaching a verifier would fail: these host outcomes require no agent.
	let runner = Runner::new(client, cache, Vec::new());
	let absent_oid = "1111111111111111111111111111111111111111";
	for revision in [None, Some(" \t"), Some("base"), Some(absent_oid)] {
		// Original response bytes are admitted by the actual HTTP lease decoder.
		let mut env = serde_json::json!({
			"kind": "lease", "protocol_version": PROTOCOL_VERSION,
			"job_id": 7, "job_capability": "fixture-capability", "repo_id": 9,
			"repo": {"host": "local", "owner": "owner", "repo": "repo",
				"clone_url": clone_url, "branch": "main"},
			"head_branch": "main", "lease_expires_at": i64::MAX,
			"scanner_config": null,
			"payload": {"kind": "verify", "finding_id": 3,
				"finding": {"scanner_id": "test", "severity": "low", "title": "unverified",
					"description": "unverified finding", "fingerprint": "test"}}
		});
		if let Some(revision) = revision {
			env["payload"]["reviewed_sha"] = serde_json::json!(revision);
		}
		*leased.lock().unwrap() = Some(env);
		let outcome = runner.step(&CancellationToken::new()).await;
		assert!(
			matches!(outcome, Ok(true)),
			"original lease admission must reach the host outcome for {revision:?}: {outcome:?}"
		);
		let (operation, verdict) =
			tokio::time::timeout(Duration::from_secs(1), received.recv()).await.unwrap().unwrap();
		assert_eq!(operation, "verdict");
		let expected_head = revision.filter(|value| !value.trim().is_empty());
		let reason = match expected_head {
			None => "original reviewed revision is unavailable: verify lease did not carry the original reviewed revision".to_owned(),
			Some(sha) => {
				let operation = if sha == "base" { "parsing" } else { "locating" };
				format!("original reviewed revision {sha} is unavailable after refreshing and re-cloning the repository: {operation} reviewed revision {sha}")
			},
		};
		assert_eq!(
			verdict,
			serde_json::json!({
				"protocol_version": PROTOCOL_VERSION,
				"verdict": {"outcome": "inconclusive", "reason": reason, "terminal": true}
			})
		);
		let (operation, complete) =
			tokio::time::timeout(Duration::from_secs(1), received.recv()).await.unwrap().unwrap();
		assert_eq!(operation, "complete");
		let mut expected_complete = serde_json::json!({
			"protocol_version": PROTOCOL_VERSION, "outcome": "succeeded"
		});
		if let Some(head) = expected_head {
			expected_complete["head_sha"] = serde_json::json!(head);
		}
		assert_eq!(complete, expected_complete);
		assert!(received.try_recv().is_err(), "host branch emitted an extra submission");
	}
	stop.cancel();
	server.await.unwrap();
}

#[tokio::test]
async fn revision_checkout_rejects_a_branch_name_that_latest_checkout_accepts() {
	let remote = tempfile::tempdir().unwrap();
	init_git_repo(remote.path());
	let commit = commit_file(remote.path(), "original\n", "Original");
	git(remote.path(), &["branch", "base"]);
	let cache = tempfile::tempdir().unwrap();
	let bare = cache.path().join("repo.git");
	clone_bare(remote.path(), &bare);
	let (workdir, observed) = checkout_latest(&bare, Some("base")).await.unwrap();
	assert_eq!(observed.expose(), commit);
	assert_eq!(std::fs::read(workdir.path().join("file.txt")).unwrap(), b"original\n");
	let error = checkout_revision(&bare, "base").await.unwrap_err();
	assert_eq!(error.to_string(), "parsing reviewed revision base");
}
