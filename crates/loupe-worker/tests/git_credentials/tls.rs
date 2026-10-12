//! Real Git smart-HTTP behind a loopback TLS endpoint and a test-only CA.
use std::convert::Infallible;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio_rustls::TlsAcceptor;

use super::*;

struct TlsGit {
	url: String,
	authenticated: Arc<AtomicUsize>,
	credentialed: Arc<AtomicUsize>,
	requests: Arc<AtomicUsize>,
	paths: Arc<Mutex<Vec<String>>>,
	redirect: Arc<Mutex<Option<String>>>,
	task: tokio::task::JoinHandle<()>,
}

use std::sync::Mutex;

impl Drop for TlsGit {
	fn drop(&mut self) {
		self.task.abort();
	}
}

impl TlsGit {
	async fn start(root: &Path) -> Self {
		let ca = loupe_tls::Ca::new("Git test CA").unwrap();
		let cert = ca.mint_server("localhost", &["localhost".into(), "127.0.0.1".into()]).unwrap();
		let ca_path = root.join("test-ca.pem");
		std::fs::write(&ca_path, ca.cert_pem()).unwrap();
		git(root, &["config", "--global", "http.sslCAInfo", ca_path.to_str().unwrap()]);
		let certs = rustls_pemfile::certs(&mut cert.cert_pem.as_bytes())
			.collect::<Result<Vec<_>, _>>()
			.unwrap();
		let key =
			rustls_pemfile::private_key(&mut cert.key_pem.expose().as_bytes()).unwrap().unwrap();
		let config = rustls::ServerConfig::builder()
			.with_no_client_auth()
			.with_single_cert(certs, key)
			.unwrap();
		let acceptor = TlsAcceptor::from(Arc::new(config));
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let url = format!("https://localhost:{}/repo.git", listener.local_addr().unwrap().port());
		let authenticated = Arc::new(AtomicUsize::new(0));
		let credentialed = Arc::new(AtomicUsize::new(0));
		let requests = Arc::new(AtomicUsize::new(0));
		let paths = Arc::new(Mutex::new(Vec::new()));
		let redirect = Arc::new(Mutex::new(None::<String>));
		let project = root.to_owned();
		let count = authenticated.clone();
		let credentials = credentialed.clone();
		let all = requests.clone();
		let seen_paths = paths.clone();
		let redirect_to = redirect.clone();
		let task = tokio::spawn(async move {
			while let Ok((stream, _)) = listener.accept().await {
				let acceptor = acceptor.clone();
				let project = project.clone();
				let count = count.clone();
				let credentials = credentials.clone();
				let all = all.clone();
				let seen_paths = seen_paths.clone();
				let redirect_to = redirect_to.clone();
				tokio::spawn(async move {
					let Ok(stream) = acceptor.accept(stream).await else {
						return;
					};
					let service = service_fn(move |request: Request<hyper::body::Incoming>| {
						let project = project.clone();
						let count = count.clone();
						let credentials = credentials.clone();
						let all = all.clone();
						let seen_paths = seen_paths.clone();
						let redirect_to = redirect_to.clone();
						async move {
							all.fetch_add(1, Ordering::SeqCst);
							seen_paths.lock().unwrap().push(request.uri().path().to_owned());
							if request.headers().contains_key("authorization") {
								credentials.fetch_add(1, Ordering::SeqCst);
							}
							let expected = format!(
								"Basic {}",
								base64::engine::general_purpose::STANDARD
									.encode(format!("x-access-token:{PAT}"))
							);
							if request.headers().get("authorization").and_then(|v| v.to_str().ok())
								!= Some(expected.as_str())
							{
								return Ok::<_, Infallible>(
									Response::builder()
										.status(StatusCode::UNAUTHORIZED)
										.header("WWW-Authenticate", "Basic realm=git-test")
										.body(Full::new(Bytes::new()))
										.unwrap(),
								);
							}
							count.fetch_add(1, Ordering::SeqCst);
							let target = redirect_to.lock().unwrap().clone();
							if let Some(target) = target {
								return Ok(Response::builder()
									.status(StatusCode::FOUND)
									.header("Location", target)
									.body(Full::new(Bytes::new()))
									.unwrap());
							}
							let (parts, body) = request.into_parts();
							let body = body.collect().await.unwrap().to_bytes();
							let response = tokio::task::spawn_blocking(move || {
								backend(&project, parts, &body)
							})
							.await
							.unwrap();
							Ok(response)
						}
					});
					let _ = hyper::server::conn::http1::Builder::new()
						.serve_connection(TokioIo::new(stream), service)
						.await;
				});
			}
		});
		Self { url, authenticated, credentialed, requests, paths, redirect, task }
	}
}

fn backend(
	project: &Path, request: hyper::http::request::Parts, body: &[u8],
) -> Response<Full<Bytes>> {
	let mut child = Command::new("/usr/bin/git")
		.arg("http-backend")
		.env_clear()
		.env("PATH", "/usr/bin:/bin")
		.env("GIT_PROJECT_ROOT", project)
		.env("GIT_HTTP_EXPORT_ALL", "1")
		.env("REQUEST_METHOD", request.method.as_str())
		.env("PATH_INFO", request.uri.path().replace("%2E", "."))
		.env("QUERY_STRING", request.uri.query().unwrap_or(""))
		.env(
			"CONTENT_TYPE",
			request.headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or(""),
		)
		.env("CONTENT_LENGTH", body.len().to_string())
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::null())
		.spawn()
		.unwrap();
	child.stdin.take().unwrap().write_all(body).unwrap();
	let output = child.wait_with_output().unwrap();
	assert!(output.status.success());
	let split = output.stdout.windows(4).position(|part| part == b"\r\n\r\n").unwrap();
	let headers = std::str::from_utf8(&output.stdout[..split]).unwrap();
	let mut response = Response::builder();
	for line in headers.split("\r\n") {
		let (key, value) = line.split_once(':').unwrap();
		if key.eq_ignore_ascii_case("status") {
			response =
				response.status(value.trim().split(' ').next().unwrap().parse::<u16>().unwrap());
		} else {
			response = response.header(key, value.trim());
		}
	}
	response.body(Full::new(Bytes::copy_from_slice(&output.stdout[split + 4..]))).unwrap()
}

fn bare_source(root: &Path) -> PathBuf {
	let source = upstream(root);
	git(
		root,
		&[
			"clone",
			"--bare",
			"-q",
			source.to_str().unwrap(),
			root.join("repo.git").to_str().unwrap(),
		],
	);
	source
}

fn trap(root: &Path) {
	let script = root.join("trap-helper");
	std::fs::write(&script, format!("#!/bin/sh\ntouch '{}/helper-called'\n", root.display()))
		.unwrap();
	std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
	git(root, &["config", "--global", "credential.helper", script.to_str().unwrap()]);
	git(root, &["config", "--global", "core.askPass", script.to_str().unwrap()]);
}

#[test]
fn clone_and_fetch_authenticate_without_inherited_helpers() {
	isolated("tls::clone_and_fetch_authenticate_without_inherited_helpers", |root| {
		let source = bare_source(root);
		trap(root);
		runtime().block_on(async {
			let server = TlsGit::start(root).await;
			let token = Arc::new(Secret::new(PAT.to_owned()));
			let cache = cache(root);
			let key = RepoKey::new("localhost", "acme", "repo");
			let first = cache.ensure_repo(&key, &server.url, Some(&token)).await.unwrap();
			assert_eq!(
				git(&first.path, &["rev-parse", "HEAD"]),
				git(&source, &["rev-parse", "HEAD"])
			);
			drop(first);
			let second = commit(&source, "tls-second");
			git(&source, &["push", "-q", root.join("repo.git").to_str().unwrap(), "main"]);
			let repo = cache.ensure_repo(&key, &server.url, Some(&token)).await.unwrap();
			for name in ["refs/heads/main", "refs/remotes/origin/main", "refs/remotes/origin/HEAD"]
			{
				assert_eq!(git(&repo.path, &["rev-parse", name]), second);
			}
			assert!(
				server.authenticated.load(Ordering::SeqCst) >= 4,
				"fixture never authenticated clone and fetch"
			);
			assert!(
				!root.join("helper-called").exists(),
				"Git invoked an inherited credential/askpass helper"
			);
			assert_eq!(
				git(&repo.path, &["config", "--local", "--get-all", "remote.origin.url"]),
				server.url
			);
		});
	});
}

#[test]
fn redirects_are_rejected_despite_url_scoped_override() {
	isolated("tls::redirects_are_rejected_despite_url_scoped_override", |root| {
		bare_source(root);
		runtime().block_on(async {
			let server = TlsGit::start(root).await;
			git(
				root,
				&["config", "--global", &format!("http.{}.followRedirects", server.url), "true"],
			);
			let token = Arc::new(Secret::new(PAT.to_owned()));
			let port = reqwest::Url::parse(&server.url).unwrap().port().unwrap();
			for (index, target) in [
				format!("{}/info/refs?service=git-upload-pack", server.url),
				format!("{}/other/info/refs?service=git-upload-pack", server.url),
				format!("https://localhost:{}/repo.git/info/refs", port + 1),
			]
			.into_iter()
			.enumerate()
			{
				*server.redirect.lock().unwrap() = Some(target);
				server.authenticated.store(0, Ordering::SeqCst);
				server.requests.store(0, Ordering::SeqCst);
				let result = cache(root)
					.ensure_repo(
						&RepoKey::new("localhost", "acme", index.to_string()),
						&server.url,
						Some(&token),
					)
					.await;
				assert!(result.is_err(), "redirect unexpectedly succeeded");
				assert_eq!(
					server.authenticated.load(Ordering::SeqCst),
					1,
					"Git followed an authenticated redirect"
				);
				assert_eq!(server.requests.load(Ordering::SeqCst), 2);
			}
		});
	});
}

#[test]
fn rejected_auth_never_falls_back_to_inherited_helpers() {
	isolated("tls::rejected_auth_never_falls_back_to_inherited_helpers", |root| {
		bare_source(root);
		trap(root);
		runtime().block_on(async {
			let server = TlsGit::start(root).await;
			let token = Arc::new(Secret::new("wrong-test-token".to_owned()));
			let result = cache(root)
				.ensure_repo(&RepoKey::new("localhost", "acme", "repo"), &server.url, Some(&token))
				.await;
			assert!(result.is_err());
			assert_eq!(server.authenticated.load(Ordering::SeqCst), 0);
			assert!(
				server.credentialed.load(Ordering::SeqCst) > 0,
				"wrong credential was never challenged"
			);
			assert!(!root.join("helper-called").exists());
			assert!(!format!("{:#}", result.err().unwrap()).contains("wrong-test-token"));
		});
	});
}

#[test]
fn rewrites_cannot_expand_credential_destination() {
	isolated("tls::rewrites_cannot_expand_credential_destination", |root| {
		bare_source(root);
		trap(root);
		runtime().block_on(async {
			let server = TlsGit::start(root).await;
			let token = Arc::new(Secret::new(PAT.to_owned()));
			let parsed = reqwest::Url::parse(&server.url).unwrap();
			let destinations = [
				server.url.replace("localhost", "other.invalid"),
				format!("https://localhost:{}/repo.git", parsed.port().unwrap() + 1),
				format!("{}-sibling", server.url),
				format!("{}/descendant", server.url),
			];
			for (index, authorized) in destinations.iter().enumerate() {
				git(
					root,
					&[
						"config",
						"--global",
						"--add",
						&format!("url.{}.insteadOf", server.url),
						authorized,
					],
				);
				let result = cache(root)
					.ensure_repo(
						&RepoKey::new("localhost", "acme", index.to_string()),
						authorized,
						Some(&token),
					)
					.await;
				assert!(result.is_err(), "rewrite broadened credential scope");
			}
			assert!(server.requests.load(Ordering::SeqCst) >= destinations.len());
			assert_eq!(
				server.credentialed.load(Ordering::SeqCst),
				0,
				"PAT reached a rewritten host, port or path"
			);
			assert!(!root.join("helper-called").exists());
		});
	});
}

#[test]
fn decoded_repository_path_authenticates_and_tracing_stays_off() {
	isolated("tls::decoded_repository_path_authenticates_and_tracing_stays_off", |root| {
		bare_source(root);
		runtime().block_on(async {
			let server = TlsGit::start(root).await;
			// Fixture setup uses raw Git. Remove its trace files so the
			// following assertions measure only the cache operation.
			for name in ["git-trace", "curl-trace", "git-events"] {
				let _ = std::fs::remove_file(root.join(name));
			}
			let url = format!("{}/", server.url.replace("repo.git", "repo%2Egit"));
			let token = Arc::new(Secret::new(PAT.to_owned()));
			let result = cache(root)
				.ensure_repo(&RepoKey::new("localhost", "acme", "repo"), &url, Some(&token))
				.await;
			assert!(result.is_ok(), "percent-escaped trailing-slash URL failed");
			assert!(server.authenticated.load(Ordering::SeqCst) > 0);
			for name in ["git-trace", "curl-trace", "git-events"] {
				assert!(!root.join(name).exists(), "Git inherited credential-bearing tracing");
			}
		});
	});
}

#[test]
fn concurrent_operations_keep_credentials_separate() {
	isolated("tls::concurrent_operations_keep_credentials_separate", |root| {
		bare_source(root);
		runtime().block_on(async {
			let server = TlsGit::start(root).await;
			let cache = cache(root);
			let good = Arc::new(Secret::new(PAT.to_owned()));
			let bad = Arc::new(Secret::new("separate-operation-token".to_owned()));
			let good_key = RepoKey::new("localhost", "acme", "good");
			let bad_key = RepoKey::new("localhost", "acme", "bad");
			let (good_result, bad_result) = tokio::join!(
				cache.ensure_repo(&good_key, &server.url, Some(&good)),
				cache.ensure_repo(&bad_key, &server.url, Some(&bad)),
			);
			assert!(good_result.is_ok());
			assert!(bad_result.is_err(), "concurrent operations shared a credential");
			assert!(server.authenticated.load(Ordering::SeqCst) > 0);
		});
	});
}

fn redirect_alias(name: &str, authorized_path: &str, rewritten_path: &str) {
	isolated(name, |root| {
		bare_source(root);
		runtime().block_on(async {
			let server = TlsGit::start(root).await;
			let token = Arc::new(Secret::new(PAT.to_owned()));
			let cache = cache(root);
			*server.redirect.lock().unwrap() =
				Some(format!("{}/info/refs?service=git-upload-pack", server.url));
			git(
				root,
				&["config", "--global", &format!("http.{}.followRedirects", server.url), "true"],
			);
			let control = cache
				.ensure_repo(
					&RepoKey::new("localhost", "control", "repo"),
					&server.url,
					Some(&token),
				)
				.await;
			assert!(control.is_err());
			assert_eq!(
				server.authenticated.load(Ordering::SeqCst),
				1,
				"unrewritten redirect control failed"
			);
			let authority = server.url.strip_suffix("/repo.git").unwrap();
			let authorized = format!("{authority}{authorized_path}");
			let rewritten = format!("{authority}{rewritten_path}");
			git(root, &["config", "--global", &format!("url.{rewritten}.insteadOf"), &authorized]);
			git(
				root,
				&["config", "--global", &format!("http.{rewritten}.followRedirects"), "true"],
			);
			*server.redirect.lock().unwrap() =
				Some(format!("{rewritten}/info/refs?service=git-upload-pack"));
			server.authenticated.store(0, Ordering::SeqCst);
			let result = cache
				.ensure_repo(&RepoKey::new("localhost", "alias", "repo"), &authorized, Some(&token))
				.await;
			assert!(result.is_err());
			assert_eq!(
				server.authenticated.load(Ordering::SeqCst),
				1,
				"Git followed redirects through a decoded credential-path alias"
			);
		});
	});
}

#[test]
fn encoded_separator_rewrite_cannot_enable_redirects() {
	redirect_alias(
		"tls::encoded_separator_rewrite_cannot_enable_redirects",
		"/acme%2Frepo.git",
		"/acme/repo.git",
	);
}

#[test]
fn reverse_separator_rewrite_cannot_enable_redirects() {
	redirect_alias(
		"tls::reverse_separator_rewrite_cannot_enable_redirects",
		"/acme/repo.git",
		"/acme%2Frepo.git",
	);
}

#[test]
fn encoded_reserved_rewrite_cannot_enable_redirects() {
	redirect_alias(
		"tls::encoded_reserved_rewrite_cannot_enable_redirects",
		"/repo%40name.git",
		"/repo@name.git",
	);
}

#[test]
fn reverse_reserved_rewrite_cannot_enable_redirects() {
	redirect_alias(
		"tls::reverse_reserved_rewrite_cannot_enable_redirects",
		"/repo@name.git",
		"/repo%40name.git",
	);
}

#[test]
fn leading_slash_rewrite_cannot_enable_redirects() {
	redirect_alias(
		"tls::leading_slash_rewrite_cannot_enable_redirects",
		"//acme/repo.git",
		"/acme/repo.git",
	);
}

#[test]
fn trailing_slash_rewrite_cannot_enable_redirects() {
	redirect_alias(
		"tls::trailing_slash_rewrite_cannot_enable_redirects",
		"/acme/repo.git//",
		"/acme/repo.git",
	);
}

fn clone_context(name: &str, context: &str) {
	isolated(name, |root| {
		bare_source(root);
		runtime().block_on(async {
			let server = TlsGit::start(root).await;
			let alias = server.url.replace("/repo.git", "//repo.git");
			let config = root.join("context.config");
			git(
				root,
				&[
					"config",
					"--file",
					config.to_str().unwrap(),
					&format!("url.{alias}.insteadOf"),
					&server.url,
				],
			);
			git(
				root,
				&[
					"config",
					"--file",
					config.to_str().unwrap(),
					&format!("http.{alias}.followRedirects"),
					"true",
				],
			);
			match context {
				"conditional" => {
					git(
						root,
						&[
							"config",
							"--global",
							&format!("includeIf.gitdir:{}/.path", root.join("cache").display()),
							config.to_str().unwrap(),
						],
					);
				},
				"template" => {
					let template = root.join("template");
					std::fs::create_dir(&template).unwrap();
					std::fs::copy(&config, template.join("config")).unwrap();
					git(
						root,
						&["config", "--global", "init.templateDir", template.to_str().unwrap()],
					);
				},
				"origin" | "remote-name" => {
					let remote = if context == "remote-name" {
						git(root, &["config", "--global", "clone.defaultRemoteName", "other"]);
						"other"
					} else {
						"origin"
					};
					git(root, &["config", "--global", &format!("remote.{remote}.url"), &alias]);
					git(
						root,
						&["config", "--global", &format!("http.{alias}.followRedirects"), "true"],
					);
				},
				_ => unreachable!(),
			}
			*server.redirect.lock().unwrap() =
				Some(format!("{alias}/info/refs?service=git-upload-pack"));
			let token = Arc::new(Secret::new(PAT.to_owned()));
			let cache = cache(root);
			let key = RepoKey::new("localhost", "acme", "repo");
			let result = cache.ensure_repo(&key, &server.url, Some(&token)).await;
			assert!(result.is_err());
			assert_eq!(
				server.authenticated.load(Ordering::SeqCst),
				1,
				"clone config displaced the pinned redirect policy"
			);
			assert!(
				server.paths.lock().unwrap().iter().all(|path| !path.starts_with("//")),
				"clone config displaced the pinned transport destination"
			);
			*server.redirect.lock().unwrap() = None;
			let repo = cache.ensure_repo(&key, &server.url, Some(&token)).await.unwrap();
			assert_eq!(
				git(&repo.path, &["config", "--local", "--get-all", "remote.origin.url"]),
				server.url
			);
			let config = git(&repo.path, &["config", "--local", "--list"]);
			assert!(!config.contains("loupe-git://"));
			assert!(!config.contains("credential.helper"));
		});
	});
}

#[test]
fn destination_conditional_config_cannot_replace_transport_pin() {
	clone_context(
		"tls::destination_conditional_config_cannot_replace_transport_pin",
		"conditional",
	);
}

#[test]
fn clone_template_config_cannot_replace_transport_pin() {
	clone_context("tls::clone_template_config_cannot_replace_transport_pin", "template");
}

#[test]
fn merged_origin_config_cannot_replace_transport_pin() {
	clone_context("tls::merged_origin_config_cannot_replace_transport_pin", "origin");
}

#[test]
fn inherited_remote_name_cannot_replace_transport_pin() {
	clone_context("tls::inherited_remote_name_cannot_replace_transport_pin", "remote-name");
}

#[test]
fn equals_in_url_keeps_exact_redirect_policy() {
	isolated("tls::equals_in_url_keeps_exact_redirect_policy", |root| {
		bare_source(root);
		runtime().block_on(async {
			let server = TlsGit::start(root).await;
			let url = server.url.replace("repo.git", "repo=name.git");
			git(root, &["config", "--global", &format!("http.{url}.followRedirects"), "true"]);
			*server.redirect.lock().unwrap() =
				Some(format!("{url}/info/refs?service=git-upload-pack"));
			let token = Arc::new(Secret::new(PAT.to_owned()));
			let result = cache(root)
				.ensure_repo(&RepoKey::new("localhost", "acme", "repo"), &url, Some(&token))
				.await;
			assert!(result.is_err());
			assert_eq!(
				server.authenticated.load(Ordering::SeqCst),
				1,
				"valid URL could not authenticate with an exact redirect policy"
			);
		});
	});
}
