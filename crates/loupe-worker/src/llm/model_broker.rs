//! Per-job, host-side model API broker.
//!
//! The sandbox receives only this session's Unix socket. The trusted worker
//! fixes the provider, upstream, model, credential, and resource ceilings
//! before accepting a connection, so repository-controlled agent settings
//! cannot redirect requests or recover host credentials.

use std::collections::HashSet;
use std::convert::Infallible;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::{stream, Stream, StreamExt};
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{
	HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, COOKIE, HOST,
	PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::UnixListener;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::sandbox::SandboxBuilder;

pub const SANDBOX_MODEL_DIR: &str = "/loupe/model";
pub const SANDBOX_MODEL_SOCKET: &str = "/loupe/model/session.sock";

const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_ADAPTER_CONNECTIONS: usize = 16;
const BROKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);
const BROKER_ERROR_TRAILER: &str = "loupe-broker-error";

type BoxError = Box<dyn Error + Send + Sync>;
type BrokerBody = http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>;
type UpstreamByteStream =
	Pin<Box<dyn Stream<Item = std::result::Result<Bytes, reqwest::Error>> + Send>>;

/// Provider protocol plus the model policy fixed for one job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelBrokerBackend {
	Claude { model: String, effort: String },
	Codex { model: String, effort: String },
}

impl ModelBrokerBackend {
	fn provider(&self) -> ModelProvider {
		match self {
			Self::Claude { .. } => ModelProvider::Claude,
			Self::Codex { .. } => ModelProvider::Codex,
		}
	}

	fn model(&self) -> &str {
		match self {
			Self::Claude { model, .. } | Self::Codex { model, .. } => model,
		}
	}

	fn effort(&self) -> &str {
		match self {
			Self::Claude { effort, .. } | Self::Codex { effort, .. } => effort,
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelProvider {
	Claude,
	Codex,
}

impl ModelProvider {
	fn endpoint(self) -> &'static str {
		match self {
			Self::Claude => "/v1/messages",
			Self::Codex => "/v1/responses",
		}
	}
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CredentialKind {
	AnthropicApiKey,
	AnthropicOAuthToken,
	OpenAiApiKey,
}

/// Host-held provider authentication. Deliberately does not implement
/// `Debug`, so logging a broker configuration cannot print the secret.
#[derive(Clone)]
pub struct ModelCredential {
	kind: CredentialKind,
	secret: String,
}

/// Worker-owned ingredients reused to create a fresh broker session for
/// each invocation of one backend.
#[derive(Clone)]
pub struct ModelBrokerContext {
	worker_binary: PathBuf,
	upstream: reqwest::Url,
	credential: ModelCredential,
	limits: ModelBrokerLimits,
}

impl ModelBrokerContext {
	pub fn new(
		worker_binary: PathBuf, upstream: reqwest::Url, credential: ModelCredential,
		limits: ModelBrokerLimits,
	) -> Self {
		Self { worker_binary, upstream, credential, limits }
	}

	pub async fn start_session(&self, backend: ModelBrokerBackend) -> Result<ModelBrokerSession> {
		ModelBrokerSession::start(
			backend,
			self.upstream.clone(),
			self.credential.clone(),
			self.limits,
		)
		.await
	}

	pub fn worker_binary(&self) -> &Path {
		&self.worker_binary
	}
}

pub fn bind_model_into_sandbox(
	sandbox: SandboxBuilder, context: &ModelBrokerContext, session: &ModelBrokerSession,
) -> SandboxBuilder {
	sandbox
		.bind_ro(context.worker_binary.clone(), super::mcp::SANDBOX_LOUPE_BIN)
		.bind_ro(session.host_dir(), SANDBOX_MODEL_DIR)
}

impl ModelCredential {
	pub fn anthropic_api_key(secret: impl Into<String>) -> Self {
		Self { kind: CredentialKind::AnthropicApiKey, secret: secret.into() }
	}

	pub fn anthropic_oauth_token(secret: impl Into<String>) -> Self {
		Self { kind: CredentialKind::AnthropicOAuthToken, secret: secret.into() }
	}

	pub fn openai_api_key(secret: impl Into<String>) -> Self {
		Self { kind: CredentialKind::OpenAiApiKey, secret: secret.into() }
	}

	fn validate_for(&self, provider: ModelProvider) -> Result<()> {
		if self.secret.is_empty() {
			anyhow::bail!("model broker credential must not be empty");
		}
		let matches = matches!(
			(provider, self.kind),
			(ModelProvider::Claude, CredentialKind::AnthropicApiKey)
				| (ModelProvider::Claude, CredentialKind::AnthropicOAuthToken)
				| (ModelProvider::Codex, CredentialKind::OpenAiApiKey)
		);
		if !matches {
			anyhow::bail!("model broker credential does not match the configured provider");
		}
		HeaderValue::from_str(&self.secret)
			.context("model broker credential is not valid as an HTTP header value")?;
		Ok(())
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelBrokerLimits {
	pub request_ceiling: u64,
	pub output_ceiling_bytes: u64,
	pub token_ceiling: Option<u64>,
}

impl ModelBrokerLimits {
	pub(crate) fn validate(self) -> Result<()> {
		if self.request_ceiling == 0 {
			anyhow::bail!("model broker request ceiling must be greater than zero");
		}
		if self.output_ceiling_bytes == 0 {
			anyhow::bail!("model broker output ceiling must be greater than zero");
		}
		if self.token_ceiling == Some(0) {
			anyhow::bail!("model broker token ceiling must be greater than zero when configured");
		}
		Ok(())
	}
}

impl Default for ModelBrokerLimits {
	fn default() -> Self {
		Self { request_ceiling: 1_000, output_ceiling_bytes: 32 * 1024 * 1024, token_ceiling: None }
	}
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModelBrokerUsage {
	pub requests: u64,
	pub output_bytes: u64,
	pub tokens: u64,
}

#[derive(Default)]
struct UsageCounters {
	requests: AtomicU64,
	output_bytes: AtomicU64,
	tokens: AtomicU64,
}

impl UsageCounters {
	fn snapshot(&self) -> ModelBrokerUsage {
		ModelBrokerUsage {
			requests: self.requests.load(Ordering::Relaxed),
			output_bytes: self.output_bytes.load(Ordering::Relaxed),
			tokens: self.tokens.load(Ordering::Relaxed),
		}
	}

	fn start_request(&self, limits: ModelBrokerLimits) -> std::result::Result<(), LimitKind> {
		if limits
			.token_ceiling
			.is_some_and(|ceiling| self.tokens.load(Ordering::Relaxed) >= ceiling)
		{
			return Err(LimitKind::Tokens);
		}
		if self.output_bytes.load(Ordering::Relaxed) >= limits.output_ceiling_bytes {
			return Err(LimitKind::Output);
		}
		self.requests
			.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
				(current < limits.request_ceiling).then_some(current + 1)
			})
			.map(|_| ())
			.map_err(|_| LimitKind::Requests)
	}

	fn reserve_output(&self, requested: usize, ceiling: u64) -> usize {
		loop {
			let current = self.output_bytes.load(Ordering::Relaxed);
			let remaining = ceiling.saturating_sub(current);
			let allowed = remaining.min(requested as u64) as usize;
			if allowed == 0 {
				return 0;
			}
			if self
				.output_bytes
				.compare_exchange_weak(
					current,
					current + allowed as u64,
					Ordering::Relaxed,
					Ordering::Relaxed,
				)
				.is_ok()
			{
				return allowed;
			}
		}
	}
}

#[derive(Clone, Copy)]
enum LimitKind {
	Requests,
	Output,
	Tokens,
}

impl LimitKind {
	fn code(self) -> &'static str {
		match self {
			Self::Requests => "request_ceiling_exhausted",
			Self::Output => "output_ceiling_exhausted",
			Self::Tokens => "token_ceiling_exhausted",
		}
	}

	fn message(self) -> &'static str {
		match self {
			Self::Requests => "model request ceiling exhausted",
			Self::Output => "model output ceiling exhausted",
			Self::Tokens => "model token ceiling exhausted",
		}
	}
}

struct BrokerState {
	backend: ModelBrokerBackend,
	upstream: reqwest::Url,
	credential: ModelCredential,
	limits: ModelBrokerLimits,
	usage: Arc<UsageCounters>,
	http: reqwest::Client,
}

/// Trusted authority for one job's model traffic.
pub struct ModelBrokerSession {
	dir: tempfile::TempDir,
	socket_path: PathBuf,
	usage: Arc<UsageCounters>,
	shutdown: CancellationToken,
	task: Option<JoinHandle<Result<()>>>,
}

impl ModelBrokerSession {
	pub async fn start(
		backend: ModelBrokerBackend, upstream: reqwest::Url, credential: ModelCredential,
		limits: ModelBrokerLimits,
	) -> Result<Self> {
		limits.validate()?;
		credential.validate_for(backend.provider())?;
		if !matches!(upstream.scheme(), "http" | "https") || upstream.host_str().is_none() {
			anyhow::bail!("model broker upstream must be an HTTP(S) URL with a host");
		}
		if !backend.model().trim().is_empty() && !backend.effort().trim().is_empty() {
			// Both values are deliberately read here so a session cannot be
			// constructed with an incomplete fixed policy.
		} else {
			anyhow::bail!("model broker model and effort must not be empty");
		}

		let dir = tempfile::Builder::new()
			.prefix("loupe-model-broker-")
			.tempdir()
			.context("creating model broker directory")?;
		let socket_path = dir.path().join("session.sock");
		let listener = UnixListener::bind(&socket_path)
			.with_context(|| format!("binding model broker socket at {}", socket_path.display()))?;
		let usage = Arc::new(UsageCounters::default());
		let http = reqwest::Client::builder()
			.redirect(reqwest::redirect::Policy::none())
			.build()
			.context("building model broker HTTP client")?;
		let state = Arc::new(BrokerState {
			backend,
			upstream,
			credential,
			limits,
			usage: usage.clone(),
			http,
		});
		let shutdown = CancellationToken::new();
		let task_shutdown = shutdown.clone();
		let task = tokio::spawn(serve_session(listener, state, task_shutdown));

		Ok(Self { dir, socket_path, usage, shutdown, task: Some(task) })
	}

	pub fn socket_path(&self) -> &Path {
		&self.socket_path
	}

	pub fn host_dir(&self) -> &Path {
		self.dir.path()
	}

	pub fn usage(&self) -> ModelBrokerUsage {
		self.usage.snapshot()
	}

	/// Revoke the socket and any in-flight response stream.
	pub async fn finish(mut self) -> Result<ModelBrokerUsage> {
		self.shutdown.cancel();
		let mut task = self.task.take().expect("broker task is present until finish");
		match tokio::time::timeout(BROKER_SHUTDOWN_TIMEOUT, &mut task).await {
			Ok(result) => result.context("model broker task panicked")??,
			Err(_) => {
				task.abort();
				let _ = task.await;
				anyhow::bail!("timed out waiting for model broker shutdown");
			},
		}
		Ok(self.usage.snapshot())
	}
}

impl Drop for ModelBrokerSession {
	fn drop(&mut self) {
		self.shutdown.cancel();
		if let Some(task) = self.task.take() {
			task.abort();
		}
	}
}

async fn serve_session(
	listener: UnixListener, state: Arc<BrokerState>, shutdown: CancellationToken,
) -> Result<()> {
	let mut connections = JoinSet::new();
	loop {
		tokio::select! {
			biased;
			_ = shutdown.cancelled() => break,
			Some(result) = connections.join_next(), if !connections.is_empty() => {
				match result {
					Ok(Ok(())) => {},
					Ok(Err(error)) => tracing::debug!(%error, "model adapter connection ended"),
					Err(error) => tracing::warn!(%error, "model adapter connection task failed"),
				}
			},
			result = listener.accept() => {
				let (stream, _) = result.context("accepting model proxy connection")?;
				if connections.len() >= MAX_ADAPTER_CONNECTIONS {
					tracing::warn!(limit = MAX_ADAPTER_CONNECTIONS, "model adapter connection limit reached");
					continue;
				}
				let connection_state = state.clone();
				let connection_shutdown = shutdown.clone();
				connections.spawn(async move {
					serve_adapter_connection(stream, connection_state, connection_shutdown).await
				});
			},
		}
	}
	connections.abort_all();
	while connections.join_next().await.is_some() {}
	Ok(())
}

async fn serve_adapter_connection(
	stream: tokio::net::UnixStream, state: Arc<BrokerState>, shutdown: CancellationToken,
) -> Result<()> {
	let service = service_fn(move |request| proxy_request(request, state.clone()));
	let connection = http1::Builder::new().serve_connection(TokioIo::new(stream), service);
	tokio::pin!(connection);
	tokio::select! {
		result = &mut connection => result.context("serving model proxy connection")?,
		_ = shutdown.cancelled() => {},
	}
	Ok(())
}

async fn proxy_request(
	request: Request<Incoming>, state: Arc<BrokerState>,
) -> std::result::Result<Response<BrokerBody>, Infallible> {
	let response = handle_request(request, state).await.unwrap_or_else(|error| {
		tracing::warn!(error = %error, "model broker rejected an internal proxy failure");
		local_error(StatusCode::BAD_GATEWAY, "upstream_error", "model upstream request failed")
	});
	Ok(response)
}

async fn handle_request(
	request: Request<Incoming>, state: Arc<BrokerState>,
) -> Result<Response<BrokerBody>> {
	if state.backend.provider() == ModelProvider::Claude
		&& request.method() == Method::HEAD
		&& request.uri().path() == "/api/hello"
		&& request.uri().query().is_none()
	{
		// Claude Code uses this as a connectivity preflight before
		// Messages. Answer locally: the sandbox learns only that its own
		// job-scoped adapter is alive, and no provider authority is spent.
		return Ok(empty_response(StatusCode::OK));
	}
	let provider = state.backend.provider();
	let endpoint = provider.endpoint();
	let query = request.uri().query();
	let query_allowed = match provider {
		ModelProvider::Claude => query.is_none() || query == Some("beta=true"),
		ModelProvider::Codex => query.is_none(),
	};
	if request.method() != Method::POST || request.uri().path() != endpoint || !query_allowed {
		return Ok(local_error(
			StatusCode::NOT_FOUND,
			"endpoint_not_allowed",
			"endpoint not allowed",
		));
	}
	let query = query.map(str::to_owned);

	let headers = sanitize_request_headers(request.headers(), &state.credential)?;
	let body = match Limited::new(request.into_body(), MAX_REQUEST_BODY_BYTES).collect().await {
		Ok(body) => body.to_bytes(),
		Err(_) => {
			return Ok(local_error(
				StatusCode::PAYLOAD_TOO_LARGE,
				"request_body_too_large",
				"model request body exceeds the local limit",
			));
		},
	};
	let body = match enforce_request_policy(&body, &state.backend) {
		Ok(body) => body,
		Err(RequestPolicyError::InvalidJson) => {
			return Ok(local_error(
				StatusCode::BAD_REQUEST,
				"invalid_request_json",
				"model request must be a JSON object",
			));
		},
		Err(RequestPolicyError::DeniedTool(tool_type)) => {
			tracing::warn!(tool_type, "model broker denied a provider-side fetch tool");
			return Ok(local_error(
				StatusCode::UNPROCESSABLE_ENTITY,
				"tool_policy_denied",
				"provider-side arbitrary-URL fetch tool is not allowed",
			));
		},
	};
	if let Err(limit) = state.usage.start_request(state.limits) {
		return Ok(local_error(StatusCode::TOO_MANY_REQUESTS, limit.code(), limit.message()));
	}

	let mut upstream = state.upstream.clone();
	upstream.set_path(endpoint);
	upstream.set_query(query.as_deref());
	upstream.set_fragment(None);
	let response = state
		.http
		.post(upstream)
		.headers(headers)
		.body(body)
		.send()
		.await
		.context("sending model request to configured upstream")?;
	if response.status().is_redirection() {
		return Ok(local_error(
			StatusCode::BAD_GATEWAY,
			"upstream_redirect_denied",
			"model upstream redirects are not allowed",
		));
	}
	Ok(stream_upstream_response(response, state))
}

fn sanitize_request_headers(
	headers: &HeaderMap, credential: &ModelCredential,
) -> Result<HeaderMap> {
	let connection_headers = connection_header_names(headers);
	let mut sanitized = HeaderMap::new();
	for (name, value) in headers {
		if !strip_request_header(name, &connection_headers) {
			sanitized.append(name.clone(), value.clone());
		}
	}
	let secret = HeaderValue::from_str(&credential.secret)
		.context("model broker credential is not valid as an HTTP header value")?;
	match credential.kind {
		CredentialKind::AnthropicApiKey => {
			sanitized.insert(HeaderName::from_static("x-api-key"), secret);
		},
		CredentialKind::AnthropicOAuthToken | CredentialKind::OpenAiApiKey => {
			let bearer = HeaderValue::from_str(&format!("Bearer {}", credential.secret))
				.context("model broker bearer credential is not a valid HTTP header value")?;
			sanitized.insert(AUTHORIZATION, bearer);
		},
	}
	Ok(sanitized)
}

fn connection_header_names(headers: &HeaderMap) -> HashSet<HeaderName> {
	headers
		.get_all(CONNECTION)
		.iter()
		.filter_map(|value| value.to_str().ok())
		.flat_map(|value| value.split(','))
		.filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
		.collect()
}

fn strip_request_header(name: &HeaderName, connection_headers: &HashSet<HeaderName>) -> bool {
	name == AUTHORIZATION
		|| name == COOKIE
		|| name == HeaderName::from_static("x-api-key")
		|| name == HOST
		|| name == CONTENT_LENGTH
		|| is_hop_by_hop(name)
		|| connection_headers.contains(name)
		|| name.as_str().starts_with("proxy-")
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
	name == CONNECTION
		|| name == HeaderName::from_static("keep-alive")
		|| name == PROXY_AUTHENTICATE
		|| name == PROXY_AUTHORIZATION
		|| name == TE
		|| name == TRAILER
		|| name == TRANSFER_ENCODING
		|| name == UPGRADE
}

enum RequestPolicyError {
	InvalidJson,
	DeniedTool(String),
}

fn enforce_request_policy(
	body: &Bytes, backend: &ModelBrokerBackend,
) -> std::result::Result<Bytes, RequestPolicyError> {
	let mut value: serde_json::Value =
		serde_json::from_slice(body).map_err(|_| RequestPolicyError::InvalidJson)?;
	let object = value.as_object_mut().ok_or(RequestPolicyError::InvalidJson)?;
	if let Some(tools) = object.get("tools").and_then(serde_json::Value::as_array) {
		for tool in tools {
			if let Some(tool_type) = tool.get("type").and_then(serde_json::Value::as_str)
				&& denied_tool_type(backend.provider(), tool_type)
			{
				return Err(RequestPolicyError::DeniedTool(tool_type.to_owned()));
			}
		}
	}
	let effort_field = match backend.provider() {
		ModelProvider::Claude => "output_config",
		ModelProvider::Codex => "reasoning",
	};
	let model_matches =
		object.get("model").and_then(serde_json::Value::as_str) == Some(backend.model());
	let effort_matches = object
		.get(effort_field)
		.and_then(serde_json::Value::as_object)
		.and_then(|config| config.get("effort"))
		.and_then(serde_json::Value::as_str)
		== Some(backend.effort());
	if model_matches && effort_matches {
		return Ok(body.clone());
	}
	object.insert("model".to_owned(), serde_json::Value::String(backend.model().to_owned()));
	let effort_config = object
		.entry(effort_field)
		.or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
	if !effort_config.is_object() {
		*effort_config = serde_json::Value::Object(serde_json::Map::new());
	}
	effort_config
		.as_object_mut()
		.expect("effort config was made an object")
		.insert("effort".to_owned(), serde_json::Value::String(backend.effort().to_owned()));
	serde_json::to_vec(&value).map(Bytes::from).map_err(|_| RequestPolicyError::InvalidJson)
}

fn denied_tool_type(provider: ModelProvider, tool_type: &str) -> bool {
	match provider {
		ModelProvider::Claude => tool_type == "web_fetch" || tool_type.starts_with("web_fetch_"),
		ModelProvider::Codex => {
			matches!(tool_type, "mcp" | "remote_mcp" | "web_fetch")
				|| tool_type.starts_with("web_fetch_")
		},
	}
}

fn stream_upstream_response(
	upstream: reqwest::Response, state: Arc<BrokerState>,
) -> Response<BrokerBody> {
	let status = upstream.status();
	let headers = sanitize_response_headers(upstream.headers());
	let stream_state = OutputStreamState {
		upstream: Box::pin(upstream.bytes_stream()),
		usage: state.usage.clone(),
		output_ceiling: state.limits.output_ceiling_bytes,
		capture: Vec::new(),
		overflowed: false,
		terminal: false,
	};
	let output = stream::unfold(stream_state, |mut state| async move {
		if state.terminal {
			return None;
		}
		if state.overflowed {
			state.terminal = true;
			let mut trailers = HeaderMap::new();
			trailers.insert(
				HeaderName::from_static(BROKER_ERROR_TRAILER),
				HeaderValue::from_static("output_ceiling_exceeded"),
			);
			return Some((Ok(Frame::trailers(trailers)), state));
		}
		match state.upstream.next().await {
			Some(Ok(chunk)) => {
				let allowed = state.usage.reserve_output(chunk.len(), state.output_ceiling);
				if allowed == 0 {
					state.overflowed = true;
					let mut trailers = HeaderMap::new();
					trailers.insert(
						HeaderName::from_static(BROKER_ERROR_TRAILER),
						HeaderValue::from_static("output_ceiling_exceeded"),
					);
					state.terminal = true;
					return Some((Ok(Frame::trailers(trailers)), state));
				}
				let chunk = if allowed < chunk.len() {
					state.overflowed = true;
					chunk.slice(..allowed)
				} else {
					chunk
				};
				state.capture.extend_from_slice(&chunk);
				Some((Ok(Frame::data(chunk)), state))
			},
			Some(Err(error)) => {
				state.terminal = true;
				Some((Err(Box::new(error) as BoxError), state))
			},
			None => {
				let tokens = token_usage_from_response(&state.capture);
				state.usage.tokens.fetch_add(tokens, Ordering::Relaxed);
				None
			},
		}
	});
	let body = StreamBody::new(output).boxed_unsync();
	let mut response = Response::new(body);
	*response.status_mut() = status;
	*response.headers_mut() = headers;
	response.headers_mut().insert(TRAILER, HeaderValue::from_static(BROKER_ERROR_TRAILER));
	response
}

struct OutputStreamState {
	upstream: UpstreamByteStream,
	usage: Arc<UsageCounters>,
	output_ceiling: u64,
	capture: Vec<u8>,
	overflowed: bool,
	terminal: bool,
}

fn sanitize_response_headers(headers: &HeaderMap) -> HeaderMap {
	let connection_headers = connection_header_names(headers);
	let mut sanitized = HeaderMap::new();
	for (name, value) in headers {
		if name != CONTENT_LENGTH && !is_hop_by_hop(name) && !connection_headers.contains(name) {
			sanitized.append(name.clone(), value.clone());
		}
	}
	sanitized
}

fn token_usage_from_response(body: &[u8]) -> u64 {
	let mut usage = ParsedTokenUsage::default();
	if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
		usage.observe(&value);
	} else if let Ok(text) = std::str::from_utf8(body) {
		for line in text.lines() {
			let Some(data) = line.strip_prefix("data:").map(str::trim) else { continue };
			if data == "[DONE]" {
				continue;
			}
			if let Ok(value) = serde_json::from_str::<serde_json::Value>(data) {
				usage.observe(&value);
			}
		}
	}
	usage.total.max(usage.input.saturating_add(usage.output))
}

#[derive(Default)]
struct ParsedTokenUsage {
	input: u64,
	output: u64,
	total: u64,
}

impl ParsedTokenUsage {
	fn observe(&mut self, value: &serde_json::Value) {
		match value {
			serde_json::Value::Object(object) => {
				if let Some(usage) = object.get("usage").and_then(serde_json::Value::as_object) {
					self.input = self.input.max(
						usage.get("input_tokens").and_then(serde_json::Value::as_u64).unwrap_or(0),
					);
					self.output = self.output.max(
						usage.get("output_tokens").and_then(serde_json::Value::as_u64).unwrap_or(0),
					);
					self.total = self.total.max(
						usage.get("total_tokens").and_then(serde_json::Value::as_u64).unwrap_or(0),
					);
				}
				for nested in object.values() {
					self.observe(nested);
				}
			},
			serde_json::Value::Array(items) => {
				for item in items {
					self.observe(item);
				}
			},
			_ => {},
		}
	}
}

fn local_error(
	status: StatusCode, code: &'static str, message: &'static str,
) -> Response<BrokerBody> {
	let body = serde_json::to_vec(&serde_json::json!({
		"error": { "type": "loupe_model_broker", "code": code, "message": message }
	}))
	.expect("static broker error JSON serializes");
	let body = Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed_unsync();
	let mut response = Response::new(body);
	*response.status_mut() = status;
	response
		.headers_mut()
		.insert(hyper::header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
	response
}

fn empty_response(status: StatusCode) -> Response<BrokerBody> {
	let body = Full::new(Bytes::new()).map_err(|never| match never {}).boxed_unsync();
	let mut response = Response::new(body);
	*response.status_mut() = status;
	response
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use axum::body::{to_bytes, Body};
	use axum::extract::{Request, State};
	use axum::http::{HeaderMap, StatusCode};
	use axum::response::Response;
	use axum::routing::any;
	use axum::Router;
	use bytes::Bytes;
	use http_body_util::{BodyExt, Full};
	use hyper::client::conn::http1::{handshake, SendRequest};
	use hyper::{Method, Request as HyperRequest};
	use hyper_util::rt::TokioIo;
	use tokio::net::{TcpListener, UnixStream};
	use tokio::sync::Mutex;

	use super::*;

	#[derive(Clone, Debug)]
	struct CapturedRequest {
		path: String,
		headers: HeaderMap,
		body: Bytes,
	}
	type CapturedRequests = Arc<Mutex<Vec<CapturedRequest>>>;
	type FakeResponse = Arc<Mutex<(StatusCode, HeaderMap, Bytes)>>;
	type FakeState = (CapturedRequests, FakeResponse);

	#[derive(Clone)]
	struct FakeUpstream {
		url: reqwest::Url,
		requests: CapturedRequests,
		response: FakeResponse,
	}

	impl FakeUpstream {
		async fn start(body: impl Into<Bytes>) -> Self {
			let requests = Arc::new(Mutex::new(Vec::new()));
			let response = Arc::new(Mutex::new((StatusCode::OK, HeaderMap::new(), body.into())));
			let state = (requests.clone(), response.clone());
			let app = Router::new().fallback(any(
				|State((requests, response)): State<FakeState>, request: Request| async move {
					let path = request
						.uri()
						.path_and_query()
						.map(|value| value.as_str())
						.unwrap_or(request.uri().path())
						.to_owned();
					let headers = request.headers().clone();
					let body = to_bytes(request.into_body(), usize::MAX).await.unwrap();
					requests.lock().await.push(CapturedRequest { path, headers, body });
					let (status, headers, body) = response.lock().await.clone();
					let mut response = Response::new(Body::from(body));
					*response.status_mut() = status;
					*response.headers_mut() = headers;
					response
				},
			));
			let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
			let address = listener.local_addr().unwrap();
			tokio::spawn(async move {
				axum::serve(listener, app.with_state(state)).await.unwrap();
			});
			Self { url: format!("http://{address}").parse().unwrap(), requests, response }
		}

		async fn captured(&self) -> Vec<CapturedRequest> {
			self.requests.lock().await.clone()
		}

		async fn respond_with(
			&self, status: StatusCode, headers: HeaderMap, body: impl Into<Bytes>,
		) {
			let mut response = self.response.lock().await;
			*response = (status, headers, body.into());
		}
	}

	type BrokerClient = SendRequest<Full<Bytes>>;

	async fn connect(session: &ModelBrokerSession) -> BrokerClient {
		let stream = UnixStream::connect(session.socket_path()).await.unwrap();
		let (sender, connection) = handshake(TokioIo::new(stream)).await.unwrap();
		tokio::spawn(async move {
			let _ = connection.await;
		});
		sender
	}

	fn request(path: &str, body: impl Into<Bytes>) -> HyperRequest<Full<Bytes>> {
		HyperRequest::builder()
			.method(Method::POST)
			.uri(path)
			.header("content-type", "application/json")
			.body(Full::new(body.into()))
			.unwrap()
	}

	fn claude_backend() -> ModelBrokerBackend {
		ModelBrokerBackend::Claude { model: "claude-test".into(), effort: "high".into() }
	}

	fn codex_backend() -> ModelBrokerBackend {
		ModelBrokerBackend::Codex { model: "gpt-test".into(), effort: "high".into() }
	}

	fn limits() -> ModelBrokerLimits {
		ModelBrokerLimits {
			request_ceiling: 8,
			output_ceiling_bytes: 1024 * 1024,
			token_ceiling: None,
		}
	}

	fn bwrap_present() -> bool {
		std::process::Command::new("bwrap")
			.arg("--version")
			.stdout(std::process::Stdio::null())
			.stderr(std::process::Stdio::null())
			.status()
			.map(|status| status.success())
			.unwrap_or(false)
	}

	#[tokio::test]
	async fn session_accepts_job_scoped_connections_and_finish_revokes_them() {
		let upstream = FakeUpstream::start("{}").await;
		let session = ModelBrokerSession::start(
			claude_backend(),
			upstream.url,
			ModelCredential::anthropic_api_key("host-secret"),
			limits(),
		)
		.await
		.unwrap();
		assert!(session.socket_path().exists());

		let mut client = connect(&session).await;
		let response = client.send_request(request("/not-allowed", "{}")).await.unwrap();
		assert_eq!(response.status(), StatusCode::NOT_FOUND);
		response.into_body().collect().await.unwrap();

		let mut second = connect(&session).await;
		let response = second.send_request(request("/still-not-allowed", "{}")).await.unwrap();
		assert_eq!(response.status(), StatusCode::NOT_FOUND);
		response.into_body().collect().await.unwrap();

		session.finish().await.unwrap();
	}

	#[tokio::test]
	async fn finish_revokes_connected_adapter_authority() {
		let upstream = FakeUpstream::start("{}").await;
		let session = ModelBrokerSession::start(
			claude_backend(),
			upstream.url,
			ModelCredential::anthropic_api_key("host-secret"),
			limits(),
		)
		.await
		.unwrap();
		let mut client = connect(&session).await;

		session.finish().await.unwrap();

		let result = client.send_request(request("/v1/messages", "{}")).await;
		assert!(result.is_err(), "a connected adapter retained authority after broker finish");
	}

	#[tokio::test]
	async fn sandbox_mount_exposes_only_its_own_job_socket() {
		if !bwrap_present() {
			eprintln!("skipping: bwrap missing");
			return;
		}
		let upstream = FakeUpstream::start("{}").await;
		let session_a = ModelBrokerSession::start(
			claude_backend(),
			upstream.url.clone(),
			ModelCredential::anthropic_api_key("host-secret-a"),
			limits(),
		)
		.await
		.unwrap();
		let session_b = ModelBrokerSession::start(
			claude_backend(),
			upstream.url.clone(),
			ModelCredential::anthropic_api_key("host-secret-b"),
			limits(),
		)
		.await
		.unwrap();
		assert_ne!(session_a.socket_path(), session_b.socket_path());

		let workdir = tempfile::tempdir().unwrap();
		let context = ModelBrokerContext::new(
			"/bin/true".into(),
			upstream.url,
			ModelCredential::anthropic_api_key("unused-host-secret"),
			limits(),
		);
		let sandbox =
			bind_model_into_sandbox(SandboxBuilder::new(workdir.path()), &context, &session_a);
		let output = sandbox
			.build("/bin/sh")
			.args([
				"-c",
				"test -S /loupe/model/session.sock && test ! -e \"$1\"",
				"socket-isolation-check",
			])
			.arg(session_b.socket_path())
			.output()
			.await
			.unwrap();
		assert!(
			output.status.success(),
			"job A sandbox could see job B socket: {}",
			String::from_utf8_lossy(&output.stderr)
		);

		session_a.finish().await.unwrap();
		session_b.finish().await.unwrap();
	}

	#[tokio::test]
	async fn deny_all_baseline_does_not_contact_upstream() {
		let upstream = FakeUpstream::start("{}").await;
		let session = ModelBrokerSession::start(
			claude_backend(),
			upstream.url.clone(),
			ModelCredential::anthropic_api_key("host-secret"),
			limits(),
		)
		.await
		.unwrap();
		let mut client = connect(&session).await;

		for (method, path) in [
			(Method::GET, "/v1/messages"),
			(Method::POST, "/v1/responses"),
			(Method::POST, "/v1/messages?redirect=https://evil.invalid"),
		] {
			let request = HyperRequest::builder()
				.method(method)
				.uri(path)
				.body(Full::new(Bytes::from_static(b"{}")))
				.unwrap();
			let response = client.send_request(request).await.unwrap();
			assert_eq!(response.status(), StatusCode::NOT_FOUND);
			response.into_body().collect().await.unwrap();
		}
		assert!(upstream.captured().await.is_empty());
		session.finish().await.unwrap();
	}

	#[tokio::test]
	async fn claude_connectivity_probe_stays_local() {
		let upstream = FakeUpstream::start("{}").await;
		let session = ModelBrokerSession::start(
			claude_backend(),
			upstream.url.clone(),
			ModelCredential::anthropic_api_key("host-secret"),
			limits(),
		)
		.await
		.unwrap();
		let mut client = connect(&session).await;
		let probe = HyperRequest::builder()
			.method(Method::HEAD)
			.uri("/api/hello")
			.body(Full::new(Bytes::new()))
			.unwrap();

		let response = client.send_request(probe).await.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
		assert!(upstream.captured().await.is_empty());
		assert_eq!(session.usage(), ModelBrokerUsage::default());
		session.finish().await.unwrap();
	}

	#[tokio::test]
	async fn claude_beta_query_is_forwarded() {
		let upstream = FakeUpstream::start("{}").await;
		let session = ModelBrokerSession::start(
			claude_backend(),
			upstream.url.clone(),
			ModelCredential::anthropic_api_key("host-secret"),
			limits(),
		)
		.await
		.unwrap();
		let mut client = connect(&session).await;

		let response = client
			.send_request(request(
				"/v1/messages?beta=true",
				r#"{"model":"claude-test","messages":[],"max_tokens":8}"#,
			))
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
		response.into_body().collect().await.unwrap();
		assert_eq!(upstream.captured().await[0].path, "/v1/messages?beta=true");
		session.finish().await.unwrap();
	}

	#[tokio::test]
	async fn claude_request_is_scoped_rewritten_and_authenticated() {
		let upstream = FakeUpstream::start(r#"{"ok":true}"#).await;
		let session = ModelBrokerSession::start(
			claude_backend(),
			upstream.url.clone(),
			ModelCredential::anthropic_api_key("host-secret"),
			limits(),
		)
		.await
		.unwrap();
		let mut client = connect(&session).await;
		let mut request =
			request("/v1/messages", r#"{"model":"repo-chosen","messages":[],"max_tokens":16}"#);
		request.headers_mut().insert("authorization", "Bearer sandbox-secret".parse().unwrap());
		request.headers_mut().insert("cookie", "session=repo-secret".parse().unwrap());
		request.headers_mut().insert("proxy-authorization", "repo-secret".parse().unwrap());
		request.headers_mut().insert("connection", "close".parse().unwrap());

		let response = client.send_request(request).await.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
		assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), r#"{"ok":true}"#);

		let captured = upstream.captured().await;
		assert_eq!(captured.len(), 1);
		assert_eq!(captured[0].path, "/v1/messages");
		assert_eq!(captured[0].headers.get("x-api-key").unwrap(), "host-secret");
		assert!(!captured[0].headers.contains_key("authorization"));
		assert!(!captured[0].headers.contains_key("cookie"));
		assert!(!captured[0].headers.contains_key("proxy-authorization"));
		assert!(!captured[0].headers.contains_key("connection"));
		let body: serde_json::Value = serde_json::from_slice(&captured[0].body).unwrap();
		assert_eq!(body["model"], "claude-test");
		assert_eq!(body["output_config"]["effort"], "high");
		session.finish().await.unwrap();
	}

	#[tokio::test]
	async fn claude_oauth_uses_host_bearer_authentication() {
		let upstream = FakeUpstream::start("{}").await;
		let session = ModelBrokerSession::start(
			claude_backend(),
			upstream.url.clone(),
			ModelCredential::anthropic_oauth_token("oauth-secret"),
			limits(),
		)
		.await
		.unwrap();
		let mut client = connect(&session).await;
		let response = client
			.send_request(request(
				"/v1/messages",
				r#"{"model":"claude-test","messages":[],"max_tokens":16}"#,
			))
			.await
			.unwrap();
		response.into_body().collect().await.unwrap();

		let captured = upstream.captured().await;
		assert_eq!(captured[0].headers.get("authorization").unwrap(), "Bearer oauth-secret");
		assert!(!captured[0].headers.contains_key("x-api-key"));
		session.finish().await.unwrap();
	}

	#[tokio::test]
	async fn codex_request_is_scoped_and_authenticated() {
		let upstream = FakeUpstream::start(r#"{"ok":true}"#).await;
		let session = ModelBrokerSession::start(
			codex_backend(),
			upstream.url.clone(),
			ModelCredential::openai_api_key("host-secret"),
			limits(),
		)
		.await
		.unwrap();
		let mut client = connect(&session).await;
		let mut request = request("/v1/responses", r#"{"model":"repo-chosen","input":"hello"}"#);
		request.headers_mut().insert("authorization", "Bearer sandbox-sentinel".parse().unwrap());

		let response = client.send_request(request).await.unwrap();
		assert_eq!(response.status(), StatusCode::OK);
		response.into_body().collect().await.unwrap();

		let captured = upstream.captured().await;
		assert_eq!(captured.len(), 1);
		assert_eq!(captured[0].path, "/v1/responses");
		assert_eq!(captured[0].headers.get("authorization").unwrap(), "Bearer host-secret");
		let body: serde_json::Value = serde_json::from_slice(&captured[0].body).unwrap();
		assert_eq!(body["model"], "gpt-test");
		assert_eq!(body["reasoning"]["effort"], "high");
		session.finish().await.unwrap();
	}

	#[tokio::test]
	async fn request_ceiling_returns_429_without_an_upstream_call() {
		let upstream = FakeUpstream::start("{}").await;
		let session = ModelBrokerSession::start(
			codex_backend(),
			upstream.url.clone(),
			ModelCredential::openai_api_key("host-secret"),
			ModelBrokerLimits { request_ceiling: 1, ..limits() },
		)
		.await
		.unwrap();
		let mut client = connect(&session).await;
		for expected in [StatusCode::OK, StatusCode::TOO_MANY_REQUESTS] {
			let response = client
				.send_request(request("/v1/responses", r#"{"model":"gpt-test","input":"hi"}"#))
				.await
				.unwrap();
			assert_eq!(response.status(), expected);
			response.into_body().collect().await.unwrap();
		}
		assert_eq!(upstream.captured().await.len(), 1);
		assert_eq!(session.usage().requests, 1);
		session.finish().await.unwrap();
	}

	#[tokio::test]
	async fn output_ceiling_terminates_an_oversized_stream() {
		let upstream = FakeUpstream::start("0123456789").await;
		let session = ModelBrokerSession::start(
			codex_backend(),
			upstream.url,
			ModelCredential::openai_api_key("host-secret"),
			ModelBrokerLimits { output_ceiling_bytes: 5, ..limits() },
		)
		.await
		.unwrap();
		let mut client = connect(&session).await;
		let mut oversized_request =
			request("/v1/responses", r#"{"model":"gpt-test","input":"hi"}"#);
		oversized_request.headers_mut().insert(TE, HeaderValue::from_static("trailers"));
		let response = client.send_request(oversized_request).await.unwrap();
		let body = response.into_body().collect().await.unwrap();
		let trailer =
			body.trailers().and_then(|trailers| trailers.get(BROKER_ERROR_TRAILER)).cloned();
		assert_eq!(body.to_bytes(), "01234");
		assert_eq!(trailer.unwrap(), "output_ceiling_exceeded");
		assert_eq!(session.usage().output_bytes, 5);
		session.finish().await.unwrap();
	}

	#[tokio::test]
	async fn token_usage_blocks_the_next_request() {
		let upstream = FakeUpstream::start(
			r#"{"usage":{"input_tokens":3,"output_tokens":4,"total_tokens":7}}"#,
		)
		.await;
		let session = ModelBrokerSession::start(
			codex_backend(),
			upstream.url.clone(),
			ModelCredential::openai_api_key("host-secret"),
			ModelBrokerLimits { token_ceiling: Some(7), ..limits() },
		)
		.await
		.unwrap();
		let mut client = connect(&session).await;

		let response = client
			.send_request(request("/v1/responses", r#"{"model":"gpt-test","input":"hi"}"#))
			.await
			.unwrap();
		response.into_body().collect().await.unwrap();
		assert_eq!(session.usage().tokens, 7);

		let response = client
			.send_request(request("/v1/responses", r#"{"model":"gpt-test","input":"again"}"#))
			.await
			.unwrap();
		assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
		response.into_body().collect().await.unwrap();
		assert_eq!(upstream.captured().await.len(), 1);
		session.finish().await.unwrap();
	}

	#[tokio::test]
	async fn tool_policy_rejects_fetch_and_preserves_allowed_request_bytes() {
		for (backend, credential, path, denied_type, allowed_type) in [
			(
				claude_backend(),
				ModelCredential::anthropic_api_key("host-secret"),
				"/v1/messages",
				"web_fetch_20250910",
				"web_search_20250305",
			),
			(
				codex_backend(),
				ModelCredential::openai_api_key("host-secret"),
				"/v1/responses",
				"mcp",
				"web_search_preview",
			),
		] {
			let upstream = FakeUpstream::start("{}").await;
			let session =
				ModelBrokerSession::start(backend, upstream.url.clone(), credential, limits())
					.await
					.unwrap();
			let mut client = connect(&session).await;
			let denied = format!(r#"{{"model":"unused","tools":[{{"type":"{denied_type}"}}]}}"#);
			let response = client.send_request(request(path, denied)).await.unwrap();
			assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
			let body = response.into_body().collect().await.unwrap().to_bytes();
			assert!(String::from_utf8_lossy(&body).contains("tool_policy_denied"));

			let expected_model = match path {
				"/v1/messages" => "claude-test",
				"/v1/responses" => "gpt-test",
				_ => unreachable!(),
			};
			let effort = match path {
				"/v1/messages" => ",\"output_config\":{\"effort\":\"high\"}",
				"/v1/responses" => ",\"reasoning\":{\"effort\":\"high\"}",
				_ => unreachable!(),
			};
			let allowed = format!(
				r#"{{"model":"{expected_model}"{effort},"tools":[{{"type":"{allowed_type}","name":"search"}}]}}"#
			);
			let response = client
				.send_request(request(path, Bytes::copy_from_slice(allowed.as_bytes())))
				.await
				.unwrap();
			assert_eq!(response.status(), StatusCode::OK);
			response.into_body().collect().await.unwrap();

			let captured = upstream.captured().await;
			assert_eq!(captured.len(), 1);
			assert_eq!(captured[0].body.as_ref(), allowed.as_bytes());
			session.finish().await.unwrap();
		}
	}

	#[tokio::test]
	async fn upstream_redirect_cannot_move_host_auth_to_another_origin() {
		let redirect_target = FakeUpstream::start("{}").await;
		let origin = FakeUpstream::start("unused").await;
		let mut headers = HeaderMap::new();
		headers.insert(
			hyper::header::LOCATION,
			HeaderValue::from_str(&format!("{}/stolen", redirect_target.url)).unwrap(),
		);
		origin.respond_with(StatusCode::TEMPORARY_REDIRECT, headers, "redirecting").await;
		let session = ModelBrokerSession::start(
			codex_backend(),
			origin.url.clone(),
			ModelCredential::openai_api_key("host-secret"),
			limits(),
		)
		.await
		.unwrap();
		let mut client = connect(&session).await;

		let response = client
			.send_request(request(
				"/v1/responses",
				r#"{"model":"gpt-test","reasoning":{"effort":"high"},"input":"hi"}"#,
			))
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
		assert!(redirect_target.captured().await.is_empty(), "host auth followed a redirect");
		session.finish().await.unwrap();
	}

	#[tokio::test]
	async fn credential_type_must_match_the_backend() {
		let upstream = FakeUpstream::start("{}").await;
		let error = match ModelBrokerSession::start(
			claude_backend(),
			upstream.url,
			ModelCredential::openai_api_key("wrong-provider-secret"),
			limits(),
		)
		.await
		{
			Ok(_) => panic!("a provider-mismatched credential must be rejected"),
			Err(error) => error,
		};
		assert!(error.to_string().contains("credential"), "unexpected error: {error:#}");
	}
}
