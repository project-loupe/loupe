//! GitHub App authentication for the issue reporter.
//!
//! A GitHub App authenticates in two steps: the server signs a short-lived
//! JWT with the app's RSA private key, then trades it for an installation
//! access token that is scoped to one repository and expires after an
//! hour. Issues filed with that token are authored by `<app>[bot]` rather
//! than by whoever minted a personal access token. This module owns both
//! steps plus a small in-memory token cache; wiring it into dispatch is
//! the job of `github.rs`.
//!
//! The JWT is hand-rolled on top of `ring` (already in the tree as the
//! rustls crypto provider) for the same reason the reporter avoids
//! `octocrab`: the integration is tiny and not worth a dependency.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use reqwest::{StatusCode, Url};
use ring::rand::SystemRandom;
use ring::signature::{self, RsaKeyPair};
use rustls::pki_types::PrivateKeyDer;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// GitHub rejects JWTs whose `iat` is in the future relative to its own
/// clock; backdating by a minute absorbs ordinary clock skew.
const JWT_BACKDATE_SECS: i64 = 60;
/// GitHub caps app JWT lifetimes at ten minutes; nine keeps a margin.
const JWT_LIFETIME_SECS: i64 = 540;
/// Installation tokens live for an hour. Reusing one for fifty minutes
/// leaves a comfortable margin before GitHub starts rejecting it.
const TOKEN_CACHE_SECS: i64 = 50 * 60;
const ACCEPT: &str = "application/vnd.github+json";
const API_VERSION: &str = "2022-11-28";

/// A GitHub App's identity plus its signing key.
pub struct GithubAppKey {
	app_id: u64,
	key_pair: RsaKeyPair,
}

impl std::fmt::Debug for GithubAppKey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("GithubAppKey").field("app_id", &self.app_id).finish_non_exhaustive()
	}
}

impl GithubAppKey {
	/// Parse the private key GitHub hands out on the app's settings page.
	/// GitHub produces PKCS#1 (`BEGIN RSA PRIVATE KEY`); PKCS#8 (`BEGIN
	/// PRIVATE KEY`) is accepted too for operators who re-encoded it.
	pub fn from_pem(app_id: u64, pem: &str) -> Result<Self> {
		let mut bytes = pem.as_bytes();
		let key = rustls_pemfile::private_key(&mut bytes)
			.map_err(|_| anyhow!("invalid GitHub App private key PEM"))?
			.ok_or_else(|| anyhow!("GitHub App private key PEM contains no private key"))?;
		let key_pair = match key {
			PrivateKeyDer::Pkcs1(der) => RsaKeyPair::from_der(der.secret_pkcs1_der()),
			PrivateKeyDer::Pkcs8(der) => RsaKeyPair::from_pkcs8(der.secret_pkcs8_der()),
			PrivateKeyDer::Sec1(_) => {
				bail!("GitHub App private key must be RSA; found an EC (SEC1) key")
			},
			_ => bail!("GitHub App private key uses an unsupported encoding"),
		}
		.map_err(|e| anyhow!("GitHub App private key is not a usable RSA key: {e}"))?;
		Ok(Self { app_id, key_pair })
	}

	pub fn app_id(&self) -> u64 {
		self.app_id
	}

	/// Sign a compact RS256 JWT that authenticates as the app itself.
	/// `now_unix` is injected so tests can pin the claims.
	pub fn sign_jwt(&self, now_unix: i64) -> Result<String> {
		let header = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
		let claims = serde_json::to_vec(&JwtClaims {
			iat: now_unix - JWT_BACKDATE_SECS,
			exp: now_unix + JWT_LIFETIME_SECS,
			iss: self.app_id.to_string(),
		})
		.context("serialising GitHub App JWT claims")?;
		let signing_input = format!("{header}.{}", b64url(&claims));
		let mut sig = vec![0u8; self.key_pair.public().modulus_len()];
		self.key_pair
			.sign(
				&signature::RSA_PKCS1_SHA256,
				&SystemRandom::new(),
				signing_input.as_bytes(),
				&mut sig,
			)
			.map_err(|_| anyhow!("signing GitHub App JWT"))?;
		Ok(format!("{signing_input}.{}", b64url(&sig)))
	}
}

#[derive(Serialize)]
struct JwtClaims {
	iat: i64,
	exp: i64,
	iss: String,
}

fn b64url(bytes: &[u8]) -> String {
	base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn now_unix() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

/// What `GET /app` reports about the app the key belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GithubAppInfo {
	pub id: u64,
	pub slug: String,
}

/// Fetch the app's own metadata. Doubles as a credential check: a wrong
/// key or app id fails here instead of at the first dispatch.
pub async fn fetch_app(
	http: &reqwest::Client, api_base: &Url, key: &GithubAppKey,
) -> Result<GithubAppInfo> {
	let jwt = key.sign_jwt(now_unix())?;
	let url = api_base.join("/app").map_err(|e| anyhow!("building app URL: {e}"))?;
	let resp =
		github_request(http.get(url), &jwt).send().await.context("fetching GitHub App metadata")?;
	let status = resp.status();
	let body = resp.bytes().await.context("reading GitHub App metadata response")?;
	parse_app_response(status, &body, key.app_id())
}

/// Decode app metadata without reflecting response content into diagnostics.
pub fn parse_app_response(status: StatusCode, body: &[u8], app_id: u64) -> Result<GithubAppInfo> {
	if !status.is_success() {
		bail!("github returned {status} when fetching app {app_id}");
	}
	decode_body(body, "parsing GitHub App metadata")
}

/// Serde errors can quote a provider-controlled string value. Keep those
/// values out of the entire error chain, including alternate Display/Debug.
pub(super) fn decode_body<T: serde::de::DeserializeOwned>(
	body: &[u8], operation: &'static str,
) -> Result<T> {
	serde_json::from_slice(body).map_err(|_| anyhow!("{operation}: invalid response body"))
}

/// Stamp the headers every GitHub API call carries. Shared with the
/// issue reporter so the API version is pinned in exactly one place.
pub(super) fn github_request(
	req: reqwest::RequestBuilder, bearer: &str,
) -> reqwest::RequestBuilder {
	req.bearer_auth(bearer).header("Accept", ACCEPT).header("X-GitHub-Api-Version", API_VERSION)
}

type TokenKey = (u64, String, String);

struct CachedToken {
	token: String,
	expires_at: i64,
}

/// Per-target cache of installation access tokens.
///
/// The lock is held across the mint so concurrent dispatches to the same
/// tracker share one token instead of racing to mint several.
#[derive(Default)]
pub struct InstallationTokens {
	cache: Mutex<HashMap<TokenKey, CachedToken>>,
}

#[derive(Deserialize)]
struct InstallationBody {
	id: u64,
}

#[derive(Serialize)]
struct AccessTokenRequest<'a> {
	repositories: [&'a str; 1],
	permissions: AccessTokenPermissions,
}

#[derive(Serialize)]
struct AccessTokenPermissions {
	issues: &'static str,
}

#[derive(Deserialize)]
struct AccessTokenBody {
	token: String,
}

impl InstallationTokens {
	/// Return a token that can file issues on `owner/repo`, minting one if
	/// the cached token is missing or about to expire.
	pub async fn token_for(
		&self, http: &reqwest::Client, api_base: &Url, key: &GithubAppKey, owner: &str, repo: &str,
	) -> Result<String> {
		let now = now_unix();
		let cache_key = (key.app_id(), owner.to_owned(), repo.to_owned());
		let mut cache = self.cache.lock().await;
		if let Some(cached) = cache.get(&cache_key)
			&& cached.expires_at > now
		{
			return Ok(cached.token.clone());
		}
		let jwt = key.sign_jwt(now)?;
		let installation_id = lookup_installation(http, api_base, &jwt, owner, repo).await?;
		let token = mint_token(http, api_base, &jwt, installation_id, repo).await?;
		cache.insert(
			cache_key,
			CachedToken { token: token.clone(), expires_at: now + TOKEN_CACHE_SECS },
		);
		Ok(token)
	}

	/// Forget the cached token for one target so the next `token_for`
	/// mints again. Called when GitHub answers 401 to a token that has
	/// not reached its cached expiry — revoked, or expired early.
	pub async fn invalidate(&self, app_id: u64, owner: &str, repo: &str) {
		self.cache.lock().await.remove(&(app_id, owner.to_owned(), repo.to_owned()));
	}
}

async fn lookup_installation(
	http: &reqwest::Client, api_base: &Url, jwt: &str, owner: &str, repo: &str,
) -> Result<u64> {
	let url = api_base
		.join(&format!("/repos/{owner}/{repo}/installation"))
		.map_err(|e| anyhow!("building installation URL: {e}"))?;
	let resp = github_request(http.get(url), jwt)
		.send()
		.await
		.with_context(|| format!("looking up the GitHub App installation for {owner}/{repo}"))?;
	let status = resp.status();
	let body = resp.bytes().await.context("reading installation response")?;
	parse_installation_response(status, &body, owner, repo)
}

/// Decode an installation lookup; owner/repo are configured request metadata.
pub fn parse_installation_response(
	status: StatusCode, body: &[u8], owner: &str, repo: &str,
) -> Result<u64> {
	if status == StatusCode::NOT_FOUND {
		bail!(
			"the GitHub App is not installed on {owner}/{repo}; add the repository to the \
			 app's installation or report with a PAT instead"
		);
	}
	if !status.is_success() {
		bail!("github returned {status} when looking up the installation for {owner}/{repo}");
	}
	let body: InstallationBody = decode_body(body, "parsing installation response")?;
	Ok(body.id)
}

async fn mint_token(
	http: &reqwest::Client, api_base: &Url, jwt: &str, installation_id: u64, repo: &str,
) -> Result<String> {
	let url = api_base
		.join(&format!("/app/installations/{installation_id}/access_tokens"))
		.map_err(|e| anyhow!("building access token URL: {e}"))?;
	let resp = github_request(http.post(url), jwt)
		.json(&AccessTokenRequest {
			repositories: [repo],
			permissions: AccessTokenPermissions { issues: "write" },
		})
		.send()
		.await
		.context("minting GitHub App installation token")?;
	let status = resp.status();
	let body = resp.bytes().await.context("reading installation token response")?;
	parse_access_token_response(status, &body, installation_id)
}

/// Decode an installation token; response bodies never become error text.
pub fn parse_access_token_response(
	status: StatusCode, body: &[u8], installation_id: u64,
) -> Result<String> {
	if !status.is_success() {
		bail!(
			"github returned {status} when minting an installation token for installation \
			 {installation_id}"
		);
	}
	let body: AccessTokenBody = decode_body(body, "parsing installation token")?;
	Ok(body.token)
}

/// Throwaway RSA key for tests. Lives outside `#[cfg(test)]`, like
/// `MasterKey::for_tests`, so integration tests in `tests/` can exercise
/// the credential routes without shipping a PEM fixture file.
#[doc(hidden)]
pub mod testing {
	/// 2048-bit PKCS#1 key generated with `openssl genrsa -traditional`.
	/// It has never been registered with any GitHub App.
	pub const APP_PRIVATE_KEY_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAjS8lZnnI1OtXYlfESriFOfXR2Y+wSyrKB25JcAA1NqyFACXa
lRItI5tzZAV0OYxWctBKgQ7soiPkWA1n4MgXjDDgNjWUve+A+oVGG2MzkUkhHTyt
xSXCkXJPHVkFrBSzHpYfCftBc7/Ji8UgMTVo8eUfUZUO5M8ocIc+YtOgAOwNG3t3
Kd/NUtLnPOy1ch5wUpNy6WI+JbeYv0iUF5UGlJ2T9OLUksJ4KikfReT6YuQc0CDJ
WpU5v6i0bpU7TN69d9Pg64lHVNZZrcI1LKNGr0HIL9DYITJS08ll38H3UCwoUT/0
HNcTpkZrA6AOCzvtfzykIaNYgyeQ6Fa9J6VZqwIDAQABAoIBADCJq97+MXhZ7HHn
4JkbtNnHVDzqtF4zOL+zP9YcjC7ewt7ZJLupQxGByPrzERET2UihqWuTOPFJS6Cm
Azd5MvdEemDIrPlblMkL9p1Fzp29OYA2szsbDzg3x1E8oMGXYDk8vTEOS2NC5USD
Id0pEopPDiRbDYLGYY3GQUFypgiKnAFUjusbvYoa3ul75bBGY0YxdN04CGr6XZTp
8DixpBOPYqo2dgJDsZ7N0gZMLMnoC5DjYlf1CQo+RIy9zJFHcRqIVhMFGL34abN4
QU4Iqx9PkB15A2IzWeIzNkX41jTRu9Unf4ckBd6ffmBeMIonfmhK9xRGsrPoLW9P
jwpTdvECgYEAv7+7c0iy6RFB1m6Z1iv9HjEmEieXDkhhvOovM/BYfCVaxofyq0QS
CwT2c7Dj+cMFDqKt1r4qTO4WCXrBbhnwu/KKHv8RBEkzswi88ZUhumc2PhPCh8MZ
81RV17w6MPHhJGv7ITlx/Qy9ivvOZ7OI/oLJTlfPEk4PDwMZ4+i9RvMCgYEAvH30
e4ycZ0wYPZpPYczQ3ul7tHcoNnorUu1ROAmsfo8UvOMI3C81RgrmpfHxnf0tz+/D
vbpRh9/XGq0VMsxUYrw69+9pHm+Y+WKKkShigT/BGfQjqj1RiPDMgQCIpdHbnRHT
zAeWnZvHveORPSu9D+p+f/Y8IrpdCjOIvl0/wGkCgYEAkn7TodJLDhGnMUKyuZRG
AAkgwwIIQFtAgOqSQaZAlCid38wBtKN+/Xg/KkhdBHbgqDvVgJktDDViFL/6hDnB
WHaG3AOXZqTeoMvuPsvnRtiP8oF6P+rpKqSmKPqfosFJd2AgL1QKKIDRVxvmqAfc
hEY7smUXyS5mBtwhraQk580CgYB7o3L2h6kf6L4NymY/lIV9clF+cpqiAUjhwGEC
DPZknZ3QuGtbYmvjYcshFq6SHzwppPAUR16rbZw/F0FMbNL9YNKdRyEAodsJ2iVi
ScczWIplZ8rtJAOTe7/o7lyzyA/x23u93UxiXYiLefYO1d3RztLjRLT1YqEcy+jq
VWg34QKBgATihXITIvJgiLjKHVH3dznvtZqCshfispjirFAu3aqlMnEE8HJuonWT
8+rgQyukpI2hZ8VQVhrLR4fnvnrc0T/YVG4Y6N8fMNapsDKAgauFxC1iGjQxAs7G
0in1Mf0bmBQe0cFVZAvpr7jm0R0PDxLqhf/nay8vU1MuiQcRgEJd
-----END RSA PRIVATE KEY-----
";
}

#[cfg(test)]
mod tests {
	use std::net::SocketAddr;
	use std::sync::{Arc, Mutex as StdMutex};

	use axum::extract::{Path, State};
	use axum::http::{HeaderMap, StatusCode};
	use axum::routing::{get, post};
	use axum::{Json, Router};

	use super::testing::APP_PRIVATE_KEY_PEM;
	use super::*;

	/// The same key as `APP_PRIVATE_KEY_PEM`, re-encoded with
	/// `openssl pkcs8 -topk8 -nocrypt`.
	const APP_PRIVATE_KEY_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCNLyVmecjU61di
V8RKuIU59dHZj7BLKsoHbklwADU2rIUAJdqVEi0jm3NkBXQ5jFZy0EqBDuyiI+RY
DWfgyBeMMOA2NZS974D6hUYbYzORSSEdPK3FJcKRck8dWQWsFLMelh8J+0Fzv8mL
xSAxNWjx5R9RlQ7kzyhwhz5i06AA7A0be3cp381S0uc87LVyHnBSk3LpYj4lt5i/
SJQXlQaUnZP04tSSwngqKR9F5Ppi5BzQIMlalTm/qLRulTtM3r130+DriUdU1lmt
wjUso0avQcgv0NghMlLTyWXfwfdQLChRP/Qc1xOmRmsDoA4LO+1/PKQho1iDJ5Do
Vr0npVmrAgMBAAECggEAMImr3v4xeFnscefgmRu02cdUPOq0XjM4v7M/1hyMLt7C
3tkku6lDEYHI+vMRERPZSKGpa5M48UlLoKYDN3ky90R6YMis+VuUyQv2nUXOnb05
gDazOxsPODfHUTygwZdgOTy9MQ5LY0LlRIMh3SkSik8OJFsNgsZhjcZBQXKmCIqc
AVSO6xu9ihre6XvlsEZjRjF03TgIavpdlOnwOLGkE49iqjZ2AkOxns3SBkwsyegL
kONiV/UJCj5EjL3MkUdxGohWEwUYvfhps3hBTgirH0+QHXkDYjNZ4jM2RfjWNNG7
1Sd/hyQF3p9+YF4wiid+aEr3FEays+gtb0+PClN28QKBgQC/v7tzSLLpEUHWbpnW
K/0eMSYSJ5cOSGG86i8z8Fh8JVrGh/KrRBILBPZzsOP5wwUOoq3WvipM7hYJesFu
GfC78ooe/xEESTOzCLzxlSG6ZzY+E8KHwxnzVFXXvDow8eEka/shOXH9DL2K+85n
s4j+gslOV88STg8PAxnj6L1G8wKBgQC8ffR7jJxnTBg9mk9hzNDe6Xu0dyg2eitS
7VE4Cax+jxS84wjcLzVGCual8fGd/S3P78O9ulGH39carRUyzFRivDr372keb5j5
YoqRKGKBP8EZ9COqPVGI8MyBAIil0dudEdPMB5adm8e945E9K70P6n5/9jwiul0K
M4i+XT/AaQKBgQCSftOh0ksOEacxQrK5lEYACSDDAghAW0CA6pJBpkCUKJ3fzAG0
o379eD8qSF0EduCoO9WAmS0MNWIUv/qEOcFYdobcA5dmpN6gy+4+y+dG2I/ygXo/
6ukqpKYo+p+iwUl3YCAvVAoogNFXG+aoB9yERjuyZRfJLmYG3CGtpCTnzQKBgHuj
cvaHqR/ovg3KZj+UhX1yUX5ymqIBSOHAYQIM9mSdndC4a1tia+NhyyEWrpIfPCmk
8BRHXqttnD8XQUxs0v1g0p1HIQCh2wnaJWJJxzNYimVnyu0kA5N7v+juXLPID/Hb
e73dTGJdiIt59g7V3dHO0uNEtPVioRzL6OpVaDfhAoGABOKFchMi8mCIuModUfd3
Oe+1moKyF+KymOKsUC7dqqUycQTwcm6idZPz6uBDK6SkjaFnxVBWGstHh+e+etzR
P9hUbhjo3x8w1qmwMoCBq4XELWIaNDECzsbSKfUx/RuYFB7RwVVkC+mvuObRHQ8P
EuqF/+drLy9TUy6JBxGAQl0=
-----END PRIVATE KEY-----
";

	const EC_KEY_PEM: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIC2KTipJAMGNjADhbHo8gybmNqSNy7QZ+1yWxspqSx+MoAoGCCqGSM49
AwEHoUQDQgAEp/ggLgnjHH5bEGf3Te7Dik9oTPB/BCrHDJvuHISRK51SG8eRPdrH
VDqD0pzLw2aWYKoIWhPBO3MRWlrcq6SnRQ==
-----END EC PRIVATE KEY-----
";

	fn b64url_decode(s: &str) -> Vec<u8> {
		base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).expect("base64url")
	}

	#[test]
	fn parses_pkcs1_and_pkcs8_encodings_of_the_same_key() {
		let pkcs1 = GithubAppKey::from_pem(42, APP_PRIVATE_KEY_PEM).unwrap();
		let pkcs8 = GithubAppKey::from_pem(42, APP_PRIVATE_KEY_PKCS8_PEM).unwrap();
		assert_eq!(pkcs1.app_id(), 42);
		assert_eq!(pkcs1.key_pair.public().as_ref(), pkcs8.key_pair.public().as_ref());
	}

	#[test]
	fn rejects_keys_that_are_not_rsa() {
		let err = GithubAppKey::from_pem(1, EC_KEY_PEM).unwrap_err().to_string();
		assert!(err.contains("must be RSA"), "error: {err}");
		let err = GithubAppKey::from_pem(1, "not a pem at all").unwrap_err().to_string();
		assert!(err.contains("contains no private key"), "error: {err}");
	}

	#[test]
	fn credential_malformed_private_pem_errors_do_not_reflect_bytes() {
		let pem = "-----BEGIN FAKE_PRIVATE_PEM_SENTINEL\n";
		let error = GithubAppKey::from_pem(42, pem).unwrap_err();
		for formatted in [format!("{error}"), format!("{error:#}"), format!("{error:?}")] {
			assert!(
				!formatted.contains("FAKE_PRIVATE_PEM_SENTINEL"),
				"private-key parser errors must not reflect private PEM bytes"
			);
		}
	}

	#[test]
	fn jwt_is_rs256_with_app_claims_and_verifies_against_the_public_key() {
		let key = GithubAppKey::from_pem(42, APP_PRIVATE_KEY_PEM).unwrap();
		let jwt = key.sign_jwt(1_000_000).unwrap();
		let parts: Vec<&str> = jwt.split('.').collect();
		assert_eq!(parts.len(), 3, "jwt: {jwt}");

		let header: serde_json::Value = serde_json::from_slice(&b64url_decode(parts[0])).unwrap();
		assert_eq!(header, serde_json::json!({"alg": "RS256", "typ": "JWT"}));
		let claims: serde_json::Value = serde_json::from_slice(&b64url_decode(parts[1])).unwrap();
		assert_eq!(claims["iat"], 1_000_000 - JWT_BACKDATE_SECS);
		assert_eq!(claims["exp"], 1_000_000 + JWT_LIFETIME_SECS);
		assert_eq!(claims["iss"], "42");

		let public = signature::UnparsedPublicKey::new(
			&signature::RSA_PKCS1_2048_8192_SHA256,
			key.key_pair.public().as_ref(),
		);
		let signing_input = format!("{}.{}", parts[0], parts[1]);
		public.verify(signing_input.as_bytes(), &b64url_decode(parts[2])).expect("signature");
		public.verify(b"tampered", &b64url_decode(parts[2])).expect_err("tampered input");
	}

	#[derive(Clone, Default)]
	struct Stub {
		installation_lookups: Arc<StdMutex<Vec<(String, String, String)>>>,
		token_mints: Arc<StdMutex<Vec<(u64, String, serde_json::Value)>>>,
		installed: Arc<StdMutex<HashMap<String, u64>>>,
	}

	fn bearer(headers: &HeaderMap) -> String {
		headers
			.get(axum::http::header::AUTHORIZATION)
			.and_then(|v| v.to_str().ok())
			.and_then(|v| v.strip_prefix("Bearer "))
			.unwrap_or("")
			.to_owned()
	}

	async fn stub_installation(
		State(stub): State<Stub>, Path((owner, repo)): Path<(String, String)>, headers: HeaderMap,
	) -> (StatusCode, Json<serde_json::Value>) {
		stub.installation_lookups.lock().unwrap().push((
			owner.clone(),
			repo.clone(),
			bearer(&headers),
		));
		match stub.installed.lock().unwrap().get(&format!("{owner}/{repo}")) {
			Some(id) => (StatusCode::OK, Json(serde_json::json!({"id": id}))),
			None => (StatusCode::NOT_FOUND, Json(serde_json::json!({"message": "Not Found"}))),
		}
	}

	async fn stub_access_token(
		State(stub): State<Stub>, Path(id): Path<u64>, headers: HeaderMap,
		Json(body): Json<serde_json::Value>,
	) -> (StatusCode, Json<serde_json::Value>) {
		let n = {
			let mut mints = stub.token_mints.lock().unwrap();
			mints.push((id, bearer(&headers), body));
			mints.len()
		};
		(
			StatusCode::CREATED,
			Json(serde_json::json!({
				"token": format!("ghs_stub_{id}_{n}"),
				"expires_at": "2099-01-01T00:00:00Z",
			})),
		)
	}

	async fn spawn_stub() -> (SocketAddr, Stub) {
		let stub = Stub::default();
		let app = Router::new()
			.route("/repos/{owner}/{repo}/installation", get(stub_installation))
			.route("/app/installations/{id}/access_tokens", post(stub_access_token))
			.with_state(stub.clone());
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr = listener.local_addr().unwrap();
		tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
		(addr, stub)
	}

	#[tokio::test]
	async fn token_for_mints_once_per_target_with_a_restricted_scope() {
		let (addr, stub) = spawn_stub().await;
		stub.installed.lock().unwrap().insert("acme/tracker".into(), 777);
		let api_base: Url = format!("http://{addr}").parse().unwrap();
		let http = reqwest::Client::new();
		let key = GithubAppKey::from_pem(42, APP_PRIVATE_KEY_PEM).unwrap();
		let tokens = InstallationTokens::default();

		let first = tokens.token_for(&http, &api_base, &key, "acme", "tracker").await.unwrap();
		let second = tokens.token_for(&http, &api_base, &key, "acme", "tracker").await.unwrap();
		assert_eq!(first, "ghs_stub_777_1");
		assert_eq!(second, first, "second call must come from the cache");

		let lookups = stub.installation_lookups.lock().unwrap().clone();
		assert_eq!(lookups.len(), 1, "lookups: {lookups:?}");
		assert_eq!((lookups[0].0.as_str(), lookups[0].1.as_str()), ("acme", "tracker"));
		assert_eq!(lookups[0].2.split('.').count(), 3, "lookup must carry the app JWT");

		let mints = stub.token_mints.lock().unwrap().clone();
		assert_eq!(mints.len(), 1, "mints: {mints:?}");
		assert_eq!(mints[0].0, 777);
		assert_eq!(mints[0].1, lookups[0].2, "mint must reuse the same JWT");
		assert_eq!(
			mints[0].2,
			serde_json::json!({"repositories": ["tracker"], "permissions": {"issues": "write"}})
		);
	}

	#[tokio::test]
	async fn token_for_explains_a_missing_installation() {
		let (addr, _stub) = spawn_stub().await;
		let api_base: Url = format!("http://{addr}").parse().unwrap();
		let http = reqwest::Client::new();
		let key = GithubAppKey::from_pem(42, APP_PRIVATE_KEY_PEM).unwrap();
		let tokens = InstallationTokens::default();

		let err = tokens
			.token_for(&http, &api_base, &key, "acme", "elsewhere")
			.await
			.unwrap_err()
			.to_string();
		assert!(err.contains("not installed on acme/elsewhere"), "error: {err}");
	}

	#[tokio::test]
	async fn invalidate_forces_the_next_token_for_to_mint_again() {
		let (addr, stub) = spawn_stub().await;
		stub.installed.lock().unwrap().insert("acme/tracker".into(), 777);
		let api_base: Url = format!("http://{addr}").parse().unwrap();
		let http = reqwest::Client::new();
		let key = GithubAppKey::from_pem(42, APP_PRIVATE_KEY_PEM).unwrap();
		let tokens = InstallationTokens::default();

		let first = tokens.token_for(&http, &api_base, &key, "acme", "tracker").await.unwrap();
		assert_eq!(first, "ghs_stub_777_1");

		// Dropping a token for another target must not touch this one.
		tokens.invalidate(42, "acme", "elsewhere").await;
		tokens.invalidate(7, "acme", "tracker").await;
		let cached = tokens.token_for(&http, &api_base, &key, "acme", "tracker").await.unwrap();
		assert_eq!(cached, first, "unrelated invalidations must keep the cached token");

		tokens.invalidate(42, "acme", "tracker").await;
		let fresh = tokens.token_for(&http, &api_base, &key, "acme", "tracker").await.unwrap();
		assert_eq!(fresh, "ghs_stub_777_2", "an invalidated token must be minted anew");
		assert_eq!(stub.token_mints.lock().unwrap().len(), 2);
	}
}
