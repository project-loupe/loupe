use std::marker::PhantomData;

use loupe_provenance::Secret;

use super::*;

#[derive(Deserialize)]
struct RawApp<'a> {
	app_id: u64,
	#[serde(borrow)]
	slug: &'a RawValue,
}
#[derive(Deserialize)]
struct RawAppResponse<'a> {
	protocol_version: u16,
	#[serde(default, borrow)]
	app: Option<RawApp<'a>>,
}
struct ShowGithubApp;
impl Validate<&[u8], Server> for ShowGithubApp {
	type Output = loupe_proto::GithubAppResponse;
	type Error = anyhow::Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Server>,
	) -> Result<Self::Output> {
		let r: RawAppResponse<'_> = serde_json::from_slice(u.get()).map_err(|_| invalid())?;
		Ok(loupe_proto::GithubAppResponse {
			protocol_version: r.protocol_version,
			app: r
				.app
				.map(|a| {
					Ok::<_, anyhow::Error>(loupe_proto::GithubAppSummary {
						app_id: a.app_id,
						slug: slug_legacy(&mark, a.slug)?,
					})
				})
				.transpose()?,
		})
	}
}
pub(crate) fn show_github_app_legacy(
	body: Untrusted<Bytes, Server>,
) -> Result<loupe_proto::GithubAppResponse> {
	#[cfg(fuzzing)]
	entered(Entry::ShowApp);
	body.as_bytes().validate(ShowGithubApp)
}

#[derive(Deserialize)]
struct RawRepo<'a> {
	id: i64,
	#[serde(borrow)]
	clone_url: &'a RawValue,
	#[serde(borrow)]
	host: &'a RawValue,
	#[serde(borrow)]
	owner: &'a RawValue,
	#[serde(borrow)]
	repo: &'a RawValue,
	#[serde(default, borrow)]
	default_branch: Option<&'a RawValue>,
	#[serde(default)]
	scan_interval_seconds: Option<i64>,
	#[serde(default)]
	disabled_at: Option<i64>,
	verification_enabled: bool,
	#[serde(default)]
	require_approval: Option<bool>,
	#[serde(default, borrow)]
	last_scanned_sha: Option<&'a RawValue>,
	#[serde(default)]
	last_scanned_at: Option<i64>,
	created_at: i64,
	#[serde(default, borrow)]
	reporting: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct RawRepos<'a> {
	protocol_version: u16,
	#[serde(borrow)]
	repos: Vec<RawRepo<'a>>,
}
struct ListRepos;
impl Validate<&[u8], Server> for ListRepos {
	type Output = loupe_proto::ListReposResponse;
	type Error = anyhow::Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Server>,
	) -> Result<Self::Output> {
		let r: RawRepos<'_> = serde_json::from_slice(u.get()).map_err(|_| invalid())?;
		let repos = r
			.repos
			.into_iter()
			.map(|r| {
				Ok(loupe_proto::RepoSummary {
					id: r.id,
					clone_url: clone_url_legacy(&mark, r.clone_url)?,
					host: host_legacy(&mark, r.host)?,
					owner: owner_legacy(&mark, r.owner)?,
					repo: repo_legacy(&mark, r.repo)?,
					default_branch: r
						.default_branch
						.map(|t| branch_legacy(&mark, t))
						.transpose()?,
					scan_interval_seconds: r.scan_interval_seconds,
					disabled_at: r.disabled_at,
					verification_enabled: r.verification_enabled,
					require_approval: r.require_approval,
					last_scanned_sha: r
						.last_scanned_sha
						.map(|t| revision_legacy(&mark, t))
						.transpose()?,
					last_scanned_at: r.last_scanned_at,
					created_at: r.created_at,
					// The response envelope, repos array, and RepoSummary consume three
					// structural recursion levels before internally tagged reporting.
					reporting: r
						.reporting
						.map(|t| reporting::reporting_summary_legacy(&mark, t, 3))
						.transpose()?,
				})
			})
			.collect::<Result<_>>()?;
		Ok(loupe_proto::ListReposResponse { protocol_version: r.protocol_version, repos })
	}
}
pub(crate) fn list_repos_legacy(
	body: Untrusted<Bytes, Server>,
) -> Result<loupe_proto::ListReposResponse> {
	#[cfg(fuzzing)]
	entered(Entry::ListRepos);
	body.as_bytes().validate(ListRepos)
}

#[derive(Deserialize)]
struct RawWorker<'a> {
	protocol_version: u16,
	worker_id: i64,
	#[serde(borrow)]
	client_cert_pem: &'a RawValue,
	#[serde(borrow)]
	client_key_pem: &'a RawValue,
	#[serde(borrow)]
	ca_cert_pem: &'a RawValue,
}
struct ServerPem(Secret<String>, PhantomData<Server>);
fn pem(mark: &Mark<'_, Server>, token: &RawValue) -> Result<ServerPem> {
	let _ = mark;
	let text = decode_json_string_bounded(
		token.get(),
		"server_pem",
		loupe_http::MAX_RESPONSE_BYTES,
		loupe_http::MAX_RESPONSE_BYTES,
	)
	.map_err(|_| invalid())?;
	Ok(ServerPem(Secret::new(text.into_owned()), PhantomData))
}
struct WorkerBundle {
	version: u16,
	id: i64,
	cert: ServerPem,
	key: ServerPem,
	ca: ServerPem,
}
struct RegisterWorker;
impl Validate<&[u8], Server> for RegisterWorker {
	type Output = WorkerBundle;
	type Error = anyhow::Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Server>,
	) -> Result<Self::Output> {
		let r: RawWorker<'_> = serde_json::from_slice(u.get()).map_err(|_| invalid())?;
		Ok(WorkerBundle {
			version: r.protocol_version,
			id: r.worker_id,
			cert: pem(&mark, r.client_cert_pem)?,
			key: pem(&mark, r.client_key_pem)?,
			ca: pem(&mark, r.ca_cert_pem)?,
		})
	}
}
pub(crate) fn register_worker_bundle_legacy(
	body: Untrusted<Bytes, Server>,
) -> Result<loupe_proto::RegisterWorkerResponse> {
	#[cfg(fuzzing)]
	entered(Entry::RegisterWorker);
	let r = body.as_bytes().validate(RegisterWorker)?;
	Ok(loupe_proto::RegisterWorkerResponse {
		protocol_version: r.version,
		worker_id: r.id,
		client_cert_pem: r.cert.0.expose().to_owned(),
		client_key_pem: r.key.0,
		ca_cert_pem: r.ca.0,
	})
}
