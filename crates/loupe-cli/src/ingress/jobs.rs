use loupe_core::{JobKind, JobState};

use super::*;

#[derive(Deserialize)]
struct RawJob<'a> {
	job_id: i64,
	repo_id: i64,
	#[serde(borrow)]
	kind: &'a RawValue,
	state: JobState,
	incremental: bool,
	#[serde(default, borrow)]
	since_sha: Option<&'a RawValue>,
	#[serde(default, borrow)]
	head_sha: Option<&'a RawValue>,
	#[serde(default)]
	parent_job_id: Option<i64>,
	#[serde(default)]
	target_finding_id: Option<i64>,
	attempts: u32,
	enqueued_at: i64,
	#[serde(default)]
	worker_id: Option<i64>,
	#[serde(default)]
	lease_expires_at: Option<i64>,
	#[serde(default)]
	started_at: Option<i64>,
	#[serde(default)]
	finished_at: Option<i64>,
	#[serde(default, borrow)]
	error: Option<&'a RawValue>,
}
enum ServerKind {
	Scan,
	Verify,
	Survey,
	Drilldown,
	Unknown(BoundedText<JobKindName, Server>),
}
impl ServerKind {
	fn legacy(self) -> JobKind {
		match self {
			Self::Scan => JobKind::Scan,
			Self::Verify => JobKind::Verify,
			Self::Survey => JobKind::Survey,
			Self::Drilldown => JobKind::Drilldown,
			Self::Unknown(s) => JobKind::Unknown(s.expose().to_owned()),
		}
	}
}
fn job_kind(mark: &Mark<'_, Server>, raw: &RawValue) -> Result<ServerKind> {
	let text = kind(mark, raw)?;
	Ok(match text.expose() {
		"scan" => ServerKind::Scan,
		"verify" => ServerKind::Verify,
		"survey" => ServerKind::Survey,
		"drilldown" => ServerKind::Drilldown,
		_ => ServerKind::Unknown(text),
	})
}
fn job_info_legacy(mark: &Mark<'_, Server>, r: RawJob<'_>) -> Result<loupe_proto::JobInfo> {
	Ok(loupe_proto::JobInfo {
		job_id: r.job_id,
		repo_id: r.repo_id,
		kind: job_kind(mark, r.kind)?.legacy(),
		state: r.state,
		incremental: r.incremental,
		since_sha: r.since_sha.map(|t| revision_legacy(mark, t)).transpose()?,
		head_sha: r.head_sha.map(|t| revision_legacy(mark, t)).transpose()?,
		parent_job_id: r.parent_job_id,
		target_finding_id: r.target_finding_id,
		attempts: r.attempts,
		enqueued_at: r.enqueued_at,
		worker_id: r.worker_id,
		lease_expires_at: r.lease_expires_at,
		started_at: r.started_at,
		finished_at: r.finished_at,
		error: r.error.map(|t| diagnostic_legacy(mark, t)).transpose()?,
	})
}
macro_rules! job_decoder {
	($name:ident, $validator:ident) => {
		struct $validator;
		impl Validate<&[u8], Server> for $validator {
			type Output = loupe_proto::JobInfo;
			type Error = anyhow::Error;
			fn validate<'v>(
				self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Server>,
			) -> Result<Self::Output> {
				let raw: RawJob<'_> = serde_json::from_slice(u.get()).map_err(|_| invalid())?;
				job_info_legacy(&mark, raw)
			}
		}
		pub(crate) fn $name(body: Untrusted<Bytes, Server>) -> Result<loupe_proto::JobInfo> {
			body.as_bytes().validate($validator)
		}
	};
}
job_decoder!(get_job_legacy, GetJob);
job_decoder!(retry_job_legacy, RetryJob);
job_decoder!(cancel_job_legacy, CancelJob);
struct ListJobs;
impl Validate<&[u8], Server> for ListJobs {
	type Output = Vec<loupe_proto::JobInfo>;
	type Error = anyhow::Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Server>,
	) -> Result<Self::Output> {
		let raw: Vec<RawJob<'_>> = serde_json::from_slice(u.get()).map_err(|_| invalid())?;
		raw.into_iter().map(|r| job_info_legacy(&mark, r)).collect()
	}
}
pub(crate) fn list_jobs_legacy(
	body: Untrusted<Bytes, Server>,
) -> Result<Vec<loupe_proto::JobInfo>> {
	body.as_bytes().validate(ListJobs)
}
