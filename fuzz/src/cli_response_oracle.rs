//! Wire-schema oracle with independent field policy and exact output checks.
use loupe_cli::fuzz_support::{Field, FieldObservation, FieldSource, ResponseCase, ResponseValue};

use crate::cli_common::{exact, path};

pub enum LegacyValue {
	App(wire::GithubAppResponse),
	Repo(loupe_proto::RegisterRepoResponse),
	Repos(wire::ListReposResponse),
	Scan(loupe_proto::ScanResponse),
	Worker(loupe_proto::RegisterWorkerResponse),
	Jobs(Vec<wire::JobInfo>),
	Job(wire::JobInfo),
	Findings(wire::ListFindingsResponse),
	Finding(wire::FindingDetail),
	Verification(loupe_proto::RetryVerifyResponse),
	Discard,
}

pub fn legacy(case: ResponseCase, raw: &[u8]) -> serde_json::Result<LegacyValue> {
	use LegacyValue as V;
	use ResponseCase as C;
	match case {
		C::ShowApp => serde_json::from_slice(raw).map(V::App),
		C::RegisterRepo => serde_json::from_slice(raw).map(V::Repo),
		C::ListRepos => serde_json::from_slice(raw).map(V::Repos),
		C::ScanRepo => serde_json::from_slice(raw).map(V::Scan),
		C::RegisterWorker => serde_json::from_slice(raw).map(V::Worker),
		C::ListJobs => serde_json::from_slice(raw).map(V::Jobs),
		C::GetJob | C::RetryJob | C::CancelJob => serde_json::from_slice(raw).map(V::Job),
		C::ListFindings | C::SearchFindings => serde_json::from_slice(raw).map(V::Findings),
		C::GetFinding => serde_json::from_slice(raw).map(V::Finding),
		C::RetryVerification => serde_json::from_slice(raw).map(V::Verification),
		C::DiscardSuccess => Ok(V::Discard),
	}
}
fn optional(value: &Option<String>, multiline: bool) -> bool {
	value.as_ref().is_none_or(|s| exact(s, multiline))
}
fn job(j: &wire::JobInfo) -> bool {
	exact(j.kind.as_str(), false)
		&& optional(&j.since_sha, false)
		&& optional(&j.head_sha, false)
		&& optional(&j.error, true)
}
fn summary(s: &wire::FindingSummary) -> bool {
	exact(&s.scanner_id, false)
		&& exact(&s.title, false)
		&& exact(&s.fingerprint, false)
		&& s.file_path.as_ref().is_none_or(|s| path(s))
		&& optional(&s.approved_by_cn, false)
		&& optional(&s.rejected_by_cn, false)
}
pub fn policies(value: &LegacyValue) -> bool {
	use LegacyValue as V;
	match value {
		V::App(a) => a.app.as_ref().is_none_or(|a| exact(&a.slug, false)),
		V::Repos(r) => r.repos.iter().all(|r| {
			[&r.clone_url, &r.host, &r.owner, &r.repo].into_iter().all(|s| exact(s, false))
				&& optional(&r.default_branch, false)
				&& optional(&r.last_scanned_sha, false)
				&& r.reporting.as_ref().is_none_or(|r| match r {
					wire::ReportingSummary::GithubIssue { target_owner, target_repo, .. } => {
						exact(target_owner, false) && exact(target_repo, false)
					},
					wire::ReportingSummary::Email { to, from, subject_prefix } => {
						to.iter().all(|s| exact(s, false))
							&& optional(from, false)
							&& optional(subject_prefix, false)
					},
					wire::ReportingSummary::Manual => true,
				})
		}),
		V::Jobs(jobs) => jobs.iter().all(job),
		V::Job(j) => job(j),
		V::Findings(f) => f.findings.iter().all(summary),
		V::Finding(f) => {
			[&f.scanner_id, &f.title, &f.fingerprint].into_iter().all(|s| exact(s, false))
				&& exact(&f.description, true)
				&& f.file_path.as_ref().is_none_or(|s| path(s))
				&& optional(&f.cwe, false)
				&& optional(&f.patch_unified, true)
				&& optional(&f.poc_unified, true)
				&& optional(&f.approved_by_cn, false)
				&& optional(&f.rejected_by_cn, false)
		},
		V::Repo(_) | V::Scan(_) | V::Worker(_) | V::Verification(_) | V::Discard => true,
	}
}
pub fn compare(expected: LegacyValue, actual: ResponseValue) {
	use LegacyValue as V;
	use ResponseValue as A;
	fn same(a: impl serde::Serialize, b: impl serde::Serialize) {
		assert_eq!(
			serde_json::to_value(a).unwrap_or_else(|e| panic!("legacy value: {e}")),
			serde_json::to_value(b).unwrap_or_else(|e| panic!("typed value: {e}")),
			"typed response changed an admitted historical field"
		);
	}
	match (expected, actual) {
		(V::App(a), A::App(b)) => same(a, b),
		(V::Repo(a), A::Repo(b)) => assert_eq!(a, b),
		(V::Repos(a), A::Repos(b)) => same(a, b),
		(V::Scan(a), A::Scan(b)) => assert_eq!(a, b),
		(V::Jobs(a), A::Jobs(b)) => same(a, b),
		(V::Job(a), A::Job(b)) => same(a, b),
		(V::Findings(a), A::Findings(b)) => same(a, b),
		(V::Finding(a), A::Finding(b)) => same(a, b),
		(V::Verification(a), A::Verification(b)) => assert_eq!(a, b),
		(V::Discard, A::Discard) => {},
		(V::Worker(a), A::Worker(b)) => {
			assert_eq!(a.protocol_version, b.protocol_version);
			assert_eq!(a.worker_id, b.worker_id);
			assert_eq!(a.client_cert_pem, b.client_cert_pem);
			assert_eq!(a.client_key_pem.expose(), b.client_key_pem.expose());
			assert_eq!(a.ca_cert_pem.expose(), b.ca_cert_pem.expose());
			for rendered in [
				format!("{:?}", b.client_key_pem),
				format!("{:#?}", b.client_key_pem),
				format!("{}", b.client_key_pem),
				format!("{:?}", b.ca_cert_pem),
			] {
				assert_eq!(rendered, "[redacted]")
			}
			let encoded = b.credential_json().unwrap_or_else(|e| panic!("credential encoder: {e}"));
			let value: serde_json::Value = serde_json::from_slice(encoded.expose())
				.unwrap_or_else(|e| panic!("encoded JSON: {e}"));
			assert_eq!(
				value,
				serde_json::json!({"protocol_version":a.protocol_version,"worker_id":a.worker_id,"client_cert_pem":a.client_cert_pem,"client_key_pem":a.client_key_pem.expose(),"ca_cert_pem":a.ca_cert_pem.expose()})
			);
		},
		_ => panic!("response selector returned the wrong output variant"),
	}
}
pub fn typed_fields(value: &LegacyValue) -> Vec<FieldObservation> {
	fn add(out: &mut Vec<FieldObservation>, field: Field, text: &str) {
		let source = if matches!(field, Field::ApprovedBy | Field::RejectedBy) {
			FieldSource::Server
		} else {
			FieldSource::Agent
		};
		out.push(FieldObservation { field, source, text: text.to_owned() });
	}
	fn summary(out: &mut Vec<FieldObservation>, s: &wire::FindingSummary) {
		add(out, Field::Scanner, &s.scanner_id);
		add(out, Field::Title, &s.title);
		add(out, Field::Fingerprint, &s.fingerprint);
		for (field, text) in [
			(Field::Path, &s.file_path),
			(Field::ApprovedBy, &s.approved_by_cn),
			(Field::RejectedBy, &s.rejected_by_cn),
		] {
			if let Some(text) = text {
				add(out, field, text)
			}
		}
	}
	let mut out = Vec::new();
	match value {
		LegacyValue::Findings(list) => {
			for s in &list.findings {
				summary(&mut out, s)
			}
		},
		LegacyValue::Finding(d) => {
			add(&mut out, Field::Scanner, &d.scanner_id);
			add(&mut out, Field::Title, &d.title);
			add(&mut out, Field::Fingerprint, &d.fingerprint);
			add(&mut out, Field::Description, &d.description);
			for (field, text) in [
				(Field::Path, &d.file_path),
				(Field::ApprovedBy, &d.approved_by_cn),
				(Field::RejectedBy, &d.rejected_by_cn),
				(Field::Cwe, &d.cwe),
				(Field::Patch, &d.patch_unified),
				(Field::Poc, &d.poc_unified),
			] {
				if let Some(text) = text {
					add(&mut out, field, text)
				}
			}
		},
		_ => {},
	}
	out.sort();
	out
}

// Independent wire shapes pin fields, serde defaults/omissions and field order.
// JobKind uses String here so schema admission stays separate from the
// exact-text predicate and the production decoder.
pub(crate) mod wire {
	use loupe_core::{FindingState, JobState, Severity};
	use loupe_proto::GithubReportingAuth;
	use serde::{Deserialize, Serialize};
	#[derive(Debug, Serialize, Deserialize)]
	pub struct GithubAppSummary {
		pub app_id: u64,
		pub slug: String,
	}
	#[derive(Debug, Serialize, Deserialize)]
	pub struct GithubAppResponse {
		pub protocol_version: u16,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub app: Option<GithubAppSummary>,
	}
	#[derive(Debug, Serialize, Deserialize)]
	pub struct ListReposResponse {
		pub protocol_version: u16,
		pub repos: Vec<RepoSummary>,
	}
	#[derive(Debug, Serialize, Deserialize)]
	pub struct RepoSummary {
		pub id: i64,
		pub clone_url: String,
		pub host: String,
		pub owner: String,
		pub repo: String,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub default_branch: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub scan_interval_seconds: Option<i64>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub disabled_at: Option<i64>,
		pub verification_enabled: bool,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub require_approval: Option<bool>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub last_scanned_sha: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub last_scanned_at: Option<i64>,
		pub created_at: i64,
		/// Reporter configuration without secrets. Optional because servers
		/// may omit this field.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub reporting: Option<ReportingSummary>,
	}
	#[derive(Debug, Serialize, Deserialize)]
	#[serde(tag = "kind", rename_all = "snake_case")]
	pub enum ReportingSummary {
		GithubIssue {
			target_owner: String,
			target_repo: String,
			#[serde(default)]
			auth: GithubReportingAuth,
		},
		Email {
			to: Vec<String>,
			#[serde(default, skip_serializing_if = "Option::is_none")]
			from: Option<String>,
			#[serde(default, skip_serializing_if = "Option::is_none")]
			subject_prefix: Option<String>,
		},
		Manual,
	}
	#[derive(Debug, Serialize, Deserialize)]
	pub struct JobInfo {
		pub job_id: i64,
		pub repo_id: i64,
		pub kind: String,
		pub state: JobState,
		pub incremental: bool,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub since_sha: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub head_sha: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub parent_job_id: Option<i64>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub target_finding_id: Option<i64>,
		pub attempts: u32,
		pub enqueued_at: i64,
		/// Worker that holds the lease, or last held it. `None` while the job
		/// has never been leased; the reaper and a retry both clear it.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub worker_id: Option<i64>,
		/// When the current lease lapses. Only meaningful while `state` is
		/// `leased` — a countdown against it is how a UI spots a stalled
		/// worker before the reaper gets to it.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub lease_expires_at: Option<i64>,
		/// When the job was first leased. Paired with `finished_at` this
		/// gives the run duration.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub started_at: Option<i64>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub finished_at: Option<i64>,
		/// Why a `failed` or `cancelled` job ended that way.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub error: Option<String>,
	}
	#[derive(Debug, Serialize, Deserialize)]
	pub struct ListFindingsResponse {
		pub protocol_version: u16,
		pub findings: Vec<FindingSummary>,
	}
	#[derive(Debug, Serialize, Deserialize)]
	pub struct FindingSummary {
		pub id: i64,
		pub repo_id: i64,
		pub job_id: i64,
		pub scanner_id: String,
		pub severity: Severity,
		pub title: String,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub file_path: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub line_start: Option<u32>,
		pub fingerprint: String,
		pub state: FindingState,
		pub verification_required: bool,
		pub created_at: i64,
		/// Approval audit trail. Populated when an admin runs
		/// `loupectl finding approve` on a finding parked in
		/// `awaiting_approval`.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub approved_at: Option<i64>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub approved_by_cn: Option<String>,
		/// Rejection audit trail. Populated when an admin runs
		/// `loupectl finding reject` on a finding parked in
		/// `awaiting_approval`. Distinct from a verifier-issued dismiss
		/// (those leave `rejected_*` NULL).
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub rejected_at: Option<i64>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub rejected_by_cn: Option<String>,
	}
	#[derive(Debug, Serialize, Deserialize)]
	pub struct FindingDetail {
		pub protocol_version: u16,
		pub id: i64,
		pub repo_id: i64,
		pub job_id: i64,
		pub scanner_id: String,
		pub severity: Severity,
		pub title: String,
		pub description: String,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub file_path: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub line_start: Option<u32>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub line_end: Option<u32>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub cwe: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub patch_unified: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub poc_unified: Option<String>,
		pub fingerprint: String,
		pub state: FindingState,
		pub verification_required: bool,
		pub created_at: i64,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub approved_at: Option<i64>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub approved_by_cn: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub rejected_at: Option<i64>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub rejected_by_cn: Option<String>,
	}
	#[derive(Debug, Serialize, Deserialize)]
	pub struct Finding {
		pub scanner_id: String,
		pub severity: Severity,
		pub title: String,
		pub description: String,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub file_path: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub line_start: Option<u32>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub line_end: Option<u32>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub cwe: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub patch_unified: Option<String>,
		/// Unified diff that adds a regression test demonstrating the
		/// vulnerability — fails on HEAD, passes after a fix is applied.
		/// Distinct from `patch_unified` which carries a candidate *fix*.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub poc_unified: Option<String>,
		pub fingerprint: String,
	}
}
