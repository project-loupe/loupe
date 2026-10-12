//! Legacy DTO schema plus independent field policy and exact output checks.
use loupe_cli::fuzz_support::{Field, FieldObservation, FieldSource, ResponseCase, ResponseValue};

use crate::cli_common::{exact, path};

pub fn legacy(case: ResponseCase, raw: &[u8]) -> serde_json::Result<ResponseValue> {
	use ResponseCase as C;
	use ResponseValue as V;
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
fn job(j: &loupe_proto::JobInfo) -> bool {
	exact(j.kind.as_str(), false)
		&& optional(&j.since_sha, false)
		&& optional(&j.head_sha, false)
		&& optional(&j.error, true)
}
fn summary(s: &loupe_proto::FindingSummary) -> bool {
	exact(&s.scanner_id, false)
		&& exact(&s.title, false)
		&& exact(&s.fingerprint, false)
		&& s.file_path.as_ref().is_none_or(|s| path(s))
		&& optional(&s.approved_by_cn, false)
		&& optional(&s.rejected_by_cn, false)
}
pub fn policies(value: &ResponseValue) -> bool {
	use ResponseValue as V;
	match value {
		V::App(a) => a.app.as_ref().is_none_or(|a| exact(&a.slug, false)),
		V::Repos(r) => r.repos.iter().all(|r| {
			[&r.clone_url, &r.host, &r.owner, &r.repo].into_iter().all(|s| exact(s, false))
				&& optional(&r.default_branch, false)
				&& optional(&r.last_scanned_sha, false)
				&& r.reporting.as_ref().is_none_or(|r| match r {
					loupe_proto::ReportingSummary::GithubIssue {
						target_owner,
						target_repo,
						..
					} => exact(target_owner, false) && exact(target_repo, false),
					loupe_proto::ReportingSummary::Email { to, from, subject_prefix } => {
						to.iter().all(|s| exact(s, false))
							&& optional(from, false)
							&& optional(subject_prefix, false)
					},
					loupe_proto::ReportingSummary::Manual => true,
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
pub fn compare(expected: ResponseValue, actual: ResponseValue) {
	use ResponseValue as V;
	match (expected, actual) {
		(V::App(a), V::App(b)) => assert_eq!(a, b),
		(V::Repo(a), V::Repo(b)) => assert_eq!(a, b),
		(V::Repos(a), V::Repos(b)) => assert_eq!(a, b),
		(V::Scan(a), V::Scan(b)) => assert_eq!(a, b),
		(V::Jobs(a), V::Jobs(b)) => assert_eq!(a, b),
		(V::Job(a), V::Job(b)) => assert_eq!(a, b),
		(V::Findings(a), V::Findings(b)) => assert_eq!(a, b),
		(V::Finding(a), V::Finding(b)) => assert_eq!(a, b),
		(V::Verification(a), V::Verification(b)) => assert_eq!(a, b),
		(V::Discard, V::Discard) => {},
		(V::Worker(a), V::Worker(b)) => {
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
pub fn typed_fields(value: &ResponseValue) -> Vec<FieldObservation> {
	fn add(out: &mut Vec<FieldObservation>, field: Field, text: &str) {
		let source = if matches!(field, Field::ApprovedBy | Field::RejectedBy) {
			FieldSource::Server
		} else {
			FieldSource::Agent
		};
		out.push(FieldObservation { field, source, text: text.to_owned() });
	}
	fn summary(out: &mut Vec<FieldObservation>, s: &loupe_proto::FindingSummary) {
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
		ResponseValue::Findings(list) => {
			for s in &list.findings {
				summary(&mut out, s)
			}
		},
		ResponseValue::Finding(d) => {
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
