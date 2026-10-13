//! Test-only synthetic Agent content and actual SQLite repository decoding.
use loupe_core::text::policy::RevisionText;
use loupe_core::text::{BoundedText, RepoPath, TextPolicy};
use loupe_provenance::{Agent, Db, Ingress, Mark, Untrusted, Unvalidated, Validate};
use loupe_storage::repos::RepoRow;

#[derive(Clone)]
pub(crate) struct ReportFinding {
	pub id: i64,
	pub finding: loupe_core::Finding<Agent>,
	pub reviewed_revision: Option<BoundedText<RevisionText, Db>>,
}
impl ReportFinding {
	pub(super) fn view(&self) -> super::render::ReportView<'_> {
		super::render::ReportView::new(self.id, &self.finding, self.reviewed_revision.as_ref())
	}
}

struct Fixture<F>(F);
impl<F, T> Validate<&str, Agent> for Fixture<F>
where
	F: for<'a> FnOnce(&'a str, &Mark<'a, Agent>) -> T,
{
	type Output = T;
	type Error = std::convert::Infallible;
	fn validate<'a>(
		self, raw: Unvalidated<'a, &str>, mark: Mark<'a, Agent>,
	) -> Result<T, Self::Error> {
		Ok((self.0)(raw.get(), &mark))
	}
}

#[allow(unsafe_code)]
fn fixture<T>(raw: &str, f: impl for<'a> FnOnce(&'a str, &Mark<'a, Agent>) -> T) -> T {
	// SAFETY: synthetic Agent content in this private cfg(test) module only.
	Untrusted::new(raw, unsafe { Ingress::<Agent>::new() }).validate(Fixture(f)).unwrap()
}

pub(crate) fn text<P: TextPolicy>(raw: &str) -> BoundedText<P, Agent> {
	fixture(raw, |raw, mark| BoundedText::new(mark, raw).unwrap())
}

pub(super) fn path(raw: &str) -> RepoPath<Agent> {
	fixture(raw, |raw, mark| RepoPath::new(mark, raw).unwrap())
}

pub(crate) fn repo(reporting: serde_json::Value) -> loupe_storage::Result<RepoRow> {
	repo_with_revision(reporting, None)
}

fn repo_with_revision(
	reporting: serde_json::Value, revision: Option<&str>,
) -> loupe_storage::Result<RepoRow> {
	let mut fixture = crate::test_support::offline::OfflineDatabase::new();
	fixture.edit(|conn| {
		conn.execute(
			"INSERT INTO registered_repos
			 (id,clone_url,host,owner,repo,scanner_config,reporting,created_at,last_scanned_sha)
			 VALUES (1,'https://github.com/acme/widget.git','github.com','acme','widget',
			         'null',?1,0,?2)",
			rusqlite::params![reporting.to_string(), revision],
		)?;
		Ok(())
	});
	loupe_storage::scope::with_operator_repository(
		&fixture.open(),
		&crate::test_support::operator(),
		loupe_storage::scope::OperatorTarget::Repository(1),
		|scope| Ok(loupe_storage::repos::get(scope)?.unwrap()),
	)
}

pub(super) fn revision(raw: &str) -> BoundedText<RevisionText, Db> {
	repo_with_revision(serde_json::json!({"kind":"manual"}), Some(raw))
		.unwrap()
		.last_scanned_sha
		.unwrap()
}

/// Use the real SQLite projection and lease issuer for renderer fixtures.
pub(super) fn prepared(
	repo: &RepoRow, findings: &[ReportFinding],
) -> loupe_storage::reports::PreparedReport {
	prepared_with_db(repo, findings).1
}

pub(crate) fn prepared_with_db(
	repo: &RepoRow, findings: &[ReportFinding],
) -> (
	std::sync::Arc<loupe_storage::Db>,
	loupe_storage::reports::PreparedReport,
	crate::test_support::offline::OfflineDatabase,
) {
	use loupe_storage::{jobs, reports, scope};
	let mut fixture = crate::test_support::offline::OfflineDatabase::new();
	fixture.edit(|conn| {
		if let loupe_core::ReportingDestination::GithubIssue{pat_secret_id:Some(id),..} = repo.reporting {
			conn.execute("INSERT INTO secrets(id,kind,label,value,created_at) VALUES(?1,'github_pat','report-fixture',?2,0)",rusqlite::params![id,b"fixture-pat"])?;
		}
		conn.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,scanner_config,reporting,created_at) VALUES(1,?1,?2,?3,?4,'null',?5,0)", rusqlite::params![repo.clone_url.expose(),repo.host.expose(),repo.owner.expose(),repo.repo.expose(),serde_json::to_string(&repo.reporting).unwrap()])?;
		conn.execute("INSERT INTO workers(id,name,kind,cert_fingerprint,created_at) VALUES(1,'report-fixture','worker',X'07',0)", [])?;
		conn.execute("INSERT INTO jobs(id,repo_id,kind,state,incremental,worker_id,lease_expires_at,job_capability_hash,enqueued_at) VALUES(1,1,'scan','leased',0,1,100,?1,0)", [vec![7u8;32]])?;
		for (index, report) in findings.iter().enumerate() {
			let mut finding = report.finding.clone();
			finding.fingerprint = text(&format!("fixture-{index}"));
			conn.execute("INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,file_path,line_start,line_end,cwe,patch_unified,poc_unified,fingerprint,state,verification_required,created_at,source,report_identity) VALUES(?1,1,1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'confirmed',0,0,'agent',randomblob(16))",
				rusqlite::params![report.id+index as i64,finding.scanner_id.expose(),finding.severity.as_str(),finding.title.expose(),finding.description.expose(),finding.file_path.as_ref().map(RepoPath::expose),finding.line_start,finding.line_end,finding.cwe.as_ref().map(BoundedText::expose),finding.patch_unified.as_ref().map(BoundedText::expose),finding.poc_unified.as_ref().map(BoundedText::expose),finding.fingerprint.expose()])?;
		}
		if let Some(revision) = findings.first().and_then(|finding| finding.reviewed_revision.as_ref()) {
			conn.execute("UPDATE jobs SET head_sha=?1 WHERE id=1", [revision.expose()])?;
		}
		Ok(())
	});
	let db = fixture.open();
	let batch = match scope::with_active_lease(
		&db,
		jobs::ActiveLease {
			identity: jobs::LeaseIdentity { job_id: 1, worker_id: 1, capability_hash: &[7; 32] },
			now: 1,
		},
		reports::prepare_assignment,
	)
	.unwrap()
	.unwrap()
	{
		reports::Preparation::Ready(batch) => *batch,
		_ => panic!("report fixture must prepare"),
	};
	(db, batch, fixture)
}
