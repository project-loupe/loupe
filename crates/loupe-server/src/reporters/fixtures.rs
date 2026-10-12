//! Test-only synthetic Agent content and actual SQLite repository decoding.
use loupe_core::text::policy::RevisionText;
use loupe_core::text::{BoundedText, RepoPath, TextPolicy};
use loupe_provenance::{Agent, Db, Ingress, Mark, Untrusted, Unvalidated, Validate};
use loupe_storage::repos::RepoRow;

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

pub(super) fn text<P: TextPolicy>(raw: &str) -> BoundedText<P, Agent> {
	fixture(raw, |raw, mark| BoundedText::new(mark, raw).unwrap())
}

pub(super) fn path(raw: &str) -> RepoPath<Agent> {
	fixture(raw, |raw, mark| RepoPath::new(mark, raw).unwrap())
}

pub(super) fn repo(reporting: serde_json::Value) -> loupe_storage::Result<RepoRow> {
	repo_with_revision(reporting, None)
}

fn repo_with_revision(
	reporting: serde_json::Value, revision: Option<&str>,
) -> loupe_storage::Result<RepoRow> {
	let db = loupe_storage::Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests())?;
	db.with_conn(|conn| {
		conn.execute(
			"INSERT INTO registered_repos
			 (id,clone_url,host,owner,repo,scanner_config,reporting,created_at,last_scanned_sha)
			 VALUES (1,'https://github.com/acme/widget.git','github.com','acme','widget',
			         'null',?1,0,?2)",
			rusqlite::params![reporting.to_string(), revision],
		)?;
		Ok(loupe_storage::repos::get(conn, 1)?.unwrap())
	})
}

pub(super) fn revision(raw: &str) -> BoundedText<RevisionText, Db> {
	repo_with_revision(serde_json::json!({"kind":"manual"}), Some(raw))
		.unwrap()
		.last_scanned_sha
		.unwrap()
}
