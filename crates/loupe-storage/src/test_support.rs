//! Synthetic source fixtures for DAO inputs. Actual SQL-read tests continue
//! through the production ingress validators, not these constructors.
use loupe_core::text::{
	Anchor, AnchorPolicy, BoundedJson, BoundedText, Error, IdentPolicy, Identifier, JsonPolicy,
	RepoPath, TextPolicy,
};
use loupe_provenance::{
	Agent, Config, Db, Ingress, Mark, Repo, Source, Untrusted, Unvalidated, Validate,
};

struct Fixture<S, F>(F, std::marker::PhantomData<S>);
impl<S: Source, F, T> Validate<&str, S> for Fixture<S, F>
where
	F: for<'a> FnOnce(&'a str, &Mark<'a, S>) -> T,
{
	type Output = T;
	type Error = std::convert::Infallible;
	fn validate<'a>(
		self, input: Unvalidated<'a, &str>, mark: Mark<'a, S>,
	) -> Result<T, Self::Error> {
		Ok((self.0)(input.get(), &mark))
	}
}
macro_rules! fixture {
	($name:ident, $source:ty) => {
		#[allow(unsafe_code)]
		pub(crate) fn $name<T>(
			raw: &str, f: impl for<'a> FnOnce(&'a str, &Mark<'a, $source>) -> T,
		) -> T {
			// SAFETY: this cfg(test)-only function labels synthetic fixture data
			// with the one explicitly named source, never a production input.
			Untrusted::new(raw, unsafe { Ingress::<$source>::new() })
				.validate(Fixture(f, std::marker::PhantomData))
				.unwrap()
		}
	};
}
fixture!(agent, Agent);
fixture!(database, Db);
fixture!(configured, Config);
fixture!(repository, Repo);

#[allow(unsafe_code)]
pub(crate) fn operator_ingress() -> Ingress<loupe_provenance::Operator> {
	// SAFETY: explicit synthetic Operator authority confined to cfg(test).
	unsafe { Ingress::new() }
}

pub(crate) fn operated<T>(
	raw: &str, f: impl for<'a> FnOnce(&'a str, &Mark<'a, loupe_provenance::Operator>) -> T,
) -> T {
	Untrusted::new(raw, operator_ingress()).validate(Fixture(f, std::marker::PhantomData)).unwrap()
}

/// White-box lifecycle fixtures already own their transaction and intentionally
/// seed malformed rows. This private cfg(test) adapter supplies their scope;
/// authority tests exercise the two real Db issuers instead.
pub(crate) fn scope(conn: &rusqlite::Connection, repo_id: i64) -> crate::scope::RepoScope<'_> {
	use std::sync::atomic::AtomicBool;
	use std::sync::{Arc, LazyLock};
	static IDENTITY: LazyLock<Arc<crate::db::DbIdentity>> =
		LazyLock::new(|| Arc::new(crate::db::DbIdentity));
	static UNCOMMITTED: LazyLock<Arc<AtomicBool>> =
		LazyLock::new(|| Arc::new(AtomicBool::new(false)));
	crate::scope::RepoScope {
		conn,
		repo_id,
		identity: &IDENTITY,
		operator: true,
		committed: &UNCOMMITTED,
	}
}

pub(crate) fn scoped<T>(
	conn: &mut rusqlite::Connection, repo: i64,
	body: impl FnOnce(&crate::scope::RepoScope<'_>) -> crate::Result<T>,
) -> crate::Result<T> {
	crate::transaction::immediate(conn, |tx| body(&scope(tx, repo)))
}

pub(crate) fn text<P: TextPolicy>(raw: &str) -> Result<BoundedText<P, Agent>, Error> {
	agent(raw, |raw, mark| BoundedText::new(mark, raw))
}
pub(crate) fn db_text<P: TextPolicy>(raw: &str) -> Result<BoundedText<P, Db>, Error> {
	database(raw, |raw, mark| BoundedText::new(mark, raw))
}
pub(crate) fn config_text<P: TextPolicy>(raw: &str) -> Result<BoundedText<P, Config>, Error> {
	configured(raw, |raw, mark| BoundedText::new(mark, raw))
}
pub(crate) fn identifier<P: IdentPolicy>(raw: &str) -> Result<Identifier<P, Agent>, Error> {
	agent(raw, |raw, mark| Identifier::new(mark, raw))
}
pub(crate) fn anchor<P: AnchorPolicy>(raw: &str) -> Result<Anchor<P, Agent>, Error> {
	agent(raw, |raw, mark| Anchor::new(mark, raw))
}
pub(crate) fn path(raw: &str) -> Result<RepoPath<Agent>, Error> {
	agent(raw, |raw, mark| RepoPath::new(mark, raw))
}
pub(crate) fn json<P: JsonPolicy>(raw: &str) -> Result<BoundedJson<P, Agent>, Error> {
	agent(raw, |raw, mark| BoundedJson::new(mark, raw))
}
pub(crate) fn config_json<P: JsonPolicy>(raw: &str) -> Result<BoundedJson<P, Config>, Error> {
	configured(raw, |raw, mark| BoundedJson::new(mark, raw))
}
pub(crate) fn db_json<P: JsonPolicy>(raw: &str) -> Result<BoundedJson<P, Db>, Error> {
	database(raw, |raw, mark| BoundedJson::new(mark, raw))
}
pub(crate) fn scanner(value: serde_json::Value) -> loupe_core::ScannerDocument<Db> {
	database("", |_, mark| loupe_core::ScannerDocument::stored(mark, value))
}
pub(crate) fn refs<const MAX: usize>(
	values: Vec<loupe_core::text::SourceRef<Agent>>,
) -> Result<crate::source_refs::SourceRefs<MAX, Agent>, Error> {
	agent("", |_, mark| crate::source_refs::SourceRefs::new(mark, values))
}
pub(crate) fn read_unit_refs(raw: &str) -> rusqlite::Result<crate::source_refs::UnitRefs<Agent>> {
	let conn = rusqlite::Connection::open_in_memory()?;
	conn.query_row("SELECT ?1", [raw], |row| crate::ingress::unit_refs(row, 0))
}
pub(crate) fn inventory_path(raw: &[u8]) -> crate::inventory::InventoryPath<Repo> {
	repository("", |_, mark| crate::inventory::InventoryPath::from_git_bytes(mark, raw).unwrap())
}
pub(crate) fn artifact_bytes(raw: &[u8]) -> crate::proofs::ArtifactBytes<'_, Repo> {
	repository("", |_, mark| crate::proofs::ArtifactBytes::new(mark, raw))
}
