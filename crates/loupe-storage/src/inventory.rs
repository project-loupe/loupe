//! Byte-exact inventory references, including visibly unrepresentable entries.
use loupe_core::text::policy::{Reason, RevisionText};
use loupe_core::text::{BoundedText, RepoPath, SourceRef};
use loupe_provenance::{Agent, Db, Mark, Repo, Source};
use rusqlite::{params, Connection};

pub use crate::ingress::InventoryRendering;
use crate::review::{is_unique, parsed, string_enum};
use crate::{ownership, Conflict, Error, Ownership, Result};
string_enum!(EntryKind { Tracked => "tracked", Submodule => "submodule" });
string_enum!(Disposition { Mapped => "mapped", Context => "context", Excluded => "excluded", Unresolved => "unresolved" });
pub const MAX_ENTRIES: usize = 4096;

pub enum InventoryPath<S: Source> {
	Representable(RepoPath<S>),
	Unrepresentable(BoundedText<InventoryRendering, S>),
}
impl InventoryPath<Repo> {
	pub fn from_git_bytes(mark: &Mark<'_, Repo>, raw: &[u8]) -> Result<Self> {
		if let Ok(text) = std::str::from_utf8(raw)
			&& let Ok(path) = RepoPath::new(mark, text)
		{
			return Ok(Self::Representable(path));
		}
		let mut rendering = String::new();
		for &byte in raw {
			if (0x20..=0x7e).contains(&byte) {
				rendering.push(byte as char);
			} else {
				use std::fmt::Write;
				#[expect(
					clippy::expect_used,
					reason = "formatting one u8 into an owned String has no fallible writer or custom formatter"
				)]
				write!(&mut rendering, "%{byte:02X}").expect("writing a String");
			}
		}
		Ok(Self::Unrepresentable(BoundedText::new(mark, &rendering)?))
	}
}
impl<S: Source> Clone for InventoryPath<S> {
	fn clone(&self) -> Self {
		match self {
			Self::Representable(path) => Self::Representable(path.clone()),
			Self::Unrepresentable(text) => Self::Unrepresentable(text.clone()),
		}
	}
}
impl<S: Source> InventoryPath<S> {
	pub fn expose(&self) -> &str {
		match self {
			Self::Representable(path) => path.expose(),
			Self::Unrepresentable(text) => text.expose(),
		}
	}
	pub fn representable(&self) -> bool {
		matches!(self, Self::Representable(_))
	}
}
impl<S: Source> std::fmt::Debug for InventoryPath<S> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"InventoryPath(len={}, representable={})",
			self.expose().len(),
			self.representable()
		)
	}
}
pub struct NewEntry<'a, PathS: Source, RevisionS: Source, ReasonS: Source> {
	pub path: &'a InventoryPath<PathS>,
	pub blob_sha: Option<&'a BoundedText<RevisionText, RevisionS>>,
	pub kind: EntryKind,
	pub disposition: Disposition,
	pub reason: Option<&'a BoundedText<Reason, ReasonS>>,
	pub highlighted: bool,
}
// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug, Clone)]
pub struct Entry {
	pub inventory_entry_id: i64,
	pub generation_id: i64,
	pub path: InventoryPath<Db>,
	pub blob_sha: Option<BoundedText<RevisionText, Db>>,
	pub kind: EntryKind,
	pub disposition: Disposition,
	pub reason: Option<BoundedText<Reason, Db>>,
	pub highlighted: bool,
}
// debug-ok: insertion outcomes contain only row counters, never inventory paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inserted {
	/// Newly inserted physical rows (replacing a display alias adds no row).
	pub inserted: usize,
	pub excluded: usize,
	/// Entries that add no row: identical retries and display-alias collisions,
	/// including replacements of aliases from earlier batches.
	pub skipped: usize,
}
// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownPaths(pub Vec<RepoPath<Agent>>);
impl std::fmt::Display for UnknownPaths {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{} references are outside the pinned inventory", self.0.len())
	}
}
impl std::error::Error for UnknownPaths {}

pub fn insert<PathS: Source, RevisionS: Source, ReasonS: Source>(
	scope: &crate::scope::RepoScope<'_>, generation: i64,
	entries: &[NewEntry<'_, PathS, RevisionS, ReasonS>], now: i64,
) -> Result<Inserted> {
	scope.require_operator()?;
	let tx = scope.conn;
	ownership::generation(tx, scope.repo_id, generation, Ownership::InventoryGeneration)?;
	if entries.len() > MAX_ENTRIES {
		return Err(Error::Conflict(Conflict::InventoryLimit));
	}
	let mut outcome = Inserted { inserted: 0, excluded: 0, skipped: 0 };
	let mut insert = tx.prepare("INSERT INTO generation_inventory (generation_id,path,blob_sha,entry_kind,disposition,disposition_reason,highlighted,created_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8 WHERE EXISTS(SELECT 1 FROM review_generations WHERE generation_id=?1 AND repo_id=?9)")?;
	// An earlier bulk batch may have reserved this display name for invalid
	// Git bytes. Real paths win, unless evidence has already consumed that
	// exclusion: never retarget evidence.
	let mut replace_alias = tx.prepare(
		"UPDATE generation_inventory
		    SET blob_sha=?3, entry_kind=?4, disposition=?5,
		        disposition_reason=?6, highlighted=?7, created_at=?8
		  WHERE generation_id=?1 AND path=?2 AND EXISTS(SELECT 1 FROM review_generations WHERE generation_id=?1 AND repo_id=?9)
		    AND disposition='excluded'
		    AND disposition_reason='unrepresentable-path'
		    AND NOT EXISTS (
		        SELECT 1 FROM review_unit_results r
		        WHERE r.corroborates_inventory_exclusion_id =
		            generation_inventory.inventory_entry_id)",
	)?;
	// Re-ingesting the same path with the same content (a retried or
	// duplicated upload) is a no-op; the same path with other content is not.
	let mut identical = tx.prepare(
		"SELECT EXISTS(SELECT 1 FROM generation_inventory
		   WHERE generation_id=?1 AND EXISTS(SELECT 1 FROM review_generations WHERE generation_id=?1 AND repo_id=?5) AND path=?2 AND blob_sha IS ?3 AND entry_kind=?4
		     AND (disposition_reason IS NULL OR disposition_reason<>'unrepresentable-path'))",
	)?;
	// Reserve real names first so an encoded invalid name never shadows one.
	for entry in entries
		.iter()
		.filter(|e| e.path.representable())
		.chain(entries.iter().filter(|e| !e.path.representable()))
	{
		let excluded = !entry.path.representable();
		if !excluded && entry.reason.is_some_and(|r| r.expose() == "unrepresentable-path") {
			return Err(loupe_core::text::Error::new(
				"disposition_reason",
				loupe_core::text::Rule::Identifier,
			)
			.into());
		}
		let disposition = if excluded { Disposition::Excluded } else { entry.disposition };
		let reason = if excluded {
			Some("unrepresentable-path")
		} else {
			entry.reason.map(BoundedText::expose)
		};
		if disposition == Disposition::Excluded && reason.is_none() {
			return Err(loupe_core::text::Error::new(
				"disposition_reason",
				loupe_core::text::Rule::Empty,
			)
			.into());
		}
		let row = params![
			generation,
			entry.path.expose(),
			entry.blob_sha.map(BoundedText::expose),
			entry.kind.as_str(),
			disposition.as_str(),
			reason,
			entry.highlighted,
			now,
			scope.repo_id
		];
		match insert.execute(row) {
			Ok(_) => {
				outcome.inserted += 1;
				outcome.excluded += usize::from(excluded);
			},
			Err(e)
				if is_unique(
					&e,
					"generation_inventory.generation_id, generation_inventory.path",
				) =>
			{
				// Skip when: this entry is itself an unrepresentable placeholder;
				// it replaced an earlier placeholder for its real name; or an
				// identical row already exists. Anything else is a real clash.
				if excluded
					|| replace_alias.execute(row)? == 1
					|| identical.query_row(
						params![
							generation,
							entry.path.expose(),
							entry.blob_sha.map(BoundedText::expose),
							entry.kind.as_str(),
							scope.repo_id
						],
						|r| r.get::<_, bool>(0),
					)? {
					outcome.skipped += 1;
				} else {
					return Err(Error::Conflict(Conflict::InventoryPath));
				}
			},
			Err(e) => return Err(e.into()),
		}
	}
	Ok(outcome)
}
pub fn list(scope: &crate::scope::RepoScope<'_>, generation: i64) -> Result<Vec<Entry>> {
	let tx = scope.conn;
	Ok(tx
		.prepare(&format!(
			"SELECT {COLUMNS} FROM generation_inventory WHERE generation_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=generation_inventory.generation_id AND g.repo_id=?2) ORDER BY path"
		))?
		.query_map(params![generation,scope.repo_id], row)?
		.collect::<rusqlite::Result<_>>()?)
}
const COLUMNS: &str = "inventory_entry_id,generation_id,path,blob_sha,entry_kind,disposition,disposition_reason,highlighted";
fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Entry> {
	let reason: Option<BoundedText<Reason, Db>> = crate::ingress::optional_reason(r, 6)?;
	let representable =
		reason.as_ref().is_none_or(|reason| reason.expose() != "unrepresentable-path");
	let path = crate::ingress::inventory_path(r, 2, representable)?;
	Ok(Entry {
		inventory_entry_id: r.get(0)?,
		generation_id: r.get(1)?,
		path,
		blob_sha: crate::ingress::optional_revision(r, 3)?,
		kind: parsed(r, 4)?,
		disposition: parsed(r, 5)?,
		reason,
		highlighted: r.get(7)?,
	})
}
pub(crate) fn validate_stored_rows(conn: &Connection) -> Result<()> {
	crate::migrations::admission::scan(conn, "generation_inventory", COLUMNS, row)?;
	crate::migrations::admission::scan(conn, "generation_inventory", "created_at", |_| {
		Ok::<_, rusqlite::Error>(())
	})
}
pub fn verify_refs(
	scope: &crate::scope::RepoScope<'_>, generation: i64, refs: &[SourceRef<Agent>],
) -> Result<()> {
	let tx = scope.conn;
	ownership::generation(tx, scope.repo_id, generation, Ownership::InventoryGeneration)?;
	let exists: bool = tx.query_row("SELECT inventory_digest IS NOT NULL OR EXISTS(SELECT 1 FROM generation_inventory WHERE generation_id=?1) FROM review_generations WHERE generation_id=?1 AND repo_id=?2",params![generation,scope.repo_id],|r|r.get(0))?;
	if !exists {
		return Ok(());
	}
	let mut unknown = Vec::new();
	let mut statement = tx.prepare("SELECT EXISTS(SELECT 1 FROM generation_inventory WHERE generation_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=generation_inventory.generation_id AND g.repo_id=?3) AND path=?2 AND (disposition_reason IS NULL OR disposition_reason<>'unrepresentable-path'))")?;
	for source in refs {
		if !statement.query_row(params![generation, source.path.expose(), scope.repo_id], |r| {
			r.get::<_, bool>(0)
		})? {
			unknown.push(source.path.clone());
		}
	}
	if unknown.is_empty() {
		Ok(())
	} else {
		Err(Error::UnknownPaths(UnknownPaths(unknown)))
	}
}
