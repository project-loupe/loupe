//! Byte-exact inventory references, including visibly unrepresentable entries.
use loupe_core::text::policy::Reason;
use loupe_core::text::{BoundedText, RepoPath, SourceRef};
use rusqlite::{params, Connection, Transaction};

use crate::review::{is_unique, optional, parsed, standalone, string_enum};
use crate::{ownership, Conflict, Error, Ownership, Result};
string_enum!(EntryKind { Tracked => "tracked", Submodule => "submodule" });
string_enum!(Disposition { Mapped => "mapped", Context => "context", Excluded => "excluded", Unresolved => "unresolved" });
pub const MAX_ENTRIES: usize = 4096;

#[derive(Clone)]
pub struct InventoryPath {
	rendering: String,
	representable: bool,
}
impl InventoryPath {
	pub fn from_git_bytes(raw: &[u8]) -> Self {
		if let Ok(text) = std::str::from_utf8(raw)
			&& RepoPath::new(text).is_ok()
		{
			return Self { rendering: text.to_owned(), representable: true };
		}
		let mut rendering = String::new();
		for &byte in raw {
			if (0x20..=0x7e).contains(&byte) {
				rendering.push(byte as char);
			} else {
				use std::fmt::Write;
				write!(&mut rendering, "%{byte:02X}").expect("writing a String");
			}
		}
		Self { rendering, representable: false }
	}
	pub fn expose(&self) -> &str {
		&self.rendering
	}
	pub fn representable(&self) -> bool {
		self.representable
	}
}
impl std::fmt::Debug for InventoryPath {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"InventoryPath(len={}, representable={})",
			self.rendering.len(),
			self.representable
		)
	}
}
pub struct NewEntry<'a> {
	pub path: &'a InventoryPath,
	pub blob_sha: Option<&'a str>,
	pub kind: EntryKind,
	pub disposition: Disposition,
	pub reason: Option<&'a BoundedText<Reason>>,
	pub highlighted: bool,
}
#[derive(Debug, Clone)]
pub struct Entry {
	pub inventory_entry_id: i64,
	pub generation_id: i64,
	pub path: InventoryPath,
	pub blob_sha: Option<String>,
	pub kind: EntryKind,
	pub disposition: Disposition,
	pub reason: Option<BoundedText<Reason>>,
	pub highlighted: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inserted {
	/// Newly inserted physical rows (replacing a display alias adds no row).
	pub inserted: usize,
	pub excluded: usize,
	/// Entries that add no row: identical retries and display-alias collisions,
	/// including replacements of aliases from earlier batches.
	pub skipped: usize,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownPaths(pub Vec<RepoPath>);
impl std::fmt::Display for UnknownPaths {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{} references are outside the pinned inventory", self.0.len())
	}
}
impl std::error::Error for UnknownPaths {}

pub fn insert(
	tx: &Transaction<'_>, repo: i64, generation: i64, entries: &[NewEntry<'_>], now: i64,
) -> Result<Inserted> {
	ownership::generation(tx, repo, generation, Ownership::InventoryGeneration)?;
	if entries.len() > MAX_ENTRIES {
		return Err(Error::Conflict(Conflict::InventoryLimit));
	}
	let mut outcome = Inserted { inserted: 0, excluded: 0, skipped: 0 };
	let mut insert = tx.prepare("INSERT INTO generation_inventory (generation_id,path,blob_sha,entry_kind,disposition,disposition_reason,highlighted,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)")?;
	// An earlier bulk batch may have reserved this display name for invalid
	// Git bytes. Real paths win, unless evidence has already consumed that
	// exclusion: never retarget evidence.
	let mut replace_alias = tx.prepare(
		"UPDATE generation_inventory
		    SET blob_sha=?3, entry_kind=?4, disposition=?5,
		        disposition_reason=?6, highlighted=?7, created_at=?8
		  WHERE generation_id=?1 AND path=?2
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
		   WHERE generation_id=?1 AND path=?2 AND blob_sha IS ?3 AND entry_kind=?4
		     AND (disposition_reason IS NULL OR disposition_reason<>'unrepresentable-path'))",
	)?;
	// Reserve real names first so an encoded invalid name never shadows one.
	for entry in entries
		.iter()
		.filter(|e| e.path.representable)
		.chain(entries.iter().filter(|e| !e.path.representable))
	{
		let excluded = !entry.path.representable;
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
			entry.blob_sha,
			entry.kind.as_str(),
			disposition.as_str(),
			reason,
			entry.highlighted,
			now
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
							entry.blob_sha,
							entry.kind.as_str()
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
pub fn list(conn: &Connection, generation: i64) -> Result<Vec<Entry>> {
	Ok(conn.prepare("SELECT inventory_entry_id,generation_id,path,blob_sha,entry_kind,disposition,disposition_reason,highlighted FROM generation_inventory WHERE generation_id=?1 ORDER BY path")?.query_map([generation],|r| {
		let reason: Option<BoundedText<Reason>> = optional(r,6)?;
		let path = InventoryPath { rendering:r.get(2)?,representable:reason.as_ref().is_none_or(|reason|reason.expose()!="unrepresentable-path") };
		Ok(Entry { inventory_entry_id:r.get(0)?,generation_id:r.get(1)?,path,blob_sha:r.get(3)?,kind:parsed(r,4)?,disposition:parsed(r,5)?,reason,highlighted:r.get(7)? })
	})?.collect::<rusqlite::Result<_>>()?)
}
pub fn verify_refs(tx: &Transaction<'_>, generation: i64, refs: &[SourceRef]) -> Result<()> {
	ownership::generation_repo(tx, generation)?;
	let exists: bool = tx.query_row("SELECT inventory_digest IS NOT NULL OR EXISTS(SELECT 1 FROM generation_inventory WHERE generation_id=?1) FROM review_generations WHERE generation_id=?1",[generation],|r|r.get(0))?;
	if !exists {
		return Ok(());
	}
	let mut unknown = Vec::new();
	let mut statement = tx.prepare("SELECT EXISTS(SELECT 1 FROM generation_inventory WHERE generation_id=?1 AND path=?2 AND (disposition_reason IS NULL OR disposition_reason<>'unrepresentable-path'))")?;
	for source in refs {
		if !statement
			.query_row(params![generation, source.path.expose()], |r| r.get::<_, bool>(0))?
		{
			unknown.push(source.path.clone());
		}
	}
	if unknown.is_empty() {
		Ok(())
	} else {
		Err(Error::UnknownPaths(UnknownPaths(unknown)))
	}
}
standalone! { insert(repo: i64, generation: i64, entries: &[NewEntry<'_>], now: i64) -> Inserted; }
