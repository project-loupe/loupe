//! The tracked-tree inventory of a pinned commit, enumerated from the bare
//! cache clone and uploaded in deterministic chunks.
//!
//! Modes are Git's canonical ones: libgit2's normalised `filemode()` maps a
//! regular file to `100644` or `100755` by its executable bit, so a
//! historical `100664` is reported as `100644`. Trees are not entries.

use std::ops::Range;

use loupe_core::inventory_manifest::{
	ManifestEntry, ManifestHasher, MAX_CHUNK_BYTES, MAX_CHUNK_ENTRIES, MAX_ENTRIES,
};
use loupe_core::review_metadata::{ReviewCommit, ReviewDigest};
use loupe_core::review_payload::Version1;
use loupe_proto::review_api::{self, InventoryBatchRequest, RawPathHex, ReviewProtocol};
use loupe_proto::review_lease::LeaseList;
use loupe_provenance::{Mark, Repo, Unvalidated, Validate};

use crate::runner::CommitObservation;

/// The server's cap on an inventory batch request body.
pub const BODY_CAP: u64 = 2 * 1024 * 1024;
/// Upper bound on everything in a batch body except the entries and the
/// commas between them.
pub const FRAME_BYTES: u64 = 256;

/// Why an inventory cannot be enumerated. Carries no repository text.
// debug-ok: static classifications only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InventoryError {
	#[error("repository commit is unavailable")]
	CommitUnavailable,
	#[error("repository tree could not be read")]
	Tree,
	#[error("inventory entry is not representable")]
	Unsupported,
	#[error("inventory exceeds its entry or byte limit")]
	TooLarge,
}

/// Sizes of one entry as the chunking core sees them.
// debug-ok: numeric sizes only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntrySize {
	/// `ManifestEntry::canonical_len`.
	pub canonical: u64,
	/// Exact length of the entry's JSON object in a batch body.
	pub encoded: u64,
}

impl EntrySize {
	pub fn new(path_bytes: u64, git_mode: u32, oid_hex: u64) -> Self {
		let mode_digits = git_mode.checked_ilog10().unwrap_or(0) as u64 + 1;
		Self {
			canonical: 4 + path_bytes + 4 + 1 + oid_hex / 2,
			// {"raw_path_hex":"…","git_mode":…,"object_id":"…"}
			encoded: 17 + 2 * path_bytes + 13 + mode_digits + 14 + oid_hex + 2,
		}
	}
}

/// Split `sizes` into consecutive, non-empty ranges that each fit one batch:
/// at most [`MAX_CHUNK_ENTRIES`] entries, at most [`MAX_CHUNK_BYTES`]
/// canonical bytes, and a body below [`BODY_CAP`]. Greedy, so the split is
/// a function of the sizes alone. An empty inventory is one empty batch.
///
/// Every entry admitted by `ManifestEntry` fits a batch on its own; an entry
/// that does not is still given its own range, and the server rejects it.
pub fn chunks(sizes: &[EntrySize]) -> Vec<Range<usize>> {
	let mut ranges = Vec::new();
	let mut start = 0;
	let (mut canonical, mut body) = (0u64, FRAME_BYTES);
	for (index, size) in sizes.iter().enumerate() {
		let separator = u64::from(index > start);
		let fits = index - start < MAX_CHUNK_ENTRIES
			&& canonical.saturating_add(size.canonical) <= MAX_CHUNK_BYTES
			&& body.saturating_add(separator).saturating_add(size.encoded) < BODY_CAP;
		if index > start && !fits {
			ranges.push(start..index);
			start = index;
			canonical = 0;
			body = FRAME_BYTES;
		}
		let separator = u64::from(index > start);
		canonical = canonical.saturating_add(size.canonical);
		body = body.saturating_add(separator).saturating_add(size.encoded);
	}
	if start < sizes.len() || sizes.is_empty() {
		ranges.push(start..sizes.len());
	}
	ranges
}

/// A complete, ordered inventory of one commit's tree.
pub(crate) struct Inventory {
	commit: ReviewCommit<Repo>,
	digest: ReviewDigest<Repo>,
	entries: Vec<review_api::ManifestEntry<Repo>>,
	sizes: Vec<EntrySize>,
}

impl Inventory {
	pub(crate) fn commit(&self) -> &ReviewCommit<Repo> {
		&self.commit
	}
	pub(crate) fn digest(&self) -> &ReviewDigest<Repo> {
		&self.digest
	}
	pub(crate) fn len(&self) -> u64 {
		self.entries.len() as u64
	}
	pub(crate) fn chunks(&self) -> Vec<Range<usize>> {
		chunks(&self.sizes)
	}
	/// The batch request for one range returned by [`Self::chunks`].
	pub(crate) fn batch(&self, range: Range<usize>) -> InventoryBatchRequest<Repo> {
		let start_position = range.start as u64;
		let entries = self.entries[range].to_vec();
		InventoryBatchRequest {
			protocol_version: ReviewProtocol,
			format_version: Version1,
			expected_entry_count: self.len(),
			expected_digest: self.digest.clone(),
			start_position,
			// `chunks` never yields more than the list bound.
			entries: LeaseList::new(entries).unwrap_or_default(),
		}
	}
}

/// Walks the observed commit's tree, sorts by raw path bytes and digests.
pub(crate) struct InventoryDecoder;

impl Validate<CommitObservation<'_>, Repo> for InventoryDecoder {
	type Output = Inventory;
	type Error = InventoryError;
	fn validate<'view>(
		self, u: Unvalidated<'view, CommitObservation<'_>>, mark: Mark<'view, Repo>,
	) -> Result<Inventory, InventoryError> {
		let observation = u.get();
		let commit_hex = observation.commit.id().to_string();
		let commit =
			ReviewCommit::new(&mark, &commit_hex).map_err(|_| InventoryError::CommitUnavailable)?;
		let tree = observation.commit.tree().map_err(|_| InventoryError::Tree)?;
		let mut raw = Vec::new();
		walk(observation.repo, &tree, &mut Vec::new(), &mut raw)?;
		raw.sort_unstable_by(|a, b| a.0.cmp(&b.0));

		let mut hasher = ManifestHasher::new(&commit_hex, raw.len() as u64)
			.map_err(|_| InventoryError::TooLarge)?;
		let mut entries = Vec::with_capacity(raw.len());
		let mut sizes = Vec::with_capacity(raw.len());
		for (path, mode, oid) in raw {
			let entry = ManifestEntry::new(&mark, &path, mode, &oid)
				.map_err(|_| InventoryError::Unsupported)?;
			hasher.push(&entry).map_err(|_| InventoryError::TooLarge)?;
			sizes.push(EntrySize::new(path.len() as u64, mode, oid.len() as u64));
			entries.push(review_api::ManifestEntry {
				raw_path_hex: RawPathHex::new(&mark, &hex(&path))
					.map_err(|_| InventoryError::Unsupported)?,
				git_mode: mode,
				object_id: ReviewCommit::new(&mark, &oid)
					.map_err(|_| InventoryError::Unsupported)?,
			});
		}
		let digest = hasher.finish().map_err(|_| InventoryError::TooLarge)?;
		let digest =
			ReviewDigest::new(&mark, &hex(&digest)).map_err(|_| InventoryError::TooLarge)?;
		Ok(Inventory { commit, digest, entries, sizes })
	}
}

/// Only the commit id, for pinning without an inventory.
pub(crate) struct CommitDecoder;

impl Validate<CommitObservation<'_>, Repo> for CommitDecoder {
	type Output = ReviewCommit<Repo>;
	type Error = InventoryError;
	fn validate<'view>(
		self, u: Unvalidated<'view, CommitObservation<'_>>, mark: Mark<'view, Repo>,
	) -> Result<ReviewCommit<Repo>, InventoryError> {
		ReviewCommit::new(&mark, &u.get().commit.id().to_string())
			.map_err(|_| InventoryError::CommitUnavailable)
	}
}

/// Depth-first over raw name bytes; libgit2's own walk hands the prefix
/// over as `&str`, which cannot carry non-UTF-8 directory names.
fn walk(
	repo: &git2::Repository, tree: &git2::Tree<'_>, prefix: &mut Vec<u8>,
	out: &mut Vec<(Vec<u8>, u32, String)>,
) -> Result<(), InventoryError> {
	for entry in tree.iter() {
		let restore = prefix.len();
		if !prefix.is_empty() {
			prefix.push(b'/');
		}
		prefix.extend_from_slice(entry.name_bytes());
		let mode = u32::try_from(entry.filemode()).map_err(|_| InventoryError::Unsupported)?;
		if mode == 0o040000 {
			let subtree = repo.find_tree(entry.id()).map_err(|_| InventoryError::Tree)?;
			walk(repo, &subtree, prefix, out)?;
		} else {
			if out.len() as u64 >= MAX_ENTRIES {
				return Err(InventoryError::TooLarge);
			}
			out.push((prefix.clone(), mode, entry.id().to_string()));
		}
		prefix.truncate(restore);
	}
	Ok(())
}

fn hex(bytes: &[u8]) -> String {
	use std::fmt::Write;
	let mut out = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		let _ = write!(out, "{byte:02x}");
	}
	out
}

#[cfg(test)]
mod tests;
