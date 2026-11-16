use std::path::Path;

use git2::{ObjectType, Oid, Repository, Signature};

use super::*;
use crate::runner::observe_commit;

/// A raw tree object, written as given: libgit2's tree builder would sort
/// the entries and reject odd modes.
fn raw_tree(repo: &Repository, entries: &[(&str, &[u8], Oid)]) -> Oid {
	let mut bytes = Vec::new();
	for (mode, name, oid) in entries {
		bytes.extend_from_slice(mode.as_bytes());
		bytes.push(b' ');
		bytes.extend_from_slice(name);
		bytes.push(0);
		bytes.extend_from_slice(oid.as_bytes());
	}
	repo.odb().unwrap().write(ObjectType::Tree, &bytes).unwrap()
}

fn commit(repo: &Repository, tree: Oid) -> String {
	let tree = repo.find_tree(tree).unwrap();
	let sig =
		Signature::new("loupe-test", "loupe-test@example.com", &git2::Time::new(0, 0)).unwrap();
	repo.commit(None, &sig, &sig, "fixture", &tree, &[]).unwrap().to_string()
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The v1 manifest layout, written out independently of `ManifestHasher`.
fn expected_digest(commit: &str, entries: &[(&[u8], u32, Oid)]) -> String {
	let commit = Oid::from_str(commit).unwrap();
	let mut digest = blake3::Hasher::new();
	digest.update(b"loupe.inventory.v1\0");
	digest.update(&[20]);
	digest.update(commit.as_bytes());
	digest.update(&(entries.len() as u64).to_be_bytes());
	for (path, mode, oid) in entries {
		digest.update(&(path.len() as u32).to_be_bytes());
		digest.update(path);
		digest.update(&mode.to_be_bytes());
		digest.update(&[20]);
		digest.update(oid.as_bytes());
	}
	hex(digest.finalize().as_bytes())
}

struct Fixture {
	_dir: tempfile::TempDir,
	repo: Repository,
}
impl Fixture {
	fn new() -> Self {
		let dir = tempfile::tempdir().unwrap();
		let repo = Repository::init_bare(dir.path().join("cache.git")).unwrap();
		Self { _dir: dir, repo }
	}
	fn path(&self) -> &Path {
		self.repo.path()
	}
	fn blob(&self, contents: &[u8]) -> Oid {
		self.repo.blob(contents).unwrap()
	}
}

fn inventory(f: &Fixture, commit: &str) -> Result<Inventory, InventoryError> {
	observe_commit(f.path(), commit, InventoryDecoder)
}

#[test]
fn odd_modes_and_raw_paths_are_canonical_and_byte_ordered() {
	let f = Fixture::new();
	let (file, exec, link, odd, raw) =
		(f.blob(b"file"), f.blob(b"exec"), f.blob(b"target"), f.blob(b"odd"), f.blob(b"raw"));
	let gitlink = Oid::from_str(&"c".repeat(40)).unwrap();
	let nested = raw_tree(&f.repo, &[("100755", b"b", exec)]);
	let raw_dir = raw_tree(&f.repo, &[("100644", b"x", raw)]);
	// Deliberately not in Git tree order.
	let root = raw_tree(
		&f.repo,
		&[
			("100644", b"z", file),
			("40000", b"a", nested),
			("100644", b"a.b", file),
			("100664", b"g", odd),
			("120000", b"link", link),
			("160000", b"sub", gitlink),
			("100644", b"\xffbin", raw),
			("40000", b"d\xfe", raw_dir),
		],
	);
	let commit = commit(&f.repo, root);
	let inventory = inventory(&f, &commit).unwrap();

	let expected: Vec<(&[u8], u32, Oid)> = vec![
		(b"a.b", 0o100644, file),
		(b"a/b", 0o100755, exec),
		(b"d\xfe/x", 0o100644, raw),
		(b"g", 0o100644, odd),
		(b"link", 0o120000, link),
		(b"sub", 0o160000, gitlink),
		(b"z", 0o100644, file),
		(b"\xffbin", 0o100644, raw),
	];
	assert_eq!(inventory.commit().expose(), commit);
	assert_eq!(inventory.len(), expected.len() as u64);
	let observed: Vec<(String, u32, String)> = inventory
		.entries
		.iter()
		.map(|e| (e.raw_path_hex.expose().to_owned(), e.git_mode, e.object_id.expose().to_owned()))
		.collect();
	let wanted: Vec<(String, u32, String)> =
		expected.iter().map(|(p, m, o)| (hex(p), *m, o.to_string())).collect();
	assert_eq!(observed, wanted);
	assert_eq!(inventory.digest().expose(), expected_digest(&commit, &expected));
}

#[test]
fn unrepresentable_entries_fail_closed_without_path_text() {
	let f = Fixture::new();
	let blob = f.blob(b"x");
	for name in [b"..".as_slice(), b"."] {
		let root = raw_tree(&f.repo, &[("100644", name, blob)]);
		let commit = commit(&f.repo, root);
		let error = inventory(&f, &commit).err().unwrap();
		assert_eq!(error, InventoryError::Unsupported);
		assert!(!format!("{error} {error:?}").contains(".."));
	}
	assert_eq!(
		inventory(&f, &"d".repeat(40)).err(),
		Some(InventoryError::CommitUnavailable),
		"a commit missing from the clone"
	);
}

#[test]
fn empty_tree_is_one_empty_batch() {
	let f = Fixture::new();
	let root = raw_tree(&f.repo, &[]);
	let commit = commit(&f.repo, root);
	let inventory = inventory(&f, &commit).unwrap();
	assert_eq!(inventory.chunks(), vec![0..0]);
	assert_eq!(inventory.digest().expose(), expected_digest(&commit, &[]));
}

#[test]
fn entry_sizes_match_the_encoded_batch() {
	let f = Fixture::new();
	let blob = f.blob(b"x");
	let long = vec![b'p'; 300];
	let root = raw_tree(
		&f.repo,
		&[
			("100644", b"a", blob),
			("100755", b"\xff\xfe", blob),
			("120000", &long, blob),
			("160000", b"m", blob),
		],
	);
	let commit = commit(&f.repo, root);
	let inventory = inventory(&f, &commit).unwrap();
	let batch = inventory.batch(0..4);
	for (entry, size) in batch.entries.as_slice().iter().zip(&inventory.sizes) {
		assert_eq!(serde_json::to_vec(entry).unwrap().len() as u64, size.encoded);
	}
	let body = serde_json::to_vec(&batch).unwrap().len() as u64;
	let entries: u64 = inventory.sizes.iter().map(|s| s.encoded + 1).sum::<u64>() - 1;
	assert!(body <= FRAME_BYTES + entries);
	// The widest possible frame still fits the reserve.
	let frame = format!(
		r#"{{"protocol_version":3,"format_version":1,"expected_entry_count":{MAX_ENTRIES},"expected_digest":"{}","start_position":{MAX_ENTRIES},"entries":[]}}"#,
		"f".repeat(64)
	);
	assert!(frame.len() as u64 <= FRAME_BYTES, "{}", frame.len());
}

#[test]
fn chunks_respect_every_batch_limit() {
	let small = EntrySize::new(1, 0o100644, 40);
	let ranges = chunks(&vec![small; MAX_CHUNK_ENTRIES * 2 + 1]);
	assert_eq!(
		ranges,
		vec![0..MAX_CHUNK_ENTRIES, MAX_CHUNK_ENTRIES..MAX_CHUNK_ENTRIES * 2, 8192..8193]
	);

	let widest = EntrySize::new(64 * 1024, 0o100644, 64);
	let per_chunk = (MAX_CHUNK_BYTES / widest.canonical) as usize;
	assert_eq!(per_chunk, 15);
	assert_eq!(chunks(&vec![widest; 31]), vec![0..15, 15..30, 30..31]);

	let wire_heavy = EntrySize { canonical: 1, encoded: BODY_CAP / 2 };
	assert_eq!(chunks(&[wire_heavy; 3]), vec![0..1, 1..2, 2..3]);

	let deliberately_oversized = EntrySize { canonical: MAX_CHUNK_BYTES + 1, encoded: 1 };
	assert_eq!(chunks(&[small, deliberately_oversized, small]), vec![0..1, 1..2, 2..3]);
	assert_eq!(chunks(&[]), vec![0..0]);
}
