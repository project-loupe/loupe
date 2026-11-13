//! Header: commit-ID length selector, u32 expected count and a flags byte;
//! then entries, each a u8 mode selector, u8 object-ID length selector, a
//! u32-length-prefixed raw path (capped at one byte over
//! the path limit) and a hex seed byte. Entries are admitted
//! raw or through their hex encoding. The oracle restates the manifest
//! format 1 contract from PR-B4-STORAGE-CONTRACT: the exact hashed byte
//! stream, strict raw-byte order, the entry and byte limits, and the
//! entry rules for paths, modes and object IDs.

use loupe_core::inventory_manifest::{
	is_git_oid, is_submodule_mode, ManifestEntry, ManifestHasher, MAX_BYTES, MAX_CHUNK_BYTES,
	MAX_CHUNK_ENTRIES, MAX_ENTRIES, MAX_PATH_BYTES,
};
use loupe_core::text::IdentPolicy;
use loupe_provenance::Agent;

use crate::utils::input::ByteSource;
use crate::utils::test_logger;

struct HexPath;
impl IdentPolicy for HexPath {
	const FIELD: &'static str = "raw_path_hex";
	const MAX_LEN: usize = MAX_PATH_BYTES * 2 + 2;
	fn accepts(_: &str) -> bool {
		true
	}
}
struct ObjectId;
impl IdentPolicy for ObjectId {
	const FIELD: &'static str = "object_id";
	const MAX_LEN: usize = 66;
	fn accepts(_: &str) -> bool {
		true
	}
}

const MODES: [u32; 6] = [0o100644, 0o100755, 0o120000, 0o160000, 0o040000, 0o100664];
const OID_LENGTHS: [usize; 6] = [40, 64, 39, 41, 63, 65];

pub fn do_test(data: &[u8]) {
	const {
		assert!(MAX_CHUNK_ENTRIES as u64 <= MAX_ENTRIES);
		assert!(MAX_CHUNK_BYTES <= MAX_BYTES);
		assert!((MAX_PATH_BYTES as u64) < MAX_CHUNK_BYTES);
	}
	let mut input = ByteSource::new(data);
	let (Some(commit_selector), Some(expected), Some(flags)) =
		(input.u8(), input.u32(), input.u8())
	else {
		return;
	};
	let commit = oid(commit_selector, 0x11);
	let expected = match flags & 3 {
		0 => u64::from(expected % 8),
		1 => MAX_ENTRIES,
		2 => MAX_ENTRIES + 1,
		_ => u64::from(expected),
	};
	let commit_valid = valid_oid(&commit);
	let hasher = ManifestHasher::new(&commit, expected);
	assert_eq!(hasher.is_ok(), commit_valid && expected <= MAX_ENTRIES, "hasher admission");
	let Ok(mut hasher) = hasher else { return };

	let commit_bytes = hex(&commit);
	let mut stream = b"loupe.inventory.v1\0".to_vec();
	stream.push(commit_bytes.len() as u8);
	stream.extend(&commit_bytes);
	stream.extend(expected.to_be_bytes());
	let mut received = 0_u64;
	let mut bytes = 0_u64;
	let mut previous: Option<Vec<u8>> = None;

	while let (Some(mode), Some(length), Some(path), Some(seed)) =
		(input.u8(), input.u8(), raw_path(&mut input), input.u8())
	{
		let mode = MODES[usize::from(mode) % MODES.len()];
		let object_id = oid(length, seed);
		let expect_entry = valid_path(path) && mode_known(mode) && valid_oid(&object_id);
		assert_eq!(is_git_oid(&object_id), valid_oid(&object_id));
		assert_eq!(is_submodule_mode(mode).ok(), mode_known(mode).then_some(mode == 0o160000));

		let entry = if flags & 4 == 0 {
			crate::fixtures::agent("", |mark, _| {
				ManifestEntry::<Agent>::new(mark, path, mode, &object_id)
			})
		} else {
			let encoded: String = path.iter().map(|byte| format!("{byte:02x}")).collect();
			let (Ok(encoded), Ok(id)) = (
				crate::fixtures::identifier::<HexPath>(&encoded),
				crate::fixtures::identifier::<ObjectId>(&object_id),
			) else {
				continue;
			};
			ManifestEntry::from_encoded(&encoded, mode, &id)
		};
		assert_eq!(entry.is_ok(), expect_entry, "manifest entry admission disagrees with oracle");
		let Ok(entry) = entry else { continue };
		assert_eq!(entry.raw_path(), path);
		assert_eq!((entry.git_mode(), entry.object_id()), (mode, object_id.as_str()));
		check_display(&entry, path);
		let id = hex(&object_id);
		let len = 4 + path.len() as u64 + 4 + 1 + id.len() as u64;
		assert_eq!(entry.canonical_len().ok(), Some(len), "canonical length disagrees");

		let accept = received < expected
			&& previous.as_deref().is_none_or(|before| before < path)
			&& bytes + len <= MAX_BYTES;
		assert_eq!(hasher.push(&entry).is_ok(), accept, "manifest push disagrees with oracle");
		if accept {
			stream.extend((path.len() as u32).to_be_bytes());
			stream.extend(path);
			stream.extend(mode.to_be_bytes());
			stream.push(id.len() as u8);
			stream.extend(&id);
			received += 1;
			bytes += len;
			previous = Some(path.to_vec());
		}
		assert_eq!(hasher.bytes(), bytes, "hasher bytes must equal the sum of canonical lengths");
		assert!(hasher.bytes() <= MAX_BYTES);
	}
	let digest = hasher.finish();
	if received == expected {
		assert_eq!(digest.ok(), Some(*blake3::hash(&stream).as_bytes()), "manifest digest");
	} else {
		assert!(digest.is_err(), "incomplete inventory must not finish");
	}
}

fn raw_path<'a>(input: &mut ByteSource<'a>) -> Option<&'a [u8]> {
	let length = usize::try_from(input.u32()?).ok()?.min(MAX_PATH_BYTES + 1);
	input.take(length)
}

fn check_display(entry: &ManifestEntry<Agent>, path: &[u8]) {
	let display = entry.display_path();
	match entry.source_path() {
		Some(source) => {
			assert_eq!(source.as_bytes(), path);
			assert_eq!(display, source);
		},
		None => {
			let expected: String = path
				.iter()
				.map(|&byte| {
					if (0x20..=0x7e).contains(&byte) {
						char::from(byte).to_string()
					} else {
						format!("%{byte:02X}")
					}
				})
				.collect();
			assert_eq!(display, expected, "display path must escape non-printable bytes");
		},
	}
}

fn oid(selector: u8, seed: u8) -> String {
	let length = OID_LENGTHS[usize::from(selector) % OID_LENGTHS.len()];
	let alphabet: &[u8] =
		if selector & 0x80 != 0 { b"0123456789ABCDEFg" } else { b"0123456789abcdef" };
	(0..length)
		.map(|index| {
			let mixed = usize::from(seed).wrapping_mul(31).wrapping_add(index * 7);
			char::from(alphabet[mixed % alphabet.len()])
		})
		.collect()
}

fn valid_oid(value: &str) -> bool {
	(value.len() == 40 || value.len() == 64)
		&& value.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn mode_known(mode: u32) -> bool {
	[0o100644, 0o100755, 0o120000, 0o160000].contains(&mode)
}

fn valid_path(path: &[u8]) -> bool {
	!path.is_empty()
		&& path.len() <= MAX_PATH_BYTES
		&& !path.contains(&0)
		&& path.split(|byte| *byte == b'/').all(|part| !matches!(part, b"" | b"." | b".."))
}

fn hex(value: &str) -> Vec<u8> {
	value
		.as_bytes()
		.chunks(2)
		.map(|pair| {
			let text = std::str::from_utf8(pair).unwrap_or_else(|_| panic!("ASCII object id"));
			u8::from_str_radix(text, 16).unwrap_or_else(|_| panic!("validated hex"))
		})
		.collect()
}

pub fn core_inventory_manifest_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn core_inventory_manifest_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
