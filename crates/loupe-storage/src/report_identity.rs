//! Private row identity, independent of SQLite's recyclable integer IDs.

use rand_core::{OsRng, RngCore};

pub(crate) const BYTES: usize = 16;

pub(crate) fn generate() -> rusqlite::Result<[u8; BYTES]> {
	let mut identity = [0; BYTES];
	OsRng.try_fill_bytes(&mut identity).map_err(|_| {
		rusqlite::Error::SqliteFailure(
			rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
			Some("finding report identity entropy unavailable".into()),
		)
	})?;
	Ok(identity)
}
