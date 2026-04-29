//! LRU-evicting cache of bare git clones, ported from
//! bkb-ingest/src/repo_cache.rs and adapted for loupe.
//!
//! Differences from the bkb-ingest original:
//!
//! - Layout is keyed on `(host, owner, repo)` so we can scan repos hosted
//!   somewhere other than github.com without colliding.
//! - Clone URL is supplied by the caller (the daemon hands it over in the
//!   lease response) rather than constructed from `owner/repo`.
//! - Cursor sidecar is `.loupe_cursor`, prefixed with a `LOUPE\x01` magic
//!   so an unrecognised version forces a clean re-fetch instead of letting
//!   the worker mis-parse a future format.
//! - Concurrent leases against the same repo are serialised by a per-repo
//!   `tokio::sync::Mutex` keyed in an in-memory map, so two scan jobs
//!   don't race the bare clone.
//! - Repo-size enforcement is the **server's** job (it checks via the
//!   GitHub API at registration time); the worker no longer carries an
//!   HTTP client just to reject oversized repos.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::{Context, Result};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, info, warn};

const CURSOR_FILENAME: &str = ".loupe_cursor";
const CURSOR_MAGIC: &[u8] = b"LOUPE";
const CURSOR_VERSION: u8 = 1;

/// Three-tuple identifier for a cached repo. Designed to be cheap to clone
/// and hashable — used as the key in both the access log and the lock map.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct RepoKey {
	pub host: String,
	pub owner: String,
	pub repo: String,
}

impl RepoKey {
	pub fn new(host: impl Into<String>, owner: impl Into<String>, repo: impl Into<String>) -> Self {
		Self { host: host.into(), owner: owner.into(), repo: repo.into() }
	}
}

/// Cache of bare git clones with LRU eviction.
pub struct RepoCache {
	cache_dir: PathBuf,
	max_cache_bytes: u64,
	access_log: Mutex<HashMap<RepoKey, SystemTime>>,
	repo_locks: Mutex<HashMap<RepoKey, Arc<AsyncMutex<()>>>>,
	/// Per-repo refcount of in-flight workers using the bare clone as
	/// the alternate for a worktree. Eviction skips any key with a
	/// non-zero refcount so a running scan doesn't get its alternate
	/// yanked out from underneath it.
	refcounts: Mutex<HashMap<RepoKey, u32>>,
}

/// RAII pin returned by [`RepoCache::pin`] (also held inside
/// [`EnsuredRepo`]). While alive, eviction will skip the underlying
/// repo. Drops decrement the refcount.
pub struct PinGuard {
	cache: Arc<RepoCache>,
	key: RepoKey,
}

impl Drop for PinGuard {
	fn drop(&mut self) {
		if let Ok(mut refs) = self.cache.refcounts.lock() {
			if let Some(n) = refs.get_mut(&self.key) {
				*n = n.saturating_sub(1);
				if *n == 0 {
					refs.remove(&self.key);
				}
			}
		}
	}
}

/// Result of `ensure_repo`: the bare clone path plus a pin that holds
/// off eviction for the lifetime of the scan. Keep the guard alive
/// until you're done reading from the worktree.
pub struct EnsuredRepo {
	pub path: PathBuf,
	pub _pin: PinGuard,
}

impl RepoCache {
	/// Create a new cache rooted at `cache_dir`. Existing repos under that
	/// path are picked up and added to the access log using their on-disk
	/// mtime, so a worker restart doesn't lose its eviction order.
	pub fn new(cache_dir: PathBuf, max_cache_bytes: u64) -> Result<Self> {
		std::fs::create_dir_all(&cache_dir)
			.with_context(|| format!("failed to create cache dir: {}", cache_dir.display()))?;

		let mut access_log = HashMap::new();
		Self::scan_existing(&cache_dir, &mut access_log);
		debug!(cache_dir = %cache_dir.display(), repos = access_log.len(), "loupe repo cache initialized");

		Ok(Self {
			cache_dir,
			max_cache_bytes,
			access_log: Mutex::new(access_log),
			repo_locks: Mutex::new(HashMap::new()),
			refcounts: Mutex::new(HashMap::new()),
		})
	}

	/// Pin a repo so it survives an eviction pass. Returns an RAII
	/// guard; while alive the entry is skipped by `evict_if_needed`.
	pub fn pin(self: &Arc<Self>, key: &RepoKey) -> PinGuard {
		if let Ok(mut refs) = self.refcounts.lock() {
			*refs.entry(key.clone()).or_insert(0) += 1;
		}
		PinGuard { cache: Arc::clone(self), key: key.clone() }
	}

	fn is_pinned(&self, key: &RepoKey) -> bool {
		self.refcounts.lock().map(|r| r.get(key).copied().unwrap_or(0) > 0).unwrap_or(false)
	}

	fn scan_existing(cache_dir: &Path, access_log: &mut HashMap<RepoKey, SystemTime>) {
		let Ok(hosts) = std::fs::read_dir(cache_dir) else { return };
		for host_entry in hosts.flatten() {
			if !host_entry.path().is_dir() {
				continue;
			}
			let host_name = host_entry.file_name().to_string_lossy().into_owned();
			let Ok(owners) = std::fs::read_dir(host_entry.path()) else { continue };
			for owner_entry in owners.flatten() {
				if !owner_entry.path().is_dir() {
					continue;
				}
				let owner_name = owner_entry.file_name().to_string_lossy().into_owned();
				let Ok(repos) = std::fs::read_dir(owner_entry.path()) else { continue };
				for repo_entry in repos.flatten() {
					let repo_dirname = repo_entry.file_name().to_string_lossy().into_owned();
					if !repo_dirname.ends_with(".git") || !repo_entry.path().is_dir() {
						continue;
					}
					let repo_stem = repo_dirname[..repo_dirname.len() - 4].to_owned();
					let mtime = repo_entry
						.metadata()
						.ok()
						.and_then(|m| m.modified().ok())
						.unwrap_or(SystemTime::UNIX_EPOCH);
					access_log.insert(
						RepoKey::new(host_name.clone(), owner_name.clone(), repo_stem),
						mtime,
					);
				}
			}
		}
	}

	/// Path where the bare clone for `key` would live.
	pub fn repo_path(&self, key: &RepoKey) -> PathBuf {
		self.cache_dir.join(&key.host).join(&key.owner).join(format!("{}.git", key.repo))
	}

	fn repo_lock(&self, key: &RepoKey) -> Arc<AsyncMutex<()>> {
		let mut map = self.repo_locks.lock().expect("repo_locks mutex poisoned");
		map.entry(key.clone()).or_insert_with(|| Arc::new(AsyncMutex::new(()))).clone()
	}

	/// Ensure the bare clone for `key` is present and up-to-date.
	/// Returns the on-disk path *plus* a pin that prevents eviction
	/// while the caller is using it. Concurrent calls for the same
	/// `key` are serialised so two leases don't race the clone/fetch.
	pub async fn ensure_repo(
		self: &Arc<Self>, key: &RepoKey, clone_url: &str, token: Option<&str>,
	) -> Result<EnsuredRepo> {
		let path = self.repo_path(key);
		let lock = self.repo_lock(key);
		let _guard = lock.lock().await;

		if path.exists() {
			let fp = path.clone();
			let ft = token.map(String::from);
			let res =
				tokio::task::spawn_blocking(move || Self::fetch_bare(&fp, ft.as_deref())).await?;
			match res {
				Ok(()) => {
					debug!(host = %key.host, owner = %key.owner, repo = %key.repo, "fetched updates")
				},
				Err(e) => {
					warn!(host = %key.host, owner = %key.owner, repo = %key.repo, error = %e, "cached repo corrupted, re-cloning");
					let _ = std::fs::remove_dir_all(&path);
					self.do_clone(&path, clone_url, token).await?;
				},
			}
		} else {
			self.evict_if_needed()?;
			if let Some(parent) = path.parent() {
				std::fs::create_dir_all(parent).with_context(|| {
					format!("failed to create cache parent dir: {}", parent.display())
				})?;
			}
			self.do_clone(&path, clone_url, token).await?;
			info!(host = %key.host, owner = %key.owner, repo = %key.repo, "cloned new bare repo");
		}

		if let Ok(mut log) = self.access_log.lock() {
			log.insert(key.clone(), SystemTime::now());
		}
		let pin = self.pin(key);
		Ok(EnsuredRepo { path, _pin: pin })
	}

	async fn do_clone(&self, path: &Path, clone_url: &str, token: Option<&str>) -> Result<()> {
		let path = path.to_owned();
		let clone_url = clone_url.to_owned();
		let token = token.map(String::from);
		tokio::task::spawn_blocking(move || Self::clone_bare(&path, &clone_url, token.as_deref()))
			.await??;
		Ok(())
	}

	/// Read the cursor (last processed HEAD SHA) for `key`. Returns `None`
	/// if the file is missing, has a bad magic, or carries an unknown
	/// version — in any of those cases the caller should treat the repo
	/// as never-scanned.
	pub fn read_cursor(&self, key: &RepoKey) -> Option<String> {
		let path = self.repo_path(key).join(CURSOR_FILENAME);
		let bytes = std::fs::read(&path).ok()?;
		decode_cursor(&bytes)
	}

	/// Write the cursor for `key`. Always writes the current cursor
	/// version; older readers will refuse to parse it (which is the safe
	/// behaviour — they'll do a fresh full scan).
	pub fn write_cursor(&self, key: &RepoKey, sha: &str) -> Result<()> {
		let path = self.repo_path(key).join(CURSOR_FILENAME);
		let bytes = encode_cursor(sha);
		std::fs::write(&path, bytes)
			.with_context(|| format!("failed to write cursor to {}", path.display()))?;
		Ok(())
	}

	fn clone_bare(path: &Path, clone_url: &str, token: Option<&str>) -> Result<()> {
		let mut callbacks = git2::RemoteCallbacks::new();
		if let Some(token) = token {
			let token = token.to_string();
			callbacks.credentials(move |_url, _username, _allowed| {
				git2::Cred::userpass_plaintext("x-access-token", &token)
			});
		}
		let mut fetch_opts = git2::FetchOptions::new();
		fetch_opts.remote_callbacks(callbacks);
		let mut builder = git2::build::RepoBuilder::new();
		builder.bare(true);
		builder.fetch_options(fetch_opts);
		builder.clone(clone_url, path).map_err(|e| {
			anyhow::anyhow!(
				"git2 clone {} failed: {} (class={}, code={})",
				clone_url,
				e.message(),
				e.class() as i32,
				e.code() as i32,
			)
		})?;
		Ok(())
	}

	fn fetch_bare(path: &Path, token: Option<&str>) -> Result<()> {
		let git_repo = git2::Repository::open_bare(path)
			.with_context(|| format!("failed to open bare repo at {}", path.display()))?;
		let mut remote =
			git_repo.find_remote("origin").context("no 'origin' remote in cached bare repo")?;

		let mut callbacks = git2::RemoteCallbacks::new();
		if let Some(token) = token {
			let token = token.to_string();
			callbacks.credentials(move |_url, _username, _allowed| {
				git2::Cred::userpass_plaintext("x-access-token", &token)
			});
		}
		let mut fetch_opts = git2::FetchOptions::new();
		fetch_opts.remote_callbacks(callbacks);

		let refspecs: Vec<String> =
			remote.refspecs().filter_map(|r| r.str().map(String::from)).collect();
		let refspec_strs: Vec<&str> = refspecs.iter().map(|s| s.as_str()).collect();
		remote
			.fetch(&refspec_strs, Some(&mut fetch_opts), None)
			.context("fetch from origin failed")?;
		Ok(())
	}

	/// Evict least-recently-used repos until total cache size is under
	/// the configured limit.
	pub fn evict_if_needed(&self) -> Result<()> {
		let total_size = dir_size(&self.cache_dir);
		if total_size <= self.max_cache_bytes {
			return Ok(());
		}

		let mut entries: Vec<(RepoKey, SystemTime, u64)> = Vec::new();
		if let Ok(log) = self.access_log.lock() {
			for (key, &access_time) in log.iter() {
				if self.is_pinned(key) {
					continue;
				}
				let path = self.repo_path(key);
				if path.exists() {
					entries.push((key.clone(), access_time, dir_size(&path)));
				}
			}
		}
		entries.sort_by_key(|(_, t, _)| *t);

		let mut freed = 0u64;
		let target = total_size.saturating_sub(self.max_cache_bytes);
		for (key, _, size) in &entries {
			if freed >= target {
				break;
			}
			let path = self.repo_path(key);
			if let Err(e) = std::fs::remove_dir_all(&path) {
				warn!(host = %key.host, owner = %key.owner, repo = %key.repo, error = %e, "failed to evict repo");
				continue;
			}
			info!(host = %key.host, owner = %key.owner, repo = %key.repo, size_mb = size / (1024 * 1024), "evicted cached repo");
			freed += size;
			if let Ok(mut log) = self.access_log.lock() {
				log.remove(key);
			}
		}
		Ok(())
	}
}

/// Encode a cursor file: `LOUPE\x01\n<sha>`.
fn encode_cursor(sha: &str) -> Vec<u8> {
	let mut out = Vec::with_capacity(CURSOR_MAGIC.len() + 2 + sha.len());
	out.extend_from_slice(CURSOR_MAGIC);
	out.push(CURSOR_VERSION);
	out.push(b'\n');
	out.extend_from_slice(sha.trim().as_bytes());
	out
}

/// Decode a cursor file. Returns `None` on missing magic, unknown
/// version, malformed body, or empty SHA.
fn decode_cursor(bytes: &[u8]) -> Option<String> {
	let header_len = CURSOR_MAGIC.len() + 2;
	if bytes.len() < header_len {
		return None;
	}
	if &bytes[..CURSOR_MAGIC.len()] != CURSOR_MAGIC {
		return None;
	}
	if bytes[CURSOR_MAGIC.len()] != CURSOR_VERSION {
		return None;
	}
	if bytes[CURSOR_MAGIC.len() + 1] != b'\n' {
		return None;
	}
	let body = &bytes[header_len..];
	let s = std::str::from_utf8(body).ok()?.trim();
	if s.is_empty() {
		None
	} else {
		Some(s.to_owned())
	}
}

/// Recursively compute the size of a directory in bytes.
pub fn dir_size(path: &Path) -> u64 {
	let mut total = 0u64;
	let Ok(entries) = std::fs::read_dir(path) else { return total };
	for entry in entries.flatten() {
		let Ok(ft) = entry.file_type() else { continue };
		if ft.is_file() {
			total += entry.metadata().map(|m| m.len()).unwrap_or(0);
		} else if ft.is_dir() {
			total += dir_size(&entry.path());
		}
	}
	total
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn repo_path_includes_host() {
		let tmp = tempfile::tempdir().unwrap();
		let cache = RepoCache::new(tmp.path().to_path_buf(), u64::MAX).unwrap();
		let path = cache.repo_path(&RepoKey::new("github.com", "acme", "widget"));
		assert_eq!(path, tmp.path().join("github.com").join("acme").join("widget.git"));
	}

	#[test]
	fn cursor_round_trips() {
		let tmp = tempfile::tempdir().unwrap();
		let cache = RepoCache::new(tmp.path().to_path_buf(), u64::MAX).unwrap();
		let key = RepoKey::new("github.com", "acme", "widget");
		std::fs::create_dir_all(cache.repo_path(&key)).unwrap();

		assert!(cache.read_cursor(&key).is_none());
		cache.write_cursor(&key, "abc123def456").unwrap();
		assert_eq!(cache.read_cursor(&key).as_deref(), Some("abc123def456"));
	}

	#[test]
	fn cursor_with_unknown_magic_is_ignored() {
		let tmp = tempfile::tempdir().unwrap();
		let cache = RepoCache::new(tmp.path().to_path_buf(), u64::MAX).unwrap();
		let key = RepoKey::new("github.com", "acme", "widget");
		std::fs::create_dir_all(cache.repo_path(&key)).unwrap();
		std::fs::write(cache.repo_path(&key).join(CURSOR_FILENAME), b"BKB\x01\nabc123").unwrap();
		assert!(cache.read_cursor(&key).is_none(), "foreign magic must not parse as a cursor");
	}

	#[test]
	fn cursor_with_future_version_is_ignored() {
		let tmp = tempfile::tempdir().unwrap();
		let cache = RepoCache::new(tmp.path().to_path_buf(), u64::MAX).unwrap();
		let key = RepoKey::new("github.com", "acme", "widget");
		std::fs::create_dir_all(cache.repo_path(&key)).unwrap();
		std::fs::write(cache.repo_path(&key).join(CURSOR_FILENAME), b"LOUPE\x09\nabc123").unwrap();
		assert!(cache.read_cursor(&key).is_none(), "unknown version must force a re-scan");
	}

	#[test]
	fn evict_drops_least_recently_used() {
		let tmp = tempfile::tempdir().unwrap();
		let cache_dir = tmp.path().to_path_buf();
		let key1 = RepoKey::new("github.com", "owner1", "repo1");
		let key2 = RepoKey::new("github.com", "owner2", "repo2");
		let p1 = cache_dir.join("github.com").join("owner1").join("repo1.git");
		let p2 = cache_dir.join("github.com").join("owner2").join("repo2.git");
		std::fs::create_dir_all(&p1).unwrap();
		std::fs::create_dir_all(&p2).unwrap();
		std::fs::write(p1.join("data"), vec![0u8; 1000]).unwrap();
		std::fs::write(p2.join("data"), vec![0u8; 1000]).unwrap();

		// Total ~2KB, limit 1.5KB ⇒ one repo must go.
		let cache = RepoCache::new(cache_dir, 1500).unwrap();
		{
			let mut log = cache.access_log.lock().unwrap();
			log.insert(key1.clone(), SystemTime::UNIX_EPOCH);
			log.insert(key2.clone(), SystemTime::now());
		}
		cache.evict_if_needed().unwrap();
		assert!(!p1.exists(), "LRU entry should have been evicted");
		assert!(p2.exists(), "more-recent entry should survive");
	}

	#[test]
	fn evict_skips_pinned_entries() {
		let tmp = tempfile::tempdir().unwrap();
		let cache_dir = tmp.path().to_path_buf();
		let key1 = RepoKey::new("github.com", "owner1", "repo1");
		let key2 = RepoKey::new("github.com", "owner2", "repo2");
		let p1 = cache_dir.join("github.com").join("owner1").join("repo1.git");
		let p2 = cache_dir.join("github.com").join("owner2").join("repo2.git");
		std::fs::create_dir_all(&p1).unwrap();
		std::fs::create_dir_all(&p2).unwrap();
		std::fs::write(p1.join("data"), vec![0u8; 1000]).unwrap();
		std::fs::write(p2.join("data"), vec![0u8; 1000]).unwrap();

		let cache = std::sync::Arc::new(RepoCache::new(cache_dir, 1500).unwrap());
		{
			let mut log = cache.access_log.lock().unwrap();
			log.insert(key1.clone(), SystemTime::UNIX_EPOCH);
			log.insert(key2.clone(), SystemTime::now());
		}
		// Pin the LRU entry; eviction must skip it and pick the other.
		let _pin = cache.pin(&key1);
		cache.evict_if_needed().unwrap();
		assert!(p1.exists(), "pinned entry must survive even when LRU");
		assert!(!p2.exists(), "an unpinned entry must be evicted instead");
	}

	#[test]
	fn pin_drop_releases_refcount() {
		let tmp = tempfile::tempdir().unwrap();
		let cache =
			std::sync::Arc::new(RepoCache::new(tmp.path().to_path_buf(), u64::MAX).unwrap());
		let key = RepoKey::new("github.com", "a", "b");
		assert!(!cache.is_pinned(&key));
		{
			let _pin = cache.pin(&key);
			assert!(cache.is_pinned(&key));
		}
		assert!(!cache.is_pinned(&key), "drop must decrement");
	}

	#[test]
	fn evict_is_a_no_op_when_under_limit() {
		let tmp = tempfile::tempdir().unwrap();
		let cache = RepoCache::new(tmp.path().to_path_buf(), u64::MAX).unwrap();
		// No files, no entries — evict_if_needed should silently return Ok.
		cache.evict_if_needed().unwrap();
	}

	#[test]
	fn dir_size_recurses() {
		let tmp = tempfile::tempdir().unwrap();
		let dir = tmp.path();
		std::fs::write(dir.join("file1"), vec![0u8; 100]).unwrap();
		std::fs::create_dir(dir.join("sub")).unwrap();
		std::fs::write(dir.join("sub").join("file2"), vec![0u8; 200]).unwrap();
		assert!(dir_size(dir) >= 300);
	}
}
