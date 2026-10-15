//! LRU-evicting bare Git cache keyed by host, owner and repository.
//! Refresh uses the current lease destination; private host authentication
//! and owned locks stay alive until the actual Git operation completes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::{Context, Result};
use loupe_core::text::BoundedText;
use loupe_provenance::{Ingress, Mark, Repo, Secret, Untrusted, Unvalidated, Validate};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, info, warn};

use crate::git_credentials::GitCredentialOperation;
use crate::ingress_text::RevisionText;

const CURSOR_FILENAME: &str = ".loupe_cursor";
const CURSOR_MAGIC: &[u8] = b"LOUPE";
const CURSOR_VERSION: u8 = 1;

/// Three-tuple identifier for a cached repo. Designed to be cheap to clone
/// and hashable — used as the key in both the access log and the lock map.
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct RepoKey {
	pub host: String,
	pub owner: String,
	pub repo: String,
}
impl std::fmt::Debug for RepoKey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("RepoKey([redacted])")
	}
}

impl RepoKey {
	pub fn new(host: impl Into<String>, owner: impl Into<String>, repo: impl Into<String>) -> Self {
		let host = host.into();
		let host = host.rsplit_once('@').map_or(host.as_str(), |(_, host)| host).to_owned();
		Self { host, owner: owner.into(), repo: repo.into() }
	}
}

/// Cache of bare git clones with LRU eviction.
pub struct RepoCache {
	cache_dir: PathBuf,
	max_cache_bytes: u64,
	worker_binary: Option<PathBuf>,
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
		if let Ok(mut refs) = self.cache.refcounts.lock()
			&& let Some(n) = refs.get_mut(&self.key)
		{
			*n = n.saturating_sub(1);
			if *n == 0 {
				refs.remove(&self.key);
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
	pub fn new(
		cache_dir: PathBuf, max_cache_bytes: u64, worker_binary: Option<PathBuf>,
	) -> Result<Self> {
		#[allow(
			clippy::disallowed_methods,
			reason = "RepoCache creates its selected Config cache root before any repository operation."
		)]
		std::fs::create_dir_all(&cache_dir).context("failed to create cache directory")?;

		let mut access_log = HashMap::new();
		Self::scan_existing(&cache_dir, &mut access_log);
		debug!(repos = access_log.len(), "loupe repo cache initialized");

		Ok(Self {
			cache_dir,
			max_cache_bytes,
			worker_binary,
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
		#[allow(
			clippy::disallowed_methods,
			reason = "Cache accounting walks the selected cache root and uses entries only as cache metadata."
		)]
		let Ok(hosts) = std::fs::read_dir(cache_dir) else {
			return;
		};
		for host_entry in hosts.flatten() {
			if !host_entry.path().is_dir() {
				continue;
			}
			let host_name = host_entry.file_name().to_string_lossy().into_owned();
			#[allow(
				clippy::disallowed_methods,
				reason = "Cache accounting reads the next directory level under the selected cache root."
			)]
			let Ok(owners) = std::fs::read_dir(host_entry.path()) else {
				continue;
			};
			for owner_entry in owners.flatten() {
				if !owner_entry.path().is_dir() {
					continue;
				}
				let owner_name = owner_entry.file_name().to_string_lossy().into_owned();
				#[allow(
					clippy::disallowed_methods,
					reason = "Cache accounting reads repository entries under the selected cache hierarchy."
				)]
				let Ok(repos) = std::fs::read_dir(owner_entry.path()) else {
					continue;
				};
				for repo_entry in repos.flatten() {
					let repo_dirname = repo_entry.file_name().to_string_lossy().into_owned();
					if !repo_dirname.ends_with(".git") || !repo_entry.path().is_dir() {
						continue;
					}
					#[allow(
						clippy::string_slice,
						reason = "The preceding guard proves an ASCII .git suffix; removing four bytes ends at its boundary."
					)]
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
		#[allow(
			clippy::expect_used,
			reason = "A poisoned host lock map indicates a prior panic; creating a second per-repo lock would violate exclusion."
		)]
		let mut map = self.repo_locks.lock().expect("repo_locks mutex poisoned");
		map.entry(key.clone()).or_insert_with(|| Arc::new(AsyncMutex::new(()))).clone()
	}

	/// Ensure the bare clone for `key` is present and up-to-date.
	/// Returns the on-disk path *plus* a pin that prevents eviction
	/// while the caller is using it. Concurrent calls for the same
	/// `key` are serialised so two leases don't race the clone/fetch.
	pub async fn ensure_repo(
		self: &Arc<Self>, key: &RepoKey, clone_url: &str, token: Option<&Arc<Secret<String>>>,
	) -> Result<EnsuredRepo> {
		self.refresh(key, clone_url, token, false).await
	}

	/// Delete and freshly clone the current lease destination, returning a
	/// pinned clone even when a previous checkout found missing objects.
	pub async fn reclone_repo(
		self: &Arc<Self>, key: &RepoKey, clone_url: &str, token: Option<&Arc<Secret<String>>>,
	) -> Result<EnsuredRepo> {
		self.refresh(key, clone_url, token, true).await
	}

	async fn refresh(
		self: &Arc<Self>, key: &RepoKey, clone_url: &str, token: Option<&Arc<Secret<String>>>,
		force_clone: bool,
	) -> Result<EnsuredRepo> {
		let guard = self.repo_lock(key).lock_owned().await;
		let pin = self.pin(key);
		let cache = Arc::clone(self);
		let key = key.clone();
		let url = clone_url.to_owned();
		let token = token.cloned();
		// Cancellation drops only the awaiting future. This closure retains
		// the lock, cache pin, secret owner and helper until Git has exited.
		tokio::task::spawn_blocking(move || {
			let _guard = guard;
			let operation =
				GitCredentialOperation::new(&url, token, cache.worker_binary.as_deref())?;
			let path = cache.repo_path(&key);
			#[allow(clippy::disallowed_methods, reason = "The cache owner checks its computed repository path while holding the per-repository lock.")]
			if force_clone && path.exists() {
				#[allow(clippy::disallowed_methods, reason = "Explicit reclone removes only the selected cached repository while retaining its lock and pin.")]
				std::fs::remove_dir_all(&path).context("removing cached Git repository")?;
			}
			#[allow(clippy::disallowed_methods, reason = "The cache owner tests its selected repository path to choose fetch or clone.")]
			if path.exists() {
				info!("fetching repo updates");
				if Self::fetch_bare(&path, &operation).is_err() {
					warn!("Git refresh failed; rebuilding cache");
					#[allow(clippy::disallowed_methods, reason = "Failed refresh replaces the selected stale cache under the same lock and pin.")]
					std::fs::remove_dir_all(&path).context("removing stale Git repository")?;
					Self::clone_bare(&path, &operation)?;
				}
			} else {
				cache.evict_if_needed()?;
				if let Some(parent) = path.parent() {
					#[allow(clippy::disallowed_methods, reason = "The cache owner creates the selected repository parent under its Config cache root.")]
					std::fs::create_dir_all(parent).context("creating Git cache directory")?;
				}
				Self::clone_bare(&path, &operation)?;
			}
			if let Ok(mut log) = cache.access_log.lock() {
				log.insert(key, SystemTime::now());
			}
			Ok(EnsuredRepo { path, _pin: pin })
		})
		.await?
	}

	/// Read the cursor (last processed HEAD SHA) for `key`. Returns `None`
	/// if the file is missing, has a bad magic, or carries an unknown
	/// version — in any of those cases the caller should treat the repo
	/// as never-scanned.
	pub fn read_cursor(&self, key: &RepoKey) -> Option<BoundedText<RevisionText, Repo>> {
		let path = self.repo_path(key).join(CURSOR_FILENAME);
		#[allow(
			clippy::disallowed_methods,
			reason = "Cursor ingress reads only the fixed cursor file and then applies the named Repo decoder."
		)]
		let bytes = std::fs::read(&path).ok()?;
		// SAFETY: actual cached repository cursor bytes, before decoding.
		#[allow(unsafe_code)]
		let bytes = Untrusted::new(bytes, unsafe { Ingress::<Repo>::new() });
		bytes.as_bytes().validate(RepoCursorDecoder).ok()?.map(RepoCursor::into_revision)
	}

	/// Write the cursor for `key`. Always writes the current cursor
	/// version; older readers will refuse to parse it (which is the safe
	/// behaviour — they'll do a fresh full scan).
	pub fn write_cursor(&self, key: &RepoKey, sha: &str) -> Result<()> {
		let path = self.repo_path(key).join(CURSOR_FILENAME);
		let bytes = encode_cursor(sha);
		#[allow(
			clippy::disallowed_methods,
			reason = "The cache owner persists the versioned cursor at the fixed repository cursor path."
		)]
		std::fs::write(&path, bytes).context("failed to write repository cursor")?;
		Ok(())
	}

	/// Clone via the `git` CLI rather than libgit2.
	///
	/// libgit2's `file://` transport doesn't use the local-clone fast
	/// path that git CLI does (hardlink pack files, copy refs verbatim).
	/// On a ~500 MB Rust workspace that's the difference between
	/// **~0.4s** (git CLI) and **~7m** (libgit2). HTTPS clones are also
	/// modestly faster via git CLI (parallel delta resolution, bitmap
	/// support) but the gap there is single-digit-x rather than 1000x.
	///
	/// Authentication uses only the operation's private host helper.
	fn clone_bare(path: &Path, operation: &GitCredentialOperation) -> Result<()> {
		let (mut command, destination) = operation.transport_command(None)?;
		#[allow(
			clippy::disallowed_methods,
			reason = "Git clone executes the destination-scoped credential command with stderr and stdout discarded."
		)]
		let status = command
			.args([
				"clone",
				"--bare",
				"--quiet",
				"--template=",
				"--origin=origin",
				"--",
				&destination,
			])
			.arg(path)
			.status()
			.context("starting Git clone")?;
		if !status.success() {
			anyhow::bail!("Git clone failed ({status})");
		}
		Self::replace_origin(path, operation)
	}

	fn replace_origin(path: &Path, operation: &GitCredentialOperation) -> Result<()> {
		// Never read a legacy origin into memory. Replace every value from
		// the current validated destination before any network command,
		// including refreshes whose lease contains no PAT.
		#[allow(
			clippy::disallowed_methods,
			reason = "Origin remediation executes only the fixed local Git configuration operation."
		)]
		let status = operation
			.command()
			.current_dir(path)
			.args(["config", "--local", "--replace-all", "remote.origin.url", &operation.url])
			.status()
			.context("starting Git origin remediation")?;
		if !status.success() {
			anyhow::bail!("Git origin remediation failed ({status})");
		}
		Ok(())
	}

	fn fetch_bare(path: &Path, operation: &GitCredentialOperation) -> Result<()> {
		Self::replace_origin(path, operation)?;
		let (mut command, destination) = operation.transport_command(Some(path))?;
		#[allow(
			clippy::disallowed_methods,
			reason = "Git fetch executes the destination-scoped credential command with fixed refspecs."
		)]
		let status = command
			.args([
				"fetch",
				"--quiet",
				"--prune",
				"--tags",
				&destination,
				"+refs/heads/*:refs/heads/*",
				"+refs/heads/*:refs/remotes/origin/*",
				"+HEAD:refs/remotes/origin/HEAD",
			])
			.status()
			.context("starting Git fetch")?;
		if !status.success() {
			anyhow::bail!("Git fetch failed ({status})");
		}
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
				#[allow(
					clippy::disallowed_methods,
					reason = "Cache eviction checks only selected unpinned repository candidates."
				)]
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
			#[allow(
				clippy::disallowed_methods,
				reason = "Cache eviction removes only a selected unpinned repository under the Config cache root."
			)]
			if std::fs::remove_dir_all(&path).is_err() {
				warn!("failed to evict repo");
				continue;
			}
			info!(size_mb = size / (1024 * 1024), "evicted cached repo");
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
fn cursor_text(bytes: &[u8]) -> Option<&str> {
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
		Some(s)
	}
}

struct RepoCursor(BoundedText<RevisionText, Repo>);
struct RepoCursorDecoder;
impl Validate<&[u8], Repo> for RepoCursorDecoder {
	type Output = Option<RepoCursor>;
	type Error = std::convert::Infallible;
	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, mark: Mark<'view, Repo>,
	) -> Result<Self::Output, Self::Error> {
		Ok(cursor_text(u.get()).and_then(|text| BoundedText::new(&mark, text).ok()).map(RepoCursor))
	}
}
impl RepoCursor {
	/// Keep the cursor's Repo provenance when handing its revision to the runner.
	fn into_revision(self) -> BoundedText<RevisionText, Repo> {
		self.0
	}
}

/// Exercise the persisted cursor and credential context boundary.
#[cfg(fuzzing)]
pub mod fuzz_support {
	#[allow(unsafe_code)]
	pub fn decode_cursor(bytes: &[u8]) -> Option<String> {
		use super::*;
		// SAFETY: cfg-only original Repo cursor fixture bytes, before decoding.
		let original = Untrusted::new(bytes, unsafe { Ingress::<Repo>::new() });
		original.validate(RepoCursorDecoder).unwrap().map(|v| v.into_revision().expose().to_owned())
	}

	pub fn encode_cursor(sha: &str) -> Vec<u8> {
		super::encode_cursor(sha)
	}

	pub fn matches_credential_context(url: &str, frame: &[u8]) -> bool {
		crate::git_credentials::matches_context(url, frame)
	}
}

/// Recursively compute the size of a directory in bytes.
pub fn dir_size(path: &Path) -> u64 {
	let mut total = 0u64;
	#[allow(
		clippy::disallowed_methods,
		reason = "Cache size accounting reads directory entries solely to aggregate byte counts."
	)]
	let Ok(entries) = std::fs::read_dir(path) else {
		return total;
	};
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
	#[test]
	fn cache_diagnostics_omit_configured_root() {
		if !crate::test_env::in_env(
			"repo_cache::tests::cache_diagnostics_omit_configured_root",
			"cache-i8",
			&[],
		) {
			return;
		}
		let capture = crate::test_support::LogCapture::default();
		capture.install();
		let directory =
			tempfile::Builder::new().prefix("private-cache-root-sentinel-").tempdir().unwrap();
		let _cache = super::RepoCache::new(directory.path().to_owned(), 1024, None).unwrap();
		let logs = capture.text();
		assert!(
			logs.contains("repo cache initialized"),
			"capture must observe real cache initialization"
		);
		assert!(
			!logs.contains("private-cache-root-sentinel"),
			"configured cache path leaked into host logs"
		);
	}
	#[test]
	fn cache_path_errors_omit_original_bytes_from_the_chain() {
		let directory = tempfile::tempdir().unwrap();
		let occupied = directory.path().join("private-cache-path-sentinel");
		std::fs::write(&occupied, "occupied").unwrap();
		let error = super::RepoCache::new(occupied.join("cache"), 1024, None).err().unwrap();
		assert!(
			!format!("{error:#}").contains("private-cache-path-sentinel"),
			"cache path leaked through the public error chain"
		);
	}

	#[test]
	fn cache_key_debug_omits_repository_components() {
		let key =
			super::RepoKey::new("github.com", "private-owner-sentinel", "private-repo-sentinel");
		let debug = format!("{key:?}");
		assert!(
			!debug.contains("private-owner-sentinel") && !debug.contains("private-repo-sentinel"),
			"repository key bytes leaked through Debug"
		);
	}
	use std::process::Command;
	use std::sync::Arc;

	use super::*;

	fn git(dir: &Path, args: &[&str]) -> String {
		let output = Command::new("git").current_dir(dir).args(args).output().unwrap();
		assert!(
			output.status.success(),
			"git {:?} in {} failed: {}",
			args,
			dir.display(),
			String::from_utf8_lossy(&output.stderr)
		);
		String::from_utf8_lossy(&output.stdout).trim().to_owned()
	}

	fn init_git_repo(path: &Path) {
		std::fs::create_dir_all(path).unwrap();
		let output = Command::new("git")
			.current_dir(path)
			.args(["init", "-q", "-b", "main"])
			.output()
			.unwrap();
		assert!(
			output.status.success(),
			"git init failed: {}",
			String::from_utf8_lossy(&output.stderr)
		);
		git(path, &["config", "user.email", "loupe-test@example.com"]);
		git(path, &["config", "user.name", "loupe-test"]);
	}

	fn commit_file(repo: &Path, contents: &str, message: &str) -> String {
		std::fs::write(repo.join("file.txt"), contents).unwrap();
		git(repo, &["add", "file.txt"]);
		git(repo, &["commit", "-q", "-m", message]);
		git(repo, &["rev-parse", "HEAD"])
	}

	#[test]
	fn repo_path_includes_host() {
		let tmp = tempfile::tempdir().unwrap();
		let cache = RepoCache::new(tmp.path().to_path_buf(), u64::MAX, None).unwrap();
		let path = cache.repo_path(&RepoKey::new("github.com", "acme", "widget"));
		assert_eq!(path, tmp.path().join("github.com").join("acme").join("widget.git"));
	}

	#[test]
	fn repo_key_does_not_expose_host_userinfo_credentials() {
		let tmp = tempfile::tempdir().unwrap();
		let cache = RepoCache::new(tmp.path().to_path_buf(), u64::MAX, None).unwrap();
		let token = "ghp_repo_path_leak_canary";
		let key = RepoKey::new(format!("x-access-token:{token}@github.com"), "acme", "widget");
		let path = cache.repo_path(&key);

		assert_eq!(key.host, "github.com", "repo key retained credential-bearing userinfo");
		assert!(
			!path.to_string_lossy().contains(token),
			"cache path leaked credential-bearing host userinfo: {}",
			path.display(),
		);
	}

	#[test]
	fn fetch_bare_advances_branch_and_remote_head_refs() {
		let remote_tmp = tempfile::tempdir().unwrap();
		init_git_repo(remote_tmp.path());
		commit_file(remote_tmp.path(), "one\n", "One");

		let cache_tmp = tempfile::tempdir().unwrap();
		let bare = cache_tmp.path().join("cache.git");
		let url = format!("file://{}", remote_tmp.path().display());
		RepoCache::clone_bare(&bare, &GitCredentialOperation::new(&url, None, None).unwrap())
			.unwrap();

		let second = commit_file(remote_tmp.path(), "two\n", "Two");
		RepoCache::fetch_bare(&bare, &GitCredentialOperation::new(&url, None, None).unwrap())
			.unwrap();

		assert_eq!(git(&bare, &["rev-parse", "refs/heads/main"]), second);
		assert_eq!(git(&bare, &["rev-parse", "refs/remotes/origin/main"]), second);
		assert_eq!(git(&bare, &["rev-parse", "refs/remotes/origin/HEAD"]), second);
	}

	#[tokio::test]
	async fn ensure_repo_reclones_when_cache_dir_was_evicted() {
		let remote_tmp = tempfile::tempdir().unwrap();
		init_git_repo(remote_tmp.path());
		let head = commit_file(remote_tmp.path(), "one\n", "One");

		let cache_tmp = tempfile::tempdir().unwrap();
		let cache =
			Arc::new(RepoCache::new(cache_tmp.path().to_path_buf(), u64::MAX, None).unwrap());
		let key = RepoKey::new("local", "local", "repo");
		let url = format!("file://{}", remote_tmp.path().display());

		let first = cache.ensure_repo(&key, &url, None).await.unwrap();
		let bare = first.path.clone();
		drop(first);
		std::fs::remove_dir_all(&bare).unwrap();

		let second = cache.ensure_repo(&key, &url, None).await.unwrap();
		assert!(second.path.exists());
		assert_eq!(git(&second.path, &["rev-parse", "HEAD"]), head);
	}

	#[tokio::test]
	async fn reclone_repo_replaces_stale_cache_with_fresh_clone() {
		let remote_tmp = tempfile::tempdir().unwrap();
		init_git_repo(remote_tmp.path());
		commit_file(remote_tmp.path(), "one\n", "One");

		let cache_tmp = tempfile::tempdir().unwrap();
		let cache =
			Arc::new(RepoCache::new(cache_tmp.path().to_path_buf(), u64::MAX, None).unwrap());
		let key = RepoKey::new("local", "local", "repo");
		let url = format!("file://{}", remote_tmp.path().display());

		let first = cache.ensure_repo(&key, &url, None).await.unwrap();
		assert!(first.path.exists());
		drop(first);

		let second_head = commit_file(remote_tmp.path(), "two\n", "Two");
		let fresh = cache.reclone_repo(&key, &url, None).await.unwrap();
		assert_eq!(git(&fresh.path, &["rev-parse", "HEAD"]), second_head);
	}

	#[test]
	fn cursor_round_trips() {
		let tmp = tempfile::tempdir().unwrap();
		let cache = RepoCache::new(tmp.path().to_path_buf(), u64::MAX, None).unwrap();
		let key = RepoKey::new("github.com", "acme", "widget");
		std::fs::create_dir_all(cache.repo_path(&key)).unwrap();

		assert!(cache.read_cursor(&key).is_none());
		cache.write_cursor(&key, "abc123def456").unwrap();
		assert_eq!(cache.read_cursor(&key).as_ref().map(|v| v.expose()), Some("abc123def456"));
	}

	#[test]
	fn cursor_repo_text_rejects_new_control_policy() {
		let tmp = tempfile::tempdir().unwrap();
		let cache = RepoCache::new(tmp.path().to_path_buf(), u64::MAX, None).unwrap();
		let key = RepoKey::new("local", "owner", "repo");
		std::fs::create_dir_all(cache.repo_path(&key)).unwrap();
		cache.write_cursor(&key, "bad\u{1}revision").unwrap();
		assert!(cache.read_cursor(&key).is_none(), "Repo cursor control bytes were admitted");
		cache.write_cursor(&key, " base ").unwrap();
		assert_eq!(cache.read_cursor(&key).as_ref().map(|v| v.expose()), Some("base"));
	}

	#[test]
	fn cursor_with_unknown_magic_is_ignored() {
		let tmp = tempfile::tempdir().unwrap();
		let cache = RepoCache::new(tmp.path().to_path_buf(), u64::MAX, None).unwrap();
		let key = RepoKey::new("github.com", "acme", "widget");
		std::fs::create_dir_all(cache.repo_path(&key)).unwrap();
		std::fs::write(cache.repo_path(&key).join(CURSOR_FILENAME), b"BKB\x01\nabc123").unwrap();
		assert!(cache.read_cursor(&key).is_none(), "foreign magic must not parse as a cursor");
	}

	#[test]
	fn cursor_with_future_version_is_ignored() {
		let tmp = tempfile::tempdir().unwrap();
		let cache = RepoCache::new(tmp.path().to_path_buf(), u64::MAX, None).unwrap();
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
		let cache = RepoCache::new(cache_dir, 1500, None).unwrap();
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

		let cache = std::sync::Arc::new(RepoCache::new(cache_dir, 1500, None).unwrap());
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
			std::sync::Arc::new(RepoCache::new(tmp.path().to_path_buf(), u64::MAX, None).unwrap());
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
		let cache = RepoCache::new(tmp.path().to_path_buf(), u64::MAX, None).unwrap();
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
