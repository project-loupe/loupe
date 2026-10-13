//! One irreversible security decision and fake credential file per worker job.
//! The fake key is deliberately published only in /loupe/credentials.json.
//! Real watches share their original credential owners and never publish bytes.
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use loupe_core::security_event::{
	emit, Broker, CapabilityDenial, EventContext, Operation, RequestedTarget, SecretCategory,
	SecurityEvent,
};
use loupe_provenance::{Secret, Zeroise};
use rand_core::{OsRng, RngCore};
use tokio_util::sync::CancellationToken;

use crate::llm::model_broker::CredentialWatch;
use crate::sandbox::SandboxBuilder;

mod observe;
#[cfg(test)]
mod tests;

pub const SANDBOX_CANARY_FILE: &str = "/loupe/credentials.json";

// debug-ok: closed failure categories with no borrowed or owned content.
#[derive(Debug, thiserror::Error)]
pub enum CanaryError {
	#[error("creating job security entropy failed")]
	Entropy,
	#[error("creating job security file failed")]
	File,
}

// debug-ok: a unit error with a fixed operator diagnostic only.
#[derive(Debug, thiserror::Error)]
#[error("injection_suspected")]
pub struct JobQuarantined;

struct CanaryFile {
	directory: tempfile::TempDir,
	key: Secret<String>,
}

impl CanaryFile {
	fn new() -> Result<Self, CanaryError> {
		let mut seed = [0u8; 32];
		if OsRng.try_fill_bytes(&mut seed).is_err() {
			seed.zeroise();
			return Err(CanaryError::Entropy);
		}
		let mut encoded = String::with_capacity(64);
		const HEX: &[u8; 16] = b"0123456789abcdef";
		for byte in &seed {
			encoded.push(char::from(HEX[usize::from(byte >> 4)]));
			encoded.push(char::from(HEX[usize::from(byte & 15)]));
		}
		seed.zeroise();
		let key = Secret::new(encoded);
		let directory = tempfile::Builder::new()
			.prefix("loupe-job-security-")
			.tempdir()
			.map_err(|_| CanaryError::File)?;
		#[allow(
			clippy::disallowed_methods,
			reason = "private job canary directory owned by this lifetime"
		)]
		std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
			.map_err(|_| CanaryError::File)?;
		#[allow(
			clippy::disallowed_methods,
			reason = "create-new fake credential, never a real credential publication"
		)]
		let mut file = std::fs::OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o400)
			.open(directory.path().join("credentials.json"))
			.map_err(|_| CanaryError::File)?;
		file.write_all(b"{\"provider\":\"loupe-test\",\"api_key\":\"")
			.map_err(|_| CanaryError::File)?;
		file.write_all(key.expose().as_bytes()).map_err(|_| CanaryError::File)?;
		file.write_all(b"\"}\n").map_err(|_| CanaryError::File)?;
		Ok(Self { directory, key })
	}
	fn path(&self) -> PathBuf {
		self.directory.path().join("credentials.json")
	}
}

/// Shared by every scanner, CLI and broker session for a single lease.
pub struct JobSecurity {
	context: EventContext,
	quarantined: AtomicBool,
	cancel: CancellationToken,
	canary: CanaryFile,
	watches: Vec<CredentialWatch>,
}

impl std::fmt::Debug for JobSecurity {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("JobSecurity([redacted])")
	}
}

impl JobSecurity {
	pub fn new(
		context: EventContext, watches: Vec<CredentialWatch>,
	) -> Result<Arc<Self>, CanaryError> {
		Ok(Arc::new(Self {
			context,
			quarantined: AtomicBool::new(false),
			cancel: CancellationToken::new(),
			canary: CanaryFile::new()?,
			watches,
		}))
	}

	/// The only deliberate fake-key publication. The job owner must outlive
	/// the prepared command and all sessions using its read-only mount.
	pub fn mount(self: &Arc<Self>, sandbox: SandboxBuilder) -> SandboxBuilder {
		sandbox.with_canary(self.clone())
	}
	pub(crate) fn canary_mount_path(&self) -> PathBuf {
		self.canary.path()
	}

	pub fn is_quarantined(&self) -> bool {
		self.quarantined.load(Ordering::SeqCst)
	}
	pub fn cancellation(&self) -> CancellationToken {
		self.cancel.clone()
	}

	/// Non-admitting observer. NoHit changes neither syntax nor field policy.
	/// Call only on a complete record admitted by its existing byte cap.
	pub(crate) fn observe(&self, record: &[u8], broker: Broker) -> bool {
		let mut category = None;
		observe::contains(record, |run| {
			category = if contains_bytes(run, self.canary.key.expose().as_bytes()) {
				Some(SecretCategory::Canary)
			} else if self.watches.iter().any(|watch| watch.matches(run)) {
				Some(SecretCategory::HostCredential)
			} else {
				None
			};
			category.is_some()
		});
		let Some(category) = category else { return false };
		if !self.quarantined.swap(true, Ordering::SeqCst) {
			// Publish and wake first. No permit, buffer lock, logger or await
			// may delay cancellation of already pending work.
			self.cancel.cancel();
			emit(SecurityEvent::CanaryHit { context: self.context, broker, category });
		}
		true
	}

	/// Non-awaiting admission point immediately before polling a concrete hop.
	pub(crate) fn admit(&self, operation: Operation) -> Result<(), JobQuarantined> {
		if self.is_quarantined() {
			emit(SecurityEvent::CapabilityDenied {
				context: self.context,
				operation,
				requested: RequestedTarget::None,
				reason: CapabilityDenial::JobQuarantined,
			});
			Err(JobQuarantined)
		} else {
			Ok(())
		}
	}

	/// Admission is adjacent to the first poll of the actual operation. A
	/// published hit cancels pending I/O, and is checked again on resumption.
	/// No admission lock or permit is retained by this future.
	pub(crate) async fn run<T, E>(
		&self, operation: Operation, work: impl std::future::Future<Output = Result<T, E>>,
	) -> anyhow::Result<T>
	where
		anyhow::Error: From<E>,
	{
		self.admit(operation)?;
		let result = tokio::select! {
			biased;
			_ = self.cancel.cancelled() => return Err(JobQuarantined.into()),
			result = work => result,
		};
		self.admit(operation)?;
		result.map_err(anyhow::Error::from)
	}

	pub(crate) async fn lock<'a, T>(
		&self, operation: Operation, mutex: &'a tokio::sync::Mutex<T>,
	) -> anyhow::Result<tokio::sync::MutexGuard<'a, T>> {
		self.run(operation, async { Ok::<_, std::convert::Infallible>(mutex.lock().await) }).await
	}
}

pub(crate) fn contains_bytes(candidate: &[u8], needle: &[u8]) -> bool {
	!needle.is_empty() && candidate.windows(needle.len()).any(|window| window == needle)
}

/// Narrow non-admitting observer seam. The fuzzer controls original bytes and
/// a synthetic watched value; it cannot create a job, credential or sink value.
#[cfg(fuzzing)]
pub fn fuzz_observes(record: &[u8], watched: &[u8]) -> bool {
	observe::contains(record, |run| contains_bytes(run, watched))
}
