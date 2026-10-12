//! Test-only access to the real MCP request loop and filesystem validators.
//! The fuzz harness supplies an HTTP stub and a worktree with `fuzz-git`.

pub use super::ingress::fuzz_support::{observe_records, RecordObservation, RequestObservation};
pub use super::repo_ingress::fuzz_support::{observe_repo, RepoCase, RepoObservation};
use super::*;

pub struct FuzzSession(Arc<Session>);

pub struct SessionOutcome {
	pub reply: Vec<u8>,
	pub completed: bool,
	pub verdict: Option<&'static str>,
	pub patch: bool,
}

impl FuzzSession {
	pub fn new(client: Arc<ServerClient>, workdir: PathBuf, verify: bool) -> Self {
		Self(Arc::new(Session {
			client,
			workdir,
			job_capability: JobCapability::from_secret("fuzz-capability"),
			repo_id: 1,
			job_id: Some(1),
			verify: verify.then(|| VerifySessionState {
				finding_id: 1,
				inner: tokio::sync::Mutex::default(),
			}),
		}))
	}

	pub async fn run(&self, input: &[u8]) -> SessionOutcome {
		let mut reply = Vec::new();
		let completed =
			run_session(self.0.clone(), input, &mut reply, crate::limits::Limits::default())
				.await
				.is_ok();
		let (verdict, patch) = if let Some(verify) = &self.0.verify {
			let inner = verify.inner.lock().await;
			let verdict = inner.verdict.as_ref().map(|verdict| match verdict {
				loupe_core::Verdict::Confirmed { .. } => "confirmed",
				loupe_core::Verdict::Dismissed { .. } => "dismissed",
				loupe_core::Verdict::Inconclusive { .. } => "inconclusive",
			});
			(verdict, inner.patch.is_some())
		} else {
			(None, false)
		};
		SessionOutcome { reply, completed, verdict, patch }
	}
}

pub fn normalize(workdir: &Path, file: &str) -> Result<String> {
	normalize_submitted_file(workdir, file)
}

pub fn fingerprint(workdir: &Path, file: &str, start: u32, end: u32) -> String {
	fingerprint_for(workdir, file, start, end)
}

pub fn finding(workdir: &Path, args: &Value) -> Result<LlmFindingSubmission> {
	ingress::fuzz_support::finding_fixture(workdir, args)
}

pub fn catalogue(verify: bool) -> Value {
	tool_definitions(true, verify)
}
