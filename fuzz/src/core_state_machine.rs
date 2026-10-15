//! Two initial-transition bytes followed by Arbitrary pairs of job/finding
//! transition bytes. At most 1024 pairs are applied; operator retries are legal.

use arbitrary::Arbitrary;
use loupe_core::{
	initial_finding_state, initial_job_state, roll_up_verdicts, FindingState as FS,
	FindingTransition as F, JobState as JS, JobTransition as J, VerdictRollup,
};

use crate::utils::{arb, test_logger};

const JOBS: [J; 9] = [
	J::Enqueue,
	J::Lease,
	J::Heartbeat,
	J::CompleteSucceeded,
	J::CompleteFailed,
	J::Cancel,
	J::Retry,
	J::ReapToQueued,
	J::ReapToFailed,
];
const FINDINGS: [F; 12] = [
	F::ScanAccepted,
	F::ScanAutoConfirm,
	F::ScanAwaitApproval,
	F::ScanRequireVerification,
	F::VerdictConfirm,
	F::VerdictAwaitApproval,
	F::VerdictDismiss,
	F::DeadlineExpire,
	F::Approve,
	F::Reject,
	F::RetryVerification,
	F::MarkReported,
];

// Adjacency lists are an independent specification, not calls to apply().
const JOB_EDGES: [(JS, J, JS); 9] = [
	(JS::Queued, J::Lease, JS::Leased),
	(JS::Queued, J::Cancel, JS::Cancelled),
	(JS::Leased, J::Heartbeat, JS::Leased),
	(JS::Leased, J::CompleteSucceeded, JS::Succeeded),
	(JS::Leased, J::CompleteFailed, JS::Failed),
	(JS::Leased, J::Cancel, JS::Cancelled),
	(JS::Leased, J::ReapToQueued, JS::Queued),
	(JS::Leased, J::ReapToFailed, JS::Failed),
	(JS::Failed, J::Retry, JS::Queued),
];
const FINDING_EDGES: [(FS, F, FS); 13] = [
	(FS::Pending, F::ScanAutoConfirm, FS::Confirmed),
	(FS::Pending, F::ScanAwaitApproval, FS::AwaitingApproval),
	(FS::Pending, F::ScanRequireVerification, FS::Validating),
	(FS::Pending, F::RetryVerification, FS::Validating),
	(FS::Validating, F::VerdictConfirm, FS::Confirmed),
	(FS::Validating, F::VerdictAwaitApproval, FS::AwaitingApproval),
	(FS::Validating, F::VerdictDismiss, FS::Dismissed),
	(FS::Validating, F::DeadlineExpire, FS::Dismissed),
	(FS::Validating, F::RetryVerification, FS::Validating),
	(FS::AwaitingApproval, F::Approve, FS::Confirmed),
	(FS::AwaitingApproval, F::Reject, FS::Dismissed),
	(FS::Dismissed, F::RetryVerification, FS::Validating),
	(FS::Confirmed, F::MarkReported, FS::Reported),
];

#[derive(Arbitrary)]
struct Step {
	job: u8,
	finding: u8,
}

pub fn do_test(data: &[u8]) {
	check_rollups();
	let mut input = arb::unstructured(data);
	let job_initial = JOBS[usize::from(arb::draw::<u8>(&mut input).unwrap_or(0)) % JOBS.len()];
	let finding_initial =
		FINDINGS[usize::from(arb::draw::<u8>(&mut input).unwrap_or(0)) % FINDINGS.len()];
	let job = initial_job_state(job_initial);
	let finding = initial_finding_state(finding_initial);
	assert_eq!(job.as_ref().ok().copied(), (job_initial == J::Enqueue).then_some(JS::Queued));
	assert_eq!(
		finding.as_ref().ok().copied(),
		(finding_initial == F::ScanAccepted).then_some(FS::Pending)
	);
	// Invalid initial operations leave the conceptual machine absent. Start a
	// new valid instance to exercise the remaining transition bytes regardless.
	let mut job = job.unwrap_or(JS::Queued);
	let mut finding = finding.unwrap_or(FS::Pending);
	for step in arb::draw_up_to::<Step>(&mut input, 1024) {
		let action = JOBS[usize::from(step.job) % JOBS.len()];
		let expected = JOB_EDGES
			.iter()
			.find(|(from, operation, _)| *from == job && *operation == action)
			.map(|(_, _, to)| *to);
		let before = job;
		let actual = job.apply(action);
		assert_eq!(actual, action.apply(job));
		assert_eq!(actual.as_ref().ok().copied(), expected, "job transition disagrees with graph");
		if let Ok(next) = actual {
			job = next;
		} else {
			assert_eq!(job, before);
		}
		assert_eq!(job.as_str().parse::<JS>().ok(), Some(job));
		assert_eq!(job.is_terminal(), matches!(job, JS::Succeeded | JS::Failed | JS::Cancelled));

		let action = FINDINGS[usize::from(step.finding) % FINDINGS.len()];
		let expected = FINDING_EDGES
			.iter()
			.find(|(from, operation, _)| *from == finding && *operation == action)
			.map(|(_, _, to)| *to);
		let before = finding;
		let actual = finding.apply(action);
		assert_eq!(actual, action.apply(finding));
		assert_eq!(
			actual.as_ref().ok().copied(),
			expected,
			"finding transition disagrees with graph"
		);
		if let Ok(next) = actual {
			finding = next;
		} else {
			assert_eq!(finding, before);
		}
		assert_eq!(finding.as_str().parse::<FS>().ok(), Some(finding));
	}
}

fn check_rollups() {
	// Bits: confirmed, dismissed, terminal inconclusive, approval required.
	const EXPECTED: [Option<FS>; 16] = [
		None,
		Some(FS::Confirmed),
		Some(FS::Dismissed),
		Some(FS::Dismissed),
		Some(FS::Dismissed),
		Some(FS::Dismissed),
		Some(FS::Dismissed),
		Some(FS::Dismissed),
		None,
		Some(FS::AwaitingApproval),
		Some(FS::Dismissed),
		Some(FS::Dismissed),
		Some(FS::Dismissed),
		Some(FS::Dismissed),
		Some(FS::Dismissed),
		Some(FS::Dismissed),
	];
	for state in [
		FS::Pending,
		FS::Validating,
		FS::AwaitingApproval,
		FS::Confirmed,
		FS::Dismissed,
		FS::Reported,
	] {
		for (bits, expected) in EXPECTED.into_iter().enumerate() {
			let rollup = VerdictRollup {
				has_confirmed: bits & 1 != 0,
				has_dismissed: bits & 2 != 0,
				terminal_inconclusive: bits & 4 != 0,
				require_approval: bits & 8 != 0,
			};
			assert_eq!(
				roll_up_verdicts(state, rollup),
				Ok(if state == FS::Validating { expected } else { None }),
				"verdict rollup disagrees with precedence table"
			);
		}
	}
}

pub fn core_state_machine_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn core_state_machine_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
