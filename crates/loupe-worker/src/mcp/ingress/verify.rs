//! Verify tool arguments. `finalize_verification` takes the server's tagged
//! terminal payload without the fields that have one accepted value, which
//! the host supplies: every `version`, the established rung, the end-to-end
//! applicability and the blocker for missing proof infrastructure.

use loupe_core::review_payload::{
	ContinuationClass, PartialSourceEvidence, PreProofApplicability, PreProofRung,
	VerificationTerminalV1, Version1, AWAITING_PROOF_INFRASTRUCTURE,
};
use loupe_core::text::policy::{
	ApplicabilityRationale, Argument, RetryExplanation, ReviewNotes, VerificationBlocker,
};
use loupe_proto::review_verification::VerificationVerdict;

use super::phase::{counterargument, finding_evidence, payload, revalidation, Args, Content};
use super::*;

pub(super) fn arguments(
	u: &Unvalidated<'_, &[u8], Sandbox>, fields: &Fields<'_>,
) -> Result<Arguments> {
	let args = Args { u, fields, top_level: true };
	let terminal = payload(terminal(&args)?, |terminal| terminal.canonical_bytes())?;
	Ok(Arguments::FinalizeVerification(Box::new(terminal)))
}

/// A continuation class, with the blocker of the class that has a fixed one.
struct Continuation {
	class: ContinuationClass,
	blocker: Option<BoundedText<VerificationBlocker, Agent>>,
}
impl Content for Continuation {
	fn admit(mark: &Mark<'_, Agent>, raw: &RawValue) -> Result<Self> {
		let class = serde_json::from_str(raw.get())
			.map_err(|_| anyhow::anyhow!("`continuation` argument is not an accepted value"))?;
		let blocker = (class == ContinuationClass::AwaitingProofInfrastructure)
			// A host constant; the Agent label only lowers its trust.
			.then(|| BoundedText::new(mark, AWAITING_PROOF_INFRASTRUCTURE))
			.transpose()?;
		Ok(Self { class, blocker })
	}
}

fn terminal(args: &Args<'_, '_, '_, '_, '_>) -> Result<VerificationTerminalV1<Agent>> {
	Ok(match args.required_closed::<VerificationVerdict>("verdict")? {
		VerificationVerdict::Verified => {
			args.only(&["verdict", "e2e_rationale", "evidence", "revalidation", "notes"])?;
			let evidence = args.object("evidence")?;
			VerificationTerminalV1::Verified {
				version: Version1,
				established_rung: PreProofRung::L2,
				e2e_applicability: PreProofApplicability::NotApplicable,
				e2e_rationale: args
					.required::<BoundedText<ApplicabilityRationale, Agent>>("e2e_rationale")?,
				evidence: Box::new(finding_evidence(&args.nested(&evidence))?),
				revalidation: revalidation(args)?,
				notes: notes(args)?,
			}
		},
		VerificationVerdict::Rejected => {
			args.only(&["verdict", "counterargument", "revalidation", "notes"])?;
			VerificationTerminalV1::Rejected {
				version: Version1,
				counterargument: counterargument(args)?,
				revalidation: revalidation(args)?,
				notes: notes(args)?,
			}
		},
		VerificationVerdict::Inconclusive => inconclusive(args)?,
	})
}

fn inconclusive(args: &Args<'_, '_, '_, '_, '_>) -> Result<VerificationTerminalV1<Agent>> {
	let Continuation { class, blocker } = args.required::<Continuation>("continuation")?;
	let mut allowed = vec![
		"verdict",
		"continuation",
		"partial_evidence",
		"retry_explanation",
		"revalidation",
		"notes",
	];
	if blocker.is_none() {
		allowed.push("blocker");
	}
	args.only(&allowed)?;
	Ok(VerificationTerminalV1::Inconclusive {
		version: Version1,
		blocker: match blocker {
			Some(blocker) => blocker,
			None => args.required::<BoundedText<VerificationBlocker, Agent>>("blocker")?,
		},
		continuation: class,
		partial_evidence: partial_evidence(args)?,
		retry_explanation: args
			.optional::<BoundedText<RetryExplanation, Agent>>("retry_explanation")?,
		revalidation: revalidation(args)?,
		notes: notes(args)?,
	})
}

fn partial_evidence(
	args: &Args<'_, '_, '_, '_, '_>,
) -> Result<Option<PartialSourceEvidence<Agent>>> {
	let Some(fields) = args.optional_object("partial_evidence")? else { return Ok(None) };
	let nested = args.nested(&fields);
	nested.only(&["argument", "source_refs"])?;
	Ok(Some(PartialSourceEvidence {
		argument: nested.required::<BoundedText<Argument, Agent>>("argument")?,
		source_refs: nested.list("source_refs", 1, 16)?,
	}))
}

fn notes(args: &Args<'_, '_, '_, '_, '_>) -> Result<Option<BoundedText<ReviewNotes, Agent>>> {
	args.optional::<BoundedText<ReviewNotes, Agent>>("notes")
}
