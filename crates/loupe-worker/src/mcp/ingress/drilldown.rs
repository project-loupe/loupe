//! Drilldown tool arguments. `finalize_drilldown` takes the server's tagged
//! terminal payload without its `version` fields, which the host supplies at
//! every level; each nested object admits only its own members.

use loupe_core::review_payload::{
	ContinuationClass, DrilldownTerminalV1, DuplicateTarget, PromotionV1, SourceHardening, Version1,
};
use loupe_core::text::policy::{
	AnchorText, Cwe, DeferReason, DuplicateRationale, Family, HardeningArgument, InstanceKey,
	RetryExplanation, ReviewFindingDescription, ReviewFindingTitle,
};
use loupe_core::text::{Anchor, Identifier};

use super::phase::{counterargument, finding_evidence, lead, payload, revalidation, Args};
use super::*;

pub(super) fn arguments(
	u: &Unvalidated<'_, &[u8], Sandbox>, name: &ToolName, fields: &Fields<'_>,
) -> Result<Arguments> {
	let args = Args { u, fields, top_level: true };
	Ok(match name {
		ToolName::SiblingLead => Arguments::SiblingLead(Box::new(lead(&args, false)?)),
		ToolName::FinalizeDrilldown => {
			Arguments::FinalizeDrilldown(Box::new(payload(terminal(&args)?, |terminal| {
				terminal.canonical_bytes()
			})?))
		},
		_ => return Err(UnknownTool.into()),
	})
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Disposition {
	Promote,
	Reject,
	Duplicate,
	Hardening,
	Defer,
}

fn terminal(args: &Args<'_, '_, '_, '_, '_>) -> Result<DrilldownTerminalV1<Agent>> {
	let disposition = args.required_closed::<Disposition>("disposition")?;
	let allowed: &[&'static str] = match disposition {
		Disposition::Promote => &["disposition", "promotion", "revalidation"],
		Disposition::Reject => &["disposition", "counterargument", "revalidation"],
		Disposition::Duplicate => &["disposition", "target", "rationale", "revalidation"],
		Disposition::Hardening => &["disposition", "explanation", "revalidation"],
		Disposition::Defer => {
			&["disposition", "reason", "continuation", "retry_explanation", "revalidation"]
		},
	};
	args.only(allowed)?;
	let revalidation = revalidation(args)?;
	Ok(match disposition {
		Disposition::Promote => {
			let fields = args.object("promotion")?;
			DrilldownTerminalV1::Promote {
				version: Version1,
				promotion: Box::new(promotion(&args.nested(&fields))?),
				revalidation,
			}
		},
		Disposition::Reject => DrilldownTerminalV1::Reject {
			version: Version1,
			counterargument: counterargument(args)?,
			revalidation,
		},
		Disposition::Duplicate => DrilldownTerminalV1::Duplicate {
			version: Version1,
			target: args.required_closed::<DuplicateTarget>("target")?,
			rationale: args.required::<BoundedText<DuplicateRationale, Agent>>("rationale")?,
			revalidation,
		},
		Disposition::Hardening => {
			let fields = args.object("explanation")?;
			let nested = args.nested(&fields);
			nested.only(&["argument", "source_refs"])?;
			DrilldownTerminalV1::Hardening {
				version: Version1,
				explanation: SourceHardening {
					argument: nested
						.required::<BoundedText<HardeningArgument, Agent>>("argument")?,
					source_refs: nested.list("source_refs", 1, 16)?,
				},
				revalidation,
			}
		},
		Disposition::Defer => DrilldownTerminalV1::Defer {
			version: Version1,
			reason: args.required::<BoundedText<DeferReason, Agent>>("reason")?,
			continuation: args.required_closed::<ContinuationClass>("continuation")?,
			retry_explanation: args
				.optional::<BoundedText<RetryExplanation, Agent>>("retry_explanation")?,
			revalidation,
		},
	})
}

fn promotion(args: &Args<'_, '_, '_, '_, '_>) -> Result<PromotionV1<Agent>> {
	args.only(&[
		"severity",
		"title",
		"description",
		"identity_family",
		"identity_anchor",
		"identity_instance_key",
		"evidence",
		"cwe",
	])?;
	let evidence = args.object("evidence")?;
	Ok(PromotionV1 {
		version: Version1,
		severity: args.required_closed("severity")?,
		title: args.required::<BoundedText<ReviewFindingTitle, Agent>>("title")?,
		description: args
			.required::<BoundedText<ReviewFindingDescription, Agent>>("description")?,
		identity_family: args.required::<Identifier<Family, Agent>>("identity_family")?,
		identity_anchor: args.required::<Anchor<AnchorText, Agent>>("identity_anchor")?,
		identity_instance_key: args
			.optional::<Anchor<InstanceKey, Agent>>("identity_instance_key")?,
		evidence: finding_evidence(&args.nested(&evidence))?,
		cwe: args.optional::<Identifier<Cwe, Agent>>("cwe")?,
	})
}
