//! Drilldown tool arguments. `finalize_drilldown` takes the server's tagged
//! terminal payload without its `version` fields, which the host supplies at
//! every level; each nested object admits only its own members.

use loupe_core::review_payload::{
	Confidence, ContinuationClass, DrilldownTerminalV1, DuplicateTarget, FindingEvidenceV1,
	L2Argument, LocationRole, MaterialLocation, PromotionV1, Revalidation, SourceCounterargument,
	SourceHardening, Version1,
};
use loupe_core::text::policy::{
	AnchorText, AssumptionsGaps, AttackerControl, AttackerSource, Cwe, DeferReason,
	DuplicateRationale, EvidenceCounterevidence, EvidenceSink, Family, HardeningArgument,
	InstanceKey, MaterialSymbol, ReachablePath, RejectionArgument, RetryExplanation,
	RevalidationRationale, ReviewFindingDescription, ReviewFindingTitle, TrustBoundary,
};
use loupe_core::text::{Anchor, Identifier};

use super::survey::{lead, payload, Args};
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
	let revalidation = match args.optional_object("revalidation")? {
		Some(fields) => {
			let nested = args.nested(&fields);
			nested.only(&["current_source_refs", "rationale"])?;
			Some(Revalidation {
				current_source_refs: nested.list("current_source_refs", 1, 16)?,
				rationale: nested
					.required::<BoundedText<RevalidationRationale, Agent>>("rationale")?,
			})
		},
		None => None,
	};
	Ok(match disposition {
		Disposition::Promote => {
			let fields = args.object("promotion")?;
			DrilldownTerminalV1::Promote {
				version: Version1,
				promotion: Box::new(promotion(&args.nested(&fields))?),
				revalidation,
			}
		},
		Disposition::Reject => {
			let fields = args.object("counterargument")?;
			let nested = args.nested(&fields);
			nested.only(&["argument", "source_refs"])?;
			DrilldownTerminalV1::Reject {
				version: Version1,
				counterargument: SourceCounterargument {
					argument: nested
						.required::<BoundedText<RejectionArgument, Agent>>("argument")?,
					source_refs: nested.list("source_refs", 1, 16)?,
				},
				revalidation,
			}
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

fn finding_evidence(args: &Args<'_, '_, '_, '_, '_>) -> Result<FindingEvidenceV1<Agent>> {
	args.only(&[
		"l2_argument",
		"material_locations",
		"counterevidence",
		"assumptions_gaps",
		"confidence",
	])?;
	let l2 = args.object("l2_argument")?;
	let l2 = args.nested(&l2);
	l2.only(&["attacker_source", "control", "sink", "reachable_path", "trust_boundary"])?;
	let mut material_locations = Vec::new();
	for raw in args.tokens("material_locations", 1, 16)? {
		let fields: Fields<'_> = raw
			.get()
			.starts_with('{')
			.then(|| serde_json::from_str(raw.get()).ok())
			.flatten()
			.context("`material_locations` entries must be objects")?;
		material_locations.push(material_location(&args.nested(&fields))?);
	}
	Ok(FindingEvidenceV1 {
		version: Version1,
		l2_argument: L2Argument {
			attacker_source: l2
				.required::<BoundedText<AttackerSource, Agent>>("attacker_source")?,
			control: l2.required::<BoundedText<AttackerControl, Agent>>("control")?,
			sink: l2.required::<BoundedText<EvidenceSink, Agent>>("sink")?,
			reachable_path: l2.required::<BoundedText<ReachablePath, Agent>>("reachable_path")?,
			trust_boundary: l2.required::<BoundedText<TrustBoundary, Agent>>("trust_boundary")?,
		},
		material_locations,
		counterevidence: args
			.required::<BoundedText<EvidenceCounterevidence, Agent>>("counterevidence")?,
		assumptions_gaps: args
			.required::<BoundedText<AssumptionsGaps, Agent>>("assumptions_gaps")?,
		confidence: args.required_closed::<Confidence>("confidence")?,
	})
}

fn material_location(args: &Args<'_, '_, '_, '_, '_>) -> Result<MaterialLocation<Agent>> {
	args.only(&["role", "file", "symbol", "line_start", "line_end"])?;
	let line = |name: &'static str| {
		args.present(name)
			.map(|raw| {
				serde_json::from_str::<u32>(raw.get())
					.ok()
					.filter(|line| *line > 0)
					.with_context(|| format!("`{name}` must be a positive integer"))
			})
			.transpose()
	};
	Ok(MaterialLocation {
		role: args.required_closed::<LocationRole>("role")?,
		file: args.required("file")?,
		symbol: args.optional::<BoundedText<MaterialSymbol, Agent>>("symbol")?,
		line_start: line("line_start")?,
		line_end: line("line_end")?,
	})
}
