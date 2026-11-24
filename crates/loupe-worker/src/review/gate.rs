//! Admission of review-phase tool calls from the attempt's host state. One
//! pure decision per phase, so the broker, its tests and the Kani harnesses
//! share it.

/// The survey catalog's tools.
// debug-ok: closed tool names only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SurveyTool {
	JobLimits,
	PublishProfile,
	ProposeUnit,
	Lead,
	UnitResult,
	Disposition,
	Candidates,
	Finalize,
}

impl SurveyTool {
	#[cfg(any(test, kani))]
	pub(crate) const ALL: [Self; 8] = [
		Self::JobLimits,
		Self::PublishProfile,
		Self::ProposeUnit,
		Self::Lead,
		Self::UnitResult,
		Self::Disposition,
		Self::Candidates,
		Self::Finalize,
	];

	/// Tools whose writes or answers depend on a published profile.
	pub(crate) const fn needs_profile(self) -> bool {
		matches!(
			self,
			Self::ProposeUnit
				| Self::Lead
				| Self::UnitResult
				| Self::Disposition
				| Self::Candidates
		)
	}

	/// Tools that open new inquiry, closed once `submit_by` has passed.
	pub(crate) const fn opens_inquiry(self) -> bool {
		matches!(self, Self::ProposeUnit | Self::Candidates)
	}
}

/// The drilldown catalog's tools.
// debug-ok: closed tool names only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrilldownTool {
	JobLimits,
	Candidates,
	SiblingLead,
	Finalize,
}

impl DrilldownTool {
	#[cfg(any(test, kani))]
	pub(crate) const ALL: [Self; 4] =
		[Self::JobLimits, Self::Candidates, Self::SiblingLead, Self::Finalize];
}

/// Which survey recipe family the attempt runs.
// debug-ok: closed recipe class only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipeClass {
	Bootstrap,
	Ordinary,
}

// debug-ok: closed denial reasons only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
	Allow,
	Deny(Denial),
}

/// Why a call is refused; each maps to one fixed text for the model.
// debug-ok: closed denial reasons only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Denial {
	Sealed,
	NotBootstrap,
	AlreadyPublished,
	ProfileFirst,
	SoftStop,
	DrilldownSealed,
	SiblingSoftStop,
}

impl Denial {
	pub(crate) const fn text(self) -> &'static str {
		match self {
			Self::Sealed => SEALED,
			Self::NotBootstrap => NOT_BOOTSTRAP,
			Self::AlreadyPublished => ALREADY_PUBLISHED,
			Self::ProfileFirst => PROFILE_FIRST,
			Self::SoftStop => SOFT_STOP,
			Self::DrilldownSealed => DRILLDOWN_SEALED,
			Self::SiblingSoftStop => SIBLING_SOFT_STOP,
		}
	}
}

pub(crate) const SEALED: &str =
	"the survey is already finalized; only get_job_limits and an identical finalize_survey replay are accepted";
pub(crate) const NOT_BOOTSTRAP: &str =
	"publish_profile is only available to a bootstrap survey; this survey already has its profile";
pub(crate) const ALREADY_PUBLISHED: &str =
	"the profile is already published for this generation and cannot be replaced";
pub(crate) const PROFILE_FIRST: &str =
	"publish the repository profile with publish_profile before this call";
pub(crate) const SOFT_STOP: &str =
	"soft stop reached: submit_by has passed, so no new review units or candidate queries; record remaining leads, results and dispositions, then call finalize_survey";

pub(crate) const DRILLDOWN_SEALED: &str =
	"the drilldown is already finalized; only get_job_limits and an identical finalize_drilldown replay are accepted; end the session";
pub(crate) const SIBLING_SOFT_STOP: &str =
	"soft stop reached: submit_by has passed, so submit_sibling_lead is closed; finalize now with finalize_drilldown (an unfinished investigation is finalized as defer with continuation source_analysis_remaining)";

/// Drilldown admission: a sealed receipt leaves only `get_job_limits` and
/// an identical finalize replay; `submit_by` closes only sibling leads, as
/// a `duplicate` finalize depends on the candidate query.
pub(crate) fn admit_drilldown(
	tool: DrilldownTool, past_submit_by: bool, receipt_sealed: bool,
) -> Admission {
	if receipt_sealed {
		return match tool {
			DrilldownTool::JobLimits | DrilldownTool::Finalize => Admission::Allow,
			_ => Admission::Deny(Denial::DrilldownSealed),
		};
	}
	if past_submit_by && tool == DrilldownTool::SiblingLead {
		return Admission::Deny(Denial::SiblingSoftStop);
	}
	Admission::Allow
}

pub(crate) fn admit(
	tool: SurveyTool, recipe: RecipeClass, profile_published: bool, past_submit_by: bool,
	receipt_sealed: bool,
) -> Admission {
	if receipt_sealed {
		return match tool {
			SurveyTool::JobLimits | SurveyTool::Finalize => Admission::Allow,
			_ => Admission::Deny(Denial::Sealed),
		};
	}
	if tool == SurveyTool::PublishProfile {
		return match (recipe, profile_published) {
			(RecipeClass::Ordinary, _) => Admission::Deny(Denial::NotBootstrap),
			(RecipeClass::Bootstrap, true) => Admission::Deny(Denial::AlreadyPublished),
			(RecipeClass::Bootstrap, false) => Admission::Allow,
		};
	}
	if past_submit_by && tool.opens_inquiry() {
		return Admission::Deny(Denial::SoftStop);
	}
	if recipe == RecipeClass::Bootstrap && !profile_published && tool.needs_profile() {
		return Admission::Deny(Denial::ProfileFirst);
	}
	Admission::Allow
}

#[cfg(test)]
mod tests {
	use SurveyTool::*;

	use super::*;

	fn allowed(tool: SurveyTool, recipe: RecipeClass, published: bool, late: bool) -> bool {
		admit(tool, recipe, published, late, false) == Admission::Allow
	}

	#[test]
	fn a_sealed_receipt_admits_only_limits_and_finalize() {
		for tool in SurveyTool::ALL {
			for recipe in [RecipeClass::Bootstrap, RecipeClass::Ordinary] {
				for published in [false, true] {
					for late in [false, true] {
						let expected = if matches!(tool, JobLimits | Finalize) {
							Admission::Allow
						} else {
							Admission::Deny(Denial::Sealed)
						};
						assert_eq!(
							admit(tool, recipe, published, late, true),
							expected,
							"{tool:?}"
						);
					}
				}
			}
		}
	}

	#[test]
	fn bootstrap_writes_wait_for_the_profile() {
		for tool in [ProposeUnit, Lead, UnitResult, Disposition, Candidates] {
			assert_eq!(
				admit(tool, RecipeClass::Bootstrap, false, false, false),
				Admission::Deny(Denial::ProfileFirst),
				"{tool:?}"
			);
			assert!(allowed(tool, RecipeClass::Bootstrap, true, false), "{tool:?}");
			assert!(allowed(tool, RecipeClass::Ordinary, false, false), "{tool:?}");
		}
		for tool in [JobLimits, Finalize] {
			assert!(allowed(tool, RecipeClass::Bootstrap, false, false), "{tool:?}");
		}
	}

	#[test]
	fn publish_profile_is_bootstrap_only_and_once() {
		assert!(allowed(PublishProfile, RecipeClass::Bootstrap, false, false));
		assert!(allowed(PublishProfile, RecipeClass::Bootstrap, false, true));
		assert_eq!(
			admit(PublishProfile, RecipeClass::Bootstrap, true, false, false),
			Admission::Deny(Denial::AlreadyPublished)
		);
		for published in [false, true] {
			assert_eq!(
				admit(PublishProfile, RecipeClass::Ordinary, published, false, false),
				Admission::Deny(Denial::NotBootstrap)
			);
		}
	}

	#[test]
	fn soft_stop_closes_exactly_new_units_and_candidate_queries() {
		for recipe in [RecipeClass::Bootstrap, RecipeClass::Ordinary] {
			for tool in [ProposeUnit, Candidates] {
				assert_eq!(
					admit(tool, recipe, true, true, false),
					Admission::Deny(Denial::SoftStop)
				);
			}
			for tool in [JobLimits, Lead, UnitResult, Disposition, Finalize] {
				assert!(allowed(tool, recipe, true, true), "{tool:?}");
			}
		}
	}

	#[test]
	fn a_sealed_drilldown_admits_only_limits_and_finalize() {
		for tool in DrilldownTool::ALL {
			for late in [false, true] {
				let expected = if matches!(tool, DrilldownTool::JobLimits | DrilldownTool::Finalize)
				{
					Admission::Allow
				} else {
					Admission::Deny(Denial::DrilldownSealed)
				};
				assert_eq!(admit_drilldown(tool, late, true), expected, "{tool:?}");
			}
		}
	}

	#[test]
	fn drilldown_soft_stop_closes_only_sibling_leads() {
		for tool in DrilldownTool::ALL {
			assert_eq!(admit_drilldown(tool, false, false), Admission::Allow, "{tool:?}");
			let expected = if tool == DrilldownTool::SiblingLead {
				Admission::Deny(Denial::SiblingSoftStop)
			} else {
				Admission::Allow
			};
			assert_eq!(admit_drilldown(tool, true, false), expected, "{tool:?}");
		}
	}

	#[test]
	fn drilldown_denials_point_at_finalize_drilldown() {
		assert!(Denial::DrilldownSealed.text().contains("finalize_drilldown"));
		assert!(Denial::DrilldownSealed.text().contains("get_job_limits"));
		let soft = Denial::SiblingSoftStop.text();
		assert!(soft.contains("submit_sibling_lead") && soft.contains("finalize_drilldown"));
		assert!(soft.contains("source_analysis_remaining"));
	}

	#[test]
	fn every_denial_names_a_way_forward() {
		let denials = [
			Denial::Sealed,
			Denial::NotBootstrap,
			Denial::AlreadyPublished,
			Denial::ProfileFirst,
			Denial::SoftStop,
		];
		for denial in denials {
			assert!(!denial.text().is_empty());
		}
		assert!(Denial::SoftStop.text().contains("finalize_survey"));
		assert!(Denial::ProfileFirst.text().contains("publish_profile"));
	}
}
