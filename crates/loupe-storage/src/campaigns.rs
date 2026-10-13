//! Canonical campaign lifecycle and generation-independent terminal snapshots.
use loupe_core::text::policy::{Payload, Reason, RevisionText};
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_provenance::{Db, Source};
use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::review::{changed, classify, optional, parsed, string_enum};
use crate::{ownership, Conflict, Entity, Error, Ownership, Result};

string_enum!(Recipe { Bootstrap => "bootstrap", Incremental => "incremental", Reconciliation => "reconciliation", Corroboration => "corroboration" });
string_enum!(Trigger { Manual => "manual", Scheduled => "scheduled", CompatScanApi => "compat_scan_api", Reconciliation => "reconciliation", Operator => "operator" });
string_enum!(State { Active => "active", Finished => "finished", Cancelled => "cancelled" });

/// Submitted metadata retains its owner. Resolved policy contains only the
/// fixed numeric scheduler schema, never caller-supplied text or JSON.
pub enum CampaignPolicyInput<'a, S: Source> {
	Submitted(&'a BoundedJson<Payload, S>),
	Resolved(&'a crate::scheduler::CampaignPolicy),
}
impl<S: Source> CampaignPolicyInput<'_, S> {
	fn canonical(&self) -> Vec<u8> {
		match self {
			Self::Submitted(value) => value.canonical().to_vec(),
			Self::Resolved(value) => {
				#[expect(
					clippy::expect_used,
					reason = "CampaignPolicy contains only fixed keys and integer fields; its derived serializer cannot fail"
				)]
				let json = serde_json::to_value(value).expect("numeric campaign policy serializes");
				loupe_core::canonical::canonical_bytes(&json)
			},
		}
	}
}

pub struct NewCampaign<'a, RevisionS: Source, PolicyS: Source> {
	pub recipe: Recipe,
	pub trigger: Trigger,
	pub requested_base_sha: Option<&'a BoundedText<RevisionText, RevisionS>>,
	pub target_commit_sha: &'a BoundedText<RevisionText, RevisionS>,
	pub generation_id: Option<i64>,
	pub effective_policy: CampaignPolicyInput<'a, PolicyS>,
	pub deadline_at: Option<i64>,
	pub root_campaign_id: Option<i64>,
	pub continuation_of_campaign_id: Option<i64>,
}
// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug, Clone)]
pub struct Campaign {
	pub campaign_id: i64,
	pub repo_id: i64,
	pub recipe: Recipe,
	pub trigger: Trigger,
	pub requested_base_sha: Option<BoundedText<RevisionText, Db>>,
	pub target_commit_sha: BoundedText<RevisionText, Db>,
	pub generation_id: Option<i64>,
	pub state: State,
	pub terminal_reason: Option<BoundedText<Reason, Db>>,
	pub effective_policy: BoundedJson<Payload, Db>,
	pub deadline_at: Option<i64>,
	pub root_campaign_id: Option<i64>,
	pub continuation_of_campaign_id: Option<i64>,
	pub coverage_at_finish: Option<crate::generations::Coverage>,
	pub terminal_counts: Option<BoundedJson<Payload, Db>>,
	pub created_at: i64,
	pub finished_at: Option<i64>,
}
// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalSummary {
	campaign_id: i64,
	pub coverage: crate::generations::Coverage,
	pub counts: CampaignCounts,
}

type CountGroup = Vec<(loupe_core::text::Identifier<loupe_core::text::policy::JsonKey, Db>, i64)>;
// debug-ok: JobCount contains redacted Db text owners and one count.
#[derive(Debug, Clone, PartialEq, Eq)]
struct JobCount {
	kind: BoundedText<loupe_core::text::policy::JobKindName, Db>,
	leaf: BoundedText<loupe_core::text::policy::JsonLeaf, Db>,
	state: BoundedText<loupe_core::text::policy::JsonLeaf, Db>,
	count: i64,
}
/// Closed SQL-count composition. Its only constructor consumes actual typed
/// row observations; cached rendering is never minted as a new Db input.
#[derive(Clone, PartialEq, Eq)]
pub struct CampaignCounts {
	jobs: Vec<JobCount>,
	lead_status: CountGroup,
	lead_disposition: CountGroup,
	findings: CountGroup,
	verdicts: CountGroup,
	canonical: String,
}
impl std::fmt::Debug for CampaignCounts {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("CampaignCounts(Db, [redacted])")
	}
}
impl CampaignCounts {
	pub fn expose(&self) -> &str {
		&self.canonical
	}
	fn finish(mut self) -> Result<Self> {
		use loupe_core::text::{JsonPolicy, Rule};
		let groups = [&self.lead_status, &self.lead_disposition, &self.findings, &self.verdicts];
		// This closed schema has seven container nodes, four nodes per job,
		// one per grouped scalar, and depth four. Keys are not JSON nodes.
		let nodes =
			groups.iter().fold(7usize.saturating_add(self.jobs.len().saturating_mul(4)), |n, g| {
				n.saturating_add(g.len())
			});
		let render = |normalized: bool| {
			let group = |values: &CountGroup| {
				values
					.iter()
					.map(|(key, n)| (key.expose().to_owned(), serde_json::Value::from(*n)))
					.collect::<serde_json::Map<_, _>>()
			};
			let jobs: Vec<_> = self.jobs.iter().map(|job| serde_json::json!({ "kind": if normalized { job.leaf.expose() } else { job.kind.expose() }, "state": job.state, "count": job.count })).collect();
			serde_json::json!({ "jobs": jobs, "leads": { "status": group(&self.lead_status), "disposition": group(&self.lead_disposition) }, "findings": group(&self.findings), "verdicts": group(&self.verdicts) })
		};
		if render(false).to_string().len() > Payload::MAX_BYTES {
			return Err(loupe_core::text::Error::new(Payload::FIELD, Rule::Bytes).into());
		}
		if nodes > Payload::MAX_NODES {
			return Err(loupe_core::text::Error::new(Payload::FIELD, Rule::JsonNodes).into());
		}
		let canonical = loupe_core::canonical::canonical_bytes(&render(true));
		if canonical.len() > Payload::MAX_BYTES {
			return Err(loupe_core::text::Error::new(Payload::FIELD, Rule::Bytes).into());
		}
		self.canonical = String::from_utf8(canonical)
			.map_err(|_| loupe_core::text::Error::new(Payload::FIELD, Rule::JsonSyntax))?;
		Ok(self)
	}
}

const COLUMNS: &str = "campaign_id,repo_id,recipe,trigger,requested_base_sha,target_commit_sha,generation_id,state,terminal_reason,effective_policy,deadline_at,root_campaign_id,continuation_of_campaign_id,coverage_at_finish,terminal_counts,created_at,finished_at";
fn row(r: &Row<'_>) -> rusqlite::Result<Campaign> {
	Ok(Campaign {
		campaign_id: r.get(0)?,
		repo_id: r.get(1)?,
		recipe: parsed(r, 2)?,
		trigger: parsed(r, 3)?,
		requested_base_sha: crate::ingress::optional_revision(r, 4)?,
		target_commit_sha: crate::ingress::revision(r, 5)?,
		generation_id: r.get(6)?,
		state: parsed(r, 7)?,
		terminal_reason: crate::ingress::optional_reason(r, 8)?,
		effective_policy: crate::ingress::db_payload(r, 9)?,
		deadline_at: r.get(10)?,
		root_campaign_id: r.get(11)?,
		continuation_of_campaign_id: r.get(12)?,
		coverage_at_finish: optional(r, 13)?,
		terminal_counts: crate::ingress::optional_db_payload(r, 14)?,
		created_at: r.get(15)?,
		finished_at: r.get(16)?,
	})
}

pub(crate) fn validate_stored_rows(conn: &Connection) -> Result<()> {
	crate::migrations::admission::scan(conn, "review_campaigns", COLUMNS, |r| -> Result<()> {
		let campaign = row(r)?;
		crate::scheduler::CampaignPolicy::from_snapshot(&campaign.effective_policy).map_err(
			|_| {
				crate::migrations::MigrationFailure::new(
					crate::migrations::MigrationStage::Admission,
					crate::migrations::MigrationReason::CampaignPolicy,
				)
				.at("review_campaigns", "effective_policy", None)
			},
		)?;
		Ok(())
	})?;
	crate::migrations::admission::scan(conn, "review_campaigns", "effective_policy_digest", |_| {
		Ok::<_, rusqlite::Error>(())
	})
}
pub fn create<RevisionS: Source, PolicyS: Source>(
	scope: &crate::scope::RepoScope<'_>, new: &NewCampaign<'_, RevisionS, PolicyS>, now: i64,
) -> Result<i64> {
	scope.require_operator()?;
	let tx = scope.conn;
	if let Some(id) = new.generation_id {
		ownership::generation(tx, scope.repo_id, id, Ownership::CampaignGeneration)?;
	}
	if let Some(id) = new.root_campaign_id {
		ownership::campaign(tx, scope.repo_id, id, Ownership::CampaignRoot)?;
	}
	if let Some(id) = new.continuation_of_campaign_id {
		ownership::campaign(tx, scope.repo_id, id, Ownership::CampaignContinuation)?;
	}
	let policy = new.effective_policy.canonical();
	#[expect(
		clippy::expect_used,
		reason = "both private CampaignPolicyInput branches return only canonical JSON UTF-8"
	)]
	let policy_text = std::str::from_utf8(&policy).expect("canonical policy is UTF-8");
	let policy_digest = loupe_core::canonical::digest(&policy);
	tx.execute("INSERT INTO review_campaigns (repo_id,recipe,trigger,requested_base_sha,target_commit_sha,generation_id,state,effective_policy,effective_policy_digest,deadline_at,root_campaign_id,continuation_of_campaign_id,created_at)
	VALUES (?1,?2,?3,?4,?5,?6,'active',?7,?8,?9,?10,?11,?12)", params![scope.repo_id,new.recipe.as_str(),new.trigger.as_str(),new.requested_base_sha.map(BoundedText::expose),new.target_commit_sha.expose(),new.generation_id,policy_text,policy_digest.as_slice(),new.deadline_at,new.root_campaign_id,new.continuation_of_campaign_id,now])
		.map_err(|e| classify(e,"review_campaigns.repo_id",Conflict::ActiveCampaign))?;
	Ok(tx.last_insert_rowid())
}
pub(crate) fn get_raw(conn: &Connection, id: i64) -> Result<Option<Campaign>> {
	Ok(conn
		.query_row(
			&format!("SELECT {COLUMNS} FROM review_campaigns WHERE campaign_id=?1"),
			[id],
			row,
		)
		.optional()?)
}

pub fn get(scope: &crate::scope::RepoScope<'_>, id: i64) -> Result<Option<Campaign>> {
	Ok(scope
		.conn
		.query_row(
			&format!("SELECT {COLUMNS} FROM review_campaigns WHERE campaign_id=?1 AND repo_id=?2"),
			params![id, scope.repo_id],
			row,
		)
		.optional()?)
}
pub fn list_for_repo(scope: &crate::scope::RepoScope<'_>) -> Result<Vec<Campaign>> {
	let tx = scope.conn;
	Ok(tx.prepare(&format!("SELECT {COLUMNS} FROM review_campaigns WHERE repo_id=?1 ORDER BY created_at DESC,campaign_id DESC"))?.query_map([scope.repo_id],row)?.collect::<rusqlite::Result<_>>()?)
}
fn counts(scope: &crate::scope::RepoScope<'_>, sql: &str, id: Option<i64>) -> Result<CountGroup> {
	let tx = scope.conn;
	let mut object = Vec::new();
	let mut statement = tx.prepare(sql)?;
	for pair in statement.query_map(params![id, scope.repo_id], |r| {
		Ok((crate::ingress::count_json_key(r, 0)?, r.get::<_, i64>(1)?))
	})? {
		let (key, count) = pair?;
		object.push((key, count));
	}
	Ok(object)
}
pub fn summarize(scope: &crate::scope::RepoScope<'_>, id: i64) -> Result<TerminalSummary> {
	let tx = scope.conn;
	let campaign = get(scope, id)?.ok_or(Error::NotFound(Entity::Campaign, id))?;
	let coverage = if let Some(generation) = campaign.generation_id {
		ownership::generation(tx, campaign.repo_id, generation, Ownership::CampaignGeneration)?;
		crate::generations::get(scope, generation)?
			.ok_or(Error::NotFound(Entity::Generation, generation))?
			.coverage
	} else {
		crate::generations::Coverage::Unknown
	};
	// Job kinds are unconstrained text (future kinds stay readable after a
	// rollback) and would not pass the JSON object-key policy, so they are
	// values in an array, never keys. The other grouping columns are
	// CHECK-constrained snake_case and remain object keys.
	let mut jobs = Vec::new();
	let mut statement = tx.prepare(
		"SELECT kind,state,COUNT(*) FROM jobs WHERE campaign_id=?1 AND repo_id=?2
		 GROUP BY kind,state ORDER BY kind,state",
	)?;
	for record in statement.query_map(params![id, scope.repo_id], |r| {
		Ok(JobCount {
			kind: crate::ingress::job_kind_text(r, 0)?,
			leaf: crate::ingress::count_json_leaf(r, 0)?,
			state: crate::ingress::count_json_leaf(r, 1)?,
			count: r.get::<_, i64>(2)?,
		})
	})? {
		jobs.push(record?);
	}
	let generation = campaign.generation_id;
	let counts = CampaignCounts { jobs,
		lead_status: counts(scope,"SELECT status,COUNT(*) FROM leads WHERE generation_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=leads.generation_id AND g.repo_id=?2) GROUP BY status",generation)?,
		lead_disposition: counts(scope,"SELECT disposition,COUNT(*) FROM leads WHERE generation_id=?1 AND EXISTS(SELECT 1 FROM review_generations g WHERE g.generation_id=leads.generation_id AND g.repo_id=?2) AND disposition IS NOT NULL GROUP BY disposition",generation)?,
		findings: counts(scope,"SELECT f.state,COUNT(*) FROM findings f JOIN finding_review_details d ON d.finding_id=f.id JOIN leads l ON l.lead_id=d.origin_lead_id WHERE l.generation_id=?1 AND f.repo_id=?2 GROUP BY f.state",generation)?,
		verdicts: counts(scope,"SELECT v.verdict,COUNT(*) FROM finding_verifications v JOIN finding_review_details d ON d.finding_id=v.finding_id JOIN leads l ON l.lead_id=d.origin_lead_id WHERE l.generation_id=?1 AND EXISTS(SELECT 1 FROM findings f WHERE f.id=v.finding_id AND f.repo_id=?2) GROUP BY v.verdict",generation)?, canonical: String::new() }.finish()?;
	Ok(TerminalSummary { campaign_id: id, coverage, counts })
}
pub fn finish<S: Source>(
	scope: &crate::scope::RepoScope<'_>, id: i64, summary: &TerminalSummary,
	reason: &BoundedText<Reason, S>, now: i64,
) -> Result<()> {
	scope.require_operator()?;
	finish_with_reason(scope, id, summary, reason.expose(), now)
}
/// Scheduler outcomes are closed host facts, not attributed input text.
// debug-ok: completion reasons are closed host scheduling outcomes.
#[derive(Debug, Clone, Copy)]
pub enum FinishedReason {
	Completed,
	Deadline,
}
pub(crate) fn finish_scheduled(
	scope: &crate::scope::RepoScope<'_>, id: i64, summary: &TerminalSummary,
	reason: FinishedReason, now: i64,
) -> Result<()> {
	scope.require_operator()?;
	finish_with_reason(
		scope,
		id,
		summary,
		match reason {
			FinishedReason::Completed => "completed",
			FinishedReason::Deadline => "deadline",
		},
		now,
	)
}
fn finish_with_reason(
	scope: &crate::scope::RepoScope<'_>, id: i64, summary: &TerminalSummary, reason: &str, now: i64,
) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	if summary.campaign_id != id {
		return Err(Error::Ownership(Ownership::CampaignSummary));
	}
	if summarize(scope, id)? != *summary {
		return Err(Error::Conflict(Conflict::CampaignSummary));
	}
	changed(tx.execute("UPDATE review_campaigns SET state='finished',terminal_reason=?2,coverage_at_finish=?3,terminal_counts=?4,finished_at=?5 WHERE campaign_id=?1 AND repo_id=?6 AND state='active'",params![id,reason,summary.coverage.as_str(),summary.counts.expose(),now,scope.repo_id])?,Conflict::CampaignState)
}
pub fn cancel<S: Source>(
	scope: &crate::scope::RepoScope<'_>, id: i64, reason: &BoundedText<Reason, S>, now: i64,
) -> Result<()> {
	scope.require_operator()?;
	let summary = summarize(scope, id)?;
	changed(scope.conn.execute("UPDATE review_campaigns SET state='cancelled',terminal_reason=?2,coverage_at_finish=?3,terminal_counts=?4,finished_at=?5 WHERE campaign_id=?1 AND repo_id=?6 AND state='active'",params![id,reason.expose(),summary.coverage.as_str(),summary.counts.expose(),now,scope.repo_id])?,Conflict::CampaignState)
}

#[cfg(test)]
#[path = "campaign_counts_tests.rs"]
mod counts_compatibility;

#[cfg(test)]
#[path = "campaign_composition_tests.rs"]
mod composition_tests;
