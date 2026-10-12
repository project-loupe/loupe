use loupe_core::source_migration::text::RepoPath;
use loupe_core::{FindingState, Severity};
use loupe_provenance::{Agent, ValidateCarrying};

use super::*;

fn span<'a>(
	u: &Unvalidated<'_, &'a [u8], Server>, token: &RawValue,
) -> Result<Untrusted<&'a [u8], Agent>> {
	let bytes = *u.get();
	let start =
		(token.get().as_ptr() as usize).checked_sub(bytes.as_ptr() as usize).ok_or_else(invalid)?;
	let end = start.checked_add(token.get().len()).ok_or_else(invalid)?;
	let value = u.carry::<Agent>(start..end).ok_or_else(invalid)?;
	#[cfg(any(test, fuzzing))]
	OBSERVED.with(|seen| seen.borrow_mut().push((start, end)));
	Ok(value)
}
#[cfg(any(test, fuzzing))]
thread_local! { pub(super) static OBSERVED: std::cell::RefCell<Vec<(usize,usize)>> = const { std::cell::RefCell::new(Vec::new()) }; }

macro_rules! agent_field {
	($name:ident, $validator:ident, $policy:ty) => {
		struct $validator;
		impl Validate<&[u8], Agent> for $validator {
			type Output = BoundedText<$policy, Agent>;
			type Error = anyhow::Error;
			fn validate<'v>(
				self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Agent>,
			) -> Result<Self::Output> {
				let token = std::str::from_utf8(u.get()).map_err(|_| invalid())?;
				let decoded = decode_json_string_bounded(
					token,
					<$policy>::FIELD,
					<$policy>::MAX_BYTES,
					<$policy>::MAX_CHARS,
				)
				.map_err(|_| invalid())?;
				BoundedText::new(&mark, &decoded).map_err(|_| invalid())
			}
		}
		fn $name(
			u: &Unvalidated<'_, &[u8], Server>, token: &RawValue,
		) -> Result<BoundedText<$policy, Agent>> {
			span(u, token)?.validate($validator)
		}
	};
}
agent_field!(scanner, Scanner, policy::ScannerIdText);
agent_field!(title, Title, policy::FindingTitle);
agent_field!(description, Description, policy::FindingDescription);
agent_field!(fingerprint, Fingerprint, policy::FindingFingerprintText);
agent_field!(cwe, Cwe, policy::CweText);
agent_field!(patch, Patch, policy::PatchUnified);
agent_field!(poc, Poc, policy::PocUnified);
struct Path;
impl Validate<&[u8], Agent> for Path {
	type Output = RepoPath<Agent>;
	type Error = anyhow::Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Agent>,
	) -> Result<Self::Output> {
		let token = std::str::from_utf8(u.get()).map_err(|_| invalid())?;
		let decoded =
			decode_json_string_bounded(token, "repo_path", 512, 512).map_err(|_| invalid())?;
		RepoPath::new(&mark, &decoded).map_err(|_| invalid())
	}
}
fn path(u: &Unvalidated<'_, &[u8], Server>, token: &RawValue) -> Result<RepoPath<Agent>> {
	span(u, token)?.validate(Path)
}

#[derive(Deserialize)]
struct RawSummary<'a> {
	id: i64,
	repo_id: i64,
	job_id: i64,
	#[serde(borrow)]
	scanner_id: &'a RawValue,
	severity: Severity,
	#[serde(borrow)]
	title: &'a RawValue,
	#[serde(default, borrow)]
	file_path: Option<&'a RawValue>,
	#[serde(default)]
	line_start: Option<u32>,
	#[serde(borrow)]
	fingerprint: &'a RawValue,
	state: FindingState,
	verification_required: bool,
	created_at: i64,
	#[serde(default)]
	approved_at: Option<i64>,
	#[serde(default, borrow)]
	approved_by_cn: Option<&'a RawValue>,
	#[serde(default)]
	rejected_at: Option<i64>,
	#[serde(default, borrow)]
	rejected_by_cn: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct RawList<'a> {
	protocol_version: u16,
	#[serde(borrow)]
	findings: Vec<RawSummary<'a>>,
}

struct Summary {
	id: i64,
	repo_id: i64,
	job_id: i64,
	scanner_id: BoundedText<policy::ScannerIdText, Agent>,
	severity: Severity,
	title: BoundedText<policy::FindingTitle, Agent>,
	file_path: Option<RepoPath<Agent>>,
	line_start: Option<u32>,
	fingerprint: BoundedText<policy::FindingFingerprintText, Agent>,
	state: FindingState,
	verification_required: bool,
	created_at: i64,
	approved_at: Option<i64>,
	approved_by_cn: Option<BoundedText<AuditName, Server>>,
	rejected_at: Option<i64>,
	rejected_by_cn: Option<BoundedText<AuditName, Server>>,
}
impl Summary {
	fn legacy(self) -> loupe_proto::FindingSummary {
		#[cfg(fuzzing)]
		observe_summary(&self);
		loupe_proto::FindingSummary {
			id: self.id,
			repo_id: self.repo_id,
			job_id: self.job_id,
			scanner_id: self.scanner_id.expose().to_owned(),
			severity: self.severity,
			title: self.title.expose().to_owned(),
			file_path: self.file_path.map(|s| s.expose().to_owned()),
			line_start: self.line_start,
			fingerprint: self.fingerprint.expose().to_owned(),
			state: self.state,
			verification_required: self.verification_required,
			created_at: self.created_at,
			approved_at: self.approved_at,
			approved_by_cn: self.approved_by_cn.map(|s| s.expose().to_owned()),
			rejected_at: self.rejected_at,
			rejected_by_cn: self.rejected_by_cn.map(|s| s.expose().to_owned()),
		}
	}
}
fn summary(u: &Unvalidated<'_, &[u8], Server>, r: RawSummary<'_>) -> Result<Summary> {
	Ok(Summary {
		id: r.id,
		repo_id: r.repo_id,
		job_id: r.job_id,
		scanner_id: scanner(u, r.scanner_id)?,
		severity: r.severity,
		title: title(u, r.title)?,
		file_path: r.file_path.map(|t| path(u, t)).transpose()?,
		line_start: r.line_start,
		fingerprint: fingerprint(u, r.fingerprint)?,
		state: r.state,
		verification_required: r.verification_required,
		created_at: r.created_at,
		approved_at: r.approved_at,
		approved_by_cn: r.approved_by_cn.map(|t| audit(&u.mark(), t)).transpose()?,
		rejected_at: r.rejected_at,
		rejected_by_cn: r.rejected_by_cn.map(|t| audit(&u.mark(), t)).transpose()?,
	})
}
struct FindingList {
	version: u16,
	findings: Vec<Summary>,
}
struct ListFindings;
impl ValidateCarrying<&[u8], Server> for ListFindings {
	type Output = FindingList;
	type Error = anyhow::Error;
	fn validate(self, u: Unvalidated<'_, &[u8], Server>) -> Result<FindingList> {
		let raw: RawList<'_> = serde_json::from_slice(u.get()).map_err(|_| invalid())?;
		Ok(FindingList {
			version: raw.protocol_version,
			findings: raw.findings.into_iter().map(|r| summary(&u, r)).collect::<Result<_>>()?,
		})
	}
}
pub(crate) fn list_findings_legacy(
	body: Untrusted<Bytes, Server>,
) -> Result<loupe_proto::ListFindingsResponse> {
	#[cfg(fuzzing)]
	entered(Entry::ListFindings);
	let list = body.as_bytes().validate_carrying(ListFindings)?;
	Ok(loupe_proto::ListFindingsResponse {
		protocol_version: list.version,
		findings: list.findings.into_iter().map(Summary::legacy).collect(),
	})
}
pub(crate) fn search_findings_legacy(
	body: Untrusted<Bytes, Server>,
) -> Result<loupe_proto::ListFindingsResponse> {
	#[cfg(fuzzing)]
	entered(Entry::SearchFindings);
	list_findings_legacy(body)
}

#[derive(Deserialize)]
struct RawDetail<'a> {
	protocol_version: u16,
	id: i64,
	repo_id: i64,
	job_id: i64,
	#[serde(borrow)]
	scanner_id: &'a RawValue,
	severity: Severity,
	#[serde(borrow)]
	title: &'a RawValue,
	#[serde(borrow)]
	description: &'a RawValue,
	#[serde(default, borrow)]
	file_path: Option<&'a RawValue>,
	#[serde(default)]
	line_start: Option<u32>,
	#[serde(default)]
	line_end: Option<u32>,
	#[serde(default, borrow)]
	cwe: Option<&'a RawValue>,
	#[serde(default, borrow)]
	patch_unified: Option<&'a RawValue>,
	#[serde(default, borrow)]
	poc_unified: Option<&'a RawValue>,
	#[serde(borrow)]
	fingerprint: &'a RawValue,
	state: FindingState,
	verification_required: bool,
	created_at: i64,
	#[serde(default)]
	approved_at: Option<i64>,
	#[serde(default, borrow)]
	approved_by_cn: Option<&'a RawValue>,
	#[serde(default)]
	rejected_at: Option<i64>,
	#[serde(default, borrow)]
	rejected_by_cn: Option<&'a RawValue>,
}
struct Detail {
	version: u16,
	summary: Summary,
	description: BoundedText<policy::FindingDescription, Agent>,
	line_end: Option<u32>,
	cwe: Option<BoundedText<policy::CweText, Agent>>,
	patch: Option<BoundedText<policy::PatchUnified, Agent>>,
	poc: Option<BoundedText<policy::PocUnified, Agent>>,
}
struct GetFinding;
impl ValidateCarrying<&[u8], Server> for GetFinding {
	type Output = Detail;
	type Error = anyhow::Error;
	fn validate(self, u: Unvalidated<'_, &[u8], Server>) -> Result<Detail> {
		let r: RawDetail<'_> = serde_json::from_slice(u.get()).map_err(|_| invalid())?;
		Ok(Detail {
			version: r.protocol_version,
			description: description(&u, r.description)?,
			line_end: r.line_end,
			cwe: r.cwe.map(|t| cwe(&u, t)).transpose()?,
			patch: r.patch_unified.map(|t| patch(&u, t)).transpose()?,
			poc: r.poc_unified.map(|t| poc(&u, t)).transpose()?,
			summary: summary(
				&u,
				RawSummary {
					id: r.id,
					repo_id: r.repo_id,
					job_id: r.job_id,
					scanner_id: r.scanner_id,
					severity: r.severity,
					title: r.title,
					file_path: r.file_path,
					line_start: r.line_start,
					fingerprint: r.fingerprint,
					state: r.state,
					verification_required: r.verification_required,
					created_at: r.created_at,
					approved_at: r.approved_at,
					approved_by_cn: r.approved_by_cn,
					rejected_at: r.rejected_at,
					rejected_by_cn: r.rejected_by_cn,
				},
			)?,
		})
	}
}
pub(crate) fn get_finding_legacy(
	body: Untrusted<Bytes, Server>,
) -> Result<loupe_proto::FindingDetail> {
	#[cfg(fuzzing)]
	entered(Entry::GetFinding);
	let d = body.as_bytes().validate_carrying(GetFinding)?;
	#[cfg(fuzzing)]
	observe_detail(&d);
	let s = d.summary.legacy();
	Ok(loupe_proto::FindingDetail {
		protocol_version: d.version,
		id: s.id,
		repo_id: s.repo_id,
		job_id: s.job_id,
		scanner_id: s.scanner_id,
		severity: s.severity,
		title: s.title,
		description: d.description.expose().to_owned(),
		file_path: s.file_path,
		line_start: s.line_start,
		line_end: d.line_end,
		cwe: d.cwe.map(|s| s.expose().to_owned()),
		patch_unified: d.patch.map(|s| s.expose().to_owned()),
		poc_unified: d.poc.map(|s| s.expose().to_owned()),
		fingerprint: s.fingerprint,
		state: s.state,
		verification_required: s.verification_required,
		created_at: s.created_at,
		approved_at: s.approved_at,
		approved_by_cn: s.approved_by_cn,
		rejected_at: s.rejected_at,
		rejected_by_cn: s.rejected_by_cn,
	})
}

#[cfg(fuzzing)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
	Scanner,
	Title,
	Fingerprint,
	Path,
	Description,
	Cwe,
	Patch,
	Poc,
	ApprovedBy,
	RejectedBy,
}
#[cfg(fuzzing)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FieldSource {
	Agent,
	Server,
}
#[cfg(fuzzing)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FieldObservation {
	pub field: Field,
	pub source: FieldSource,
	pub text: String,
}
#[cfg(fuzzing)]
thread_local! {static TYPED:std::cell::RefCell<Vec<FieldObservation>>=const{std::cell::RefCell::new(Vec::new())};}
#[cfg(fuzzing)]
fn record(field: Field, source: FieldSource, text: &str) {
	TYPED.with(|s| s.borrow_mut().push(FieldObservation { field, source, text: text.to_owned() }));
}
#[cfg(fuzzing)]
fn observe_summary(s: &Summary) {
	fn agent<P: TextPolicy>(field: Field, text: &BoundedText<P, Agent>) {
		record(field, FieldSource::Agent, text.expose());
	}
	agent(Field::Scanner, &s.scanner_id);
	agent(Field::Title, &s.title);
	agent(Field::Fingerprint, &s.fingerprint);
	if let Some(path) = &s.file_path {
		let path: &RepoPath<Agent> = path;
		record(Field::Path, FieldSource::Agent, path.expose());
	}
	for (field, text) in
		[(Field::ApprovedBy, &s.approved_by_cn), (Field::RejectedBy, &s.rejected_by_cn)]
	{
		if let Some(text) = text {
			let text: &BoundedText<AuditName, Server> = text;
			record(field, FieldSource::Server, text.expose());
		}
	}
}
#[cfg(fuzzing)]
fn observe_detail(d: &Detail) {
	fn agent<P: TextPolicy>(field: Field, text: &BoundedText<P, Agent>) {
		record(field, FieldSource::Agent, text.expose());
	}
	agent(Field::Description, &d.description);
	if let Some(text) = &d.cwe {
		agent(Field::Cwe, text);
	}
	if let Some(text) = &d.patch {
		agent(Field::Patch, text);
	}
	if let Some(text) = &d.poc {
		agent(Field::Poc, text);
	}
}
#[cfg(fuzzing)]
pub(crate) fn reset_observations() {
	OBSERVED.with(|s| s.borrow_mut().clear());
	TYPED.with(|s| s.borrow_mut().clear());
}
#[cfg(fuzzing)]
pub(crate) fn take_observations() -> (Vec<(usize, usize)>, Vec<FieldObservation>) {
	(
		OBSERVED.with(|s| std::mem::take(&mut *s.borrow_mut())),
		TYPED.with(|s| std::mem::take(&mut *s.borrow_mut())),
	)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::ingress::test_support::received;

	#[tokio::test]
	async fn carries_original_array_tokens_and_keeps_audit_as_server() {
		let token = r#""e\u0301\"\\\uD83D\uDE00""#;
		let row = format!(
			r#"{{"id":1,"repo_id":2,"job_id":3,"scanner_id":{token},"severity":"high","title":{token},"fingerprint":{token},"state":"confirmed","verification_required":false,"created_at":0,"approved_by_cn":{token}}}"#
		);
		let raw = format!(r#"{{"protocol_version":2,"findings":[{row},{row}]}}"#);
		let all: Vec<_> = raw.match_indices(token).map(|(s, t)| (s, s + t.len())).collect();
		assert_eq!(all.len(), 8);
		let input = received(raw.as_bytes()).await;
		OBSERVED.with(|seen| seen.borrow_mut().clear());
		let typed = input.as_bytes().validate_carrying(ListFindings).unwrap();
		let expected = vec![all[0], all[1], all[2], all[4], all[5], all[6]];
		OBSERVED.with(|seen| assert_eq!(*seen.borrow(), expected));
		let decoded = "e\u{301}\"\\😀";
		for row in &typed.findings {
			let title: &BoundedText<policy::FindingTitle, Agent> = &row.title;
			let audit: &BoundedText<AuditName, Server> = row.approved_by_cn.as_ref().unwrap();
			assert_eq!(title.expose(), decoded);
			assert_eq!(audit.expose(), decoded);
		}
		// The collected owner and every later view keep the exact collector allocation.
		struct Pointer;
		impl Validate<&[u8], Server> for Pointer {
			type Output = (usize, usize);
			type Error = std::convert::Infallible;
			fn validate<'v>(
				self, u: Unvalidated<'v, &[u8]>, _: Mark<'v, Server>,
			) -> std::result::Result<Self::Output, Self::Error> {
				Ok((u.get().as_ptr() as usize, u.get().len()))
			}
		}
		let pointer = input.as_bytes().validate(Pointer).unwrap();
		super::super::RECEIVED_ALLOCATION.with(|seen| assert_eq!(pointer, seen.get()));
	}

	#[tokio::test]
	async fn detail_carries_each_equal_diff_and_preserves_exact_multiline() {
		let token = r#"" e\u0301\r\n\t\\\"\uD83D\uDE00\n\n\n ""#;
		let raw = format!(
			r#"{{"protocol_version":2,"id":1,"repo_id":2,"job_id":3,"scanner_id":"same","severity":"high","title":"same","description":{token},"patch_unified":{token},"poc_unified":{token},"file_path":"src/a.rs","cwe":"","fingerprint":"same","state":"confirmed","verification_required":false,"created_at":0}}"#
		);
		let expected: Vec<_> = raw.match_indices(token).map(|(s, t)| (s, s + t.len())).collect();
		let input = received(raw.as_bytes()).await;
		OBSERVED.with(|seen| seen.borrow_mut().clear());
		let typed = input.as_bytes().validate_carrying(GetFinding).unwrap();
		OBSERVED.with(|seen| {
			let actual: Vec<_> =
				seen.borrow().iter().copied().filter(|r| expected.contains(r)).collect();
			assert_eq!(actual, expected);
		});
		let exact = " e\u{301}\r\n\t\\\"😀\n\n\n ";
		assert_eq!(typed.description.expose(), exact);
		assert_eq!(typed.patch.as_ref().unwrap().expose(), exact);
		assert_eq!(typed.poc.as_ref().unwrap().expose(), exact);
		assert_eq!(typed.cwe.as_ref().unwrap().expose(), "");
		assert_eq!(typed.summary.file_path.as_ref().unwrap().expose(), "src/a.rs");
	}
}
