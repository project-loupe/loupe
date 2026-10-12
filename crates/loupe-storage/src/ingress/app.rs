//! The full and summary GitHub App reads keep separate PEM allocation paths.
use loupe_provenance::Secret;
use serde::Deserialize;
use serde_json::value::RawValue;

use super::*;

#[derive(Deserialize)]
struct RawApp<'a> {
	app_id: u64,
	#[serde(borrow)]
	slug: &'a RawValue,
	#[serde(borrow)]
	private_key_pem: &'a RawValue,
}
#[derive(Deserialize)]
struct RawSummary<'a> {
	app_id: u64,
	#[serde(borrow)]
	slug: &'a RawValue,
}
struct StoredApp {
	app_id: u64,
	slug: BoundedText<policy::GithubAppSlug, Db>,
	private_key_pem: Secret<String>,
}
struct StoredSummary {
	app_id: u64,
	slug: BoundedText<policy::GithubAppSlug, Db>,
}
struct App;
struct Summary;
fn slug(
	mark: &Mark<'_, Db>, raw: &RawValue,
) -> Result<BoundedText<policy::GithubAppSlug, Db>, ReadError> {
	let decoded = text::decode_json_string_bounded(
		raw.get(),
		policy::GithubAppSlug::FIELD,
		policy::GithubAppSlug::MAX_BYTES,
		policy::GithubAppSlug::MAX_CHARS,
	)
	.map_err(ReadError::decoded)?;
	BoundedText::new(mark, &decoded).map_err(ReadError::admission)
}
impl Validate<&[u8], Db> for App {
	type Output = StoredApp;
	type Error = ReadError;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Db>,
	) -> Result<Self::Output, ReadError> {
		let bytes = Secret::new(u.get().to_vec());
		let raw: RawApp<'_> =
			serde_json::from_slice(bytes.expose()).map_err(|_| ReadError::Syntax)?;
		let slug = slug(&mark, raw.slug)?;
		// Named intentional credential decode, guarded immediately. PEM
		// syntax/authentication remain with the existing credential consumer.
		let private_key_pem = serde_json::from_str::<String>(raw.private_key_pem.get())
			.map(Secret::new)
			.map_err(|_| ReadError::Syntax)?;
		Ok(StoredApp { app_id: raw.app_id, slug, private_key_pem })
	}
}
impl Validate<&[u8], Db> for Summary {
	type Output = StoredSummary;
	type Error = ReadError;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Db>,
	) -> Result<Self::Output, ReadError> {
		let bytes = Secret::new(u.get().to_vec());
		// Unknown PEM is skipped by serde, never decoded as an owned String.
		let raw: RawSummary<'_> =
			serde_json::from_slice(bytes.expose()).map_err(|_| ReadError::Syntax)?;
		Ok(StoredSummary { app_id: raw.app_id, slug: slug(&mark, raw.slug)? })
	}
}
fn app_error(error: ReadError) -> rusqlite::Error {
	rusqlite::Error::FromSqlConversionFailure(0, Type::Blob, Box::new(error))
}
pub(crate) fn app_legacy(row: &Row<'_>) -> rusqlite::Result<crate::github_app::StoredGithubApp> {
	let marked = blob(row, 0)?.validate(App).map_err(app_error)?;
	Ok(crate::github_app::StoredGithubApp {
		app_id: marked.app_id,
		slug: marked.slug.expose().to_owned(),
		private_key_pem: marked.private_key_pem,
	})
}
pub(crate) fn app_summary_legacy(
	row: &Row<'_>,
) -> rusqlite::Result<crate::github_app::StoredGithubAppSummary> {
	let marked = blob(row, 0)?.validate(Summary).map_err(app_error)?;
	Ok(crate::github_app::StoredGithubAppSummary {
		app_id: marked.app_id,
		slug: marked.slug.expose().to_owned(),
	})
}
