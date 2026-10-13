//! Private adapters for campaign SQL checks paired with server integration tests.
pub(crate) mod marked {
	pub(crate) mod agent {
		pub(crate) fn json<P: loupe_core::text::JsonPolicy>(
			raw: &str,
		) -> loupe_core::text::BoundedJson<P, loupe_provenance::Agent> {
			crate::test_support::json(raw).unwrap()
		}
		pub(crate) fn empty_refs<const MAX: usize>(
		) -> crate::source_refs::SourceRefs<MAX, loupe_provenance::Agent> {
			crate::test_support::refs(vec![]).unwrap()
		}
	}
	pub(crate) mod repo {
		pub(crate) fn try_text<P: loupe_core::text::TextPolicy>(
			raw: &str,
		) -> Result<loupe_core::text::BoundedText<P, loupe_provenance::Repo>, loupe_core::text::Error>
		{
			crate::test_support::repository(raw, |raw, mark| {
				loupe_core::text::BoundedText::new(mark, raw)
			})
		}
		pub(crate) fn text<P: loupe_core::text::TextPolicy>(
			raw: &str,
		) -> loupe_core::text::BoundedText<P, loupe_provenance::Repo> {
			try_text(raw).unwrap()
		}
	}
	pub(crate) mod operator {
		pub(crate) fn text<P: loupe_core::text::TextPolicy>(
			raw: &str,
		) -> loupe_core::text::BoundedText<P, loupe_provenance::Operator> {
			crate::test_support::operated(raw, |raw, mark| {
				loupe_core::text::BoundedText::new(mark, raw).unwrap()
			})
		}
		pub(crate) fn json<P: loupe_core::text::JsonPolicy>(
			raw: &str,
		) -> loupe_core::text::BoundedJson<P, loupe_provenance::Operator> {
			crate::test_support::operated(raw, |raw, mark| {
				loupe_core::text::BoundedJson::new(mark, raw).unwrap()
			})
		}
	}
}

pub(crate) fn assert_survey_recipe(
	conn: &rusqlite::Connection, job: &crate::jobs::JobRow, recipe: &str,
) {
	let expected = format!(
		r#"{{"assignment_key":"ordinary","phase":"survey","recipe":"{recipe}","version":1}}"#
	);
	let stored = job.recipe.as_ref().unwrap();
	assert_eq!(stored.expose(), expected);
	assert_eq!(*stored.digest(), loupe_core::canonical::digest(expected.as_bytes()));
	let raw: String =
		conn.query_row("SELECT recipe FROM jobs WHERE id=?1", [job.id], |row| row.get(0)).unwrap();
	assert_eq!(raw, expected);
}
