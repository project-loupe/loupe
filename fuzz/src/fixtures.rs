//! Fixed synthetic sources for harness-owned inputs. These constructors exist
//! only in the fuzz package; production decoders still own their real capture.
use loupe_core::text::{
	Anchor, AnchorPolicy, BoundedJson, BoundedText, Error, IdentPolicy, Identifier, JsonPolicy,
	RepoPath, TextPolicy,
};
use loupe_provenance::{Agent, Ingress, Mark, Untrusted, Unvalidated, Validate};

struct AgentFixture<F>(F);
impl<T, F> Validate<&str, Agent> for AgentFixture<F>
where
	F: for<'view> FnOnce(&Mark<'view, Agent>, &str) -> T,
{
	type Output = T;
	type Error = std::convert::Infallible;
	fn validate<'view>(
		self, value: Unvalidated<'view, &str>, mark: Mark<'view, Agent>,
	) -> Result<T, Self::Error> {
		Ok((self.0)(&mark, value.get()))
	}
}

pub(crate) fn agent<T>(
	raw: &str, run: impl for<'view> FnOnce(&Mark<'view, Agent>, &str) -> T,
) -> T {
	// SAFETY: these are harness-created bytes and the source is fixed to Agent.
	#[allow(unsafe_code)]
	let ingress = unsafe { Ingress::<Agent>::new() };
	match Untrusted::new(raw, ingress).validate(AgentFixture(run)) {
		Ok(value) => value,
		Err(impossible) => match impossible {},
	}
}
pub(crate) fn text<P: TextPolicy>(raw: &str) -> Result<BoundedText<P, Agent>, Error> {
	agent(raw, |mark, raw| BoundedText::new(mark, raw))
}
pub(crate) fn identifier<P: IdentPolicy>(raw: &str) -> Result<Identifier<P, Agent>, Error> {
	agent(raw, |mark, raw| Identifier::new(mark, raw))
}
pub(crate) fn json<P: JsonPolicy>(raw: &str) -> Result<BoundedJson<P, Agent>, Error> {
	agent(raw, |mark, raw| BoundedJson::new(mark, raw))
}
pub(crate) fn path(raw: &str) -> Result<RepoPath<Agent>, Error> {
	agent(raw, RepoPath::new)
}
pub(crate) fn anchor<P: AnchorPolicy>(raw: &str) -> Result<Anchor<P, Agent>, Error> {
	agent(raw, |mark, raw| Anchor::new(mark, raw))
}
