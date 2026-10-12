//! The sources a value can arrive from. Sealed: the set is the one
//! `SECURITY-FIRST-REFACTOR.md` section 2 lists, and a crate outside
//! this one cannot add another.

mod sealed {
	pub trait Sealed {}
}

/// Where a value came from. Implemented only by the marker types in
/// this module; the trait is sealed so the set of sources is closed.
///
/// A source is a type, not a value: [`Untrusted<T, S>`](crate::Untrusted)
/// carries it as a parameter so a function can accept bytes from one
/// source only (`fn render(m: Untrusted<&[u8], Agent>)`), and the
/// label follows the value through `map_ref` and into every
/// [`Validate`](crate::Validate) impl at zero runtime cost.
pub trait Source: sealed::Sealed + Send + Sync + 'static {
	/// A short lowercase name for logs and `Debug` output. Never
	/// carries data, so it is safe to print anywhere.
	const NAME: &'static str;
}

macro_rules! sources {
    ($($(#[$doc:meta])* $name:ident = $text:literal;)*) => {
        $(
            $(#[$doc])*
            #[derive(Debug, Clone, Copy)]
            pub struct $name;

            impl sealed::Sealed for $name {}

            impl Source for $name {
                const NAME: &'static str = $text;
            }
        )*
    };
}

sources! {
	/// Text authored by a model: titles, descriptions, proofs of
	/// concept, hypotheses, profiles, proposed commands. Never arrives
	/// on its own; it is carried out of `Worker`, `Sandbox`, `Db` or `Server`
	/// bytes. Hostile: the prompt-injection carrier.
	Agent = "agent";
	/// Bytes of the repository under review: file contents, paths and
	/// `git` output from the pinned checkout. Hostile.
	Repo = "repo";
	/// Bytes from the agent sandbox on the worker host: the MCP socket,
	/// the model-proxy socket, the CLI's stdout and stderr, the
	/// artifact export directory. Hostile: a compromised agent.
	Sandbox = "sandbox";
	/// Requests from a worker over mTLS, as seen by the server. A
	/// trusted host that may be compromised and that relays agent
	/// text. Trust-asserting: minted only after the worker row lookup.
	Worker = "worker";
	/// Responses from the Loupe server, as seen by a worker, the CLI
	/// or the dashboard. Trusted, parsed strictly. Trust-asserting:
	/// minted only after the mTLS client verified the server.
	Server = "server";
	/// Requests from an operator over admin mTLS (`loupectl`, the
	/// dashboard). Trusted; must not panic the server. Trust-asserting:
	/// minted only after the admin row lookup.
	Operator = "operator";
	/// Responses from a model provider's API, streamed by the host
	/// model broker. Hostile web; the host parses bounded JSON/SSE
	/// for token accounting and sanitises response headers under the
	/// output ceiling.
	Provider = "provider";
	/// Responses from a report destination (an issue tracker API, a
	/// mailer's exit status). Hostile web.
	Reporter = "reporter";
	/// Rows read back from the database. Own data; corruption is
	/// possible, and agent text stored in a row is still agent text.
	Db = "db";
	/// Configuration files, environment variables and command-line
	/// arguments. User-controlled; must not panic.
	Config = "config";
	/// Loopback HTTP requests to the dashboard. A hostile local
	/// process.
	Browser = "browser";
}
