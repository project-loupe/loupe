# Web source ownership

This M owner preserves the browser proxy contract. It does not interpret finding
fields or claim Agent provenance for transparent Server forwarding. Later
sandbox, audit, scope and prompt/report work remain separate graph nodes.

## Actual captures and final sinks

- `guard::browser_guard` captures Browser once before interpreting the actual
  request. Its private BrowserRequest token serves the guard, capability check,
  scalar ID/limit decoders, two query decoders and six body decoders. Successful
  browser capability validation confers no Operator role; upstream mTLS remains
  an independent server authentication boundary.
- `ingress::bodies` admits original Browser bytes into six private endpoint
  owners. `client::AdminRequest` selects a closed endpoint; each body owner's
  `send` encodes and sends directly through the selected reqwest request. No
  caller receives body Bytes, Value or a decoded PAT. Missing Content-Type
  ignores the body and emits the host's stamped empty object. Wrong media or
  rejected guards never collect. Nonobjects, unknown fields, escaped names,
  duplicate-last semantics and protocol overwrite retain their old behavior.
- `ingress::queries::{BrowserJobs,BrowserSearch}` retains bounded Browser text
  until its selected request's query encoder, and sends from that owner. No
  vector of owned raw strings leaves it. Unknown job-filter strings still reach
  the server. Private wire-only query structs exist only inside the actual
  Browser validators; they are not alternative public query admission APIs.
- `ingress::server::receive` captures Server at response receipt. Successful
  responses validate the protocol header before collection; non-success ignores
  that header. The original guarded bytes and optional guarded lossy UTF-8 view
  stay inside ServerText through ServerJson's fixed Browser response encoder.
  JSON Content-Type is not required. Empty success and HTTP status behavior are
  unchanged, including 401/403 diagnostics mapping to 502. Upstream headers and
  cookies are not forwarded. There is no arbitrary Value or typed-deserializer
  response API. `health` retains an opaque redacted HealthResponse.
- `client::UpstreamError` holds either a closed host Failure or the original
  ServerDiagnostic. Display deliberately renders the trimmed diagnostic at the
  terminal; Debug redacts it. There is no early unlabelled message String.
- `config::input` native UrlParser/PathParser/PemParser callbacks return closed
  ConfigUrl/ConfigPath/ConfigPem values into ConnArgs. Selection preserves those
  source owners: nonempty raw, nonempty base64, then native file; invalid selected
  base64 never falls back. File contents are captured as Config at the actual
  guarded read before TLS interpretation. ConfigTlsPem retains Secret ownership
  to `tls_client`. Only that constructor borrows PEM into the shared TLS parser.
  ConfigUrl reaches the named HTTP constructor and explicit startup diagnostic
  sink; ConfigPath reaches the selected file read. No raw owned conversion,
  Deserialize, general string getter or source selector is public.

Production captures remain six: Browser request, Server response, three native
Config parser instances and one Config file-content read. The parser macro has
one allowlisted statement instantiated for three concrete fixed-source owners.
No fixture mint exists. The binary forbids unsafe; the library denies it except
those narrowly scoped capture functions. Root owns the shared unsafe registry.

## Policy, bytes and secrets

BrowserSearchQuery remains exact/significant, multiline including CR, empty
allowed, with 2 MiB byte/scalar ceilings. BrowserJobFilter has the same exact
limits and empty rule but is single-line. Neither normalizes or trims. Scalar
signed i64 paths/limits are unchanged. Pinned form decoding retains plus,
percent escapes, lossy UTF-8 and query order. A streaming known-field preflight
counts replacement bytes before allocating the decoded String. HTTP Uri has a
smaller encoded-size ceiling; pure policy tests do not claim a 2 MiB HTTP URI.

The Browser collector reserves one initialized 2 MiB wiping allocation. It
checks chunks before copying and wipes on error, cancellation and last drop.
PAT values stay encoded there, including superseded duplicate and unknown
values. Temporary decoded map keys use Secret<String>. Serde retains grammar
and recursion decisions. The emitter builds borrowed object projections, keeps
recursive duplicate-last and sorted-key behavior, and uses serde Number spelling.
Strings stay encoded without normalization. It counts exact output before one
guarded allocation. Protocol insertion may expand past 2 MiB; no second input
cap is imposed. Bytes::from_owner retains the output guard through HTTP clones.

The shared Server collector retains its 16 MiB limit. Valid UTF-8 needs no extra
copy. Invalid UTF-8 retains original bytes plus a counted guarded replacement,
at most 48 MiB, with standard maximal-subpart semantics. Browser response output
is also counted and guarded. Replacement or reencoded bytes never become Agent
tokens. The JavaScript UI's existing textContent/createElement rendering remains
unchanged beyond this HTTP sink.

No guarantee is claimed for OS argv/environment, parser scratch, TLS/reqwest
internals, chunks, kernel buffers or intentional outbound copies. Existing
PemInput and TLS secret owners remain; no blanket Secret Clone/serde or false
dependency Zeroise promise was added. Tests observe live pointers and initialized
zeroed storage before free.

## API and validation joins

AdminClient exposes only typed Config construction and opaque fixed health.
`from_parts` accepts a ConfigUrl obtained at actual native admission, allowing
integration transports to resolve an ephemeral address without a raw URL exit.
The router dispatches only the private AdminRequest operation set. Former
call/get_typed/with_protocol_version, Value adapters, raw query DTOs and all
into_*_legacy exits are removed. Compile-negative docs cover those APIs and
attempted Value/Agent extraction; positive docs retain opaque Debug capability.

Unit cleanup tests now traverse named production routes to a real echo upstream.
Response/budget tests traverse the real health route. Explicit protocol stamping,
nonobject, absent/present limit, status, diagnostics, body cap and redaction
assertions are retained. Native-path and child-environment exact-value controls
moved to private config unit tests so production config gets no test getter.
Actual process loopback-before-credential and missing-file error tests remain
integration tests. Full-server dashboard assertions retain their intent and need
the combined M server/storage build.

`DIRECT-COVERAGE.md` describes the unchanged direct fuzz boundary obligations and
required typed fixture joins. cfg observations are not production conversion
APIs. Full combined campaigns, Kani and independent review remain root gates.
