# Web ingress staging inventory

This I-stage owner keeps the accepted browser proxy contract. It does not finish
M, Agent field attribution, sink policy, v6, or scope/audit integration. M must
remove the staging source-migration dependency and every source-erasing legacy
exit below; retained terminal serializers must become explicit final egress.

## Actual captures and validators

- `guard::browser_guard` mints Browser once for the actual request before guard
  interpretation. Its private `BrowserRequest` extension retains only that fixed
  token, reused by `BrowserGuard`, `DashboardTokenCheck`, `BrowserPath`,
  `LimitDecoder`, `JobsDecoder`, `SearchDecoder` and the six body validators.
  Browser validation never grants Operator authority. Admin mTLS remains the
  independent upstream authentication boundary.
- `ingress::bodies::{CreateRepo,UpdateRepo,RotatePat,SetGithubReporting,
  EnqueueScan,RetryVerify}` admit the original collected Browser bytes with a
  serde-driven grammar pass. Each fixed private output retains the same guarded
  byte owner. Missing Content-Type ignores the body and uses closed host `{}`;
  wrong media and failed guards never collect the body. Nonobjects, unknown
  fields, escaped names and duplicate-last behavior remain compatible.
- `ingress::server::receive` mints Server once at actual response receipt, before
  `DashboardServerHeader`; the same token admits the collected owner through
  `DashboardServerJson` or `DashboardServerDiagnostic`. Success checks the
  protocol header before collecting; non-success ignores that header and keeps
  its status. Diagnostics are intentionally forwarded data, distinct from closed
  parser/transport errors. JSON Content-Type is not required. `health` uses the
  same owner and redacted opaque output; it no longer decodes/logs a raw Value.
- `config::input::{UrlParser,PathParser,PemParser}::parse_ref` each captures the
  actual supplied native Clap/environment value as Config before URL/path/PEM
  interpretation. `WebServerUrlDecoder`, `WebHostPathDecoder` and
  `WebPemInputDecoder` are fixed-source validators. Native paths preserve their
  exact OsStr bytes; there is no RepoPath conversion or lossy UTF-8 label.
- `config::input::selected` captures the actual selection/read of Config PEM
  inputs, including the existing public programmatic ConnArgs facade. Raw
  nonempty beats base64 nonempty, then file; invalid selected base64 never falls
  back. `WebRawPemDecoder` shares the existing guarded input and uses its concrete
  TLS conversion; `WebBase64PemDecoder` borrows original guarded base64 text.
  `WebTlsPemEgress` sees the original guarded file text returned by the shared
  reader before application TLS interpretation. The reader already performs its
  own UTF-8 check; this wrapper does not claim to precede that dependency step.

The six production unsafe statements are precisely those capture sites: one
Browser, one Server, and four Config (three parser methods, one selected input
read). Root integrates their unsafe-registry entries. No fixture mint was added.
All validators and source owners are private; no source selector, arbitrary
labelled tree, generic typed source decoder, or public mint is introduced.

## Policies, bytes and secrets

`BrowserSearchQuery` is exact/significant, permits empty, LF/CR/TAB, with named
2 MiB byte/scalar ceilings. `BrowserJobFilter` has the same exact/empty ceilings
but is single-line. Neither normalizes Unicode or trims. Canonical cross-process
policy naming remains an M join. Scalar i64 path/limit semantics remain unchanged;
unknown job filter strings are retained for the server's existing validation.
Pinned form decoding retains plus/percent/UTF-8 replacement and query ordering.
A streaming known-field preflight counts replacement output before allocating
its decoded String. The HTTP Uri itself has a smaller encoded-size limit; unit
boundary evidence for the 2 MiB policy is not a claim that HTTP admits a 2 MiB URI.

The Browser collector reserves one initialized 2 MiB wiping allocation and checks
each transport chunk before copying. No populated Vec reallocates. Error,
cancellation and last-owner drops wipe still-live storage. PAT values remain
encoded under this guard, including superseded duplicate and unknown tokens;
they never become production Value/String owners. Temporary decoded map keys
use Secret<String>. Serde owns the grammar, recursion budget and opaque scratch.
The emitter builds only one object-level borrowed projection at a time (plus
ancestor projections during recursion), preserving duplicate-last and ordered
keys. It never builds a recursive decoded JSON tree. Numeric spelling follows
serde_json::Number; string tokens remain encoded without normalization.

The private writer first counts exact output then fills one initialized guarded
allocation. Protocol insertion may exceed the 2 MiB input cap; there is no new
outbound cap. Bytes::from_owner preserves the guard through reqwest/body clones.
Server collection retains loupe-http's 16 MiB limit and guarded owner. Valid
UTF-8 requires no replacement copy. Invalid UTF-8 retains the original owner and
builds a counted guarded view, at most 48 MiB, with the old maximal-subpart
replacement semantics. Output encoding is also guarded and counted. At M, Agent
field carries must originate from original Server spans, never this replacement
view or reserialized output. Malformed original UTF-8 needs an explicit M policy.

No guarantee is claimed for OS argv/environment, Clap/parser scratch, reqwest,
TLS internals, transport chunks, kernel buffers, or intentional outbound wire
copies. Existing PemInput and concrete TLS owners remain unchanged; no blanket
Secret Clone/serde or false dependency Zeroise was added. Safe tests observe only
live owner pointers and zeroed storage before free.

## Exact temporary exits (delete or close at M)

- `ingress::bodies::Document::into_upstream_legacy` and each of the six
  `Browser{CreateRepo,UpdateRepo,RotatePat,SetGithubReporting,EnqueueScan,
  RetryVerify}::into_upstream_legacy` methods.
- `ingress::queries::{BrowserJobs,BrowserSearch}::into_pairs_legacy`.
- `ingress::server::ServerJson::{into_response_legacy,into_value_legacy}`;
  `ServerDiagnostic::{into_error_response_legacy,into_error_legacy}`;
  `Outcome::{into_response_legacy,into_call_legacy,into_health_legacy}`;
  `Failure::into_error_legacy` (the last has closed metadata only).
- `config::input::ConfigUrl::into_url_legacy`,
  `ConfigPath::into_path_legacy`, `ConfigPem::into_input_legacy`, and
  `ConfigTlsPem::move_legacy`, and `WebTlsPemEgress::move_legacy`.
- Existing public `AdminClient::{call,get_typed,with_protocol_version}` and
  `UpstreamError` remain compatibility facades. Only `call_forward` is used by
  production routes; health also uses that named path. `json::legacy_value_bytes`
  is exclusively the old call-input adapter, never a routed credential owner.
  `ServerJson::into_value_legacy` is exclusively the old call return adapter.
- Public `ConnArgs` raw URL/path/PemInput fields and the legacy
  `routes::api::{LimitQuery,JobsQuery,SearchQuery}` serde structs remain temporary
  I interfaces. They must not become final arbitrary labelled Deserialize APIs.

The scalar-only LimitQuery pairs and closed host protocol insertion need no
synthetic source. Static assets, generated token, bind/poll scalars, and transport
status facts retain their existing ownership. This node does not add events or
new runtime authority decisions.

## Required serialized W4 join

Root owns shared lock/unsafe registry and fuzz sources. Extend actual web_api
router coverage for the six owner bodies, optional media, known exact queries,
last-wins/escaped names/nonobjects, guards, no-upstream rejection and guarded PAT
formatting. Add actual Server response target for header/status/diagnostic/UTF-8,
chunk/cap/cancellation cases; target the private production path via fixed
cfg(fuzzing) fixtures if needed, not only the old public Value facade. Config
child-environment precedence is separately tested here. Root must run affected
replays, campaigns, narrow oracle mutations and combined default gate before
claiming W4/W5 complete. None of those joins is claimed by this source candidate.
