# Server ingress targets

These targets exercise production validators, router paths and HTTP consumers.
`server_config` writes each input into a temporary file
and calls the actual `FileConfig::load`; its paths are resolved against that
file's absolute parent directory. Targets never add files to the source corpus
while a campaign runs.

| Target | Input and oracle |
| --- | --- |
| `server_capability_header` | Raw header bytes; exact 43-byte admission for printable ASCII **or HTAB**, the current `HeaderValue::to_str` predicate. No base64url alphabet restriction. Accepted bytes hash unchanged; rejection has one fixed diagnostic. |
| `server_report_github` | JSON `Finding`; title normalization and 100-character cap, body admission at 65,536 Unicode scalar values. A separate fence scanner observes the deferred containment property. |
| `server_report_email` | JSON object with `from`, `to`, `subject`, and `finding`; CR/LF validation equivalence and exact header block independent of finding content. |
| `server_config` | Original TOML bytes; independent owner Unicode/2 MiB policy and positive worker-budget checks, fixed error chains and exact path resolution. Compact `[255, edge]` inputs generate owner cap−1/cap/cap+1 without imposing a whole-file product cap. Other review values retain the loader's existing behavior. |
| `server_request_parsers` | Selector byte modulo five, then bytes: protocol header, state filter, kind filter, clone URL, FTS search. Bit 7 selects an absent optional field for the first three cases. |
| `server_github_response` | Selector byte modulo five, little-endian u16 HTTP status, then body bytes: app metadata, installation lookup, token, issue receipt, label result. Missing status defaults to 200. Errors must match the complete metadata-only diagnostic; decoded credentials have constant redacted Debug output. |
| `server_ingress_requests` | Six Worker and eight Operator body decoders plus three query validators, selected by byte zero modulo17. Independent field admission and append-time original Agent token spans; compact recipes cover escaped and literal field limits. These fixtures exercise private decoders before legacy projection. |
| `server_ingress_transport` | Actual bounded request collection, authenticated router and leased heartbeat, plus all five Reporter HTTP consumers. Independent wipe/lifetime, budget-charge ordering, auth/status/body precedence and retry-count assertions; compact recipes reach request, response and token caps. |

The protocol oracle recognizes unsigned decimal with an optional leading plus,
including leading zeros. `JobKind::from_str` is infallible: unknown strings become
`Unknown`, which the route refuses. Clone URL parsing remains permissive: HTTPS
hostnames can be empty, empty path components are skipped, and extra components
are ignored. FTS filtering uses byte lengths and inserts its own double quotes;
the input's quotes and other operators are stripped.

GitHub's `escape-closing-fence` seed and email's `escape-oversize-body` seed are
acceptance inputs for S3. Main currently renders description/title content outside
fences and uses fixed PoC fences; email has no body cap. The email seed exceeds
65,536 bytes as a concrete large-body example; the selected S3 email destination
cap still awaits renderer implementation. These properties are observed rather than asserted as existing
guarantees. The fence scanner has positive and negative examples to ensure that
it distinguishes enclosed content from plain text and embedded closing fences.

L8 keeps remote bodies and serde details out of reporter error chains while
retaining status, operation and configured request identifiers. Real HTTP
regressions cover all five operations and malformed success JSON, and failed
before the correction. The target independently models typed-serde object and
exact-sequence forms, duplicate/required-field checks, and ignored-value syntax.
Unknown fields can contain bytes that a whole-body JSON Value decoder rejects;
known credential and identifier fields still require their declared types.

The response target also invokes all five private Reporter validators through
fixed cfg-only fixtures, independently checking exact app-slug policy and
original field values. Its historical status helpers remain compatibility
controls. Collection belongs to the transport target: ordinary bodies have a
16 MiB cap and token bodies a 256 KiB cap, with real early-close, truncated,
chunked and declared-length recipes. Successful label responses and the first
App-authentication 401 retain their intentional ignored-body behavior.

Request transport fixtures use actual stored peer identities and router
middleware, including denied peers, protocol/media ordering and byte debt.
They do not exercise TLS handshakes or arbitrary raw request framing. Wiping
audits observe initialized allocations during Drop, including replacement and
last-owner release; they make no claim about allocator, library or kernel copies.

Additional fuzz-only dependencies are the existing product crates and their
existing `http`, `blake3`, `serde`, `toml`, and `tempfile` libraries: header/hash
oracles, corpus shapes, independent TOML inspection, and filesystem loader
fixtures respectively. None is introduced into a product dependency graph.
