# Server input ownership

The server retains source labels through its request DTOs, storage calls and
reporter inputs. The staging feature and named legacy conversion methods have
been removed. Source-bearing DTOs serialize deliberately but do not implement
arbitrary Deserialize; private named decoders own each actual boundary.

## Authority and body capture

`auth::mtls_auth` alone creates Worker or Operator request authority, after the
current certificate fingerprint resolves to an active database row. The stored
worker name remains Db. `AuthedWorker` has private row/authority fields and no
public authority getter or source selection. Revocation is checked per request.

Worker middleware charges request/lease budgets, then actual chunks before its
2 MiB cap. It collects once into `RequestBuffer`, puts shared guarded `Bytes`
behind a private Worker capture, and consumes that capture in the extractor.
Operator JSON routes collect under the authenticated Operator authority and the
same cap. Operator no-body routes ignore bodies; workers collect even ignored
bodies. Growth allocates before copying and wipes old live capacity; errors,
cancellation and final shared-owner Drop wipe collected storage. OS, HTTP
transport chunks and parser scratch remain dependency-owned copies.

Order remains authentication/worker budgets, protocol header, role, media/body
extraction, body version, job capability and operation checks. Empty heartbeat
requires no media header; its nonempty body uses its custom 400 error.
Application/json and application/*+json admission are unchanged. Closed errors
retain syntax/data/policy categories and static reasons, never supplied parser
text or hidden serde/TOML sources. Response version headers remain outermost.

One bounded compatibility exception remains: malformed objects/arrays in a
string field receive syntax 400 after RawValue scans the value, where legacy
serde could stop at its opening type with 422. Well-formed wrong types remain
422; scalar numeric overflow remains 400. Ignored outer fields retain their
admission. Tagged reporting/verdict content uses an envelope-shaped validation
pass to retain the original recursion budget. Registration moves the parsed
scanner document from that pass into the opaque `ScannerDocument<Operator>`;
it has no generic Value extraction or labelled Deserialize API.

## Request and stored content

Private `ingress` decoders return final source-bearing DTOs. Operator owns repo
registration/update/reporting, worker registration, App setup, scan enqueue and
retry-verification inputs. Worker owns lease, heartbeat and completion content.
Finding, LLM and verdict decoders carry designated original RawValue token
subranges from Worker to Agent before string decoding. Pointer/range checks
reject reconstructed tokens; equal decoded text does not select a span.

The LLM decoder attaches only its fixed scanner literal as protocol metadata
under the same live Agent mark. It does not accept a caller-selected override.
Strict title/description checks use a trimmed view, while original admitted
bytes reach SQL and HTTP output. Queries retain Worker or Operator through
search; closed job kind/state and scalar limits remain metadata. FTS sanitation
occurs at the actual search operation. Shared exact policy names come from core;
`json_text` supports exact policies and cannot stand in for semantic policies'
pre-normalization margins.

Storage reads establish Db for ordinary metadata and carry designated original
stored content to Agent. Historical `source = agent` is conservative content
classification, not authorship or request authority. Reporter input therefore
combines an Agent finding with its Db revision and typed destination settings.
Host deadline reasons, policy defaults, phase recipes, counts and pending follow
ups use their named closed compositions; they do not mint a source for generated
text or allow arbitrary host JSON construction.

## Configuration and secrets

`ServerFileConfigDecoder` validates original Config file bytes. Actual native
Clap parsers retain `ConfiguredPath`, `ConfiguredHostname` and guarded PEM input
owners; selected PEM remains `ConfiguredPem` through the TLS operation. There
is no public post-hoc string constructor. Relative paths retain native PathBuf
semantics and raw/base64/file precedence is unchanged. Mixed certificate inputs
remain guarded. Public test setup uses these actual parsers/readers.

`ServerMasterKeyDecoder` validates original Config before hex decoding into the
existing opaque key. Init's dynamic hostnames and data directory use the same
Config owners; generation and explicit credential export retain their closed
interfaces. Secret values are borrowed only at their concrete crypto, transport
or storage operation. Source ownership does not imply that opaque dependencies
or operating-system buffers can be wiped by Loupe.

## Reporter responses and sinks

Actual metadata, installation, issue and unsuccessful-label responses use the
16 MiB guarded HTTP collector before named Reporter validation. Tokens retain
the separate 256 KiB cap and guarded scratch. App slugs remain Reporter through
storage; cache and dispatch share the existing guarded token owner. Successful
label statuses ignore bodies. Status 422 plus the ASCII already_exists byte
substring remains accepted for malformed or invalid-UTF8 bodies, preserving the
old lossy-text decision. App retry, PAT dispatch and cache behavior are unchanged.

Pure compatibility helpers and synthetic owner observations are available only
under test/fuzz cfg. They do not provide normal-build arbitrary labelled decode
APIs. Reporter render entry points require the final typed finding/destination
owners. Full later report containment, prompt framing and scope/canary work are
separate obligations; typed sink inputs alone do not claim those properties.

## Evidence boundaries

The original runtime red/green controls cover reflected errors, original LLM
bytes and bounded Reporter bodies. Numeric and depth controls preserve their
proven compatibility domains. Authority/source compile probes are API evidence;
live wipe observations are not freed-memory inspection. Direct decoder fuzzing
uses actual private production validators, independently retained wire schemas
and original-span ledgers. Transport targets separately exercise collection,
authentication and byte charging; pure DTO fixtures do not claim HTTP coverage.
