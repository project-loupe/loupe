# Server ingress during source migration (I)

This is staged adoption, before the atomic source-bearing API migration (M).
Private validators establish actual input sources; the named legacy exits below
are temporary, explicit conversions to existing unlabelled DTO/DAO consumers.
They are not evidence that those consumers already retain provenance. The
`source-migration` feature and these exits must disappear at M.

## Actual owners and authority

`auth::mtls_auth` alone creates Worker or Operator authority, after the current
certificate fingerprint resolves to an active database row. `AuthedWorker` has
private row/authority fields; its read-only metadata and Clone cannot change the
role. No row conversion, Default, public token getter or generic source choice
exists. Debug contains only id and closed role metadata. Revocation is checked
again on each request.

Worker middleware charges request/lease budgets, then actual chunks before its
2 MiB cap. It collects once into `RequestBuffer`, puts shared guarded `Bytes`
behind a private Worker capture, and consumes that capture in the typed
extractor. Operator JSON routes collect with the matching authority and the
same cap. Operator no-body routes still ignore bodies; workers still collect
ignored bodies. Growth allocates before copying and wipes the old live capacity;
error, cancellation and final shared-owner Drop wipe collected storage. OS,
HTTP transport chunks and parser scratch are dependency-owned copies.

Order remains authentication/worker budgets, protocol header, role, media/body
extraction, body version, job capability and operation checks. Empty heartbeat
still requires no media header; its nonempty body uses its custom 400 error.
Application/json and application/*+json MIME grammar are unchanged. Errors keep
closed syntax/data/policy categories and static reasons, never serde/TOML input
or hidden parser sources. Response version headers remain outermost.

One bounded compatibility exception is intentional: malformed object/array
values in a string field now receive syntax 400 after RawValue finishes scanning,
where legacy serde could stop at the opening type with 422. Well-formed wrong
types remain 422; scalar numeric overflow remains syntax 400. Ignored outer
fields retain their old admission. Internally tagged reporting/verdict content
uses an envelope-shaped post-validation pass to preserve recursion budgets.
Registration returns scanner_config Value from that one pass, without a second
standalone parse or a whole-document Value/serialization prepass.

## Fixed schemas and temporary exits

All request validators are private `ingress` schemas. Operator owns repository
registration/update/reporting, worker registration, App setup, scan enqueue and
retry-verification requests. Worker owns lease, heartbeat and completion.
Finding/LLM/verdict validators carry only designated RawValue token subslices
from the original Worker body to Agent, before string decoding. Pointer/range
checks and the primitive carry contract reject reconstructed external tokens.
Scalar metadata never gains an artificial Agent label.

The exact exit inventory is:

- `registry::{RegisterRepoDecoder, UpdateRepoDecoder, EnqueueScanDecoder,
  RetryVerifyDecoder, RegisterWorkerDecoder, RotateRepoPatDecoder,
  SetGithubAppDecoder, SetRepoGithubReportingDecoder}::decode_legacy`.
- `jobs::{LeaseRequestDecoder, HeartbeatDecoder, CompleteDecoder,
  FindingsBatchDecoder, LlmFindingDecoder, VerdictSubmissionDecoder}::decode_legacy`.
- `query::SearchQueryDecoder::{worker_legacy, operator_legacy}`. Actual role
  selects one concrete source. JobListQueryDecoder returns closed states/kind
  and scalar limit, with fixed errors. FTS sanitization stays at the operation.
- `config::ServerFileConfigDecoder::decode_legacy`; paths retain native PathBuf
  and relative resolution, allowed owners retain exact Config spelling.
- Binary `ServerHostPathDecoder::decode_legacy` and
  `ServerTlsPemEgress::move_legacy`. The latter is a named forward-payload
  admission, not a PEM syntax/trust validator: it borrows existing guarded UTF-8
  PEM and moves the original Secret to the existing TLS constructor. Mixed
  bundles, allocation identity, raw/base64/file precedence and grammar remain.
- `reporters::ingress::AppMetadataDecoder::decode_legacy` for id/marked Reporter
  slug. InstallationDecoder and IssueReceiptDecoder return scalars;
  LabelResponseDecoder preserves the closed acceptance decision.

`ServerMasterKeyDecoder` and `ServerBase64PemDecoder` consume actual Config
captures and return the existing concrete guarded key/PEM outputs. Capture
occurs before hex/base64 decoding. File/CLI path selection remains in the
process owner. There is no new whole-config, host-path or PEM cap. Init's closed
certificate generation and explicit export remain existing behavior; M must
inventory its actual dynamic hostnames/data-dir inputs separately rather than
claiming this Serve/config-reader join already migrates them.

Local exact policies `RevisionText`, `JobDiagnostic` and `SearchText` need
canonical owner coordination at M. Shared WorkerName, LeaseCapabilityName and
GithubAppSlug policies come from core. `json_text` currently supports exact
policies only: semantic future uses require the accepted decoded-raw margin
before normalization/final caps. Paths use RepoPath where appropriate; scanner
configuration uses its named Operator forward-document owner, not Payload
normalization. LLM title/description still require trim-view minima, but the
original admitted bytes now reach SQL and HTTP output unchanged.

## Reporter responses

Actual metadata, installation, issue and unsuccessful-label readers now use
loupe-http's guarded 16 MiB collector before named Reporter validation. This is
a newly applied Reporter ceiling. The existing token reader retains its separate
256 KiB ceiling and guarded mutable scratch. Token output remains Secret and
existing Arc cache/Bearer ownership, expiry/revoke/retry behavior is unchanged.
Successful label statuses ignore their bodies. Status 422 plus the ASCII
already_exists byte substring remains accepted even for malformed/non-JSON or
invalid-UTF8 label bodies, matching the prior lossy-text decision.

Existing public pure compatibility/fuzz adapters remain temporary unlabelled
entry points: github_app::{parse_app_response, parse_installation_response,
parse_access_token_response} and github::parse_issue_response. Actual HTTP
readers no longer use them as provenance validators. M must close or replace
these public legacy entries; a generic serde helper must never become an
arbitrary labelled decode escape.

## Evidence interpretation

Runtime red/green controls cover reflected JSON, heartbeat, TOML and query
errors, original LLM bytes and uncapped Reporter bodies. Original passing
compatibility controls remain. Numeric and envelope-depth controls distinguish
the earlier candidate from the repaired one. Authority compile-negative checks
are API evidence (pre-change public mutation compiled), while new source-type,
allocation identity and live cleanup tests are acceptance evidence, not claims
of earlier runtime disclosure or observation of freed memory.
