# SQL text ingress during S3 I

The private `ingress` module owns actual SQLite TEXT/BLOB reads. Its two narrow
unsafe sites can only receive a `Row`; neither accepts caller-supplied bytes.
Named validators produce concrete staged marked wrappers. They never select
a source from row contents or expose a generic source/output decoder.

Public DAO records and parameters retain their legacy types until M. Every
source-erasing projection is named below. This preparation does not complete
source retention, schema v6, scope authorization, or the atomic M adoption.

| Read owner | Content interpretation |
| --- | --- |
| repos and reporting-reference counts | Db clone URL, host, owner, repository, branch, revisions and reporting fields |
| scanner configuration | private Db document; historical malformed JSON to null fallback; no new Payload conversion or whole-document cap |
| workers | Db WorkerName; closed kind parser; authentication still requires the existing active lookup |
| findings | Db original columns carried to Agent for scanner/title/description/path/CWE/patch/PoC/fingerprint/patch notes; approval/rejection/proposer CNs remain Db |
| jobs | Db revisions, diagnostics and unknown kind spellings; known state and scheduling band remain closed scalars |
| GitHub App full/summary | original BLOB read has a guarded copy during its named Db decode; slug stays Db; full PEM remains Secret; summary never decodes a PEM String |
| review units/results/leads/observations | designated prose, identity, payload and nested refs carry to Agent; keys, revisions, stale/defer/retry/invalidated metadata stay Db |
| generations/campaigns/checkpoints/receipts | Db policy/profile/prior-follow-up/response/snapshot payloads, stored titles/reasons, revisions and operation/kind/grouping spellings |
| inventory | Db exact RepoPath when representable; separate exact display text for explicitly unrepresentable Git-byte renderings |

Closed enums alone implement `review::ClosedSqlEnum`. Unknown JobKind remains
forward compatible and is validated under its named Db owner before the
explicit legacy exit. Startup still refuses unknown kinds, but counts distinct
spellings in SQL and returns only that count; raw kind strings never enter
the startup error. IDs, timestamps, digests, flags, counts and known enum tags
retain existing scalar semantics.

## Admission and compatibility

New exact legacy fields use the accepted 2 MiB byte/scalar ceiling, allow
empty text and retain Unicode spelling and significant whitespace. Finding
paths use the accepted 512-byte RepoPath policy. Exact multiline descriptions,
patches, PoCs, notes and diagnostics preserve CR/LF/TAB. Invalid rows are
rejected at reads without updating, truncating or substituting their columns.

Existing semantic prose, identifier, anchor and JSON policies are shared with
core. The additional private policies are RevisionText, AuditName,
JobDiagnostic, JobKindName, CheckpointOperation, InventoryRendering and CountKey.
RevisionText, AuditName, JobDiagnostic and unknown-kind composition require
cross-crate name/type reconciliation at M. No SHA-only revision grammar is
introduced; the existing `base` revision remains valid. Anchors retain their
existing contraction/normalization behavior without a new raw-input bound.

SourceRefs retains 32/64 count limits, the 64 KiB raw and canonical limits,
duplicate/unknown/default/null/sequence rules, exact path spelling and semantic
symbol normalization. Checked pointer subtraction locates each original
RawValue token, including repeated equal tokens. Db-to-Agent carry precedes
bounded string decoding. Symbol's decoded-raw preflight retains its existing
MAX_BYTES*4 margin before semantic normalization. No reserialized value or
equal-content search is used for carry.

Reporting and App field decodes use core's source-neutral bounded string
preflight. Reporting validates the complete original JSON document after
designated field preflight with a discarding serde visitor, preserving the
internally tagged decoder's ignored-value and original-root recursion rules.
There is no new aggregate reporting/scanner-document cap. Opaque serde parser
scratch and SQLite's buffers are not claimed to be Secret-owned erasure.

Read conversion errors keep only static field names and closed rules, with
no original serde error, raw column or offending code point retained. The
private Syntax/ExistingPolicy categories are distinct from new Admission
failures. The reporter/scope join must preserve the difference between an old
whole-list conversion failure and a new per-entry admission failure when it
implements partial GitHub delivery; this unit does not change delivery scope.
The first error alone does not establish that the rest of a row satisfied the
old schema. A new title admission error can precede an invalid stored state;
an invalid new mail address can precede an ignored malformed JSON value.
The later reporting batch must check such compound failures and preserve the
old whole-list rejection before selecting per-entry deferred admission errors.

## Mandatory M deletion inventory

Remove these private source-erasing functions (including macro-generated
required/optional forms) when public DAO types retain their sources:

- `agent_payload_legacy`
- `anchor_legacy`
- `app_legacy`
- `app_summary_legacy`
- `argument_legacy`
- `audit_legacy`
- `branch_legacy`
- `client_key_legacy`
- `clone_url_legacy`
- `count_key_legacy`
- `cwe_legacy`
- `db_payload_legacy`
- `description_legacy`
- `diagnostic_legacy`
- `family_legacy`
- `finding_title_legacy`
- `fingerprint_legacy`
- `inspected_refs_legacy`
- `instance_legacy`
- `inventory_legacy`
- `inventory_path_legacy`
- `job_kind_legacy`
- `job_kind_text_legacy`
- `objective_legacy`
- `operation_legacy`
- `optional_agent_payload_legacy`
- `optional_argument_legacy`
- `optional_audit_legacy`
- `optional_branch_legacy`
- `optional_cwe_legacy`
- `optional_db_payload_legacy`
- `optional_diagnostic_legacy`
- `optional_finding_path_legacy`
- `optional_instance_legacy`
- `optional_patch_legacy`
- `optional_patch_notes_legacy`
- `optional_poc_legacy`
- `optional_reason_legacy`
- `optional_receipt_title_legacy`
- `optional_revision_legacy`
- `patch_legacy`
- `patch_notes_legacy`
- `poc_legacy`
- `reason_legacy`
- `receipt_title_legacy`
- `refs_legacy`
- `repo_host_legacy`
- `repo_name_legacy`
- `repo_owner_legacy`
- `reporting_legacy`
- `revision_legacy`
- `scanner_document_legacy`
- `scanner_legacy`
- `title_legacy`
- `unit_refs_legacy`
- `worker_name_legacy`

The SourceRefs canonical projection is never used as carry input. Current
legacy write DTOs, public FromStr/Deserialize implementations and fixture-only
D readers are also staging debt; M adopts the final types and removes those
exits. Existing NewReview/NewAttempt/proof methods currently write supplied
values or query scalar ownership facts; this unit invents no content read or
HTTP producer for them. M must retain explicit mixed attribution for submitted
rationale versus closed host reasons.

## Evidence and integration

Actual pre-change DAO tests distinguish newly rejected inputs and reflected
diagnostics from compatibility controls. Production-reader tests observe live
column and token ranges without accessing freed memory. Existing scope,
identity, canonical JSON, secret ownership, summary skipping, replay and
scheduler tests continue to exercise their real behavior.

The integrator must add `crates/loupe-storage/src/ingress/mod.rs` to the unsafe
allowlist (actual SQL Db ingress) and update the single server test constructor
from `Error::UnknownJobKinds(vec![])` to `Error::UnknownJobKinds(0)`.
The storage manifest enables the already-present source-migration, ingress
and raw_value features; no lockfile package change is expected. Full workspace
gate and final source-retention/fuzz joins remain integrator-owned.
