# SQL source retention

The private ingress module owns actual SQLite TEXT/BLOB reads. Its two narrow
unsafe sites receive a Row, never caller-supplied bytes. Named validators return
final source-bearing values. No source-selectable decoder, public labelled
Deserialize, unmarked constructor or legacy raw projection remains.

| Read owner | Retained source |
| --- | --- |
| repositories, reporting, workers and App metadata | Db; App PEM remains Secret and summary reads skip PEM decoding |
| findings | Agent designated content after exact `agent` metadata validation; approval/rejection/proposer names stay Db; immutable report identity is separate |
| review units/results/leads/observations | Agent designated content after exact metadata validation; keys, revisions and defer/stale/retry/invalidation reasons stay Db |
| jobs, generations, campaigns, checkpoints and receipts | Db text, revisions and stored JSON; known tags and counts remain closed/scalar |
| inventory | Db RepoPath or explicitly unrepresentable native-path rendering |
| scanner document | opaque ScannerDocument<Db>, preserving malformed-JSON-to-null fallback; no public Value extraction |

Finding, Verdict, RepoSpec, ReportingDestination and JobKind carry explicit
source parameters. DAO writes borrow those owners. Different revision, policy,
request, artifact-display and narrative sources use independent parameters;
there is no runtime source dispatch on writes. Generic proof/attempt metadata
records the designated content parameter's Source::NAME, not a supplied string.
Those APIs still have no production HTTP producer or typed read endpoint.
Their test-only closed AgentContent/RecordedContent projections preserve other
known classifications as Db, rejecting unknown/noncanonical names. Metadata is
not authorship or authority and never reconstructs Config/Repo/Sandbox values.

Schema v5 eagerly creates immutable 16-byte random finding identities; v6 adds
exactly twelve content-classification columns, conservatively backfilled agent.
New finding writes obtain OS entropy before insertion. Only the repository /
fingerprint uniqueness conflict is ignored; identity collisions and entropy
errors propagate. Reads reject missing/invalid identities. Rowid reuse cannot
reuse the deleted finding's identity. Later report-scope receipts must bind it.

VerificationInput separates Submitted Agent verdict notes/reason from the exact
closed DeadlineExpired tuple. NULL job alone does not identify the host tuple.
The existing roll-up behavior and all unusual legacy tuple controls remain.
No source token is minted for the deadline literal or initialization literals.

Checkpoint outcomes preserve Fresh<S> versus Replayed<Db>. The survey-batch
initializer is a closed host operation. CampaignCounts is a closed composition
of actual typed Db job-kind/group observations and scalar counts. It preserves
historical Payload canonical bytes, raw/final 64 KiB limits and node admission;
there is no arbitrary public JSON constructor or remint for the rendered bytes.
SearchQuery retains its typed keyword/syntax input until the concrete FTS sink.

Exact legacy text uses its existing 2 MiB policy with significant whitespace,
original Unicode and applicable CR/LF/TAB. Invalid rows are refused without
rewriting bytes. Shared RevisionText/AuditName/JobDiagnostic/JobKindName policies
replace temporary duplicates. Local CheckpointOperation, InventoryRendering
and finding SearchText retain their actual domain contracts.

SourceRefs retains 32/64 counts, raw/canonical 64 KiB bounds and original serde
map/sequence/duplicate/unknown rules. Carry binds original SQLite column/token
ranges before decoded text construction, including equal-content spans. Paths
stay exact; semantic symbols use their existing normalization and raw margin.
Reporting/App decoders retain source-bound string preflight and the original
envelope recursion/ignored-value semantics. Scanner documents have no newly
invented Payload normalization or whole-document ceiling.

Conversion errors contain only fixed field/rule/category metadata, never serde
errors or SQL values. ExistingPolicy and Admission remain distinct. Later
partial reporting must preserve whole-list rejection for old schema failures,
including compound failures hidden behind an earlier admission error. This
migration does not implement that later delivery-scope policy.

SQLite and parser scratch remain opaque dependency copies. Fixed-source test
fixtures exist only under cfg(test); they do not replace actual ingress. Runtime
DAO, schema, replay, identity, count-budget, secret and source-span controls use
real encrypted databases. Full atomic-M consumer/fuzz/Kani and scope joins are
validated at the workspace integration boundary.
