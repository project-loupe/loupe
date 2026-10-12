# CLI ingress staging

This is the CLI's temporary I owner. Atomic M must remove every legacy exit
below and connect the retained source-bearing values to typed requests and
renderers. No public protocol DTO, rendering sink, event producer or scope
migration is completed here.

## Actual input owners

`config_input::argument` mints Config only inside concrete Clap value-parser
callbacks, on the actual borrowed native argv/environment value before parsing.
`config_input::read_pem` mints a borrowed Config view at the actual guarded TLS
file read. The existing Secret owner stays alive; no PEM-sized copy is made to
attach provenance. UTF-8 has already been checked by the guarded reader; PEM
syntax/trust remains with each existing TLS operation. The returned Secret is
a deliberate credential legacy join, not a final Config-labelled TLS API.

`ingress::receive` mints Server on the exact Bytes returned by the existing
16 MiB guarded collector. It adds no plaintext body copy. Response Content-Type,
protocol header absence/mismatch, and numeric protocol-version mismatch retain
the old CLI behavior. Non-success responses retain the useful bounded lossy
short diagnostic; main still applies TerminalText to the entire final error.
There is no claim that terminal error escaping was broken.

There are three `Ingress::new` sites in two files. Tests obtain Server through
real loopback HTTP and use the actual Clap callbacks; no test mint was added.
Root joins the two file entries into the shared unsafe registry.

## Text and source contracts

Finding scanner/title/fingerprint/path and detail description/CWE/patch/PoC
are Agent content. `findings::span` checks the actual borrowed RawValue pointer
against the original live response, then carries its encoded range from Server
to Agent BEFORE bounded string decoding. No equal-content search, reserialization,
post-parse mint or whole-row relabelling is used. Finding audit common names
stay Server, even when equal to an Agent field.

Metadata, revisions, JobInfo diagnostics, repository reporting identity and App
slug stay Server. Known job-kind spellings become a closed local enum; unknown
spellings retain `BoundedText<JobKindName, Server>` before their explicit legacy
projection. Unknown kinds remain forward compatible and never become closed
trusted metadata.

Core exact policies cover FindingTitle, FindingDescription, ScannerIdText,
FindingFingerprintText, CweText, PatchUnified, PocUnified, CloneUrl, RepoHost,
RepoOwner, RepoName, GitBranch, WorkerName, GithubAppSlug, MailAddress and
MailSubjectPrefix. Legacy text ceilings are 2 MiB decoded bytes and scalars;
empty text and significant Unicode/spacing remain. RepoPath has the accepted
512-byte relative-path admission. These are deliberate admission changes,
not old strict LLM grammar or a historical 256 KiB patch cap.

Local policy names that must converge with other owners at M:

| Policy | Source | Exact contract |
| --- | --- | --- |
| SearchQuery | Config | 2 MiB, multiline LF/TAB/CR, empty allowed |
| CertificateName | Config | 2 MiB, single line, empty allowed, no new hostname grammar |
| RevisionText | Server | 2 MiB, single line, nonhex and empty allowed |
| AuditName | Server | 2 MiB, single line, empty allowed |
| JobDiagnostic | Server | 2 MiB, multiline LF/TAB/CR, empty allowed |
| JobKindName | Server | 2 MiB, single line, unknown/empty allowed |

All are Exact/Significant; there is no NFC, trimming, truncation, case folding
or diff rewriting. PEMs and PATs do not inherit prose caps or grammar. Server
PEM decoding is bounded by the existing 16 MiB response budget. Native paths
remain native PathBuf values without RepoPath restrictions or lossy conversion.
The server URL retains reqwest's existing URL parsing and normalization.
Clap's closed default common name `loupe-server` is not minted as Config.

## Exact temporary legacy exits

These are private fixed-source operations, not generic source-selectable
converters. M deletes/replaces them together with the staged core namespace.

- Config text parser exits: `CloneUrlLegacy`, `BranchLegacy`, `OwnerLegacy`,
  `RepoLegacy`, `WorkerNameLegacy`, `SearchLegacy`, `HostnameLegacy`, and
  `CommonNameLegacy`. Their named validators first produce concrete marked
  bounded text; the parsers then return the old String argument types. The
  default branch of CommonNameLegacy is a closed host literal.
- Config native/domain exits: `PathLegacy` and `UrlLegacy` project their
  private configured native-path/parsed-URL holders; `PemLegacy` projects the
  configured guarded PemInput. `read_pem` returns the guarded file owner after
  validating its borrowed Config view. Native path display remains presentation.
- Request joins in main: `register_repo_request_legacy`,
  `set_reporting_request_legacy`, and `register_worker_request_legacy` construct
  the three existing text-bearing DTOs from admitted private arguments. Search
  egress is the existing `finding_search` query call; certificate names go to
  the existing mint-server constructor. M must retain Config through these
  operation-specific sinks instead of keeping these early parser projections.
- Credential exit: `PatInput::into_pat` moves the unique Secret allocation, or
  makes a deliberately guarded copy only while another Clap handle exists.
  Register/rotate/reporting request builders pass that Secret to the existing
  credential_json and owner-backed request body. App/PEM loaders retain their
  existing guarded byte owners and precedence. Worker/certificate export stays
  explicitly guarded until the intentional stdout/file/env delivery.
- `show_github_app_legacy`, `list_repos_legacy`,
  `reporting::reporting_summary_legacy`, `register_worker_bundle_legacy`.
- `get_job_legacy`, `retry_job_legacy`, `cancel_job_legacy`, `list_jobs_legacy`,
  `jobs::job_info_legacy`, and `ServerKind::legacy` (the only Unknown(String)
  exit). Concrete Server leaf exits in ingress/mod.rs are `revision_legacy`,
  `diagnostic_legacy`, `clone_url_legacy`, `host_legacy`, `owner_legacy`,
  `repo_legacy`, `branch_legacy`, `slug_legacy`.
- `list_findings_legacy`, `search_findings_legacy`, `Summary::legacy`, and
  `get_finding_legacy`; each projects the already validated mixed-source fields.
- `ServerDiagnostic::validate` is the explicit diagnostic legacy exit to the
  existing bounded status/action/error presentation. It is distinct from the
  newly checked JobInfo.error field.

`register_repo`, `scan_repo`, and `retry_verification` decode scalar-only
concrete DTOs; `discard` preserves arbitrary ignored success bodies. They do
not create unlabelled text exits. No generic decoder, public cast, labelled
Deserialize or From<legacy> route was introduced.

## Wire compatibility and evidence

Raw records preserve original serde field order, positional sequences,
required/default/null/present-empty behavior, ignored unknown members and
known duplicate rejection. Existing external unit-enum map spellings remain;
JobKind and internal reporting tags retain their original string semantics.
Reporting alone uses a no-output Content traversal with three enclosing levels
(response, repos array, RepoSummary), preserving the original recursion and
number handling. Ordinary ignored DTO extras retain their iterative ignore
behavior rather than receiving a blanket whole-body Value restriction.

Actual baseline PAT Debug and text-admission assertions are saved outside the
checkout. Additional terminal rejection assertions ran on a separate unchanged
baseline: four expected reds, while the original five escaping controls passed.
The original invalid successful-response payload remains in ingress_terminal
as rejection coverage; terminal successful-output cases now separately admit
Unicode/markup/spacing. Error-body and direct-render control assertions remain.

New-API evidence checks original token ranges across equal array members,
detail diff/prose equality, retained Server audit types, response allocation
identity, exact limits, schema equivalence and PAT handle ownership. It is not
misrepresented as a preexisting missing-API regression. OS argv/env, Clap's
backing storage, transport and kernel copies remain opaque dependency limits.
