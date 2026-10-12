# CLI ingress ownership

The CLI retains Config values through concrete request and local-operation
inputs, and Server/Agent values through final protocol DTOs and rendering.
This describes the CLI portion of atomic M; other consumers and the combined
integration gates remain separate obligations.

## Actual input owners

`config_input::argument` mints Config only inside concrete Clap value-parser
callbacks, on the actual borrowed native argv/environment value before parsing.
`config_input::read_pem` mints a borrowed Config view at the actual guarded TLS
file read. The existing Secret owner stays alive; no PEM-sized copy is made to
attach provenance. UTF-8 has already been checked by the guarded reader; PEM
syntax/trust remains with each existing TLS operation. This named file/TLS
operation returns a private fixed-Config `SelectedPem` holding the existing
guarded allocation. Raw/base64 selection also returns `SelectedPem`; selection
does not erase Config. Concrete TLS/CA constructors borrow through `for_tls`.
The selected App wire operation consumes the holder into the existing closed
credential encoder without exposing a reusable raw Secret or plaintext copy.

`ingress::receive` mints Server on the exact Bytes returned by the existing
16 MiB guarded collector. It adds no plaintext body copy. Response Content-Type,
protocol header absence/mismatch, and numeric protocol-version mismatch retain
the old CLI behavior. Non-success responses retain the bounded lossy short
diagnostic in a guarded, fixed-Server `TerminalDiagnostic` until its intentional
Display operation. Main applies TerminalText to the entire final error.

The three production `Ingress::new` sites remain in two files. Normal tests
obtain Server through real loopback HTTP and use the actual Clap callbacks;
the separate fixed-Server fuzz fixture is cfg-only. Registry changes belong
to the root integration owner.

## Text and source contracts

Finding scanner/title/fingerprint/path and detail description/CWE/patch/PoC
are Agent content. `findings::span` checks the actual borrowed RawValue pointer
against the original live response, then carries its encoded range from Server
to Agent BEFORE bounded string decoding. No equal-content search, reserialization,
post-parse mint or whole-row relabelling is used. Finding audit common names
stay Server, even when equal to an Agent field. Final summaries and details
retain both sources through their fixed Agent/Server renderer inputs.

Metadata, revisions, JobInfo diagnostics, repository reporting identity and App
slug stay Server. Known job-kind spellings become the closed core enum; unknown
spellings retain `BoundedText<JobKindName, Server>` through the named terminal
formatter. Known kinds and Unknown spellings retain their previous visible
Debug spelling without adding a second layer of string quoting.

Core exact policies cover FindingTitle, FindingDescription, ScannerIdText,
FindingFingerprintText, CweText, PatchUnified, PocUnified, CloneUrl, RepoHost,
RepoOwner, RepoName, GitBranch, WorkerName, GithubAppSlug, MailAddress and
MailSubjectPrefix. Legacy text ceilings are 2 MiB decoded bytes and scalars;
empty text and significant Unicode/spacing remain. RepoPath has the accepted
512-byte relative-path admission. These are deliberate admission changes,
not old strict LLM grammar or a historical 256 KiB patch cap.

SearchQuery and CertificateName remain owner-local; the other policies below
use the shared core definitions:

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

## Named output operations

Config text parsers return the concrete bounded Config values consumed by
typed request constructors. Configured native paths, parsed URLs and guarded
PEMs have crate-private borrows named for filesystem, HTTP and TLS operations.
The common-name enum distinguishes the closed default from explicit Config
input. Search and certificate operations borrow text only at their existing
query and certificate-library calls.

Repository registration uses `scanner_config: None` when the CLI supplies no
document. It does not synthesize a Config mark or a null document. Actual
Server response decoders map missing/null job optionals and repository
reporting fields to their historical defaults while retaining populated
source-bearing values. Ordinary JSON and credential output operate on the
final DTOs, including the original field ordering and omission behavior.

`PatInput::into_pat` moves the unique Secret allocation, or makes a deliberately
guarded copy only while another Clap handle exists. Request builders pass that
Secret to the existing credential_json and owner-backed request body. Worker
and certificate export stays guarded until intentional stdout/file/env delivery.

Scalar-only responses and `discard` preserve their original behavior. There is
no generic decoder, public cast, labelled Deserialize, raw source constructor or
early prose response-to-legacy projection. Worker registration retains its
accepted credential response representation: certificate text and guarded
private-key/CA owners pass into the closed credential exporter. Historical raw
DTOs exist only in private test support as a frozen serde compatibility oracle.

## Wire compatibility and evidence

Raw records preserve original serde field order, positional sequences,
required/default/null/present-empty behavior, ignored unknown members and
known duplicate rejection. Existing external unit-enum map spellings remain;
JobKind and internal reporting tags retain their original string semantics.
Reporting alone uses a no-output Content traversal with three enclosing levels
(response, repos array, RepoSummary), preserving the original recursion and
number handling. Ordinary ignored DTO extras retain their iterative ignore
behavior rather than receiving a blanket whole-body Value restriction.

Baseline PAT Debug and text-admission assertions are saved outside the checkout.
Terminal rejection assertions also ran on unchanged baseline production: four
expected reds, while the original five escaping controls passed. Invalid
successful-response fields now exercise actual admission refusal. Separate
direct TerminalText/Style tests retain literal escaping controls, including
every C0/C1 character, CR and LF; valid renderer fixtures enter through the
actual response owner and retain Unicode, markup and significant spacing.

The missing/null/default response fixtures are compatibility positives, not
historical regression reds. Populated job parentage, failure fields and the
390-second duration are checked through get/retry/cancel/list owners. The job
kind output test distinguishes the unfinished M candidate's extra quoting
from the corrected named terminal operation.

Original-token evidence checks equal array members, detail diff/prose equality,
retained Server audit types, response allocation identity and exact limits.
OS argv/env, Clap's backing storage, transport and kernel copies remain opaque
dependency limits. Complete atomic M and full fuzz-target validation require
the combined consumer tree.
