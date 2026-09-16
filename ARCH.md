# Architecture

This file is for "what is in the box and how does it talk to itself."
For "how do I run it," see `README.md`.

## Components

```
crates/
  loupe-core      shared types: Finding, Severity, Verdict, RepoSpec,
                  ReportingDestination
  loupe-proto     wire-format DTOs + protocol versioning
  loupe-tls       internal CA + cert minting + fingerprint helpers
  loupe-storage   SQLCipher-encrypted SQLite DAO surface, FTS5 index,
                  migrations, secrets table
  loupe-server    daemon binary + mTLS routes + reporters + scheduler/reaper
  loupe-worker    worker binary + scanner trait + LLM backend + sandbox
                  + host-side model/MCP brokers (model-proxy and mcp-proxy)
  loupe-cli       loupectl admin CLI
  loupe-web       loupe-web local operator dashboard (loopback HTTP,
                  proxies the same admin RPCs as loupectl)
```

Four deployable binaries: `loupe-server`, `loupe-worker`, `loupectl`, and
`loupe-web`. The model and MCP brokers run *in the worker process*, on the
trusted side of the sandbox boundary. The agent reaches them through
credential-free bridges (`loupe-worker model-proxy` and `mcp-proxy`) backed
by distinct per-invocation Unix sockets. Provider credentials, the fixed
model/effort policy, and server/job authority stay in those host brokers.
`loupe-web` is an optional operator
convenience: it
holds the same admin certificate `loupectl` uses and proxies the same
routes, so it adds no new authority to the system and no new trust root.
It binds loopback only, for the reasons in README §9.

## Component diagram

```
                       ┌────────────────────────┐
                       │        operator        │
                       │       (loupectl)       │
                       └────────────┬───────────┘
                                    │ admin mTLS
                                    │ /v1/repos, /v1/findings, …
                                    ▼
                       ┌────────────────────────┐           ┌────────────────────┐
                       │      loupe-server      │ ─HTTPS──► │ api.github.com     │
                       │                        │  (PAT)    │ (GitHub Issues)    │
                       │  ┌──────────────────┐  │           └────────────────────┘
                       │  │ SQLCipher DB     │  │ ─sendmail─► local MTA
                       │  │ • repos          │  │
                       │  │ • jobs           │  │
                       │  │ • findings       │  │
                       │  │ • finding_fts    │  │ FTS5 over title +
                       │  │ • secrets (PATs) │  │ description + path
                       │  │ • workers        │  │
                       │  └──────────────────┘  │
                       │  ┌──────────────────┐  │
                       │  │ scheduler+reaper │  │
                       │  └──────────────────┘  │
                       └─────────┬─────┬────────┘
                                 │     │
        worker mTLS              │     │ worker mTLS (long-poll)
    (lease, heartbeat,           │     │ POST /v1/jobs/lease
     submit_findings, complete,  │     │
     submit_verdict,             │     │
     search_findings)            │     │
                                 ▼     ▼
                       ┌────────────────────────┐
                       │      loupe-worker      │
                       │  ┌──────────────────┐  │
                       │  │ repo cache       │  │   repo clone/fetch
                       │  │ (LRU bare clones)│  │
                       │  └──────────────────┘  │
                       │  ┌──────────────────┐  │
                       │  │ scanners:        │  │
                       │  │ • regex-secrets  │  │
                       │  │ • llm-code-review│  │
                       │  │ • llm-verifier   │  │
                       │  └────────┬─────────┘  │
                       └───────────┬────────────┘
                                   │ spawns inside bwrap
                                   ▼
              ┌──────────────────────────────────────────────────────────────┐
              │                        agent sandbox                         │
              │ read-only /workdir; fresh /tmp and $HOME                     │
              │                                                              │
              │ agent ──HTTP loopback──► model-proxy                         │
              │   ├────stdio MCP───────► mcp-proxy                           │
              │   └────stdio MCP───────► bkb-mcp (optional)                  ├──HTTP──► BKB API
              └───────────────┬─────────────────────────────┬────────────────┘
                              │ Unix socket                 │ Unix socket
              ────────────────┼─────────────────────────────┼───────────────── trust boundary
                              ▼                             ▼
                  ┌───────────────────────┐     ┌───────────────────────┐
                  │ host-side model broker│     │ host-side MCP broker  │
                  │                       │     │                       │
                  │ provider/model/effort │     │ worker client +       │
                  │ limits + credential   │     │ repo/job capability   │
                  └───────────┬───────────┘     └───────────┬───────────┘
                              │ HTTPS                       │ mTLS
                              ▼                             ▼
                        provider API                  loupe-server
```

The `bkb-mcp` branch is optional: the worker attaches it to the per-call
MCP configuration only when `bkb-mcp` is
on PATH at startup. Workers that don't have it installed run without
that branch and the agent's prompt makes no mention of bkb tools.

The host-side MCP broker exposes a phase-specific tool catalogue. Its
**discovery mode** is used for scan jobs. A verify-mode session (spawned for a
`kind=verify` job) exposes a different surface: `query_prior_findings`
and `get_finding_by_id` carry over, while `submit_finding` /
`validate_poc` are replaced with `submit_verdict`, `submit_patch`,
and `validate_patch` — the verifier records a
`confirm | dismiss | inconclusive` verdict and may optionally attach
a minimally-invasive candidate fix. See
`crates/loupe-worker/src/mcp.rs` `tool_definitions()` for the
canonical mode-split.

## Data lifecycle

A finding's journey from "agent saw something" to "human looked at it":

```
   walk worktree                         │
   produce file list                     │
                                         │  loupe-worker
   ┌─────────────────────────────────┐   │
   │ for each file in parallel:      │   │
   │   spawn agent in bwrap          │   │
   │   prompt: DISCOVERY             │   │
   │   ┌── one agent session ──────┐ │   │   agent fan-out
   │   │ • read /workdir/{file}    │ │   │
   │   │ • enumerate every real    │ │   │
   │   │   bug, severity-ordered   │ │   │
   │   │ for each candidate:       │ │   │
   │   │   • query_prior_findings  │ │   │   (semantic dedup;
   │   │   • get_finding_by_id     │ │   │    dup → skip *this* one,
   │   │     (on a hit)            │ │   │    keep iterating)
   │   │   • generate PoC diff     │ │   │
   │   │   • validate_poc          │ │   │   (`git apply --check`)
   │   │   • submit_finding ───────┼─┼───┼─── Unix-socket JSON-RPC
   │   └───────────────────────────┘ │   │   to host-side MCP broker
   │   wait for session exit         │   │
   │ scanner returns Vec::new()      │   │
   │   (submission already happened) │   │
   └─────────────────────────────────┘   │
                  │
                  ▼
   ┌─────────────────────────────────┐
   │ host-side MCP broker:           │
   │   build LlmFindingSubmission    │     loupe-worker
   │     from MCP args + worktree    │
   │     (read source window, hash)  │
   └─────────────────────────────────┘
                  │ mTLS + X-Loupe-Job-Capability
                  ▼ POST /v1/jobs/{id}/llm-findings
                    (one call per finding; multiple per session OK)
                                         ┴───────────── network hop ─────────
   ┌─────────────────────────────────┐
   │ strict LLM finding handler:     │
   │   validate submission           │
   │   stamp scanner identity        │
   │   INSERT OR IGNORE on findings  │     loupe-server
   │   on UNIQUE(repo_id,            │
   │             fingerprint)        │
   │   → state = pending             │
   └─────────────────────────────────┘
                  │
                  ▼ POST /v1/jobs/{id}/complete  (no findings batch — broker
                                                  already submitted them)
   ┌─────────────────────────────────┐
   │ if verification_required = 0:   │
   │   pending → confirmed           │     scan complete handler
   │   (or → awaiting_approval if    │
   │    require_approval is on)      │
   │ if verification_required = 1:   │
   │   pending → validating          │
   │   enqueue verify jobs           │
   └─────────────────────────────────┘
                  │
                  ▼ (verify lease → verifier scanner → POST /verdict)
   ┌─────────────────────────────────┐
   │ rollup: any dismissed →         │
   │   dismissed.                    │     verdict rollup
   │ else any confirmed →            │
   │   confirmed (or awaiting_       │
   │   approval).                    │
   │ else stay validating until      │
   │   reaper deadline.              │
   └─────────────────────────────────┘
                  │
                  ▼ (when state = confirmed)
   ┌─────────────────────────────────┐
   │ dispatch:                       │
   │   GithubIssue → POST issue +    │
   │     stamp reported_at           │     dispatch
   │   Email → sendmail +            │
   │     stamp reported_at           │
   │   Manual → no external call;    │
   │     stamp reported_at anyway    │
   └─────────────────────────────────┘
                  │
                  ▼ (operator triage)
   ┌─────────────────────────────────┐
   │ POST /v1/findings/:id/approve → │
   │   confirmed → reported          │     human-in-the-loop
   │ POST /v1/findings/:id/reject  → │     (only relevant when
   │   awaiting_approval → dismissed │      require_approval = on)
   └─────────────────────────────────┘
```

States the finding row passes through, in their possible orderings:

```
                   pending
                     │
       ┌─────────────┴──────────────┐
       │                            │
  (verify off)                 (verify on)
       │                            │
       ▼                            ▼
   confirmed                   validating
       │                            │
       │       ┌──────────────┬─────┴──────┬───────────────┐
       │       ▼              ▼            ▼               │
       │  confirmed       awaiting     dismissed       (deadline)
       │                  approval                     reaper →
       │                      │                        dismissed
       │  ┌───────────────────┘
       ▼  ▼
  (require_approval gate, server-default or per-repo)
       │
       ├── off ──► (continue to dispatch)
       └── on  ──► awaiting_approval
                         │
                  ┌──────┴───────┐
                  ▼              ▼
              approved        rejected
                  │              │
                  ▼              ▼
              dispatch       dismissed
                  │
                  ▼
               reported
```

## TLS topology

Every connection in the system is mTLS. The CA is internal — minted
by `loupe-server init` and trusted nowhere outside this loupe
instance. There are three client cert "roles":

- **server**: server's leaf cert, presented when clients connect
  (DNS / IP SANs are populated from `--hostname` at init time).
- **admin**: minted once at init, used by `loupectl` and by `loupe-web`.
  Authorized for the `admin_only` route group (CRUD on repos / workers /
  jobs, approve/reject, ad-hoc scan triggers). Note that a client cert
  does not encode its role — `admin` versus `worker` is decided solely by
  the `kind` column in the `workers` table, so only the server can tell
  them apart. Anything that terminates a connection *outside* the server
  therefore cannot authorize by chain validation alone; this is why
  `loupe-web` gates on a local token rather than on a presented cert. The
  browser keeps that token in origin-scoped session storage and presents
  it only in a dedicated API header; a cookie would leak across loopback
  ports.
- **worker**: minted at `loupectl worker register` time. Authorized
  for the `worker_only` group (lease, heartbeat, submit_findings,
  submit_verdict, complete) plus the shared `authed` group (FTS
  search). Workers are recorded in the `workers` table by SHA-256
  fingerprint of their cert; an unrecognised fingerprint (or one
  whose row is `revoked_at != NULL`) gets a 401.

```
                       ┌───────────────────┐
                       │   loupe-server    │    CA (host of trust)
                       │   ┌───────────┐   │    │
                       │   │ server    │   │    ├── server.pem (leaf)
                       │   │ cert      │   │    ├── admin.pem (leaf, kind=admin)
                       │   └───────────┘   │    └── worker-N.pem (leaf, kind=worker)
                       └─────────┬─────────┘
                                 │
           ┌─────────────────────┼─────────────────────┐
           │                     │                     │
           ▼                     ▼                     ▼
  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
  │ admin           │   │ worker A        │   │ worker B        │
  │ (loupectl)      │   │ + scanners      │   │ + verifier      │
  └─────────────────┘   └────────┬────────┘   └─────────────────┘
                                 │
                                 │ (the worker cert never
                                 │  crosses into bwrap; only
                                 │  a Unix socket is bound in)
                                 ▼
                        ┌─────────────────┐
                        │ loupe-worker    │    in the bwrap sandbox,
                        │ mcp-proxy       │    forwards stdio to the
                        │ (no cert, no    │    broker in the trusted
                        │ URL, no id)     │    parent process
                        └─────────────────┘
```

A compromised agent therefore cannot reach `loupe-server` at all: it
holds no certificate, and does not even learn the server URL. Every
call it makes is mediated by the broker, which pins the request to one
repository and one live lease through the job capability issued with
that lease.

The sandbox does not inherit the host `/etc` tree. It receives only the
public loader, account lookup, resolver, and CA-certificate inputs needed
by the agent runtime; Loupe configuration and worker TLS material remain
outside the namespace even when a bare-metal deployment stores them under
`/etc/loupe`.

All secrets at rest in the SQLite DB (PATs, finding bodies, repo
metadata) are sealed by SQLCipher under the operator's master key —
the same key the server gets at startup via `LOUPE_MASTER_KEY` (or a
file). See README's "Bootstrap the data directory" + "Run the
server" sections for the master-key sourcing rules.

## Storage layout for the review harness

Schema v3 has a typed storage API ahead of the v2 scheduler and endpoints.
It adds no phase routes, worker behavior, or migration. Only `scan` and
`verify` are runtime-enabled: known but unsupported phase kinds and future
kinds remain readable, but cannot be leased, mutated, or authorized by the
legacy runtime. The startup guard still rejects kinds absent from the
database's `job_kinds` table.

| Modules | Responsibility |
| --- | --- |
| `campaigns`, `generations`, `inventory` | Lifecycle, terminal snapshots, pinned paths, coverage preconditions |
| `review_units`, `review_unit_results` | Review scopes, assignment epochs, append-only evidence |
| `leads`, `lead_observations`, `identity` | Semantic identity, collision outcomes, preserved observations |
| `checkpoints`, `terminal_receipt` | Operation-qualified replay and capability-bound terminal replay |
| `finding_details`, `proofs` | Canonical review metadata and project-scoped proof rows |
| `ownership`, `transaction` | In-transaction scope checks and standalone transaction boundaries |

Every new mutation accepts a caller-owned `rusqlite::Transaction` and
returns `storage::Result`. It never begins a nested transaction or commits.
Each module's `standalone` wrappers open an IMMEDIATE transaction and
commit only on success. Multi-step callers must propagate an operation's
error and roll back the whole transaction; a failed batch may have executed
earlier statements. In particular, domain writes and their checkpoints or
terminal receipt must commit together. The lease-transaction helper passes
the same transaction and preserves typed errors.
Checkpoint handlers use `checkpoints::run`, which owns the whole sequence:
a hit returns the original response without running the domain body; a
miss runs the body and records its response under the key. Everything
happens in the caller's transaction, so retries cannot append duplicate
observations and a failing body records nothing. `lookup` and
`record_or_replay` remain available for callers that need the pieces, but
the three-step convention is no longer something a handler has to remember.

Ownership is checked before mutation, including relations where a foreign
key proves existence but not repository or generation scope. An explicit
job generation cannot be overridden by a same-repository campaign link;
the campaign fallback applies only to jobs without a generation. Unit
carry-forward requires explicitly remapped dependency IDs. Assignment
claims compare and bump the epoch and exclude active competing assignments.
Lead identity collisions append the submitted observation even for closed
leads; only stale-closed identities can create a successor.

### Text and digest boundaries

`loupe-core::text` provides private, policy-bound values. Agent-authored
strings enter the new DAOs only through these validated types; commit SHAs,
IDs, times, capability hashes, and captured binary content are host inputs.
Proof-command `argv` and `env_names` are agent-authored requests: they pass
the payload policy *before* the host executes them, so the recorded command
is byte-for-byte the executed one (an argument with a control character or
trailing whitespace is refused, not normalized after the fact). `limits` is
host-authored but shares the bounded JSON shape.
Semantic text is NFC-normalized and rejects invisible/control characters,
unsafe whitespace, and oversized values. Validation errors report field,
rule, and offending code point without echoing the payload.

| Policy | Character / byte cap | Fields |
| --- | --- | --- |
| `ClientKey`, `Family`, `Label`, `JsonKey` | 128, 64, 64, 64 ASCII bytes | Replay/unit keys, identity family, artifact label, JSON object keys |
| `Title`, `Objective` | 200 / 400; 2000 / 4000 | Unit title/objective, receipt title |
| `Reason`, `Argument` | 1000 / 2000; 4000 / 8000 | Lifecycle explanations; evidence and closure arguments |
| `Symbol`, `AnchorText`, `InstanceKey` | 256 / 512; 300 / 600; 200 / 400 | Source symbols and normalized semantic identity |
| `JsonLeaf`, `Payload` | 4000 / 8000 per string; 64 KiB, depth 16, 4096 nodes per document | Bounded canonical JSON, rejecting duplicate keys |
| `RepoPath` | 512 bytes, exact spelling | Relative source paths, without dot components or normalization |
| `SourceRefs<32/64>` | 32 unit / 64 inspected refs, 64 KiB | Canonical structured arrays preserving path bytes, unlike generic JSON leaves |
| `proofs::MediaType`, `OriginalName` | 100 / 200; 512 / 1024 | Single-line artifact metadata; names are display-only |

Proof working directories use an explicit `Root` variant (stored as
`.`) or a validated `RepoPath`; this does not relax source-path rules.
Inventory ingestion preserves both composed and decomposed Git names.
Unrepresentable names become excluded percent-encoded display entries,
never referenceable paths; real names take precedence within a bulk batch.
Reference checks require byte-exact membership once an inventory exists.

`loupe-core::canonical` is the single JSON renderer: sorted object keys,
compact UTF-8, serde_json number rendering, array order preserved.
BLAKE3-256 of these bytes compares retransmissions and attests payloads;
it is not a deduplication identity. Semantic identities instead hash the
versioned, NUL-delimited family/anchor/instance tuple. Storage supplies the
repository or generation uniqueness scope. Proof blobs separately use
SHA-256 derived from their captured content, deduplicated only within one
repository; artifact length and hash are copied from that blob.

Text validation does not prevent prompt injection expressed as ordinary
prose. Newtypes have redacted `Debug`; rendering requires explicit
`.expose()`. Future sinks must label untrusted content and use a structured
boundary or a per-render random boundary of at least 128 bits verified
absent from that content. A fixed sentinel is not collision-safe. Logs use
redacted values, UI isolates bidirectional text, reports escape Markdown,
and CLI rendering escapes controls. Searching for formatting sites is an
audit aid, not proof of these guarantees.

The future phase endpoints must enforce HTTP body caps before
deserialization, validate payload field semantics and job-specific
budgets, and validate the lease before first finalization. Proof capture,
finalization, garbage collection, and sink wiring are not implemented by
this storage layer.

## Cross-references

- Finding state machine details (verdict rollup policy, approval
  gate audit trail): `crates/loupe-server/src/routes/jobs.rs` —
  `submit_verdict` and `complete` handlers walk through the
  transitions inline.
- Sandbox mount layout (which host paths get bind-mounted where):
  `crates/loupe-worker/src/sandbox.rs` module docs.
- MCP tool catalogue: `crates/loupe-worker/src/mcp.rs` —
  `tool_definitions()` is the canonical list; `LOUPE_MCP_PROTOCOL_VERSION`
  versions the worker-agent tool-call surface.
- Wire-format DTOs + protocol-version handling:
  `crates/loupe-proto/src/lib.rs`.
- Storage schema versioning: `crates/loupe-storage/src/migrations.rs`
  records `schema_meta.version` and mirrors it to SQLite
  `PRAGMA user_version`.
