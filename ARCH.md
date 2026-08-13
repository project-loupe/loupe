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
                  + host-side MCP broker (mcp-proxy subcommand)
  loupe-cli       loupectl admin CLI
  loupe-web       loupe-web local operator dashboard (loopback HTTP,
                  proxies the same admin RPCs as loupectl)
```

Four deployable binaries: `loupe-server`, `loupe-worker`, `loupectl`, and
`loupe-web`. The MCP server runs *in the worker process*, on the trusted
side of the sandbox boundary; the agent reaches it through a
credential-free bridge (`loupe-worker mcp-proxy`) that forwards stdio to
a per-invocation Unix socket. `loupe-web` is an optional operator
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
                       ┌────────────────────────┐         ┌──────────────────┐
                       │      loupe-server      │ ──HTTPS─► api.github.com   │
                       │                        │  (PAT)  │  (GitHub Issues) │
                       │                        │ ─sendmail→ local MTA       │
                       │  ┌──────────────────┐  │         └──────────────────┘
                       │  │   SQLCipher DB   │  │
                       │  │ • repos          │  │
                       │  │ • jobs           │  │
                       │  │ • findings       │  │
                       │  │ • finding_fts    │  │  (FTS5 over title +
                       │  │ • secrets (PATs) │  │   description + path)
                       │  │ • workers        │  │
                       │  └──────────────────┘  │
                       │  ┌──────────────────┐  │
                       │  │ scheduler+reaper │  │
                       │  └──────────────────┘  │
                       └─────────┬─────┬────────┘
                                 │     │
                worker mTLS      │     │   worker mTLS (long-poll)
            (lease, heartbeat,   │     │     POST /v1/jobs/lease
             submit_findings,    │     │
             complete,           │     │
             submit_verdict,     │     │
             search_findings)    │     │
                                 ▼     ▼
                       ┌────────────────────────┐
                       │      loupe-worker      │
                       │  ┌──────────────────┐  │
                       │  │   repo cache     │  │   `git clone --bare`
                       │  │   (LRU bare      │  │    via shell-out
                       │  │    clones)       │  │
                       │  └──────────────────┘  │
                       │  ┌──────────────────┐  │
                       │  │ scanners:        │  │
                       │  │  • regex-secrets │  │
                       │  │  • llm-code-     │  │
                       │  │     review       │  │
                       │  │  • llm-verifier  │  │
                       │  └─────┬────────────┘  │
                       └───────┬┴───────────────┘
                               │ spawns inside bwrap sandbox
                               ▼
                       ┌────────────────────────┐
                       │      bwrap sandbox     │
                       │  (worktree mounted ro  │
                       │   at /workdir, fresh   │
                       │   /tmp + /home/scanner)│
                       │                        │
                       │  ┌──────────────────┐  │ HTTPS  ┌────────────────┐
                       │  │ configured agent │ ─┼───────►│ provider API   │
                       │  │  + MCP config    │  │        │                │
                       │  └─┬─────────┬──────┘  │        └────────────────┘
                       │    │         │
                       │    │         │ stdio JSON-RPC (MCP)
                       │    │         ▼
                       │    │     ┌──────────────────┐  HTTP   ┌────────────────┐
                       │    │     │ bkb-mcp (opt.)   │ ───────►│  bkb HTTP API  │
                       │    │     │                  │         │  (BKB_API_URL) │
                       │    │     │ tools:           │         └────────────────┘
                       │    │     │ • bkb_search     │
                       │    │     │ • bkb_lookup_bip │
                       │    │     │ • bkb_lookup_bolt│
                       │    │     │ • bkb_lookup_lud │
                       │    │     │ • bkb_lookup_nut │
                       │    │     │ • bkb_lookup_blip│
                       │    │     │ • bkb_find_commit│
                       │    │     │ • bkb_get_doc    │
                       │    │     │ • bkb_get_refs   │
                       │    │     │ • bkb_timeline   │
                       │    │     └──────────────────┘
                       │    │ stdio JSON-RPC (MCP)
                       │    ▼
                       │  ┌──────────────────┐  │
                       │  │ loupe-worker     │  │  no credentials,
                       │  │   mcp-proxy      │  │  no server URL,
                       │  │ (stdio ⇄ socket) │  │  no job id
                       │  └────────┬─────────┘  │
                       └───────────┼────────────┘
                          sandbox  │  Unix socket bind-mounted
                        ───────────┼───────────────────────────
                          trusted  │  worker process
                                   ▼
                          ┌──────────────────┐   mTLS (worker cert)
                          │ host-side MCP    │ ──────────► loupe-server
                          │ broker           │   + X-Loupe-Job-Capability
                          │                  │
                          │ holds: client,   │   GET  /v1/repos/:id/
                          │ job capability,  │          findings/search
                          │ repo id, job id  │   GET  /v1/findings/:id
                          │                  │   POST /v1/jobs/:id/
                          │ tools:           │          llm-findings
                          │ • query_prior_   │
                          │   findings       │
                          │ • get_finding_   │
                          │   by_id          │
                          │ • submit_finding │
                          │ • validate_poc   │
                          └──────────────────┘
```

The `bkb-mcp` block is dashed because it's optional: the worker
attaches it to the per-call MCP configuration only when `bkb-mcp` is
on PATH at startup. Workers that don't have it installed run without
that branch and the agent's prompt makes no mention of bkb tools.

The broker tool list shown above is the
**discovery-mode** catalogue. A verify-mode session (spawned for a
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
                       ┌─────────────────┐
                       │  loupe-server   │  CA (host of trust)
                       │  ┌───────────┐  │     │
                       │  │  server   │  │     ├── server.pem (leaf)
                       │  │   cert    │  │     ├── admin.pem  (leaf, kind=admin)
                       │  └───────────┘  │     └── worker-N.pem (leaf, kind=worker)
                       └────────┬────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
              ▼                 ▼                 ▼
     ┌─────────────┐   ┌────────────────┐   ┌────────────────┐
     │   admin     │   │   worker A     │   │  worker B      │
     │ (loupectl)  │   │  + scanners    │   │  + verifier    │
     └─────────────┘   └────────┬───────┘   └────────────────┘
                                │
                                │ (the worker cert never
                                │  crosses into bwrap; only
                                │  a Unix socket is bound in)
                                ▼
                       ┌────────────────┐
                       │ loupe-worker   │   in the bwrap sandbox,
                       │   mcp-proxy    │   forwards stdio to the
                       │ (no cert, no   │   broker in the trusted
                       │  URL, no id)   │   parent process
                       └────────────────┘
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
