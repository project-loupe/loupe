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
                  + MCP server (mcp-serve subcommand)
  loupe-cli       loupectl admin CLI
```

Three deployable binaries: `loupe-server`, `loupe-worker`, and
`loupectl`. The worker binary doubles as the MCP server (`loupe-worker
mcp-serve`) — same code, different subcommand, spawned by the agent
inside the sandbox.

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
                       │  │  claude (agent)  │ ─┼───────►│ api.anthropic. │
                       │  │  --mcp-config    │  │        │      com       │
                       │  └────────┬─────────┘  │        └────────────────┘
                       │           │ stdio JSON-RPC
                       │           │ (MCP protocol)
                       │           ▼
                       │  ┌──────────────────┐  │   mTLS (worker cert)
                       │  │ loupe-worker     │ ─┼──────────► loupe-server
                       │  │   mcp-serve      │  │   GET /v1/repos/:id/
                       │  │ • query_prior_   │  │       findings/search
                       │  │   findings       │  │   (and future tools)
                       │  └──────────────────┘  │
                       └────────────────────────┘
```

## Data lifecycle

A finding's journey from "agent saw something" to "human looked at it":

```
   walk worktree                         │
   produce file list                     │
                                         │  loupe-worker
   ┌─────────────────────────────────┐   │
   │ for each file in parallel:      │   │
   │   spawn `claude` inside bwrap   │   │
   │   prompt: DISCOVERY             │   │
   │   parse JSON from stdout        │   │   discovery pass
   │   → Discovered{file,line,…}     │   │
   └─────────────────────────────────┘   │
                  │                      │
                  ▼                      │
   ┌─────────────────────────────────┐   │
   │ dedup pass (both layers active):│   │
   │   stage 1: compute fingerprint, │   │
   │     POST known-fingerprints,    │   │   dedup
   │     drop matches (deterministic)│   │
   │   stage 2: model self-suppress  │   │
   │     via query_prior_findings    │   │
   │     during DISCOVERY (semantic) │   │
   └─────────────────────────────────┘   │
                  │                      │
                  ▼                      │
   ┌─────────────────────────────────┐   │
   │ for each surviving discovery:   │   │
   │   spawn `claude` inside bwrap   │   │
   │   prompt: VALIDATE              │   │   validation pass
   │   accept verdict=confirmed only │   │
   │   → Validated{discovered,poc}   │   │
   └─────────────────────────────────┘   │
                  │                      │
                  ▼                      │
   ┌─────────────────────────────────┐   │
   │ build_finding(workdir, v):      │   │
   │   read source window from disk  │   │   emit
   │   compute fingerprint =         │   │
   │     blake3(scanner_id|file|     │   │
   │            normalized_window)   │   │
   └─────────────────────────────────┘   │
                  │                      │
                  ▼ POST /v1/jobs/{id}/findings (one batch, end-of-scan)
                                         ┴───────────── network hop ─────────
   ┌─────────────────────────────────┐
   │ INSERT OR IGNORE into findings  │
   │ on UNIQUE(repo_id, fingerprint) │  loupe-server
   │ → state = pending               │
   └─────────────────────────────────┘
                  │
                  ▼ POST /v1/jobs/{id}/complete
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
- **admin**: minted once at init, used by `loupectl`. Authorized
  for the `admin_only` route group (CRUD on repos / workers / jobs,
  approve/reject, ad-hoc scan triggers).
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
                                │ (worker shares its cert
                                │  with the MCP child via
                                │  bind-mount into bwrap)
                                ▼
                       ┌────────────────┐
                       │ loupe-worker   │   in the bwrap sandbox,
                       │   mcp-serve    │   talks back to
                       │ (uses worker   │   loupe-server with
                       │  cert)         │   the SAME mTLS cert
                       └────────────────┘
```

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
  `tool_definitions()` is the canonical list.
- Wire-format DTOs + protocol-version handling:
  `crates/loupe-proto/src/lib.rs`.
