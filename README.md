# loupe

A security-scanning harness for source repositories. `loupe` runs LLM
agents (and, in future milestones, fuzzers and other tooling) over a
codebase, validates the resulting reports, and files them as GitHub
issues so they show up where the rest of the team's bugs live.

The system is split into three components that talk to each other over
mTLS:

- **`loupe-server`** — long-running daemon. Holds the SQLite database
  (registered repos, jobs, findings, secrets), runs the scheduler, hands
  out leases, accepts findings + verdicts, and dispatches confirmed
  findings to the configured reporter (GitHub issues today; sendmail
  for plain email).
- **`loupe-worker`** — fleet of stateless workers. Authenticate with the
  server using a client cert minted at registration time, lease a job,
  clone the repo into a local cache, run the configured scanners, and
  submit findings back. A worker can also serve cross-model verification
  jobs by advertising a `verify:*` capability.
- **`loupectl`** — operator CLI. Authenticates with the admin client
  cert produced by `loupe-server init` and exposes the things you'd
  otherwise be doing by hand: register repos, mint worker certs, trigger
  scans, inspect findings.

The full design and milestone status (LLM-scanner pipeline, verification
flow, deferred work) live in `LOUPE.md`.

## Prerequisites

Before installing, the host needs:

- **Rust** (stable toolchain). Nightly is only required if you intend to
  run `cargo fmt` — `rustfmt.toml` uses nightly-only options. CI runs
  `fmt` on nightly and `clippy`/`test` on stable.
- **`git`** on PATH. `loupe-worker` shells out to `git` for repo
  cloning into the local cache.
- **`bubblewrap`** (`bwrap`) on PATH on every machine running
  `loupe-worker` *with the LLM scanner enabled*. The worker
  hard-fatals at startup if the LLM scanner is on but `bwrap` is
  missing — set `LOUPE_DISABLE_SANDBOX=1` to override on dev
  machines that genuinely cannot install it. Debian/Ubuntu:
  `sudo apt-get install bubblewrap`. Fedora/RHEL: `sudo dnf install
  bubblewrap`. macOS does not have a port; LLM scanning runs on Linux
  workers only.
- **`claude` CLI** on PATH on every machine running `loupe-worker`
  *with the LLM scanner enabled*. The first LLM backend shells out to
  `claude --dangerously-skip-permissions -p`, with the worker's
  bubblewrap mount keeping each invocation's `/tmp` and `$HOME` fresh.
  See https://github.com/anthropics/claude-code for install
  instructions.
- **`/usr/sbin/sendmail`** on the *server* host, only if you intend to
  use the email reporter. The GitHub-issue reporter has no extra
  prereq beyond outbound HTTPS to `api.github.com`.
- **A GitHub personal access token** with `Issues: write` scope on
  every target tracker repo, only if you intend to use the
  GitHub-issue reporter. Tokens are stored encrypted at rest when
  `LOUPE_MASTER_KEY` is set on the server (see below); plaintext
  otherwise, with a startup warning.

## Building

```
cargo build --workspace --release
```

The binaries land in `target/release/`:

- `target/release/loupe-server` (daemon)
- `target/release/loupe-worker` (worker)
- `target/release/loupectl` (admin CLI)

`cargo test --workspace --all-targets` runs the unit and integration
test suites; the LLM-backend live test skips automatically when
`claude` is not on PATH, and the bubblewrap integration tests skip
when `bwrap` is missing.

## Quickstart

The walkthrough below assumes a single host running both the server
and one worker, talking to `127.0.0.1:8443`. Multi-host deployments
follow the same shape — copy the worker's cert bundle to the worker
host, set `LOUPE_SERVER_URL` to the server's hostname, and make sure
the server cert's SAN list (`--hostname` at init time) covers it.

### 1. Bootstrap the data directory

```
loupe-server init --data-dir /var/lib/loupe --hostname loupe.example.internal
```

This mints the internal CA, the server cert, and the admin client
cert; writes `ca.pem`, `ca.key`, `server.pem`, `server.key`,
`admin.pem`, `admin.key` under the data dir with `0600` perms; and
prints the admin client cert + key on stdout. Save the admin bundle
somewhere you can reach with `loupectl` — `init` is the only time the
admin key leaves the machine.

`init` refuses to run against an already-initialised data dir.

### 2. Run the server

```
# Optional but recommended: 32 random bytes, base64-encoded, used to
# encrypt secrets (GitHub PATs) at rest. Keep it stable across
# restarts.
export LOUPE_MASTER_KEY="$(openssl rand -base64 32)"

loupe-server serve \
  --bind 127.0.0.1:8443 \
  --db /var/lib/loupe/loupe.db \
  --server-cert /var/lib/loupe/server.pem \
  --server-key  /var/lib/loupe/server.key \
  --ca-cert     /var/lib/loupe/ca.pem \
  --ca-key      /var/lib/loupe/ca.key
```

All flags also accept the matching `LOUPE_*` env vars (`LOUPE_BIND`,
`LOUPE_DB`, `LOUPE_SERVER_CERT`, etc.).

### 3. Point `loupectl` at the server

```
export LOUPE_SERVER_URL=https://127.0.0.1:8443
export LOUPE_CA_CERT=/var/lib/loupe/ca.pem
export LOUPE_ADMIN_CERT=/var/lib/loupe/admin.pem
export LOUPE_ADMIN_KEY=/var/lib/loupe/admin.key

loupectl repo list   # sanity check — empty list, no error
```

### 4. Mint a worker bundle

```
loupectl worker register --name worker-01 --out /etc/loupe/worker-01.json
```

The output JSON carries a fresh client cert + key + the CA cert. The
key is **only** ever returned here — the server doesn't keep a copy.

Pull the three PEMs out for the worker process:

```
jq -r .client_cert_pem /etc/loupe/worker-01.json > /etc/loupe/worker.pem
jq -r .client_key_pem  /etc/loupe/worker-01.json > /etc/loupe/worker.key
jq -r .ca_cert_pem     /etc/loupe/worker-01.json > /etc/loupe/ca.pem
chmod 600 /etc/loupe/worker.key
```

### 5. Run a worker

```
loupe-worker \
  --server-url https://127.0.0.1:8443 \
  --ca-cert    /etc/loupe/ca.pem \
  --cert       /etc/loupe/worker.pem \
  --key        /etc/loupe/worker.key \
  --cache-dir  /var/lib/loupe/cache \
  --enable-llm-scanner       # omit to run only the regex scanner
```

The worker probes for `bwrap` at startup when `--enable-llm-scanner`
is on and exits 1 if it is missing (set `LOUPE_DISABLE_SANDBOX=1` to
bypass for dev work). Cache size defaults to 40 GB and evicts LRU
clones above the cap.

### 6. Register a repo and trigger a scan

```
export LOUPE_TRACKER_PAT=ghp_xxx_with_issues_write_scope

loupectl repo add \
  --clone-url     https://github.com/acme/widget.git \
  --target-owner  acme \
  --target-repo   widget-security \
  --pat           "$LOUPE_TRACKER_PAT" \
  --scan-interval-seconds 86400      # optional; daily

loupectl repo list
loupectl repo scan 1                 # one-shot scan of repo id 1
```

Confirmed findings dispatch automatically — the GitHub reporter
posts to `https://api.github.com/repos/acme/widget-security/issues`
and stamps `reported_at` on the row.

### 7. Inspect what happened

```
loupectl job list
loupectl job get  <job-id>
loupectl finding list <repo-id>
loupectl finding get  <finding-id>     # full body, PoC, patch
```

### 8. Adjust an existing repo

```
loupectl repo update <id> --disable                  # pause scheduler
loupectl repo update <id> --enable
loupectl repo update <id> --interval 3600            # hourly
loupectl repo update <id> --verification-enabled     # route via verify flow
```

The clone URL and reporting destination are deliberately *not*
patchable: silently re-pointing where new findings get filed is too
easy a footgun. Re-register the repo if you need to change either.

## Verification flow (cross-model second opinion)

Setting `verification_enabled = true` on a repo causes scan-time
findings to land in `validating` state with one `kind=verify` job
enqueued per finding. The verify job is leased by a worker advertising
a `verify:*` capability, which runs an independent LLM pass over the
finding and submits a `confirm | dismiss | inconclusive` verdict. The
server applies a rollup policy in-transaction (any `dismissed` →
finding `dismissed`; else any `confirmed` → `confirmed` + dispatch;
else stay in `validating`). The full state machine, reaper, and
runbook for the verification flow are in `LOUPE.md`.

> **Heads-up.** The `LlmVerifierScanner` exists in the codebase
> (`loupe-worker::scanners::llm_verifier`) but is **not yet wired
> into the `loupe-worker` binary's scanner list**, so no worker
> currently advertises `verify:llm` out of the box. Until that's
> wired (a small change mirroring `--enable-llm-scanner`), enabling
> `verification_enabled` on a repo will queue verify jobs that no
> worker can lease — they'll eventually be marked `inconclusive` by
> the reaper. Leave `verification_enabled` off for the first run.

## Continuous integration

GitHub Actions (`.github/workflows/ci.yml`) runs three jobs on every
push and pull request:

- **fmt** — `cargo fmt --all -- --check` on a nightly toolchain.
- **clippy** — `cargo clippy --workspace --all-targets --all-features
  -- -D warnings` on stable.
- **test** — `cargo test --workspace --all-targets` on stable.

## Layout

```
crates/
  loupe-core      shared types: Finding, Verdict, ReportingDestination
  loupe-proto     wire-format DTOs (versioned protocol, X-Loupe-Protocol)
  loupe-tls       internal CA + cert minting + fingerprint helpers
  loupe-storage   SQLite DAO surface, migrations, secrets table
  loupe-server    daemon binary + routes + reporters + scheduler/reaper
  loupe-worker    worker binary + scanner trait + LLM backend + sandbox
  loupe-cli       loupectl admin CLI
```

See each crate's module-level docs for the design intent and the
public surface.
