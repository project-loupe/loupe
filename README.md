# loupe

A security-scanning harness for source repositories. `loupe` runs LLM
agents (and, in future milestones, fuzzers and other tooling) over a
codebase, lets each agent self-validate its findings (write a
regression-test PoC, check it applies), and files confirmed findings
as GitHub issues so they show up where the rest of the team's bugs
live.

The system is split into three components that talk to each other over
mTLS:

- **`loupe-server`** — long-running daemon. Holds the SQLite database
  (registered repos, jobs, findings, secrets), runs the scheduler, hands
  out leases, accepts findings + verdicts, and dispatches confirmed
  findings to the configured reporter — today: GitHub issues, or no
  reporter at all (manual triage via `loupectl`).
- **`loupe-worker`** — fleet of stateless workers. Authenticate with the
  server using a client cert minted at registration time, lease a job,
  clone the repo into a local cache, run the configured scanners, and
  submit findings back. A worker can also serve cross-model verification
  jobs by advertising a `verify:*` capability.
- **`loupectl`** — operator CLI. Authenticates with the admin client
  cert produced by `loupe-server init` and exposes the things you'd
  otherwise be doing by hand: register repos, mint worker certs, trigger
  scans, inspect findings.

For the architecture in one page (component diagram, data lifecycle,
mTLS topology), see `ARCH.md`.

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
  *with the LLM scanner enabled*. The discovery backend shells out to
  `claude --dangerously-skip-permissions -p`, with the worker's
  bubblewrap mount keeping each invocation's `/tmp` and `$HOME` fresh.
  See https://github.com/anthropics/claude-code for install
  instructions.
- **`codex` CLI** (optional) on PATH on every machine running
  `loupe-worker` *with the LLM verifier enabled*. The verifier prefers
  codex so the cross-model second opinion comes from a different model
  family than discovery; falls back to `claude` if `codex` isn't
  installed. The verifier shells out to `codex exec
  --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check`.
  See https://github.com/openai/codex for install instructions.
- **`bkb-mcp`** (optional) on PATH on workers scanning bitcoin /
  lightning / cashu codebases. When the binary is present at startup,
  the discovery agent's per-call MCP config gets a second server
  entry exposing the bkb tool surface (`bkb_search`, `bkb_lookup_bip`,
  `bkb_lookup_bolt`, `bkb_lookup_lud`, `bkb_lookup_nut`,
  `bkb_lookup_blip`, `bkb_find_commit`, `bkb_get_document`,
  `bkb_get_references`, `bkb_timeline`) so the agent can pull spec +
  historical context the worktree alone won't carry. Install with
  `cargo install bkb-mcp`. The worker pins `BKB_API_URL` to
  `https://bitcoinknowledge.dev` (the public hosted instance) for
  every spawn so behaviour is uniform across the fleet regardless
  of what bkb-mcp's compiled-in default happens to be — operators
  pointing at a self-hosted BKB instance should patch the
  `BKB_API_URL` constant in `crates/loupe-worker/src/llm/claude_cli.rs`
  and rebuild. Absence is silent: workers without bkb-mcp run
  normally and the agent's prompt doesn't mention bkb at all.
- **A GitHub personal access token** for each target tracker repo,
  only if you intend to use the GitHub-issue reporter (skip this
  prereq when registering repos with `--no-reporting` for manual
  triage). The GitHub-issue reporter has no extra prereq beyond
  outbound HTTPS to `api.github.com`. The token is
  used by the server to call `POST /repos/{owner}/{repo}/issues`, so
  it needs scope to file issues on the *tracker* repo (not the source
  repo being scanned — those can be different). Required scopes:
  - **Fine-grained PAT** (recommended): repository access scoped to
    the tracker repo, with the **Issues** permission set to
    *Read and write*.
  - **Classic PAT**: the `repo` scope. (`public_repo` is enough if
    the tracker repo is public.)
  PATs are stored in the `secrets` table inside an
  SQLCipher-encrypted SQLite file. The whole database — secrets,
  findings (descriptions, PoCs, suggested fixes), repo metadata,
  audit trails — is sealed with AES-256 + HMAC-SHA512 under
  `loupe-server`'s master key, so an attacker reading
  `loupe.sqlite` off disk gets ciphertext for every row. The master
  key is mandatory (the server refuses to start without one);
  `loupe-server init` mints it the first time you bootstrap a data
  dir.

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

This mints the internal CA, the server cert, the admin client cert,
**and** the database master key (32 random bytes, hex-encoded);
writes `ca.pem`, `ca.key`, `server.pem`, `server.key`, `admin.pem`,
`admin.key`, and `master.key` under the data dir with `0600` perms;
and prints the admin client cert + key on stdout. Save the admin
bundle somewhere you can reach with `loupectl` — `init` is the only
time the admin key leaves the machine.

If `LOUPE_MASTER_KEY` is already set in the environment when you run
`init` (e.g. you're managing the key in a secret store / systemd
credentials / vault), `init` uses it as-is and does **not** write a
`master.key` file. That keeps the env var the source of truth for
operators who don't want the key on disk at all.

`init` refuses to run against an already-initialised data dir.

### 2. Run the server

```
# Source the master key. Either point the server at the on-disk file:
export LOUPE_MASTER_KEY="$(cat /var/lib/loupe/master.key)"
# …or load from a secret manager and skip persisting to disk:
# export LOUPE_MASTER_KEY="$(systemd-creds cat loupe-master)"

loupe-server serve \
  --bind 127.0.0.1:8443 \
  --db /var/lib/loupe/loupe.sqlite \
  --server-cert /var/lib/loupe/server.pem \
  --server-key  /var/lib/loupe/server.key \
  --ca-cert     /var/lib/loupe/ca.pem \
  --ca-key      /var/lib/loupe/ca.key
```

If you'd rather have the server read the key from the on-disk file
itself, drop `LOUPE_MASTER_KEY` and pass `--master-key-file
/var/lib/loupe/master.key` (also `LOUPE_MASTER_KEY_FILE`) instead.
The env var still takes precedence when both are set. The server
refuses to start if neither source supplies a key — there's no
plaintext-mode fallback because the database itself is sealed.

All flags also accept the matching `LOUPE_*` env vars (`LOUPE_BIND`,
`LOUPE_DB`, `LOUPE_SERVER_CERT`, etc.).

#### Or: keep settings in `config.toml`

Anything you'd otherwise pass on the command line can live in a TOML
config file (a sample ships in `contrib/config.toml`). Drop it next to
the data directory and point the server at it:

```
cp contrib/config.toml /var/lib/loupe/config.toml
$EDITOR /var/lib/loupe/config.toml      # adjust to taste

loupe-server serve --config /var/lib/loupe/config.toml
```

Path-typed fields under `[paths]` are interpreted relative to the
config file's directory, so a single file can ship next to the certs
and database without absolute paths. The master key path can also
live under `[paths] master_key`; the env var still wins on conflict
so `LOUPE_MASTER_KEY` overrides the file. CLI flags and `LOUPE_*`
env vars override anything the file supplies, so a typical deploy
keeps stable settings in `config.toml` and uses the env to flip
per-environment knobs.

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
  --cache-dir  /var/lib/loupe/cache
```

The worker auto-detects `claude` and `codex` on PATH at startup and
wires the LLM scanners accordingly:

- **`claude` installed** → discovery scanner advertises `scan:llm`
  (claude owns submission via the loupe MCP server's
  `submit_finding` tool).
- **`claude` or `codex` installed** → verifier scanner advertises
  `verify:llm`. Codex is preferred when both are present so the
  second opinion comes from a different model family than discovery;
  claude is the fallback if codex isn't on PATH (same-family check —
  still useful, not a true cross-model verification).
- **Neither installed** → worker refuses to start. A "regex-only"
  loupe-worker isn't a deployment we want operators to fall into by
  accident; install at least one agent CLI.

The worker also probes for `bwrap` at startup and exits 1 if it is
missing (set `LOUPE_DISABLE_SANDBOX=1` to bypass for dev work).
Cache size defaults to 40 GB and evicts LRU clones above the cap.

Verifier jobs only get queued when a repo is registered with
`--verification-enabled`.

#### Deploy with systemd

`contrib/` ships sample units and local-to-remote deploy scripts:

- `contrib/loupe-server.service` runs `/opt/loupe/bin/loupe-server serve`
  as `loupe`, reading non-secret settings from
  `/etc/loupe/loupe-server.env`.
- `contrib/loupe-worker.service` runs `/opt/loupe/bin/loupe-worker run`
  as `loupe-worker`, reading non-secret settings from
  `/etc/loupe/loupe-worker.env`.
- `contrib/deploy-server.sh` and `contrib/deploy-worker.sh` build the
  relevant release binary locally, upload it over SSH, install it with
  `sudo install`, optionally update the unit/env file, stream runtime
  secrets from local environment variables over SSH stdin, and restart
  the matching service.

First provision each host once as root, then use an unprivileged SSH
deploy user for routine updates. The service users need to exist before
systemd starts the units:

```
# server host
sudo useradd --system --home /var/lib/loupe --shell /usr/sbin/nologin loupe
sudo install -d -o loupe -g loupe -m 0700 /var/lib/loupe
sudo install -d -m 0755 /opt/loupe/bin /etc/loupe
sudo install -d -m 0755 /usr/local/sbin

# worker host
sudo useradd --system --home /var/lib/loupe-worker --shell /usr/sbin/nologin loupe-worker
sudo install -d -o loupe-worker -g loupe-worker -m 0700 /var/lib/loupe-worker
sudo install -d -o loupe-worker -g loupe-worker -m 0700 /var/cache/loupe-worker
sudo install -d -m 0755 /opt/loupe/bin /etc/loupe
sudo install -d -m 0755 /usr/local/sbin
```

Grant the SSH deploy users only the commands the scripts need. Verify
your distro's paths with `command -v install systemctl`, then install
sudoers fragments with `visudo -f /etc/sudoers.d/loupe-...`:

```
deploy-server ALL=(root) NOPASSWD: \
  /usr/bin/install -D -m 0755 /tmp/loupe-server-deploy.*.bin /opt/loupe/bin/loupe-server, \
  /usr/bin/install -D -m 0644 /tmp/loupe-server-deploy.*.service /etc/systemd/system/loupe-server.service, \
  /usr/bin/install -D -m 0600 /tmp/loupe-server-deploy.*.env /etc/loupe/loupe-server.env, \
  /usr/bin/install -D -m 0755 /tmp/loupe-server-deploy.*.runtime-helper /usr/local/sbin/loupe-server-runtime-secrets, \
  /usr/bin/systemctl daemon-reload, \
  /usr/bin/systemctl restart loupe-server.service, \
  /usr/local/sbin/loupe-server-runtime-secrets *

deploy-worker ALL=(root) NOPASSWD: \
  /usr/bin/install -D -m 0755 /tmp/loupe-worker-deploy.*.bin /opt/loupe/bin/loupe-worker, \
  /usr/bin/install -D -m 0644 /tmp/loupe-worker-deploy.*.service /etc/systemd/system/loupe-worker.service, \
  /usr/bin/install -D -m 0600 /tmp/loupe-worker-deploy.*.env /etc/loupe/loupe-worker.env, \
  /usr/bin/install -D -m 0755 /tmp/loupe-worker-deploy.*.runtime-helper /usr/local/sbin/loupe-worker-runtime-secrets, \
  /usr/bin/systemctl daemon-reload, \
  /usr/bin/systemctl restart loupe-worker.service, \
  /usr/local/sbin/loupe-worker-runtime-secrets *
```

The generated env files deliberately exclude secret values. Server
TLS material is streamed from `LOUPE_SERVER_CERT_PEM`,
`LOUPE_SERVER_KEY_PEM`, `LOUPE_CA_CERT_PEM`, and `LOUPE_CA_KEY_PEM`
into systemd's runtime manager environment for the explicit restart;
the helper stores those PEMs as single-line `*_PEM_B64` runtime env
vars and the daemon decodes them at startup. The database master key
is passed the same way as `LOUPE_MASTER_KEY`. Worker mTLS material
follows the same shape with `LOUPE_WORKER_*_PEM`, and agent API keys
are also passed as runtime env. By default the deploy helpers unset
those systemd manager env vars immediately after the restart; rerun
the deploy script after a reboot or for a manual restart that needs
secrets rehydrated.

Examples from your local checkout:

```
LOUPE_SERVER_SSH=deploy-server@server-host \
LOUPE_CONFIG=/var/lib/loupe/config.toml \
LOUPE_MASTER_KEY="$(cat ./secrets/loupe-master.key)" \
LOUPE_SERVER_CERT_PEM="$(cat .deploy/server-data/server.pem)" \
LOUPE_SERVER_KEY_PEM="$(cat .deploy/server-data/server.key)" \
LOUPE_CA_CERT_PEM="$(cat .deploy/server-data/ca.pem)" \
LOUPE_CA_KEY_PEM="$(cat .deploy/server-data/ca.key)" \
  contrib/deploy-server.sh

LOUPE_WORKER_SSH=deploy-worker@worker-host \
LOUPE_SERVER_URL=https://loupe.example.internal:8443 \
LOUPE_WORKER_CA_CERT_PEM="$(jq -r .ca_cert_pem .deploy/workers/worker-01.json)" \
LOUPE_WORKER_CERT_PEM="$(jq -r .client_cert_pem .deploy/workers/worker-01.json)" \
LOUPE_WORKER_KEY_PEM="$(jq -r .client_key_pem .deploy/workers/worker-01.json)" \
LOUPE_CACHE_DIR=/var/cache/loupe-worker \
LOUPE_WORKER_PATH=/usr/local/bin:/usr/bin:/bin \
ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  contrib/deploy-worker.sh
```

Set `LOUPE_*_ENV_FILE_LOCAL=/path/to/env` if you prefer to upload an
exact non-secret env file instead of generating one from the current
shell. Set `LOUPE_*_INSTALL_SERVICE=0` and `LOUPE_*_WRITE_ENV=0` for
binary-only restarts after the unit and env file are already in place.

### 6. Register a repo and trigger a scan

The `--pat` value here is the GitHub PAT you minted in the
prerequisites: a fine-grained token with **Issues: Read and write**
on the *tracker* repo, or a classic token with the `repo` scope.
Pass it via the `LOUPE_TRACKER_PAT` env var rather than as a
positional flag so it doesn't end up in shell history. The server
encrypts it at rest with the master key (see prerequisites) before
persisting; the plaintext PAT never travels back out of the server in
any response.

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
reads the PAT out of the secrets table (transparently decrypted by
SQLCipher when the row is fetched) and posts to
`https://api.github.com/repos/acme/widget-security/issues`, stamping
`reported_at` on the finding row.

#### Or: scan-only mode (no tracker)

If you want to use loupe purely as a "find issues, queue them for me"
system — no tracker repo, no automatic GitHub issue creation, just
a queue you triage with `loupectl finding ...` and act on
out-of-band — pass `--no-reporting`:

```
loupectl repo add \
  --clone-url https://github.com/acme/widget.git \
  --no-reporting
```

`--no-reporting` implies `--require-approval = true` unless you
override it (else findings would silently flip to `reported` before
a human ever sees them — defeating the point). The full pipeline
(scan → optional verify → approval gate) runs as usual, but on
approve the dispatcher simply stamps `reported_at` and state
`reported` without calling any external system. Reject still moves
the finding to terminal `dismissed`. Operators take whatever
follow-up action they want — open a ticket elsewhere, fix the bug
directly, ignore it — and `loupectl finding list` shows what's been
triaged versus still pending.

### 7. Inspect what happened

```
loupectl job list
loupectl job get  <job-id>
loupectl finding list <repo-id>
loupectl finding show <finding-id>          # pretty-printed for human review
loupectl finding show <finding-id> --json   # raw FindingDetail DTO
loupectl finding search <repo-id> "<keywords>"  # FTS5 keyword search
```

`finding search` is also reachable from inside the LLM scanner — the
MCP tool `query_prior_findings` calls the same endpoint, so the
agent can ask "have we seen anything like this before?" mid-scan.

#### Continuous scans

When you set `--scan-interval-seconds`, loupe runs the scan periodically
without operator intervention. Two complementary dedup mechanisms
keep re-scans cheap:

- **Semantic dedup (agent-driven):** every discovery session has the
  `query_prior_findings` and `get_finding_by_id` MCP tools. The
  prompt asks the agent to enumerate *every* exploitable bug in the
  file (severity-ordered) and search for prior reports before
  submitting each — a duplicate hit suppresses *that one* candidate
  and the agent moves on to the next, so a re-scan still surfaces
  bugs ranked below an already-reported finding. Catches paraphrases,
  refactor-shifted bugs (function moved to a different file), and
  renamed functions. Conservative — only suppresses on a clear match.
- **Hash dedup (free, server-side):** every finding carries a
  `blake3(scanner_id | file | normalized_content_window)`
  fingerprint. The `findings` table has `UNIQUE(repo_id,
  fingerprint)`, so any submission that hash-matches an existing
  row is silently dropped at insert (`INSERT OR IGNORE`). Survives
  `cargo fmt`-style cosmetic edits because the hash normalises
  whitespace and case. This is the deterministic floor under the
  agent's semantic decisions.

To verify dedup is working: run `loupectl repo scan <id>` twice in
a row and compare the new-finding counts in `loupectl finding list
<repo-id>` between the two jobs — the second run shouldn't add rows
the first one already covered.

### 8. Adjust an existing repo

```
loupectl repo update <id> --disable                  # pause scheduler
loupectl repo update <id> --enable
loupectl repo update <id> --interval 3600            # hourly
loupectl repo update <id> --verification-enabled     # route via verify flow
loupectl repo update <id> --require-approval         # hold for human sign-off
loupectl repo update <id> --no-require-approval      # opt out of the approval gate
loupectl repo update <id> --inherit-approval         # fall back to the server default
```

The clone URL and reporting destination are deliberately *not*
patchable: silently re-pointing where new findings get filed is too
easy a footgun. Re-register the repo if you need to change either.

## Human-in-the-loop approval

By default, confirmed findings dispatch immediately. For repos where
you want a human to read the finding before an issue is filed, turn on
the approval gate. Two layers compose:

- **Per-repo `require_approval`** (`loupectl repo add --require-approval`,
  or `loupectl repo update <id> --require-approval`). Pinning it
  `true` always holds; pinning it `false` always dispatches; leaving
  it unpinned (`--inherit-approval` clears the override) falls back
  to the server default.
- **Server-wide default `require_approval_default`** in
  `config.toml`'s `[policy]` section, or via the
  `--require-approval-default` flag / `LOUPE_REQUIRE_APPROVAL_DEFAULT`
  env. Off by default. Per-repo overrides win.

When the gate is active, a confirmed finding (auto-pass or
verifier-confirmed) parks in state `awaiting_approval` instead of
hitting the reporter. The operator handles it with:

```
loupectl finding list <repo-id>                 # state=awaiting_approval
loupectl finding show <finding-id>              # pretty: title, severity,
                                                #   location, description,
                                                #   PoC diff (regression test
                                                #   that fails on HEAD)
loupectl finding show <finding-id> --json       # raw DTO for scripting
loupectl finding approve <finding-id>           # → confirmed → dispatched
loupectl finding reject  <finding-id>           # → terminal dismissed
```

`finding show` is the review surface: it renders the model's
description, the location of the suspect code, and — most
importantly — the **proof-of-concept regression test** as a unified
diff (with `+`/`-` colored like `git diff` when stdout is a TTY). The
PoC is the strongest evidence the finding is real: applying the diff
against a fresh worktree and running the test should fail on HEAD.
`--json` falls back to the raw `FindingDetail` DTO when you need
machine-readable output. `NO_COLOR=1` (or piping into a non-TTY)
suppresses ANSI escapes.

`approve` runs the dispatcher synchronously, so the issue is filed
the moment the call returns. `reject` is terminal; the audit columns
`approved_by_cn` / `rejected_by_cn` record the admin client cert's
`workers.name` so dashboards can later answer "who clicked what". A
verifier-issued `dismiss` and a human `reject` both land on
`state = 'dismissed'`, but only the human path stamps `rejected_*`.

## Verification flow (cross-model second opinion)

Setting `verification_enabled = true` on a repo causes scan-time
findings to land in `validating` state with one `kind=verify` job
enqueued per finding. The verify job is leased by a worker advertising
a `verify:*` capability, which runs an independent LLM pass over the
finding and submits a `confirm | dismiss | inconclusive` verdict. The
server applies a rollup policy in-transaction (any `dismissed` →
finding `dismissed`; else any `confirmed` → `confirmed` + dispatch;
else stay in `validating`). The full state machine + reaper details
are in `ARCH.md` and the `submit_verdict` / `complete` handlers in
`crates/loupe-server/src/routes/jobs.rs`.

A worker with `codex` (or just `claude`) on PATH advertises
`verify:llm` automatically — see step 5 for backend selection. A
deployment can run discovery and verifier on the same worker, on
separate workers, or share a single worker with both — the lease
loop matches by capability, not by binary. To force role separation,
install only `claude` on the discovery hosts and only `codex` on the
verifier hosts; the auto-detect picks the matching capability tags.

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
  loupe-storage   SQLCipher DAO surface, FTS5 index, schema-versioned migrations
  loupe-server    daemon binary + mTLS routes + reporters + scheduler/reaper
  loupe-worker    worker binary (`run` + `mcp-serve` subcommands) +
                  scanner trait + LLM backend + versioned MCP tool surface +
                  bwrap sandbox
  loupe-cli       loupectl admin CLI
```

See each crate's module-level docs for the design intent, and
`ARCH.md` for the cross-crate flow at a glance.
