# loupe

A security-scanning harness for source repositories. `loupe` runs LLM
agents (and, in future milestones, fuzzers and other tooling) over a
codebase, lets each agent self-validate its findings (write a
regression-test PoC, check it applies), and dispatches confirmed
findings to the configured reporter so they show up where the rest of
the team's bugs live.

The system is split into three components that talk to each other over
mTLS:

- **`loupe-server`** — long-running daemon. Holds the SQLite database
  (registered repos, jobs, findings, secrets), runs the scheduler, hands
  out leases, accepts findings + verdicts, and dispatches confirmed
  findings to the configured reporter — today: GitHub issues, email
  via sendmail, or no reporter at all (manual triage via `loupectl`).
- **`loupe-worker`** — fleet of stateless workers. Authenticate with the
  server using a client cert minted at registration time, lease a job,
  clone the repo into a local cache, run the configured scanners, and
  submit findings back. A worker can also serve LLM verification
  jobs by advertising a `verify:*` capability.
- **`loupectl`** — operator CLI. Authenticates with the admin client
  cert produced by `loupe-server init` and exposes the things you'd
  otherwise be doing by hand: register repos, mint worker certs, trigger
  scans, inspect findings.

For the architecture in one page (component diagram, data lifecycle,
mTLS topology), see `ARCH.md`.

Join the Project Loupe Discord: https://discord.gg/d4Z58kTZF4

## Prerequisites

Before installing, the host needs:

- **Rust 1.88 or newer**. Nightly is only required if you intend to
  run `cargo fmt` — `rustfmt.toml` uses nightly-only options. CI runs
  `fmt` on nightly and `clippy`/`test` on stable.
- **`git`** on PATH. `loupe-worker` shells out to `git` for repo
  cloning into the local cache.
- **Sandbox networking tools** on PATH on every machine running
  `loupe-worker` *with the LLM scanner enabled*. The worker
  needs `bubblewrap`, `slirp4netns`, `nft`, `ip`, and an `nsenter`
  with `--user-parent`; it hard-fatals at startup if any are
  missing or if `LOUPE_DISABLE_SANDBOX=1` is set. Debian Trixie:
  `sudo apt-get install bubblewrap slirp4netns nftables iproute2
  util-linux`. Other distributions need util-linux 2.41 or newer.
  The host kernel must expose `/dev/net/tun`. macOS does not have
  Bubblewrap; LLM scanning runs on Linux workers only.
- **`claude` CLI** on PATH on every machine running `loupe-worker`
  that uses Claude for scan or verify jobs. The default scan agent is
  Claude when it is authenticated. Claude invocations run inside
  bubblewrap, with the worker's mount keeping each invocation's `/tmp`
  and `$HOME` fresh. The worker keeps the provider credential on the
  trusted host and gives the sandbox only a per-job model-broker socket.
  See https://github.com/anthropics/claude-code for install instructions.
- **`codex` CLI** on PATH on every machine running `loupe-worker` that
  uses Codex for scan or verify jobs. The default verifier prefers
  Codex so the second opinion comes from a different model family than
  the default scanner; it falls back to Claude if Codex is not ready.
  Codex invocations automatically select the worker's embedded `loupe`
  permission profile with approvals disabled: the repository is read-only,
  `/tmp` and the disposable scanner home are writable, and command network
  access follows the outer sandbox policy. Build scratch copies under
  `/tmp`; no separate Codex configuration is needed.
  For API-key auth, set `CODEX_API_KEY`; `OPENAI_API_KEY` remains a
  compatibility alias. The key is consumed by the worker-host broker and
  is never passed to the Codex sandbox.
  See https://github.com/openai/codex for install instructions.
- **`bkb-mcp`** (optional) on PATH on workers scanning bitcoin /
  lightning / cashu codebases. When the binary is present at startup,
  the discovery agent's per-call MCP config gets a second server
  entry exposing the bkb tool surface (`bkb_search`, `bkb_lookup_bip`,
  `bkb_lookup_bolt`, `bkb_lookup_lud`, `bkb_lookup_nut`,
  `bkb_lookup_blip`, `bkb_find_commit`, `bkb_get_document`,
  `bkb_get_references`, `bkb_timeline`) so the agent can pull spec +
  historical context the worktree alone won't carry. Install with
  `cargo install bkb-mcp`. The worker sets `BKB_API_URL` to
  `https://bitcoinknowledge.dev` (the public hosted instance) for
  every spawn by default; operators pointing at a self-hosted BKB
  instance can override `[bkb].api_url` in the worker config. Absence
  is silent: workers without bkb-mcp run normally and the agent's
  prompt doesn't mention bkb at all.
- **A GitHub App** owned by the organization that holds your tracker
  repos, only if you intend to use the GitHub-issue reporter (skip
  this prereq when registering repos with `--no-reporting` for manual
  triage). The GitHub-issue reporter has no extra prereq beyond
  outbound HTTPS to `api.github.com`. One server-wide credential (App
  ID + RSA private key) covers every tracker repo the app is
  installed on: the server mints short-lived installation tokens
  restricted to that single tracker repo with **Issues: Read and
  write**, reuses each one for up to 50 minutes, and the issues are
  authored by `<app-slug>[bot]` rather than by a human account. The
  GitHub-side steps are under "GitHub App setup" below.
- **Or: a GitHub personal access token** for a tracker repo, as a
  per-repo fallback where the app is not an option. The token is
  used by the server to call `POST /repos/{owner}/{repo}/issues`, so
  it needs scope to file issues on the *tracker* repo (not the source
  repo being scanned — those can be different). Required scopes:
  - **Fine-grained PAT** (recommended): repository access scoped to
    the tracker repo, with the **Issues** permission set to
    *Read and write*.
  - **Classic PAT**: the `repo` scope. (`public_repo` is enough if
    the tracker repo is public.)
  The app key and PATs are stored in the `secrets` table inside an
  SQLCipher-encrypted SQLite file. The whole database — secrets,
  findings (descriptions, PoCs, suggested fixes), repo metadata,
  audit trails — is sealed with AES-256 + HMAC-SHA512 under
  `loupe-server`'s master key, so an attacker reading
  `loupe.sqlite` off disk gets ciphertext for every row. The master
  key is mandatory (the server refuses to start without one);
  `loupe-server init` mints it the first time you bootstrap a data
  dir.
- **A sendmail-compatible local mailer** on the server host, only if
  you intend to use the email reporter. The built-in reporter shells
  out to `/usr/sbin/sendmail -t -i` and writes an RFC 5322 message on
  stdin; a local MTA or wrapper such as postfix, msmtp, or nullmailer
  needs to own delivery.

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

Before every commit, run `ci/check.sh` with stable Rust, nightly Rust
(including rustfmt), and `jq` installed. It checks formatting, lints,
each crate independently, documentation, and tests. Build output defaults
to a branch-specific directory under `/tmp`; set `CARGO_TARGET_DIR` to a
fresh directory there when invoking Cargo directly.

`ci/check.sh --full` adds fuzz corpus replay, generated-runner checks,
available Kani harnesses, and ignored integration tests. Fuzz replay needs
only stable Rust. Campaigns additionally need `cargo-fuzz`, Bash and
util-linux. See [fuzzing](fuzz/README.md) and the [campaign runbook](ci/README.md).

Kani 0.68.0 is optional for ordinary contributor checks and required for the
full verification gate. Install it with `cargo install --locked kani-verifier
--version 0.68.0` and `cargo kani setup`, which installs its pinned toolchain.
Run proofs only through `ci/kani.sh`; it enforces the shared process and
memory limits and requires satisfied cover properties to rule out empty
proofs. Weekly CI runs the harnesses marked `// ci: fast`; the complete set
runs locally through the full gate and continuous campaign.

For release validation and crates.io publication, see
[the release guide](contrib/releasing.md).

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

Authenticated worker requests share per-worker token buckets across job
routes, identity, finding search and finding detail. The defaults allow
bursts of 600 requests, 16 MiB of body bytes and 60 lease attempts, with
refill of 10 requests, 256 KiB and one lease attempt per whole monotonic
second. Total admitted traffic can include the burst plus earned refill.

Authentication and charging precede protocol checks and long polling.
Body accounting uses actual chunks, including input rejected later as
malformed; received bytes stay charged if a later chunk fails. Exhaustion
returns 429. Worker bodies above 2 MiB return 413, and broken body streams
return 400. Public health and operator requests have no worker budget.
Exhaustion logs contain only a fixed event/category and the worker ID.

These positive settings can be overridden in the server TOML file:

```toml
[worker_budgets]
max_workers = 4096
idle_seconds = 120

[worker_budgets.requests]
capacity = 600
refill_per_second = 10

[worker_budgets.bytes]
capacity = 16777216
refill_per_second = 262144

[worker_budgets.leases]
capacity = 60
refill_per_second = 1
```

At most `max_workers` identities are retained; a new identity receives
429 if that map is full. Idle entries are reclaimed only after all three
buckets have naturally refilled, so eviction cannot reset spent credit.

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

Worker settings can also live in TOML:

```bash
cp contrib/worker-config.toml /etc/loupe/worker.config.toml
$EDITOR /etc/loupe/worker.config.toml
loupe-worker run --config /etc/loupe/worker.config.toml
```

The worker config owns non-secret runtime settings: server URL, TLS
file paths, cache settings, sandbox networking, logging, LLM job-agent
selection, Claude/Codex model + effort, model-broker ceilings, scanner
defaults, and BKB API URL. CLI flags and matching env vars override the
config. API keys and PEM contents still belong in env or secret files.

Every agent invocation receives a private network namespace. The
default `[sandbox].network = "public"` policy allows public IPv4 while
blocking host addresses, connected routes, private/special ranges,
CGNAT, and IPv6. Set it to `"allowlist"` for default-deny egress;
`[sandbox].allowlist` then adds hostnames or IPv4 addresses. Provider API
hosts are not added: the agent reaches a loopback adapter backed by its
job-scoped Unix socket, while the trusted worker broker owns the fixed
upstream, model, effort, and credential. The host from `[bkb].api_url` is
allowed when `bkb-mcp` is attached, so an empty allowlist means no external
agent egress unless BKB is enabled. Overrides are
`--sandbox-network` / `LOUPE_SANDBOX_NETWORK` and
`--sandbox-allowlist` / `LOUPE_SANDBOX_ALLOWLIST`; the environment
allowlist is comma-separated.

Hostnames are resolved to IPv4 before each sandbox starts and remain
fixed for that invocation. Filtering is by destination IP, so it
cannot distinguish virtual hosts sharing an address. DNS through
slirp's resolver remains available, operator allowlists may explicitly
name private IPv4 destinations, and IPv6 allowlist entries are not
supported.

`[broker].request_ceiling` (default `1000`) and
`[broker].output_ceiling_bytes` (default `33554432`) bound each job's model
session. `[broker].token_ceiling` is optional and defaults to no reported
token cutoff. The matching environment overrides are
`LOUPE_BROKER_REQUEST_CEILING`, `LOUPE_BROKER_OUTPUT_CEILING_BYTES`, and
`LOUPE_BROKER_TOKEN_CEILING`. These limits, provider authentication, model
pinning, and provider-side fetch-tool filtering are enforced by the trusted
worker broker rather than by repository-controlled agent settings.

The worker auto-detects authenticated `claude` and `codex` CLIs at
startup. `[agents].scan` and `[agents].verify` choose which LLM agent
is used for each job kind:

- `scan = "auto"` → discovery scanner advertises `scan:llm` only when
  authenticated Claude is ready. This preserves the historical default.
- `verify = "auto"` → verifier scanner advertises `verify:llm` with
  Codex preferred and Claude as the fallback.
- `scan = "claude" | "codex"` or `verify = "claude" | "codex"` →
  require that exact authenticated CLI and fail startup if it is not
  ready.
- CLI/env overrides are `--scan-agent` / `LOUPE_SCAN_AGENT` and
  `--verify-agent` / `LOUPE_VERIFY_AGENT`.
- **No authenticated agent CLI** → worker refuses to start. A
  "regex-only" loupe-worker isn't a deployment we want operators to
  fall into by accident; install at least one agent CLI and provide
  its API key. For Claude, `ANTHROPIC_API_KEY` or a headless
  `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`); interactive
  subscription login state is not mounted into the sandbox.

> **Note:** scan jobs use LLM providers and may count against paid,
> metered, or rate-limited usage. The discovery scanner launches one
> configured agent session per discovered source file, so large
> repositories may trigger hundreds or thousands of LLM CLI invocations.
> Verifier jobs run after a finding already exists. Actual cost or quota
> impact depends on the
> provider, model, account plan, retries, failed-call accounting, and
> token usage. Run a small test repository or narrow scanner
> configuration first if usage limits matter.

The worker probes the complete Bubblewrap/slirp4netns/nftables setup at
startup and exits 1 if it cannot create and configure an isolated
network namespace. Sandboxing cannot be bypassed for an LLM-enabled worker.
The sandbox exposes only an allowlist of public runtime files from
`/etc`; the worker configuration and TLS files under `/etc/loupe` stay
outside the agent namespace.

Cache size defaults to 40 GB and evicts LRU clones above the cap.

Verifier jobs only get queued when a repo resolves to
`verification_enabled = true`, either because it was registered with
`--verification-enabled` or because the server's verification default
is on.

#### Deploy with containers

Production deployment now lives under `contrib/docker/`. The supported
path is rootful Podman managed by systemd, with server/worker secrets
persisted in one protected env file per host and mounted read-only into
the containers. Secrets are not written into systemd units or Podman env
metadata, so normal systemd restarts and host reboots keep working.

See `contrib/docker/README.md` for fresh Debian host prerequisites,
image builds, two-host deployment, restart behaviour, and the exact
secret-handling model.

For existing installations moving to schema v3, follow the
[offline upgrade runbook](contrib/upgrading-schema-v3.md) before deploying the
new server. Back up first and stop the old server and all workers; queued
legacy work may remain, but leased jobs block the migration.

### 6. Register a repo and trigger a scan

Store the GitHub App credential once per server. The App ID and the
private key PEM come from the app's settings page on GitHub (see
"GitHub App setup" below). The server signs a throwaway JWT with the
key and checks it against GitHub's `GET /app` before persisting, so a
wrong key or ID is rejected here rather than at the first dispatch.
The key is encrypted at rest with the master key (see prerequisites)
and never travels back out of the server in any response.

```
loupectl github-app set --app-id 123456 --private-key-file loupe-reporter.pem
loupectl github-app show             # app_id=123456 slug=loupe-reporter
```

`--private-key-file` can also come from `LOUPE_GITHUB_APP_KEY`; to
avoid a key file on disk, pass the PEM itself via
`LOUPE_GITHUB_APP_KEY_PEM` or base64-encoded via
`LOUPE_GITHUB_APP_KEY_PEM_B64`.

Then register the repo. Without `--pat` the reporter files issues
through the app, which is the default; the server answers `400` if no
app is configured yet.

```
loupectl repo add \
  --clone-url     https://github.com/acme/widget.git \
  --target-owner  acme \
  --target-repo   widget-security \
  --scan-interval-seconds 86400      # optional; daily

loupectl repo list                   # reporting=github(app)→acme/widget-security
loupectl repo scan 1                 # one-shot scan of repo id 1
```

Add `--verification-enabled` if this repo should route scan findings
through verifier jobs before reporting. If the server-wide verification
default is on, omit it to inherit the default, or pass
`--no-verification` to opt this repo out.

Confirmed findings dispatch automatically — the GitHub reporter signs
a short-lived JWT with the app key, resolves the app's installation
for the tracker repo, mints a one-hour installation token restricted
to that single repo with Issues write (cached in memory for 50
minutes, never persisted), and posts to
`https://api.github.com/repos/acme/widget-security/issues` as
`loupe-reporter[bot]`, stamping `reported_at` on the finding row.

#### GitHub App setup

On GitHub, under the organization that owns the tracker repos, open
*Settings → Developer settings → GitHub Apps → New GitHub App*:

- **Webhook**: uncheck *Active*. Loupe never receives events.
- **Repository permissions**: *Issues: Read and write*. GitHub adds
  *Metadata: Read-only* on its own; nothing else is needed.
- **Where can this GitHub App be installed?**: *Only on this account*.
- After creating the app, note its **App ID** and generate a private
  key. GitHub downloads a PKCS#1 PEM, which is what
  `loupectl github-app set --private-key-file` expects.
- Install the app on the organization and pick *Only select
  repositories*, listing the tracker repos. When a new tracker repo
  appears later, add it to the installation's repository selection
  first — the server cannot resolve an installation for it otherwise.

`loupectl github-app show` prints the configured App ID and slug.
`loupectl github-app clear` removes the credential, but is refused
with `409` while any repo still reports through the app; switch those
to a PAT with `loupectl repo set-github-reporting <id> ... --pat`
first, or remove and re-register them.

Security model: the app key is strictly more powerful than one PAT —
it reaches every tracker the app is installed on, with Issues write
only. Installing an app grants access *to* the app owner, never
*from* it, so a third party cannot obtain credentials by installing
it, and *Only on this account* prevents installation elsewhere
anyway. The installation's repository selection is the real
allowlist, so install the app on tracker repos only. With the app
configured, the admin certificate alone decides where findings go;
there is no per-destination secret to hand over any more. As belt and
braces, the optional `[github_app] allowed_target_owners = ["acme"]`
key in the server config restricts app-mode destinations to the
listed owners (compared case-insensitively), enforced when a repo is
registered or switched and again at dispatch time; an empty list is
rejected at startup. A repo whose owner is excluded later fails every
dispatch with a warning in the server log and its findings stay
`confirmed` for retry; `loupectl repo list` does not flag it, so check
the log after tightening the list. To revoke the credential,
regenerate or delete the key on the app's settings page: new tokens
stop immediately, while an installation token already minted keeps
working for the rest of its hour (scoped to issues on one repo). Then
`loupectl github-app set` the new key.

Notifications: GitHub does not email you about issues the bot files
unless you watch the tracker repo with *All activity*. Set your watch
to *Participating and @mentions* to hear only about threads you take
part in.

Upgrading an existing deployment: deploy the server first. The
database schema bumps from 3 to 4 automatically — no table changes,
but older binaries refuse the database up front instead of failing
on the first app-mode repo row. Configure the app, then switch repos
one at a time with `loupectl repo set-github-reporting` (below), or
script it from `loupectl repo list --json`. PAT repos keep working
untouched.
The dashboard's add-repo form defaults to the app as well and shows
which app is configured.

#### Or: with a PAT

Pass `--pat` to make a single repo report with a personal access
token instead of the app: a fine-grained token with **Issues: Read
and write** on the *tracker* repo, or a classic token with the `repo`
scope. Pass it via the `LOUPE_TRACKER_PAT` env var rather than as a
positional flag so it doesn't end up in shell history. The server
encrypts it at rest with the master key before persisting; the
plaintext PAT never travels back out of the server in any response,
and the reporter reads it out of the secrets table (transparently
decrypted by SQLCipher when the row is fetched) at dispatch time.

```
export LOUPE_TRACKER_PAT=ghp_xxx_with_issues_write_scope

loupectl repo add \
  --clone-url     https://github.com/acme/widget.git \
  --target-owner  acme \
  --target-repo   widget-security \
  --pat           "$LOUPE_TRACKER_PAT"

loupectl repo list                   # reporting=github(pat)→acme/widget-security
```

`loupectl repo rotate-pat <id>` replaces the token of a PAT repo and
is only for PAT repos. `loupectl repo set-github-reporting <id>
--target-owner O --target-repo R` without `--pat` switches an existing
PAT repo to the app and drops the orphaned PAT; with `--pat` it
switches back. `loupectl repo list --json` prints the raw listing for
scripting, where `reporting` carries `auth: app|pat`.

#### Or: email reporting

The server also has an email reporting destination on the wire:
`ReportingSetup::Email { to, from, subject_prefix }`. It sends
confirmed findings through the server host's sendmail-compatible
binary and does not require a PAT or other reporter secret.

`loupectl repo add` does not expose email flags yet, so registering an
email-backed repo currently means calling `POST /v1/repos` with an
admin mTLS client or using a small client built on `loupe-proto`.
Once registered, the scan, verification, approval, and dispatch flow
is the same as the GitHub reporter.

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

The full pipeline (scan → optional verify → approval gate) runs as
usual, but with no reporter configured the dispatcher leaves confirmed
findings in state `confirmed`. You can either handle them out-of-band,
or configure reporting later and retry delivery:

```
loupectl repo set-github-reporting <repo-id> \
  --target-owner acme \
  --target-repo widget-security     # add --pat to use a PAT instead of the app

loupectl finding retry-report <finding-id>
```

Reject still moves a held finding to terminal `dismissed`.

### 7. Inspect what happened

```
loupectl repo list [-n <limit>]            # reporting=github(app|pat)→owner/repo
loupectl repo list --json                  # raw listing; reporting.auth is app|pat
loupectl job list [-n <limit>]
loupectl job get  <job-id>
loupectl job retry <job-id>                # requeue a failed job
loupectl finding list <repo-id> [-n <limit>] # default limit is 100
loupectl finding show <finding-id>          # pretty-printed for human review
loupectl finding show <finding-id> --json   # raw FindingDetail DTO
loupectl finding search <repo-id> "<keywords>"  # FTS5 keyword search
```

`GET /v1/jobs` also accepts `state` and `kind` filters, which is what the
dashboard's job board uses. `state` takes a comma-separated set, so the
whole "finished" group is one request:

```
GET /v1/jobs?state=queued
GET /v1/jobs?state=succeeded,failed,cancelled&kind=scan&limit=25
```

Unknown values are rejected with a 400 naming the accepted set rather
than being ignored — a filter that looks like it worked but didn't is
worse than an error. There is no pagination anywhere yet; `limit` is the
only knob, and it is deliberately uncapped so older rows stay reachable.

`finding search` is also reachable from inside the LLM scanner — the
MCP tool `query_prior_findings` calls the same endpoint, so the
agent can ask "have we seen anything like this before?" mid-scan.

Scanner tools and report headers identify findings as `LUP-1234`, so
references are distinct from GitHub issue numbers such as `#1234`.
The number is unique across repositories within one Loupe database.
`get_finding_by_id` accepts `"LUP-1234"` and legacy numeric IDs such as
`1234`; database IDs, HTTP endpoints, and CLI arguments remain numeric.
New GitHub and email reports include the prefixed ID and omit the
scanner metadata. Existing published reports are not rewritten.

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
loupectl repo update <id> --no-verification          # skip verify; dispatch on insert
loupectl repo update <id> --require-approval         # hold for human sign-off
loupectl repo update <id> --no-require-approval      # opt out of the approval gate
loupectl repo update <id> --inherit-approval         # fall back to the server default
```

The clone URL and reporting destination are deliberately *not*
patchable: silently re-pointing where new findings get filed is too
easy a footgun. Re-register the repo if you need to change either.

### 9. Or drive it from a browser

`loupe-web` serves the same admin operations as a dashboard. It is an
ordinary admin client — same certificate, same `/v1` routes, no database
access — so it needs exactly the environment `loupectl` already needs:

```
export LOUPE_SERVER_URL=https://127.0.0.1:8443
export LOUPE_CA_CERT=/var/lib/loupe/ca.pem
export LOUPE_ADMIN_CERT=/var/lib/loupe/admin.pem
export LOUPE_ADMIN_KEY=/var/lib/loupe/admin.key

loupe-web                       # binds 127.0.0.1:8455 by default
```

It prints a URL with a one-off token in the fragment. The page moves the
token into session storage scoped to that exact scheme, host, and port,
removes the fragment from the address bar, and sends the token in an
`X-Loupe-Capability` header on API requests:

```
loupe-web listening on http://127.0.0.1:8455

    http://127.0.0.1:8455/#t=<43-char token>
```

Session storage is scoped by origin and top-level browsing context, so
reloading the authorized tab keeps working. A new independent tab or
window starts without the token and its first API call answers `401`;
reopen the startup URL there to authorize it. An auxiliary context opened
from an authorized page can initially inherit a copy of its session
storage, after which the two stores are independent. The token itself does
not change while the process runs.

Covers repo list/add/update/delete (the add form defaults to the GitHub
App, shows which app is configured, and takes a PAT only if you fill the
field in), PAT rotation, switching a repo between app and PAT reporting,
ad-hoc scans (full and incremental), the job board, and finding review
including the proof-of-concept diff and approve/reject.
Worker registration is **not** exposed: there is no list-workers RPC to
drive a revoke UI from, and `worker register` returns a private key the
server keeps no copy of, which has no business travelling through a
browser. Keep using `loupectl worker` for that.

#### What it does and does not assume

`loupe-web` **refuses to bind anything but loopback.** It holds the admin
certificate and its own listener has no transport authentication, so a
routable bind would hand loupe admin rights to anyone who can reach the
port. On loopback the trust boundary is the one you already have: whoever
can run `loupectl` on that machine can drive this. That is also why the
browser needs no client certificate — there is nothing to import.

Two consequences of loopback HTTP are handled rather than assumed:

- **Any local process can connect**, including one that cannot read
  `admin.key`. Hence the token, printed once to your terminal so another
  user on a shared host cannot obtain it. Treat it like the admin key.
  The token is not stored in a cookie because cookies are shared across
  every port on a host; session storage and the capability header keep it
  scoped to the dashboard's origin. The cost of that choice is that the
  token is readable by script on the page, where an `HttpOnly` cookie
  would not have been. The CSP below is therefore load-bearing: it blocks
  injected inline script and restricts fetch and resource destinations.
  It is not complete containment after arbitrary script execution; for
  example, it does not block every top-level navigation. An injected
  same-origin script could drive the API with an `HttpOnly` cookie anyway,
  while a cookie leaks the token to every other local port
  unconditionally, so origin isolation is the better trade here.
- **Any page you visit can issue requests to `127.0.0.1`.** The browser
  blocks reading the response, but a state-changing request would still
  execute. Mutating requests must therefore be same-origin *and* carry an
  `X-Loupe-Dashboard` header a cross-origin caller cannot set without a
  preflight, and every request must be addressed to the dashboard's own
  `Host` so a rebound DNS name cannot pose as same-origin.

Finding titles, descriptions and diffs come from scanned repositories and
model output, so they are untrusted. Nothing is interpolated server-side:
the page renders them as text under a CSP that forbids inline script.

Polling is limited to the visible view and pauses when the tab is hidden.
Each timer is armed only after the prior refresh finishes, and manual or
automatic refreshes are coalesced so only one three-request job refresh
can run at a time. Every request lands on the server's single database
connection and also stamps `workers.last_seen_at`, so an idle dashboard
left open would otherwise compete with worker lease traffic.

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
loupectl finding retry-report <finding-id>      # retry a confirmed finding
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

`approve` runs the dispatcher synchronously when a reporter is
configured. Without a reporter, the finding stays `confirmed`; add
reporting with `repo set-github-reporting`, then run
`finding retry-report`. `reject` is terminal; the audit columns
`approved_by_cn` / `rejected_by_cn` record the admin client cert's
`workers.name` so dashboards can later answer "who clicked what". A
verifier-issued `dismiss` and a human `reject` both land on
`state = 'dismissed'`, but only the human path stamps `rejected_*`.

## Verification flow (LLM second opinion)

Setting `verification_enabled = true` on a repo causes scan-time
findings to land in `validating` state with one `kind=verify` job
enqueued per finding. You can set it per repo with
`loupectl repo add --verification-enabled` or
`loupectl repo update <id> --verification-enabled`.

For verifier-first deployments, set the server-wide
`verification_default` in `config.toml`'s `[policy]` section,
or pass `--verification-default` / set
`LOUPE_VERIFICATION_DEFAULT=true`. New repo registrations that
do not pass either `--verification-enabled` or `--no-verification`
inherit that default. Existing repos keep their stored value; update
them explicitly if you change the server default later.

The verify job is leased by a worker advertising a `verify:*`
capability, which runs an independent LLM pass over the finding and
submits a `confirm | dismiss | inconclusive` verdict. The server
applies a rollup policy in-transaction (any `dismissed` → finding
`dismissed`; else any `confirmed` → `confirmed` + dispatch; else stay
in `validating`). The full state machine + reaper details are in
`ARCH.md` and the `submit_verdict` / `complete` handlers in
`crates/loupe-server/src/routes/jobs.rs`.

A worker with an authenticated verifier agent advertises `verify:llm`
according to `[agents].verify` — see step 5 for backend selection. A
deployment can run discovery and verifier on the same worker, on
separate workers, or share a single worker with both — the lease loop
matches by capability, not by binary. To force role separation, either
install only the desired CLI on each host with `auto`, or set
`scan = "claude" | "codex"` and `verify = "claude" | "codex"` in each
worker's config.

## Continuous integration

GitHub Actions (`.github/workflows/ci.yml`) runs four jobs on every
push and pull request:

- **fmt** — `cargo fmt --all -- --check` on a nightly toolchain.
- **clippy** — `cargo clippy --workspace --all-targets --all-features
  -- -D warnings` on stable.
- **test** — `cargo test --workspace --all-targets` on stable.
- **fuzz-replay** — replay committed seeds and verify generated runners.

## Layout

```
crates/
  loupe-core      shared types: Finding, Verdict, ReportingDestination
  loupe-proto     wire-format DTOs (versioned protocol, X-Loupe-Protocol)
  loupe-tls       internal CA + cert minting + fingerprint helpers
  loupe-storage   SQLCipher DAO surface, FTS5 index, schema-versioned migrations
  loupe-server    daemon binary + mTLS routes + reporters + scheduler/reaper
  loupe-worker    worker binary (`run` + credential-free `mcp-proxy` and
                  `model-proxy`) + scanner trait + LLM backend + versioned
                  MCP tool surface + bwrap sandbox
  loupe-cli       loupectl admin CLI
  loupe-web       loupe-web local operator dashboard (loopback HTTP,
                  proxies the same admin RPCs as loupectl)
```

See each crate's module-level docs for the design intent, and
`ARCH.md` for the cross-crate flow at a glance.
