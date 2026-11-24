# Loupe Container Deployment

This directory contains the production container path for running a
`loupe-server` host and one or more `loupe-worker` hosts.

The production path is rootful Podman managed by systemd. The images are
Docker-compatible, but the production helpers install systemd units and keep
runtime secrets in one protected env file per host.

When upgrading an existing database to schema 6, complete the
[offline upgrade runbook](../upgrading-schema-v3.md) before using the deploy
helpers. Stop all workers for migration and deploy server and worker images
from the same release. Restart workers only after verifying the new server.

## Host Prerequisites

Fresh Debian service and worker hosts need:

- `podman`
- `systemd`
- SSH access
- non-interactive sudo permission for deploy commands, or an interactive root shell

Worker hosts additionally need a Linux kernel with user/network namespaces,
TUN, nftables, and conntrack support. `/dev/net/tun` must be a
character device before the worker container starts. The worker-role bootstrap
installs `kmod`, persists `tun`, `nf_tables`, and `nf_conntrack` module requests,
and attempts to load them immediately. The server role does none of this.

The deploy helpers run unattended over SSH, so routine deploys need passwordless
sudo for the required `podman`, `install`, and `systemctl` commands. For the
one-time bootstrap, password-prompting sudo is fine, but upload the script first
so sudo can read the password from a TTY instead of from the script's stdin.

Server deployment waits for `loupe-server listening` in the new systemd
invocation's journal. This message follows successful migration and listener
binding. Keep INFO logging enabled for the server binary. The default wait is
300 seconds; set `LOUPE_SERVER_START_TIMEOUT_SECONDS` to allow a longer upgrade.
An exited/restarted service or timeout makes deployment fail. A timeout does
not stop the server or roll back a migration that already committed: inspect
the journal before restarting workers or attempting recovery.

The worker host does not need host Rust, Cargo, Node, npm, Git, `bubblewrap`,
`slirp4netns`, `nft`, `ip`, `nsenter`, Claude Code, Codex, or `bkb-mcp`.
Those are installed in the worker image.

The worker image also includes Go, OpenJDK, Python with virtual-environment
support, GCC/G++, CMake, Ninja, Autotools, and native development libraries
for Boost, OpenSSL, SQLite, compression, IPC, messaging, tracing, and Qt 6.
Rust, Cargo, rustfmt, and Clippy use the image's pinned `RUST_VERSION`
(`LOUPE_RUST_VERSION` in `build-images.sh`). Rust and Java are installed so
they work through the sandbox's read-only `/usr` mount with a fresh home;
they do not need the operator's toolchain configuration.

Build a scratch copy under `/tmp` and place Cargo output in
`/tmp/cargo-target`. Package caches belong in the disposable scanner home.
Toolchain installation does not change the read-only repository mount,
the network policy, or the prompts' restrictions on dependency sources.
Jobs that need downloaded dependencies also need an explicit source policy
and either permitted download hosts or an approved offline cache.

`build-images.sh` pulls current base images and refreshes OS packages on every
build, including upgrades of packages already present in the base. Worker
images track Node's supported LTS line and the npm `latest` releases of Claude
Code and Codex. The pinned BKB MCP release is built with current compatible
dependencies rather than freezing its published lockfile. Running containers do
not auto-update: rebuild and deploy both images to pick up security fixes.
Restarting or redeploying an existing image keeps its installed versions.

Both targets share one dependency-refresh stamp, allowing reuse of the freshly
built Rust binaries within that invocation. Refreshing builder packages also
invalidates the downstream compilation cache between invocations; security
updates take precedence over that cache. Host OS/kernel/Podman updates remain
separate operator maintenance and are not performed by these helpers.

For manual builds, use `--pull` and pass a fresh
`--build-arg DEPENDENCY_REFRESH="$(date +%s)-$$"` for both targets.
The `CLAUDE_CODE_VERSION` and
`CODEX_VERSION` build arguments still accept explicit versions for rollback
or diagnosis. Retain a known-good image for rollback when tracking `latest`.
Before deployment, inspect the installed versions, scan both resulting images
with a current vulnerability database, and run the sandbox/toolchain checks
below. A successful Rust dependency audit does not cover OS packages or every
bundled native library.

Set `LOUPE_TEST_CLAUDE_BIN` and `LOUPE_TEST_CODEX_BIN` to the candidate
executables when running `cargo test -p loupe-worker --test model_broker`.
The opt-in tests log the selected versions and check real CLI request routing
inside the no-egress sandbox, without requiring a hard-coded version. The
Codex test also completes a scripted conversation with command execution,
scratch writes, blocked repository writes, and a Loupe MCP call. It uses a
local model fixture, so it does not validate a provider's live behavior;
smoke-test new images before deployment. Broker credential and endpoint
restrictions remain enforced if a newer CLI is incompatible.

Optional bootstrap. The script takes the host's role and prepares only that
role, so a host running both needs one run per role:

```bash
scp contrib/docker/bootstrap-debian-host.sh deploy@server:/tmp/loupe-bootstrap.sh
ssh -t deploy@server 'sudo bash /tmp/loupe-bootstrap.sh server'
ssh deploy@server rm -f /tmp/loupe-bootstrap.sh

scp contrib/docker/bootstrap-debian-host.sh deploy@worker:/tmp/loupe-bootstrap.sh
ssh -t deploy@worker 'sudo bash /tmp/loupe-bootstrap.sh worker'
ssh deploy@worker rm -f /tmp/loupe-bootstrap.sh
```

The worker unit runs rootful Podman with `--privileged` so the non-root worker
process inside the container can run nested `bubblewrap`. The worker still
smoke-tests Bubblewrap, slirp4netns, nftables, namespace entry, and TUN at
startup and refuses to lease jobs if the sandbox cannot run.

## Build Images

Build both image targets on the operator/build machine:

```bash
eval "$(contrib/docker/build-images.sh)"
```

This exports local shell variables similar to:

```bash
export LOUPE_SERVER_IMAGE=localhost/loupe-server:<git-sha>
export LOUPE_WORKER_IMAGE=localhost/loupe-worker:<git-sha>
```

Without a registry, load images onto the hosts:

```bash
podman save "$LOUPE_SERVER_IMAGE" | ssh deploy@server sudo podman load
podman save "$LOUPE_WORKER_IMAGE" | ssh deploy@worker sudo podman load
```

With a registry, push/pull the same image names and set
`LOUPE_SERVER_PULL_IMAGE=1` or `LOUPE_WORKER_PULL_IMAGE=1` when deploying.

### Check the worker toolchains

The opt-in `toolchains` tests compile and run small Rust, Go, Java, Python,
and native CMake fixtures through Loupe's actual sandbox, with no network
and a fresh home for each test. Run them against a built worker image on
a Linux host with the same architecture and a compatible glibc:

```bash
set -euo pipefail
export CARGO_TARGET_DIR="$(mktemp -d /tmp/cargo-target-loupe-toolchain-tests.XXXXXX)"
test_binary=$(cargo test --locked -p loupe-worker --test toolchains \
  --no-run --message-format=json | jq -r \
  'select(.reason == "compiler-artifact" and .target.name == "toolchains") | .executable // empty')
sudo podman run --rm --privileged \
  --entrypoint /toolchain-tests \
  --volume "$test_binary:/toolchain-tests:ro" \
  "$LOUPE_WORKER_IMAGE" --ignored --nocapture
```

These checks run as the image's worker user and use the same container
privilege setting as deployment. They do not require provider credentials.

## Server Configuration

To configure worker request budgets or other TOML-only server settings, place
the server TOML file in the host's persistent server data directory. Make it
readable by container UID 10001, then set the path as seen inside the container:

```bash
export LOUPE_CONFIG=/var/lib/loupe/server.toml
```

The deploy helper persists this setting in `server.conf`, and the launcher
passes it to the server. The default host directory is
`/var/lib/loupe-container/server`, mounted at `/var/lib/loupe` in the container.
The helper does not upload the TOML file; provision it before deploying.

## Bootstrap Server Secrets

Run server init in the container and capture the emitted env locally:

```bash
ssh deploy@server sudo podman run --rm --pull=never \
  --volume /var/lib/loupe-container/server:/var/lib/loupe \
  "$LOUPE_SERVER_IMAGE" \
  loupe-server init \
    --data-dir /var/lib/loupe \
    --hostname loupe.example.com \
    --emit-env \
    --no-persist-secrets > ./server.env
chmod 0600 ./server.env
```

This creates only the encrypted SQLite database on the service host. The master
key and PEM material are printed over SSH to the operator machine. The deploy
helper persists only the server runtime subset of those values back onto the
service host. The `--hostname` value is baked into the server certificate; use
the same hostname in `LOUPE_SERVER_URL` when registering and deploying workers.

Load those values into the local shell, or use your own secret manager:

```bash
set -a
. ./server.env
set +a
```

Deploy/restart the server:

```bash
LOUPE_SERVER_SSH=deploy@server \
LOUPE_SERVER_IMAGE="$LOUPE_SERVER_IMAGE" \
contrib/docker/deploy-server.sh
```

The server deploy writes `/etc/loupe-container/server.secrets.env` with mode
`0600`, owned by the container UID `10001`. It contains the database master key,
server certificate/key, and CA certificate/key. It does not persist the admin
client key; keep `server.env` protected on the operator machine.

## Register And Deploy A Worker

Register a worker from the operator machine using the server image's bundled
`loupectl`:

```bash
podman run --rm \
  --env LOUPE_SERVER_URL=https://loupe.example.com:8443 \
  --env LOUPE_CA_CERT_PEM_B64 \
  --env LOUPE_ADMIN_CERT_PEM_B64 \
  --env LOUPE_ADMIN_KEY_PEM_B64 \
  "$LOUPE_SERVER_IMAGE" \
  loupectl worker register --name worker-1 --emit-env > ./worker-1.env
chmod 0600 ./worker-1.env
```

Deploy/restart the worker:

```bash
set -a
. ./worker-1.env
set +a

export ANTHROPIC_API_KEY=...
# Or use a long-lived headless token from `claude setup-token`:
# export CLAUDE_CODE_OAUTH_TOKEN=...
# Optional, enables Codex scan or verifier jobs:
export CODEX_API_KEY=...
# Optional, defaults preserve Claude scan + Codex verifier when ready:
export LOUPE_SCAN_AGENT=auto
export LOUPE_VERIFY_AGENT=auto
export LOUPE_SURVEY_AGENT=auto
export LOUPE_DRILLDOWN_AGENT=auto
# Optional: force Daybreak Blue with a compatible configured Codex model:
# export LOUPE_CODEX_DAYBREAK=blue
export LOUPE_SANDBOX_NETWORK=public
# Optional per-job model-broker limits:
# export LOUPE_BROKER_REQUEST_CEILING=1000
# export LOUPE_BROKER_OUTPUT_CEILING_BYTES=33554432
# export LOUPE_BROKER_TOKEN_CEILING=100000
# For BKB plus selected destinations instead (model traffic is brokered):
# export LOUPE_SANDBOX_NETWORK=allowlist
# export LOUPE_SANDBOX_ALLOWLIST=github.com,203.0.113.10
export LOUPE_SERVER_URL=https://loupe.example.com:8443

LOUPE_WORKER_SSH=deploy@worker \
LOUPE_WORKER_IMAGE="$LOUPE_WORKER_IMAGE" \
contrib/docker/deploy-worker.sh
```

The worker deploy writes `/etc/loupe-container/worker.secrets.env` with mode
`0600`, owned by the container UID `10002`. It contains the worker certificate
bundle and whichever LLM credentials are set. It also writes
`/etc/loupe-container/worker.config.toml` for non-secret worker settings
(cache, sandbox networking, logging, job-agent selection, scanner defaults,
BKB API URL, broker ceilings, Claude/Codex model/effort, and Codex Daybreak), mounts it
read-only into the container, and sets
`LOUPE_WORKER_CONFIG`. `LOUPE_SCAN_AGENT`, `LOUPE_VERIFY_AGENT`,
`LOUPE_SURVEY_AGENT` and `LOUPE_DRILLDOWN_AGENT` accept `auto`, `claude`, or
`codex`; explicit `claude`/`codex` selections fail
startup if that CLI is not authenticated. For Codex, use `CODEX_API_KEY`;
for compatibility the deploy script also writes `CODEX_API_KEY` from
`OPENAI_API_KEY` when `CODEX_API_KEY` is absent.

`LOUPE_CODEX_DAYBREAK` accepts `default`, `off`, `blue`, or `red`. Deployment
omits the setting when unset, preserving Codex defaults. `blue` and `red`
enable the CLI feature and require the selected program on every brokered
Codex model request; `off` requires `standard`. The model remains separately
configured, and incompatible or unavailable access returns a provider error.
Use `default` to override a previously configured policy. The container
launcher also forwards this variable when supplied directly on the worker host.

Provider credentials remain in the trusted worker process. Each agent
sandbox receives a fresh job-scoped model socket, a loopback adapter, and a
fixed non-secret client sentinel; it receives neither the provider key nor
the worker's saved CLI login state.

Every Codex invocation automatically selects the `loupe` permission profile
embedded in the worker binary. Rebuild and deploy the worker image to activate
it; there is no separate profile file to install or mount. Codex can read the
filesystem exposed by Bubblewrap and write to `/tmp` and `/home/scanner`.
The repository remains read-only, approvals are disabled, and command network
access remains constrained by `LOUPE_SANDBOX_NETWORK` and its allowlist.
Worker-provided Loupe and optional BKB MCP tools are explicitly preapproved;
the host-side Loupe broker continues to enforce each job's capability and scope.
This configuration does not control provider-side safety restrictions.

## Secret Handling

The deploy helpers keep secrets out of systemd unit files, Podman `--env`
arguments, and persistent Podman container metadata. They do persist one
protected host-side env file per service so systemd can restart the container
after a crash or VM reboot without another deploy.

Each secret env file is a single-line `NAME=value` file. TLS PEM material is
stored in the generated `_B64` env vars; API keys and OAuth tokens are stored
directly. The file is bind-mounted read-only into the container at
`/run/loupe/secrets.env`, and the container entrypoint allowlists and exports
those variables before starting Loupe.

The secret file stays outside the container's writable filesystem and survives
container replacement. Root on the host can inspect it, and root can also
inspect a running service process environment; the protection boundary is file
ownership plus mode `0600`, not secrecy from host root.

## Verification

Useful checks after deployment:

```bash
ssh deploy@server systemctl status loupe-server-container.service
ssh deploy@worker systemctl status loupe-worker-container.service

ssh deploy@server sudo ls -l /etc/loupe-container/server.secrets.env
ssh deploy@worker sudo ls -l /etc/loupe-container/worker.secrets.env
ssh deploy@worker test -c /dev/net/tun

ssh deploy@server sudo systemctl restart loupe-server-container.service
ssh deploy@worker sudo systemctl restart loupe-worker-container.service

ssh deploy@server sudo podman inspect loupe-server | grep -E 'LOUPE_MASTER_KEY|PEM|API_KEY' || true
ssh deploy@worker sudo podman inspect loupe-worker | grep -E 'LOUPE_MASTER_KEY|PEM|API_KEY' || true
```

`podman inspect` should not show secret values because the helpers mount the
secret file instead of passing secrets through Podman env flags.
