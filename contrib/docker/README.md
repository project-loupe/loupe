# Loupe Container Deployment

This directory contains the production container path for running a
`loupe-server` host and one or more `loupe-worker` hosts.

The production path is rootful Podman managed by systemd. The images are
Docker-compatible, but the production helpers install systemd units and keep
runtime secrets in one protected env file per host.

## Host Prerequisites

Fresh Debian service and worker hosts need:

- `podman`
- `systemd`
- SSH access
- non-interactive sudo permission for deploy commands, or an interactive root shell

The deploy helpers run unattended over SSH, so routine deploys need passwordless
sudo for the required `podman`, `install`, and `systemctl` commands. For the
one-time bootstrap, password-prompting sudo is fine, but upload the script first
so sudo can read the password from a TTY instead of from the script's stdin.

The worker host does not need host Rust, Cargo, Node, npm, Git, `bubblewrap`,
Claude Code, Codex, or `bkb-mcp`. Those are installed in the worker image.

Optional bootstrap:

```bash
scp contrib/docker/bootstrap-debian-host.sh deploy@server:/tmp/loupe-bootstrap.sh
ssh -t deploy@server 'sudo bash /tmp/loupe-bootstrap.sh'
ssh deploy@server rm -f /tmp/loupe-bootstrap.sh

scp contrib/docker/bootstrap-debian-host.sh deploy@worker:/tmp/loupe-bootstrap.sh
ssh -t deploy@worker 'sudo bash /tmp/loupe-bootstrap.sh'
ssh deploy@worker rm -f /tmp/loupe-bootstrap.sh
```

The worker unit runs rootful Podman with `--privileged` so the non-root worker
process inside the container can run nested `bubblewrap`. The worker still
smoke-tests `bubblewrap` at startup and refuses to lease jobs if the sandbox
cannot run.

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
# Optional, enables Codex verifier:
export OPENAI_API_KEY=...
export LOUPE_SERVER_URL=https://loupe.example.com:8443

LOUPE_WORKER_SSH=deploy@worker \
LOUPE_WORKER_IMAGE="$LOUPE_WORKER_IMAGE" \
contrib/docker/deploy-worker.sh
```

The worker deploy writes `/etc/loupe-container/worker.secrets.env` with mode
`0600`, owned by the container UID `10002`. It contains the worker certificate
bundle and whichever LLM API keys are set. It also writes
`/etc/loupe-container/worker.config.toml` for non-secret worker settings
(cache, logging, scanner defaults, BKB API URL, and Claude/Codex
model/effort), mounts it read-only into the container, and sets
`LOUPE_WORKER_CONFIG`.

As a temporary alternative to `OPENAI_API_KEY`, a worker can use Codex login
state from an explicit local `auth.json` path:

```bash
unset OPENAI_API_KEY
export CODEX_AUTH_JSON_PATH="$HOME/.codex/auth.json"
```

The worker deploy copies that file to
`/etc/loupe-container/codex/auth.json` on the worker host with mode `0600`
and mounts it read-only at `/var/lib/loupe-worker/.codex/auth.json`.

## Secret Handling

The deploy helpers keep secrets out of systemd unit files, Podman `--env`
arguments, and persistent Podman container metadata. They do persist one
protected host-side env file per service so systemd can restart the container
after a crash or VM reboot without another deploy.

Each secret env file is a single-line `NAME=value` file. TLS PEM material is
stored in the generated `_B64` env vars; API keys are stored directly. The file
is bind-mounted read-only into the container at `/run/loupe/secrets.env`, and
the container entrypoint allowlists and exports those variables before starting
Loupe.

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

ssh deploy@server sudo systemctl restart loupe-server-container.service
ssh deploy@worker sudo systemctl restart loupe-worker-container.service

ssh deploy@server sudo podman inspect loupe-server | grep -E 'LOUPE_MASTER_KEY|PEM|API_KEY' || true
ssh deploy@worker sudo podman inspect loupe-worker | grep -E 'LOUPE_MASTER_KEY|PEM|API_KEY' || true
```

`podman inspect` should not show secret values because the helpers mount the
secret file instead of passing secrets through Podman env flags.
