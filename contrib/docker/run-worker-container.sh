#!/usr/bin/env bash
set -euo pipefail

CONF="${LOUPE_CONTAINER_WORKER_CONF:-/etc/loupe-container/worker.conf}"
if [ -r "$CONF" ]; then
	# shellcheck disable=SC1090
	. "$CONF"
fi

: "${LOUPE_CONTAINER_IMAGE:?Set LOUPE_CONTAINER_IMAGE in /etc/loupe-container/worker.conf}"

CONTAINER_NAME="${LOUPE_CONTAINER_NAME:-loupe-worker}"
SECRET_FILE="${LOUPE_SECRET_FILE:-/etc/loupe-container/worker.secrets.env}"
CACHE_DIR="${LOUPE_WORKER_CACHE_DIR:-/var/cache/loupe-worker-container}"
CONFIG_HOST="${LOUPE_WORKER_CONFIG_HOST:-/etc/loupe-container/worker.config.toml}"
CONFIG_CONTAINER="${LOUPE_WORKER_CONFIG_CONTAINER:-/etc/loupe/worker.config.toml}"
CODEX_AUTH_DIR="${LOUPE_CODEX_AUTH_DIR:-}"

if [ ! -r "$SECRET_FILE" ]; then
	echo "error: missing secret env file at $SECRET_FILE" >&2
	exit 78
fi
if [ ! -r "$CONFIG_HOST" ] && [ -z "${LOUPE_SERVER_URL:-}" ]; then
	echo "error: missing worker config at $CONFIG_HOST and LOUPE_SERVER_URL is unset" >&2
	exit 78
fi

install -d -o 10002 -g 10002 -m 0700 "$CACHE_DIR"

env_args=()
volume_args=(--volume "$CACHE_DIR:/var/cache/loupe-worker" --volume "$SECRET_FILE:/run/loupe/secrets.env:ro")
if [ -n "$CODEX_AUTH_DIR" ]; then
	if [ ! -r "$CODEX_AUTH_DIR/auth.json" ]; then
		echo "error: missing codex auth.json at $CODEX_AUTH_DIR/auth.json" >&2
		exit 78
	fi
	volume_args+=(--volume "$CODEX_AUTH_DIR:/var/lib/loupe-worker/.codex:ro")
fi
if [ -r "$CONFIG_HOST" ]; then
	volume_args+=(--volume "$CONFIG_HOST:$CONFIG_CONTAINER:ro")
	env_args+=(--env "LOUPE_WORKER_CONFIG=$CONFIG_CONTAINER")
fi
if [ -n "${LOUPE_SERVER_URL:-}" ]; then
	env_args+=(--env "LOUPE_SERVER_URL=$LOUPE_SERVER_URL")
fi
for name in \
	RUST_LOG \
	LOUPE_LOG_LEVEL \
	LOUPE_LOG_JSON \
	LOUPE_MAX_CACHE_GB \
	LOUPE_MAX_WORKDIR_GB \
	LOUPE_MAX_CONCURRENT_FILES \
	LOUPE_MAX_FILE_BYTES \
	LOUPE_PER_REQUEST_TIMEOUT_SECONDS \
	LOUPE_LOG_AGENT_OUTPUT \
	LOUPE_DISABLE_SANDBOX \
	LOUPE_CLAUDE_MODEL \
	LOUPE_CLAUDE_EFFORT \
	LOUPE_CODEX_MODEL \
	LOUPE_CODEX_EFFORT \
	LOUPE_BKB_API_URL
do
	if [ -n "${!name+x}" ]; then
		env_args+=(--env "$name=${!name}")
	fi
done

exec podman run \
	--rm \
	--replace \
	--pull=never \
	--log-driver=none \
	--privileged \
	--name "$CONTAINER_NAME" \
	"${volume_args[@]}" \
	"${env_args[@]}" \
	"$LOUPE_CONTAINER_IMAGE"
