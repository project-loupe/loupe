#!/usr/bin/env bash
set -euo pipefail

CONF="${LOUPE_CONTAINER_WORKER_CONF:-/etc/loupe-container/worker.conf}"
if [ -r "$CONF" ]; then
	# shellcheck disable=SC1090
	. "$CONF"
fi

: "${LOUPE_CONTAINER_IMAGE:?Set LOUPE_CONTAINER_IMAGE in /etc/loupe-container/worker.conf}"
: "${LOUPE_SERVER_URL:?Set LOUPE_SERVER_URL in /etc/loupe-container/worker.conf}"

CONTAINER_NAME="${LOUPE_CONTAINER_NAME:-loupe-worker}"
SECRET_FILE="${LOUPE_SECRET_FILE:-/etc/loupe-container/worker.secrets.env}"
CACHE_DIR="${LOUPE_WORKER_CACHE_DIR:-/var/cache/loupe-worker-container}"

if [ ! -r "$SECRET_FILE" ]; then
	echo "error: missing secret env file at $SECRET_FILE" >&2
	exit 78
fi

install -d -o 10002 -g 10002 -m 0700 "$CACHE_DIR"

env_args=(--env "LOUPE_SERVER_URL=$LOUPE_SERVER_URL")
for name in \
	RUST_LOG \
	LOUPE_LOG_JSON \
	LOUPE_MAX_CONCURRENT_FILES \
	LOUPE_LOG_AGENT_OUTPUT \
	LOUPE_DISABLE_SANDBOX
do
	if [ -n "${!name+x}" ]; then
		env_args+=(--env "$name=${!name}")
	fi
done

exec podman run \
	--rm \
	--replace \
	--pull=never \
	--privileged \
	--name "$CONTAINER_NAME" \
	--volume "$CACHE_DIR:/var/cache/loupe-worker" \
	--volume "$SECRET_FILE:/run/loupe/secrets.env:ro" \
	"${env_args[@]}" \
	"$LOUPE_CONTAINER_IMAGE"
