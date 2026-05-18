#!/usr/bin/env bash
set -euo pipefail

CONF="${LOUPE_CONTAINER_SERVER_CONF:-/etc/loupe-container/server.conf}"
if [ -r "$CONF" ]; then
	# shellcheck disable=SC1090
	. "$CONF"
fi

: "${LOUPE_CONTAINER_IMAGE:?Set LOUPE_CONTAINER_IMAGE in /etc/loupe-container/server.conf}"

CONTAINER_NAME="${LOUPE_CONTAINER_NAME:-loupe-server}"
SECRET_FILE="${LOUPE_SECRET_FILE:-/etc/loupe-container/server.secrets.env}"
DATA_DIR="${LOUPE_SERVER_DATA_DIR:-/var/lib/loupe-container/server}"
PUBLISH="${LOUPE_SERVER_PUBLISH:-8443:8443}"

if [ ! -r "$SECRET_FILE" ]; then
	echo "error: missing secret env file at $SECRET_FILE" >&2
	exit 78
fi

install -d -o 10001 -g 10001 -m 0700 "$DATA_DIR"

env_args=()
for name in \
	RUST_LOG \
	LOUPE_LOG_JSON \
	LOUPE_BIND \
	LOUPE_DB \
	LOUPE_REQUIRE_APPROVAL_DEFAULT \
	LOUPE_VERIFICATION_DEFAULT
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
	--name "$CONTAINER_NAME" \
	--publish "$PUBLISH" \
	--volume "$DATA_DIR:/var/lib/loupe" \
	--volume "$SECRET_FILE:/run/loupe/secrets.env:ro" \
	"${env_args[@]}" \
	"$LOUPE_CONTAINER_IMAGE"
