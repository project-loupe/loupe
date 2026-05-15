#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

SSH_TARGET="${LOUPE_WORKER_SSH:?Set LOUPE_WORKER_SSH=user@host}"
IMAGE="${LOUPE_WORKER_IMAGE:?Set LOUPE_WORKER_IMAGE, usually by running eval \"\$(contrib/docker/build-images.sh)\"}"
SERVICE_NAME="${LOUPE_WORKER_SERVICE:-loupe-worker-container.service}"
REMOTE_TMP="${LOUPE_WORKER_REMOTE_TMP:-/tmp/loupe-worker-container-deploy.$$}"
REMOTE_RUN="${LOUPE_WORKER_REMOTE_RUN:-/usr/local/lib/loupe-container/run-worker}"
REMOTE_UNIT="${LOUPE_WORKER_REMOTE_UNIT:-/etc/systemd/system/$SERVICE_NAME}"
REMOTE_CONF="${LOUPE_WORKER_REMOTE_CONF:-/etc/loupe-container/worker.conf}"
REMOTE_SECRET="${LOUPE_WORKER_SECRET_FILE:-/etc/loupe-container/worker.secrets.env}"
LOAD_IMAGE="${LOUPE_WORKER_LOAD_IMAGE:-0}"
PULL_IMAGE="${LOUPE_WORKER_PULL_IMAGE:-0}"
START_GRACE_SECONDS="${LOUPE_WORKER_START_GRACE_SECONDS:-3}"

RUN_FILE="$ROOT/contrib/docker/run-worker-container.sh"
UNIT_FILE="$ROOT/contrib/docker/loupe-worker-container.service"

tmp_conf=""
cleanup() {
	if [ -n "$tmp_conf" ]; then
		rm -f "$tmp_conf"
	fi
}
trap cleanup EXIT

secret_set() {
	local name="$1"
	[ -n "${!name+x}" ] && [ -n "${!name}" ]
}

require_secret() {
	local name="$1"
	if ! secret_set "$name"; then
		echo "error: missing required secret env var $name" >&2
		exit 2
	fi
}

emit_secret_env_var() {
	local name="$1"
	local value="${!name}"
	if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
		echo "error: secret env var $name must be a single line" >&2
		exit 2
	fi
	printf '%s=%s\n' "$name" "$value"
}

emit_secret_env() {
	for name in \
		LOUPE_WORKER_CA_CERT_PEM_B64 \
		LOUPE_WORKER_CERT_PEM_B64 \
		LOUPE_WORKER_KEY_PEM_B64 \
		ANTHROPIC_API_KEY \
		OPENAI_API_KEY
	do
		if secret_set "$name"; then
			emit_secret_env_var "$name"
		fi
	done
}

write_conf_var() {
	local name="$1"
	local value="$2"
	printf '%s=%q\n' "$name" "$value"
}

remote_quote() {
	local value="$1"
	printf "'"
	printf '%s' "$value" | sed "s/'/'\\\\''/g"
	printf "'"
}

build_conf_file() {
	tmp_conf="$(mktemp)"
	{
		write_conf_var LOUPE_CONTAINER_IMAGE "$IMAGE"
		write_conf_var LOUPE_CONTAINER_NAME "${LOUPE_WORKER_CONTAINER_NAME:-loupe-worker}"
		write_conf_var LOUPE_SECRET_FILE "$REMOTE_SECRET"
		write_conf_var LOUPE_SERVER_URL "$LOUPE_SERVER_URL"
		write_conf_var LOUPE_WORKER_CACHE_DIR "${LOUPE_WORKER_CACHE_DIR:-/var/cache/loupe-worker-container}"
		for name in \
			RUST_LOG \
			LOUPE_LOG_JSON \
			LOUPE_MAX_CONCURRENT_FILES \
			LOUPE_LOG_AGENT_OUTPUT \
			LOUPE_DISABLE_SANDBOX
		do
			if [ -n "${!name+x}" ]; then
				write_conf_var "$name" "${!name}"
			fi
		done
	} >"$tmp_conf"
}

load_image_if_requested() {
	if [ "$LOAD_IMAGE" != "1" ]; then
		return
	fi
	local engine="${CONTAINER_ENGINE:-}"
	if [ -z "$engine" ]; then
		if command -v podman >/dev/null 2>&1; then
			engine=podman
		elif command -v docker >/dev/null 2>&1; then
			engine=docker
		else
			echo "error: LOUPE_WORKER_LOAD_IMAGE=1 requires local podman or docker" >&2
			exit 127
		fi
	fi
	"$engine" save "$IMAGE" | ssh "$SSH_TARGET" sudo podman load
}

verify_remote_image() {
	if ! ssh "$SSH_TARGET" sudo podman image exists "$IMAGE"; then
		echo "error: image $IMAGE is not present in rootful Podman on $SSH_TARGET" >&2
		echo "hint: load it with: podman save \"\$LOUPE_WORKER_IMAGE\" | ssh $SSH_TARGET sudo podman load" >&2
		exit 1
	fi
}

: "${LOUPE_SERVER_URL:?Set LOUPE_SERVER_URL=https://server:8443}"
for name in \
	LOUPE_WORKER_CA_CERT_PEM_B64 \
	LOUPE_WORKER_CERT_PEM_B64 \
	LOUPE_WORKER_KEY_PEM_B64
do
	require_secret "$name"
done
if ! secret_set ANTHROPIC_API_KEY && ! secret_set OPENAI_API_KEY; then
	echo "error: set ANTHROPIC_API_KEY and/or OPENAI_API_KEY for the worker" >&2
	exit 2
fi

build_conf_file

echo "==> Uploading loupe worker container unit to $SSH_TARGET"
scp "$RUN_FILE" "${SSH_TARGET}:${REMOTE_TMP}.run"
scp "$UNIT_FILE" "${SSH_TARGET}:${REMOTE_TMP}.service"
scp "$tmp_conf" "${SSH_TARGET}:${REMOTE_TMP}.conf"

ssh "$SSH_TARGET" bash -s -- \
	"${REMOTE_TMP}.run" \
	"${REMOTE_TMP}.service" \
	"${REMOTE_TMP}.conf" \
	"$REMOTE_RUN" \
	"$REMOTE_UNIT" \
	"$REMOTE_CONF" \
	"$SERVICE_NAME" <<'REMOTE'
set -euo pipefail
run_tmp="$1"
service_tmp="$2"
conf_tmp="$3"
remote_run="$4"
remote_unit="$5"
remote_conf="$6"
service_name="$7"

sudo install -d -m 0755 /etc/loupe-container /usr/local/lib/loupe-container
sudo install -d -m 0700 /var/cache/loupe-worker-container
sudo install -D -m 0755 "$run_tmp" "$remote_run"
sudo install -D -m 0644 "$service_tmp" "$remote_unit"
sudo install -D -m 0644 "$conf_tmp" "$remote_conf"
rm -f "$run_tmp" "$service_tmp" "$conf_tmp"
sudo systemctl daemon-reload
sudo systemctl enable "$service_name" >/dev/null
REMOTE

load_image_if_requested
if [ "$PULL_IMAGE" = "1" ]; then
	ssh "$SSH_TARGET" sudo podman pull "$IMAGE"
fi
verify_remote_image

echo "==> Writing persistent worker secret env file to $SSH_TARGET:$REMOTE_SECRET"
secret_writer='
set -euo pipefail
secret="$1"
owner="$2"
dir="$(dirname "$secret")"
base="$(basename "$secret")"
install -d -m 0755 "$dir"
tmp="$(mktemp "$dir/.${base}.XXXXXX")"
trap "rm -f \"$tmp\"" EXIT
cat > "$tmp"
chown "$owner:$owner" "$tmp"
chmod 0600 "$tmp"
mv "$tmp" "$secret"
trap - EXIT
'
emit_secret_env | ssh "$SSH_TARGET" \
	"sudo bash -c $(remote_quote "$secret_writer") bash $(remote_quote "$REMOTE_SECRET") 10002"

echo "==> Restarting $SERVICE_NAME"
ssh "$SSH_TARGET" sudo systemctl restart "$SERVICE_NAME"
sleep "$START_GRACE_SECONDS"
ssh "$SSH_TARGET" systemctl --no-pager --lines=30 status "$SERVICE_NAME"

echo "==> loupe worker container deployed"
