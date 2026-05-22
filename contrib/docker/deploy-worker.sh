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
REMOTE_WORKER_CONFIG="${LOUPE_WORKER_CONFIG_FILE:-/etc/loupe-container/worker.config.toml}"
CONTAINER_WORKER_CONFIG="${LOUPE_WORKER_CONFIG_CONTAINER:-/etc/loupe/worker.config.toml}"
REMOTE_SECRET="${LOUPE_WORKER_SECRET_FILE:-/etc/loupe-container/worker.secrets.env}"
LOCAL_CODEX_AUTH_JSON="${CODEX_AUTH_JSON_PATH:-}"
REMOTE_CODEX_AUTH_DIR="${LOUPE_CODEX_AUTH_REMOTE_DIR:-/etc/loupe-container/codex}"
LOAD_IMAGE="${LOUPE_WORKER_LOAD_IMAGE:-0}"
PULL_IMAGE="${LOUPE_WORKER_PULL_IMAGE:-0}"
START_GRACE_SECONDS="${LOUPE_WORKER_START_GRACE_SECONDS:-3}"

RUN_FILE="$ROOT/contrib/docker/run-worker-container.sh"
UNIT_FILE="$ROOT/contrib/docker/loupe-worker-container.service"

tmp_conf=""
tmp_worker_config=""
cleanup() {
	if [ -n "$tmp_conf" ]; then
		rm -f "$tmp_conf"
	fi
	if [ -n "$tmp_worker_config" ]; then
		rm -f "$tmp_worker_config"
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

emit_secret_env_value() {
	local name="$1"
	local value="$2"
	if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
		echo "error: secret env var $name must be a single line" >&2
		exit 2
	fi
	printf '%s=%s\n' "$name" "$value"
}

emit_secret_env_var() {
	local name="$1"
	emit_secret_env_value "$name" "${!name}"
}

codex_api_key_set() {
	secret_set CODEX_API_KEY || secret_set OPENAI_API_KEY
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
	if secret_set CODEX_API_KEY; then
		emit_secret_env_var CODEX_API_KEY
	elif secret_set OPENAI_API_KEY; then
		emit_secret_env_value CODEX_API_KEY "$OPENAI_API_KEY"
	fi
}

write_conf_var() {
	local name="$1"
	local value="$2"
	printf '%s=%q\n' "$name" "$value"
}

toml_escape() {
	local value="$1"
	value="${value//\\/\\\\}"
	value="${value//\"/\\\"}"
	printf '%s' "$value"
}

toml_string() {
	printf '"%s"' "$(toml_escape "$1")"
}

bool_value() {
	local value="${1:-}"
	case "${value,,}" in
		1 | true | yes | on) printf 'true' ;;
		0 | false | no | off | '') printf 'false' ;;
		*) printf 'true' ;;
	esac
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
		write_conf_var LOUPE_WORKER_CACHE_DIR "${LOUPE_WORKER_CACHE_DIR:-/var/cache/loupe-worker-container}"
		write_conf_var LOUPE_WORKER_CONFIG_HOST "$REMOTE_WORKER_CONFIG"
		write_conf_var LOUPE_WORKER_CONFIG_CONTAINER "$CONTAINER_WORKER_CONFIG"
		if [ -n "$LOCAL_CODEX_AUTH_JSON" ]; then
			write_conf_var LOUPE_CODEX_AUTH_DIR "$REMOTE_CODEX_AUTH_DIR"
		fi
		if [ -n "${RUST_LOG+x}" ]; then
			write_conf_var RUST_LOG "$RUST_LOG"
		fi
	} >"$tmp_conf"
}

build_worker_config_file() {
	tmp_worker_config="$(mktemp)"
	{
		printf '[server]\n'
		printf 'url = %s\n\n' "$(toml_string "$LOUPE_SERVER_URL")"

		printf '[cache]\n'
		printf 'dir = "/var/cache/loupe-worker"\n'
		printf 'max_gb = %s\n\n' "${LOUPE_MAX_CACHE_GB:-40}"

		printf '[runtime]\n'
		printf 'max_workdir_gb = %s\n' "${LOUPE_MAX_WORKDIR_GB:-5}"
		printf 'disable_sandbox = %s\n\n' "$(bool_value "${LOUPE_DISABLE_SANDBOX:-}")"

		printf '[logging]\n'
		printf 'level = %s\n' "$(toml_string "${LOUPE_LOG_LEVEL:-info}")"
		printf 'json = %s\n' "$(bool_value "${LOUPE_LOG_JSON:-}")"
		printf 'agent_output = %s\n\n' "$(bool_value "${LOUPE_LOG_AGENT_OUTPUT:-}")"

		printf '[agents.claude]\n'
		printf 'model = %s\n' "$(toml_string "${LOUPE_CLAUDE_MODEL:-claude-opus-4-7}")"
		printf 'effort = %s\n\n' "$(toml_string "${LOUPE_CLAUDE_EFFORT:-max}")"

		printf '[agents.codex]\n'
		printf 'model = %s\n' "$(toml_string "${LOUPE_CODEX_MODEL:-gpt-5.5}")"
		printf 'effort = %s\n\n' "$(toml_string "${LOUPE_CODEX_EFFORT:-xhigh}")"

		printf '[scanner_defaults]\n'
		printf 'max_concurrent_files = %s\n' "${LOUPE_MAX_CONCURRENT_FILES:-8}"
		printf 'max_file_bytes = %s\n' "${LOUPE_MAX_FILE_BYTES:-2097152}"
		printf 'per_request_timeout_seconds = %s\n\n' "${LOUPE_PER_REQUEST_TIMEOUT_SECONDS:-1800}"

		printf '[bkb]\n'
		printf 'api_url = %s\n' "$(toml_string "${LOUPE_BKB_API_URL:-https://bitcoinknowledge.dev}")"
	} >"$tmp_worker_config"
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
if [ -n "$LOCAL_CODEX_AUTH_JSON" ] && [ ! -r "$LOCAL_CODEX_AUTH_JSON" ]; then
	echo "error: CODEX_AUTH_JSON_PATH does not point to a readable file: $LOCAL_CODEX_AUTH_JSON" >&2
	exit 2
fi
if [ -n "$LOCAL_CODEX_AUTH_JSON" ] && codex_api_key_set; then
	echo "warning: CODEX_AUTH_JSON_PATH and an API key are both set; codex may prefer CODEX_API_KEY" >&2
fi
if ! secret_set ANTHROPIC_API_KEY && ! codex_api_key_set && [ -z "$LOCAL_CODEX_AUTH_JSON" ]; then
	echo "error: set ANTHROPIC_API_KEY, CODEX_API_KEY, OPENAI_API_KEY, or CODEX_AUTH_JSON_PATH for the worker" >&2
	exit 2
fi

build_conf_file
build_worker_config_file

echo "==> Uploading loupe worker container unit to $SSH_TARGET"
scp "$RUN_FILE" "${SSH_TARGET}:${REMOTE_TMP}.run"
scp "$UNIT_FILE" "${SSH_TARGET}:${REMOTE_TMP}.service"
scp "$tmp_conf" "${SSH_TARGET}:${REMOTE_TMP}.conf"
scp "$tmp_worker_config" "${SSH_TARGET}:${REMOTE_TMP}.worker-config"

ssh "$SSH_TARGET" bash -s -- \
	"${REMOTE_TMP}.run" \
	"${REMOTE_TMP}.service" \
	"${REMOTE_TMP}.conf" \
	"${REMOTE_TMP}.worker-config" \
	"$REMOTE_RUN" \
	"$REMOTE_UNIT" \
	"$REMOTE_CONF" \
	"$REMOTE_WORKER_CONFIG" \
	"$SERVICE_NAME" <<'REMOTE'
set -euo pipefail
run_tmp="$1"
service_tmp="$2"
conf_tmp="$3"
worker_config_tmp="$4"
remote_run="$5"
remote_unit="$6"
remote_conf="$7"
remote_worker_config="$8"
service_name="$9"

sudo install -d -m 0755 /etc/loupe-container /usr/local/lib/loupe-container
sudo install -d -m 0700 /var/cache/loupe-worker-container
sudo install -D -m 0755 "$run_tmp" "$remote_run"
sudo install -D -m 0644 "$service_tmp" "$remote_unit"
sudo install -D -m 0644 "$conf_tmp" "$remote_conf"
sudo install -D -m 0644 "$worker_config_tmp" "$remote_worker_config"
rm -f "$run_tmp" "$service_tmp" "$conf_tmp" "$worker_config_tmp"
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

if [ -n "$LOCAL_CODEX_AUTH_JSON" ]; then
	echo "==> Writing persistent codex auth.json to $SSH_TARGET:$REMOTE_CODEX_AUTH_DIR/auth.json"
	codex_auth_writer='
set -euo pipefail
dir="$1"
install -d -o 10002 -g 10002 -m 0700 "$dir"
tmp="$(mktemp "$dir/.auth.json.XXXXXX")"
trap "rm -f \"$tmp\"" EXIT
cat > "$tmp"
chown 10002:10002 "$tmp"
chmod 0600 "$tmp"
mv "$tmp" "$dir/auth.json"
trap - EXIT
'
	ssh "$SSH_TARGET" \
		"sudo bash -c $(remote_quote "$codex_auth_writer") bash $(remote_quote "$REMOTE_CODEX_AUTH_DIR")" \
		<"$LOCAL_CODEX_AUTH_JSON"
fi

echo "==> Restarting $SERVICE_NAME"
ssh "$SSH_TARGET" sudo systemctl restart "$SERVICE_NAME"
sleep "$START_GRACE_SECONDS"
ssh "$SSH_TARGET" systemctl --no-pager --lines=30 status "$SERVICE_NAME"

echo "==> loupe worker container deployed"
