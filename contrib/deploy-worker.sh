#!/usr/bin/env bash
set -euo pipefail

# Build and deploy loupe-worker from this checkout to one remote host.
#
# What this does:
#   1. `cargo build --release -p loupe-worker`
#   2. `scp` the non-secret binary/unit/env/helper files to the host.
#   3. Run narrowly-scoped `sudo install ...` commands on the host.
#   4. Stream secret values from local env vars over SSH stdin to a
#      root helper, which injects worker mTLS PEMs and agent credentials
#      through systemd runtime env.
#   5. Restart `loupe-worker.service`.
#
# First-time host prep still needs root once:
#   sudo useradd --system --home /var/lib/loupe-worker --shell /usr/sbin/nologin loupe-worker
#   sudo install -d -o loupe-worker -g loupe-worker -m 0700 /var/lib/loupe-worker
#   sudo install -d -o loupe-worker -g loupe-worker -m 0700 /var/cache/loupe-worker
#   sudo install -d -m 0755 /opt/loupe/bin /etc/loupe
#   sudo visudo -f /etc/sudoers.d/loupe-worker-deploy
#
# Secret inputs are env vars on the deployment machine, not files:
#   LOUPE_WORKER_CA_CERT_PEM=<CA cert PEM>
#   LOUPE_WORKER_CERT_PEM=<worker client cert PEM>
#   LOUPE_WORKER_KEY_PEM=<worker client key PEM>
#   ANTHROPIC_API_KEY=<optional claude API key>
#   OPENAI_API_KEY=<optional codex API key>
#
# The PEM values and agent API keys are streamed over SSH stdin into
# systemd's runtime manager environment for the explicit restart. They
# are never written to /etc/loupe/loupe-worker.env.
#
# The service also needs `git`, `bwrap`, and at least one of `claude`
# or `codex` available on its PATH. If those live outside systemd's
# default PATH, set LOUPE_WORKER_PATH and this script will write it as
# PATH=...
#
# Minimal use, keeping an already-installed service/env file:
#   LOUPE_WORKER_SSH=deploy@worker-host \
#   LOUPE_WORKER_INSTALL_SERVICE=0 \
#   LOUPE_WORKER_WRITE_ENV=0 \
#     contrib/deploy-worker.sh
#
# Install/update the service and generate `/etc/loupe/loupe-worker.env`
# from local non-secret environment variables plus runtime secret paths:
#   LOUPE_WORKER_SSH=deploy@worker-host \
#   LOUPE_SERVER_URL=https://loupe.example.internal:8443 \
#   LOUPE_WORKER_CA_CERT_PEM="$LOUPE_WORKER_CA_CERT_PEM" \
#   LOUPE_WORKER_CERT_PEM="$LOUPE_WORKER_CERT_PEM" \
#   LOUPE_WORKER_KEY_PEM="$LOUPE_WORKER_KEY_PEM" \
#   LOUPE_CACHE_DIR=/var/cache/loupe-worker \
#   LOUPE_WORKER_PATH=/usr/local/bin:/usr/bin:/bin \
#   ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
#     contrib/deploy-worker.sh
#
# Or provide the exact non-secret env file to upload:
#   LOUPE_WORKER_SSH=deploy@worker-host \
#   LOUPE_WORKER_ENV_FILE_LOCAL=./prod/loupe-worker.env \
#     contrib/deploy-worker.sh
#
# Required:
#   LOUPE_WORKER_SSH=deploy@worker-host
#
# Common optional deployment settings:
#   LOUPE_WORKER_REMOTE_BIN=/opt/loupe/bin/loupe-worker
#   LOUPE_WORKER_SERVICE=loupe-worker.service
#   LOUPE_WORKER_INSTALL_SERVICE=1
#   LOUPE_WORKER_ENV_PATH=/etc/loupe/loupe-worker.env
#   LOUPE_WORKER_ENV_FILE_LOCAL=/path/to/loupe-worker.env
#   LOUPE_WORKER_RUNTIME_HELPER_REMOTE=/usr/local/sbin/loupe-worker-runtime-secrets
#   LOUPE_WORKER_INSTALL_RUNTIME_HELPER=1
#   LOUPE_WORKER_KEEP_SYSTEMD_ENV=0
#
# If LOUPE_WORKER_KEEP_SYSTEMD_ENV=0 (default), runtime env values are
# unset from systemd's manager environment immediately after restart.
# That keeps secrets out of persistent host state, but an automatic
# systemd restart after a crash will need this deploy/restart path again.
#
# If LOUPE_WORKER_ENV_FILE_LOCAL is unset, the script writes an env file
# from the non-secret vars below when any of them are present:
#   RUST_LOG PATH(via LOUPE_WORKER_PATH) HOME(via LOUPE_WORKER_HOME)
#   LOUPE_LOG_JSON LOUPE_SERVER_URL LOUPE_CA_CERT
#   LOUPE_WORKER_CERT LOUPE_WORKER_KEY LOUPE_CACHE_DIR
#   LOUPE_DISABLE_SANDBOX LOUPE_MAX_CONCURRENT_FILES
#   LOUPE_LOG_AGENT_OUTPUT
#
# Add custom copied variables with:
#   LOUPE_WORKER_EXTRA_ENV_VARS="FOO BAR"

SSH_TARGET="${LOUPE_WORKER_SSH:?Set LOUPE_WORKER_SSH=user@host}"
BINARY="${LOUPE_WORKER_BINARY:-target/release/loupe-worker}"
REMOTE_BIN="${LOUPE_WORKER_REMOTE_BIN:-/opt/loupe/bin/loupe-worker}"
SERVICE_NAME="${LOUPE_WORKER_SERVICE:-loupe-worker.service}"
SERVICE_FILE="${LOUPE_WORKER_SERVICE_FILE:-contrib/loupe-worker.service}"
INSTALL_SERVICE="${LOUPE_WORKER_INSTALL_SERVICE:-1}"
ENV_PATH="${LOUPE_WORKER_ENV_PATH:-/etc/loupe/loupe-worker.env}"
REMOTE_TMP="${LOUPE_WORKER_REMOTE_TMP:-/tmp/loupe-worker-deploy.$$}"
RUNTIME_HELPER_FILE="${LOUPE_WORKER_RUNTIME_HELPER_FILE:-contrib/loupe-worker-runtime-secrets.sh}"
RUNTIME_HELPER_REMOTE="${LOUPE_WORKER_RUNTIME_HELPER_REMOTE:-/usr/local/sbin/loupe-worker-runtime-secrets}"
INSTALL_RUNTIME_HELPER="${LOUPE_WORKER_INSTALL_RUNTIME_HELPER:-1}"
KEEP_SYSTEMD_ENV="${LOUPE_WORKER_KEEP_SYSTEMD_ENV:-0}"

tmp_env=""
cleanup() {
	if [ -n "$tmp_env" ]; then
		rm -f "$tmp_env"
	fi
}
trap cleanup EXIT

secret_set() {
	local name="$1"
	[ -n "${!name+x}" ] && [ -n "${!name}" ]
}

have_worker_pem_secrets() {
	secret_set LOUPE_WORKER_CA_CERT_PEM ||
		secret_set LOUPE_WORKER_CERT_PEM ||
		secret_set LOUPE_WORKER_KEY_PEM
}

have_agent_runtime_env() {
	secret_set ANTHROPIC_API_KEY || secret_set OPENAI_API_KEY || secret_set CODEX_HOME
}

have_runtime_secrets() {
	have_worker_pem_secrets || have_agent_runtime_env
}

require_runtime_secret_shape() {
	local missing=""
	if have_worker_pem_secrets; then
		for name in \
			LOUPE_WORKER_CA_CERT_PEM \
			LOUPE_WORKER_CERT_PEM \
			LOUPE_WORKER_KEY_PEM
		do
			if ! secret_set "$name"; then
				missing="$missing $name"
			fi
		done
	fi
	if [ -n "$missing" ]; then
		echo "error: when any worker PEM env var is set, all are required; missing:$missing" >&2
		exit 1
	fi
}

quote_systemd_env() {
	local value="$1"
	value="${value//\\/\\\\}"
	value="${value//\"/\\\"}"
	printf '"%s"' "$value"
}

write_env_var() {
	local output_name="$1"
	local input_name="${2:-$1}"
	if [ -n "${!input_name+x}" ]; then
		printf '%s=' "$output_name"
		quote_systemd_env "${!input_name}"
		printf '\n'
	fi
}

write_env_literal() {
	local name="$1"
	local value="$2"
	printf '%s=' "$name"
	quote_systemd_env "$value"
	printf '\n'
}

build_env_file() {
	tmp_env="$(mktemp)"
	if [ -n "${LOUPE_WORKER_ENV_FILE_LOCAL:-}" ]; then
		cp "$LOUPE_WORKER_ENV_FILE_LOCAL" "$tmp_env"
		return 0
	fi

	{
		printf '# Managed by contrib/deploy-worker.sh\n'
		write_env_var PATH LOUPE_WORKER_PATH
		write_env_var HOME LOUPE_WORKER_HOME
		for name in \
			RUST_LOG \
			LOUPE_LOG_JSON \
			LOUPE_SERVER_URL
		do
			write_env_var "$name"
		done

		if have_worker_pem_secrets; then
			:
		else
			for name in \
				LOUPE_CA_CERT \
				LOUPE_WORKER_CERT \
				LOUPE_WORKER_KEY
			do
				write_env_var "$name"
			done
		fi

		for name in \
			LOUPE_CACHE_DIR \
			LOUPE_DISABLE_SANDBOX \
			LOUPE_MAX_CONCURRENT_FILES \
			LOUPE_LOG_AGENT_OUTPUT
		do
			write_env_var "$name"
		done
		for name in ${LOUPE_WORKER_EXTRA_ENV_VARS:-}; do
			write_env_var "$name"
		done
	} >"$tmp_env"
}

should_write_env() {
	if [ -n "${LOUPE_WORKER_WRITE_ENV:-}" ]; then
		[ "$LOUPE_WORKER_WRITE_ENV" = "1" ]
		return
	fi
	if [ -n "${LOUPE_WORKER_ENV_FILE_LOCAL:-}" ] ||
		[ -n "${LOUPE_WORKER_EXTRA_ENV_VARS:-}" ] ||
		[ -n "${LOUPE_WORKER_PATH+x}" ] ||
		[ -n "${LOUPE_WORKER_HOME+x}" ] ||
		have_runtime_secrets; then
		return 0
	fi
	for name in \
		RUST_LOG \
		LOUPE_LOG_JSON \
		LOUPE_SERVER_URL \
		LOUPE_CA_CERT \
		LOUPE_WORKER_CERT \
		LOUPE_WORKER_KEY \
		LOUPE_CACHE_DIR \
		LOUPE_DISABLE_SANDBOX \
		LOUPE_MAX_CONCURRENT_FILES \
		LOUPE_LOG_AGENT_OUTPUT
	do
		if [ -n "${!name+x}" ]; then
			return 0
		fi
	done
	return 1
}

b64_env_value() {
	local name="$1"
	printf '%s' "${!name}" | base64 | tr -d '\n'
}

emit_runtime_secret_payload() {
	if have_worker_pem_secrets; then
		for name in \
			LOUPE_WORKER_CA_CERT_PEM \
			LOUPE_WORKER_CERT_PEM \
			LOUPE_WORKER_KEY_PEM
		do
			printf '%s=%s\n' "$name" "$(b64_env_value "$name")"
		done
	fi
	for name in ANTHROPIC_API_KEY OPENAI_API_KEY CODEX_HOME; do
		if secret_set "$name"; then
			printf '%s=%s\n' "$name" "$(b64_env_value "$name")"
		fi
	done
}

require_runtime_secret_shape

echo "==> Building loupe-worker"
cargo build --release -p loupe-worker
test -x "$BINARY"
echo "==> Binary size: $(du -h "$BINARY" | cut -f1)"

write_env=0
if should_write_env; then
	build_env_file
	write_env=1
fi

echo "==> Uploading loupe-worker to $SSH_TARGET"
scp "$BINARY" "${SSH_TARGET}:${REMOTE_TMP}.bin"
if [ "$INSTALL_SERVICE" = "1" ]; then
	scp "$SERVICE_FILE" "${SSH_TARGET}:${REMOTE_TMP}.service"
fi
if [ "$write_env" = "1" ]; then
	scp "$tmp_env" "${SSH_TARGET}:${REMOTE_TMP}.env"
fi
if [ "$INSTALL_RUNTIME_HELPER" = "1" ]; then
	scp "$RUNTIME_HELPER_FILE" "${SSH_TARGET}:${REMOTE_TMP}.runtime-helper"
fi

echo "==> Installing loupe-worker artifacts"
ssh "$SSH_TARGET" bash -s -- \
	"${REMOTE_TMP}.bin" \
	"${REMOTE_TMP}.service" \
	"${REMOTE_TMP}.env" \
	"${REMOTE_TMP}.runtime-helper" \
	"$REMOTE_BIN" \
	"$SERVICE_NAME" \
	"/etc/systemd/system/$SERVICE_NAME" \
	"$ENV_PATH" \
	"$RUNTIME_HELPER_REMOTE" \
	"$INSTALL_SERVICE" \
	"$write_env" \
	"$INSTALL_RUNTIME_HELPER" <<'REMOTE'
set -euo pipefail
bin_tmp="$1"
service_tmp="$2"
env_tmp="$3"
runtime_helper_tmp="$4"
remote_bin="$5"
service_name="$6"
service_dest="$7"
env_path="$8"
runtime_helper_dest="$9"
install_service="${10}"
write_env="${11}"
install_runtime_helper="${12}"

sudo install -D -m 0755 "$bin_tmp" "$remote_bin"
if [ "$install_service" = "1" ]; then
	sudo install -D -m 0644 "$service_tmp" "$service_dest"
fi
if [ "$write_env" = "1" ]; then
	sudo install -D -m 0600 "$env_tmp" "$env_path"
fi
if [ "$install_runtime_helper" = "1" ]; then
	sudo install -D -m 0755 "$runtime_helper_tmp" "$runtime_helper_dest"
fi
rm -f "$bin_tmp" "$service_tmp" "$env_tmp" "$runtime_helper_tmp"
if [ "$install_service" = "1" ] || [ "$install_runtime_helper" = "1" ]; then
	sudo systemctl daemon-reload
fi
REMOTE

if have_runtime_secrets; then
	echo "==> Installing runtime secrets and restarting $SERVICE_NAME"
	helper_args=(--service "$SERVICE_NAME" --restart --status-lines 20)
	if [ "$KEEP_SYSTEMD_ENV" = "1" ]; then
		helper_args+=(--keep-manager-env)
	fi
	emit_runtime_secret_payload | ssh "$SSH_TARGET" sudo "$RUNTIME_HELPER_REMOTE" "${helper_args[@]}"
else
	echo "==> Restarting $SERVICE_NAME"
	ssh "$SSH_TARGET" sudo systemctl restart "$SERVICE_NAME"
	ssh "$SSH_TARGET" systemctl --no-pager --lines=20 status "$SERVICE_NAME"
fi

echo "==> loupe-worker deployed"
