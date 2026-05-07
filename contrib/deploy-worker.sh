#!/usr/bin/env bash
set -euo pipefail

# Build and deploy loupe-worker from this checkout to one remote host.
#
# What this does:
#   1. `cargo build --release -p loupe-worker`
#   2. `scp` the binary, and optionally the systemd unit/env file, to the host.
#   3. Run narrowly-scoped `sudo install ...` commands on the host.
#   4. `sudo systemctl restart loupe-worker.service`.
#
# First-time host prep still needs root once:
#   sudo useradd --system --home /var/lib/loupe-worker --shell /usr/sbin/nologin loupe-worker
#   sudo install -d -o loupe-worker -g loupe-worker -m 0700 /var/lib/loupe-worker
#   sudo install -d -o loupe-worker -g loupe-worker -m 0700 /var/cache/loupe-worker
#   sudo install -d -m 0755 /opt/loupe/bin /etc/loupe
#   sudo visudo -f /etc/sudoers.d/loupe-worker-deploy
#
# The service expects cert/key files to be readable by `loupe-worker`.
# It also needs `git`, `bwrap`, and at least one of `claude` or `codex`
# available on its PATH. If those live outside systemd's default PATH,
# set LOUPE_WORKER_PATH and this script will write it as PATH=...
#
# Minimal use, keeping an already-installed service/env file:
#   LOUPE_WORKER_SSH=deploy@worker-host \
#   LOUPE_WORKER_INSTALL_SERVICE=0 \
#   LOUPE_WORKER_WRITE_ENV=0 \
#     contrib/deploy-worker.sh
#
# Install/update the service and generate `/etc/loupe/loupe-worker.env`
# from local environment variables:
#   LOUPE_WORKER_SSH=deploy@worker-host \
#   LOUPE_SERVER_URL=https://loupe.example.internal:8443 \
#   LOUPE_CA_CERT=/etc/loupe/worker/ca.pem \
#   LOUPE_WORKER_CERT=/etc/loupe/worker/worker.pem \
#   LOUPE_WORKER_KEY=/etc/loupe/worker/worker.key \
#   LOUPE_CACHE_DIR=/var/cache/loupe-worker \
#   LOUPE_WORKER_PATH=/usr/local/bin:/usr/bin:/bin \
#   ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
#     contrib/deploy-worker.sh
#
# Or provide the exact env file to upload:
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
#
# If LOUPE_WORKER_ENV_FILE_LOCAL is unset, the script writes an env file
# from the vars below when any of them are present:
#   RUST_LOG PATH(via LOUPE_WORKER_PATH) HOME(via LOUPE_WORKER_HOME)
#   LOUPE_LOG_JSON LOUPE_SERVER_URL LOUPE_CA_CERT
#   LOUPE_WORKER_CERT LOUPE_WORKER_KEY LOUPE_CACHE_DIR
#   LOUPE_DISABLE_SANDBOX LOUPE_MAX_CONCURRENT_FILES
#   LOUPE_LOG_AGENT_OUTPUT ANTHROPIC_API_KEY OPENAI_API_KEY CODEX_HOME
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

tmp_env=""
cleanup() {
	if [ -n "$tmp_env" ]; then
		rm -f "$tmp_env"
	fi
}
trap cleanup EXIT

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
			LOUPE_SERVER_URL \
			LOUPE_CA_CERT \
			LOUPE_WORKER_CERT \
			LOUPE_WORKER_KEY \
			LOUPE_CACHE_DIR \
			LOUPE_DISABLE_SANDBOX \
			LOUPE_MAX_CONCURRENT_FILES \
			LOUPE_LOG_AGENT_OUTPUT \
			ANTHROPIC_API_KEY \
			OPENAI_API_KEY \
			CODEX_HOME
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
		[ -n "${LOUPE_WORKER_HOME+x}" ]; then
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
		LOUPE_LOG_AGENT_OUTPUT \
		ANTHROPIC_API_KEY \
		OPENAI_API_KEY \
		CODEX_HOME
	do
		if [ -n "${!name+x}" ]; then
			return 0
		fi
	done
	return 1
}

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

echo "==> Installing and restarting $SERVICE_NAME"
ssh "$SSH_TARGET" bash -s -- \
	"${REMOTE_TMP}.bin" \
	"${REMOTE_TMP}.service" \
	"${REMOTE_TMP}.env" \
	"$REMOTE_BIN" \
	"$SERVICE_NAME" \
	"/etc/systemd/system/$SERVICE_NAME" \
	"$ENV_PATH" \
	"$INSTALL_SERVICE" \
	"$write_env" <<'REMOTE'
set -euo pipefail
bin_tmp="$1"
service_tmp="$2"
env_tmp="$3"
remote_bin="$4"
service_name="$5"
service_dest="$6"
env_path="$7"
install_service="$8"
write_env="$9"

sudo install -D -m 0755 "$bin_tmp" "$remote_bin"
if [ "$install_service" = "1" ]; then
	sudo install -D -m 0644 "$service_tmp" "$service_dest"
	sudo systemctl daemon-reload
fi
if [ "$write_env" = "1" ]; then
	sudo install -D -m 0600 "$env_tmp" "$env_path"
fi
rm -f "$bin_tmp" "$service_tmp" "$env_tmp"
sudo systemctl restart "$service_name"
systemctl --no-pager --lines=20 status "$service_name"
REMOTE

echo "==> loupe-worker deployed"
