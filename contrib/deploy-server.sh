#!/usr/bin/env bash
set -euo pipefail

# Build and deploy loupe-server from this checkout to one remote host.
#
# What this does:
#   1. `cargo build --release -p loupe-server`
#   2. `scp` the binary, and optionally the systemd unit/env file, to the host.
#   3. Run narrowly-scoped `sudo install ...` commands on the host.
#   4. `sudo systemctl restart loupe-server.service`.
#
# First-time host prep still needs root once:
#   sudo useradd --system --home /var/lib/loupe --shell /usr/sbin/nologin loupe
#   sudo install -d -o loupe -g loupe -m 0700 /var/lib/loupe
#   sudo install -d -m 0755 /opt/loupe/bin /etc/loupe
#   sudo visudo -f /etc/sudoers.d/loupe-server-deploy
#
# The service expects server data/certs to be readable by the `loupe`
# service user. A typical server env file is:
#   LOUPE_CONFIG=/var/lib/loupe/config.toml
#   LOUPE_MASTER_KEY=<64 hex chars>
#   RUST_LOG=info
#
# Minimal use, keeping an already-installed service/env file:
#   LOUPE_SERVER_SSH=deploy@server-host \
#   LOUPE_SERVER_INSTALL_SERVICE=0 \
#   LOUPE_SERVER_WRITE_ENV=0 \
#     contrib/deploy-server.sh
#
# Install/update the service and generate `/etc/loupe/loupe-server.env`
# from local environment variables:
#   LOUPE_SERVER_SSH=deploy@server-host \
#   LOUPE_CONFIG=/var/lib/loupe/config.toml \
#   LOUPE_MASTER_KEY="$(cat ./secrets/loupe-master.key)" \
#     contrib/deploy-server.sh
#
# Or provide the exact env file to upload:
#   LOUPE_SERVER_SSH=deploy@server-host \
#   LOUPE_SERVER_ENV_FILE_LOCAL=./prod/loupe-server.env \
#     contrib/deploy-server.sh
#
# Required:
#   LOUPE_SERVER_SSH=deploy@server-host
#
# Common optional deployment settings:
#   LOUPE_SERVER_REMOTE_BIN=/opt/loupe/bin/loupe-server
#   LOUPE_SERVER_SERVICE=loupe-server.service
#   LOUPE_SERVER_INSTALL_SERVICE=1
#   LOUPE_SERVER_ENV_PATH=/etc/loupe/loupe-server.env
#   LOUPE_SERVER_ENV_FILE_LOCAL=/path/to/loupe-server.env
#
# If LOUPE_SERVER_ENV_FILE_LOCAL is unset, the script writes an env file
# from the LOUPE_* vars below when any of them are present:
#   RUST_LOG LOUPE_LOG_JSON LOUPE_CONFIG LOUPE_BIND LOUPE_DB
#   LOUPE_SERVER_CERT LOUPE_SERVER_KEY LOUPE_CA_CERT LOUPE_CA_KEY
#   LOUPE_MASTER_KEY LOUPE_MASTER_KEY_FILE
#   LOUPE_REQUIRE_APPROVAL_DEFAULT
#
# Add custom copied variables with:
#   LOUPE_SERVER_EXTRA_ENV_VARS="FOO BAR"

SSH_TARGET="${LOUPE_SERVER_SSH:?Set LOUPE_SERVER_SSH=user@host}"
BINARY="${LOUPE_SERVER_BINARY:-target/release/loupe-server}"
REMOTE_BIN="${LOUPE_SERVER_REMOTE_BIN:-/opt/loupe/bin/loupe-server}"
SERVICE_NAME="${LOUPE_SERVER_SERVICE:-loupe-server.service}"
SERVICE_FILE="${LOUPE_SERVER_SERVICE_FILE:-contrib/loupe-server.service}"
INSTALL_SERVICE="${LOUPE_SERVER_INSTALL_SERVICE:-1}"
ENV_PATH="${LOUPE_SERVER_ENV_PATH:-/etc/loupe/loupe-server.env}"
REMOTE_TMP="${LOUPE_SERVER_REMOTE_TMP:-/tmp/loupe-server-deploy.$$}"

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
	local name="$1"
	if [ -n "${!name+x}" ]; then
		printf '%s=' "$name"
		quote_systemd_env "${!name}"
		printf '\n'
	fi
}

build_env_file() {
	tmp_env="$(mktemp)"
	if [ -n "${LOUPE_SERVER_ENV_FILE_LOCAL:-}" ]; then
		cp "$LOUPE_SERVER_ENV_FILE_LOCAL" "$tmp_env"
		return 0
	fi

	{
		printf '# Managed by contrib/deploy-server.sh\n'
		for name in \
			RUST_LOG \
			LOUPE_LOG_JSON \
			LOUPE_CONFIG \
			LOUPE_BIND \
			LOUPE_DB \
			LOUPE_SERVER_CERT \
			LOUPE_SERVER_KEY \
			LOUPE_CA_CERT \
			LOUPE_CA_KEY \
			LOUPE_MASTER_KEY \
			LOUPE_MASTER_KEY_FILE \
			LOUPE_REQUIRE_APPROVAL_DEFAULT
		do
			write_env_var "$name"
		done
		for name in ${LOUPE_SERVER_EXTRA_ENV_VARS:-}; do
			write_env_var "$name"
		done
	} >"$tmp_env"
}

should_write_env() {
	if [ -n "${LOUPE_SERVER_WRITE_ENV:-}" ]; then
		[ "$LOUPE_SERVER_WRITE_ENV" = "1" ]
		return
	fi
	if [ -n "${LOUPE_SERVER_ENV_FILE_LOCAL:-}" ] || [ -n "${LOUPE_SERVER_EXTRA_ENV_VARS:-}" ]; then
		return 0
	fi
	for name in \
		RUST_LOG \
		LOUPE_LOG_JSON \
		LOUPE_CONFIG \
		LOUPE_BIND \
		LOUPE_DB \
		LOUPE_SERVER_CERT \
		LOUPE_SERVER_KEY \
		LOUPE_CA_CERT \
		LOUPE_CA_KEY \
		LOUPE_MASTER_KEY \
		LOUPE_MASTER_KEY_FILE \
		LOUPE_REQUIRE_APPROVAL_DEFAULT
	do
		if [ -n "${!name+x}" ]; then
			return 0
		fi
	done
	return 1
}

echo "==> Building loupe-server"
cargo build --release -p loupe-server
test -x "$BINARY"
echo "==> Binary size: $(du -h "$BINARY" | cut -f1)"

write_env=0
if should_write_env; then
	build_env_file
	write_env=1
fi

echo "==> Uploading loupe-server to $SSH_TARGET"
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

echo "==> loupe-server deployed"
