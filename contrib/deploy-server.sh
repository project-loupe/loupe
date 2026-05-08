#!/usr/bin/env bash
set -euo pipefail

# Build and deploy loupe-server from this checkout to one remote host.
#
# What this does:
#   1. `cargo build --release -p loupe-server`
#   2. `scp` the non-secret binary/unit/env/helper files to the host.
#   3. Run narrowly-scoped `sudo install ...` commands on the host.
#   4. Stream secret values from local env vars over SSH stdin to a
#      root helper, which injects TLS PEMs and LOUPE_MASTER_KEY through
#      systemd runtime env.
#   5. Restart `loupe-server.service`.
#
# First-time host prep still needs root once:
#   sudo useradd --system --home /var/lib/loupe --shell /usr/sbin/nologin loupe
#   sudo install -d -o loupe -g loupe -m 0700 /var/lib/loupe
#   sudo install -d -m 0755 /opt/loupe/bin /etc/loupe
#   sudo visudo -f /etc/sudoers.d/loupe-server-deploy
#
# Secret inputs are env vars on the deployment machine, not files:
#   LOUPE_MASTER_KEY=<64 hex chars>
#   LOUPE_SERVER_CERT_PEM=<server cert PEM>
#   LOUPE_SERVER_KEY_PEM=<server key PEM>
#   LOUPE_CA_CERT_PEM=<CA cert PEM>
#   LOUPE_CA_KEY_PEM=<CA key PEM>
#
# The PEM values and LOUPE_MASTER_KEY are streamed over SSH stdin into
# systemd's runtime manager environment for the explicit restart. They
# are never written to /etc/loupe/loupe-server.env.
#
# Minimal use, keeping an already-installed service/env file:
#   LOUPE_SERVER_SSH=deploy@server-host \
#   LOUPE_SERVER_INSTALL_SERVICE=0 \
#   LOUPE_SERVER_WRITE_ENV=0 \
#     contrib/deploy-server.sh
#
# Install/update the service and generate `/etc/loupe/loupe-server.env`
# from local non-secret environment variables plus runtime secret paths:
#   LOUPE_SERVER_SSH=deploy@server-host \
#   LOUPE_CONFIG=/var/lib/loupe/config.toml \
#   LOUPE_MASTER_KEY="$LOUPE_MASTER_KEY_FROM_SECRET_MANAGER" \
#   LOUPE_SERVER_CERT_PEM="$LOUPE_SERVER_CERT_PEM" \
#   LOUPE_SERVER_KEY_PEM="$LOUPE_SERVER_KEY_PEM" \
#   LOUPE_CA_CERT_PEM="$LOUPE_CA_CERT_PEM" \
#   LOUPE_CA_KEY_PEM="$LOUPE_CA_KEY_PEM" \
#     contrib/deploy-server.sh
#
# Or provide the exact non-secret env file to upload:
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
#   LOUPE_SERVER_RUNTIME_HELPER_REMOTE=/usr/local/sbin/loupe-server-runtime-secrets
#   LOUPE_SERVER_INSTALL_RUNTIME_HELPER=1
#   LOUPE_SERVER_KEEP_SYSTEMD_ENV=0
#
# If LOUPE_SERVER_KEEP_SYSTEMD_ENV=0 (default), runtime env values are
# unset from systemd's manager environment immediately after restart.
# That keeps secrets out of persistent host state, but an automatic
# systemd restart after a crash will need this deploy/restart path again.
#
# If LOUPE_SERVER_ENV_FILE_LOCAL is unset, the script writes an env file
# from the non-secret LOUPE_* vars below when any of them are present:
#   RUST_LOG LOUPE_LOG_JSON LOUPE_CONFIG LOUPE_BIND LOUPE_DB
#   LOUPE_SERVER_CERT LOUPE_SERVER_KEY LOUPE_CA_CERT LOUPE_CA_KEY
#   LOUPE_MASTER_KEY_FILE LOUPE_REQUIRE_APPROVAL_DEFAULT
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
RUNTIME_HELPER_FILE="${LOUPE_SERVER_RUNTIME_HELPER_FILE:-contrib/loupe-server-runtime-secrets.sh}"
RUNTIME_HELPER_REMOTE="${LOUPE_SERVER_RUNTIME_HELPER_REMOTE:-/usr/local/sbin/loupe-server-runtime-secrets}"
INSTALL_RUNTIME_HELPER="${LOUPE_SERVER_INSTALL_RUNTIME_HELPER:-1}"
KEEP_SYSTEMD_ENV="${LOUPE_SERVER_KEEP_SYSTEMD_ENV:-0}"

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

have_server_pem_secrets() {
	secret_set LOUPE_SERVER_CERT_PEM ||
		secret_set LOUPE_SERVER_KEY_PEM ||
		secret_set LOUPE_CA_CERT_PEM ||
		secret_set LOUPE_CA_KEY_PEM
}

have_runtime_secrets() {
	have_server_pem_secrets || secret_set LOUPE_MASTER_KEY
}

require_runtime_secret_shape() {
	local missing=""
	if have_server_pem_secrets; then
		for name in \
			LOUPE_SERVER_CERT_PEM \
			LOUPE_SERVER_KEY_PEM \
			LOUPE_CA_CERT_PEM \
			LOUPE_CA_KEY_PEM
		do
			if ! secret_set "$name"; then
				missing="$missing $name"
			fi
		done
	fi
	if [ -n "$missing" ]; then
		echo "error: when any server PEM env var is set, all are required; missing:$missing" >&2
		exit 1
	fi
	if secret_set LOUPE_MASTER_KEY &&
		! printf '%s' "$LOUPE_MASTER_KEY" | grep -Eq '^[0-9a-fA-F]{64}$'; then
		echo "error: LOUPE_MASTER_KEY must be exactly 64 hex characters" >&2
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
	local name="$1"
	if [ -n "${!name+x}" ]; then
		printf '%s=' "$name"
		quote_systemd_env "${!name}"
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
			LOUPE_DB
		do
			write_env_var "$name"
		done

		if have_server_pem_secrets; then
			:
		else
			for name in \
				LOUPE_SERVER_CERT \
				LOUPE_SERVER_KEY \
				LOUPE_CA_CERT \
				LOUPE_CA_KEY
			do
				write_env_var "$name"
			done
		fi

		for name in \
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
	if [ -n "${LOUPE_SERVER_ENV_FILE_LOCAL:-}" ] ||
		[ -n "${LOUPE_SERVER_EXTRA_ENV_VARS:-}" ] ||
		have_runtime_secrets; then
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
		LOUPE_MASTER_KEY_FILE \
		LOUPE_REQUIRE_APPROVAL_DEFAULT
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
	if have_server_pem_secrets; then
		for name in \
			LOUPE_SERVER_CERT_PEM \
			LOUPE_SERVER_KEY_PEM \
			LOUPE_CA_CERT_PEM \
			LOUPE_CA_KEY_PEM
		do
			printf '%s=%s\n' "$name" "$(b64_env_value "$name")"
		done
	fi
	if secret_set LOUPE_MASTER_KEY; then
		printf 'LOUPE_MASTER_KEY=%s\n' "$(b64_env_value LOUPE_MASTER_KEY)"
	fi
}

require_runtime_secret_shape

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
if [ "$INSTALL_RUNTIME_HELPER" = "1" ]; then
	scp "$RUNTIME_HELPER_FILE" "${SSH_TARGET}:${REMOTE_TMP}.runtime-helper"
fi

echo "==> Installing loupe-server artifacts"
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

echo "==> loupe-server deployed"
