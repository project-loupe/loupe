#!/usr/bin/env bash
set -euo pipefail

# Root helper for contrib/deploy-server.sh.
#
# Reads base64-encoded secret environment values on stdin, injects them
# into systemd's runtime manager environment, restarts loupe-server, then
# removes them from the manager environment unless --keep-manager-env is
# set.
#
# Input format, one line per value:
#   NAME=base64(value)
#
# Supported input names:
#   LOUPE_SERVER_CERT_PEM
#   LOUPE_SERVER_KEY_PEM
#   LOUPE_CA_CERT_PEM
#   LOUPE_CA_KEY_PEM
#   LOUPE_MASTER_KEY
#
# PEM input values are installed into systemd as *_PEM_B64 variables so
# the manager environment stays single-line. The daemon decodes them at
# startup.

service_name="loupe-server.service"
restart=0
keep_manager_env=0
status_lines=20

usage() {
	cat >&2 <<'EOF'
usage: loupe-server-runtime-secrets [options]

Options:
  --service NAME          systemd unit to restart (default: loupe-server.service)
  --restart               restart the service after setting runtime env
  --keep-manager-env      leave secret values in systemd manager env
  --status-lines N        status lines to print after restart (default: 20)
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--service)
			service_name="${2:?--service requires a value}"
			shift 2
			;;
		--restart)
			restart=1
			shift
			;;
		--keep-manager-env)
			keep_manager_env=1
			shift
			;;
		--status-lines)
			status_lines="${2:?--status-lines requires a value}"
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "error: unknown option: $1" >&2
			usage
			exit 2
			;;
	esac
done

if [ "$(id -u)" -ne 0 ]; then
	echo "error: loupe-server-runtime-secrets must run as root" >&2
	exit 1
fi

systemd_env_names=""

cleanup_manager_env() {
	if [ "$keep_manager_env" -eq 0 ]; then
		for name in $systemd_env_names; do
			systemctl unset-environment "$name" >/dev/null 2>&1 || true
		done
	fi
}
trap cleanup_manager_env EXIT

decode_value() {
	printf '%s' "$1" | base64 -d
}

set_runtime_env() {
	local name="$1"
	local encoded="$2"
	local value

	value="$(decode_value "$encoded")"
	case "$name" in
		LOUPE_MASTER_KEY)
			if ! printf '%s' "$value" | grep -Eq '^[0-9a-fA-F]{64}$'; then
				echo "error: LOUPE_MASTER_KEY must be exactly 64 hex characters" >&2
				exit 2
			fi
			;;
		LOUPE_SERVER_CERT_PEM|LOUPE_SERVER_KEY_PEM|LOUPE_CA_CERT_PEM|LOUPE_CA_KEY_PEM)
			if ! printf '%s' "$value" | grep -q -- '-----BEGIN '; then
				echo "error: $name does not look like PEM content" >&2
				exit 2
			fi
			name="${name}_B64"
			value="$encoded"
			;;
		*)
			echo "error: unsupported runtime env var: $name" >&2
			exit 2
			;;
	esac
	systemctl set-environment "$name=$value"
	systemd_env_names="$systemd_env_names $name"
}

while IFS= read -r line; do
	[ -n "$line" ] || continue
	name="${line%%=*}"
	encoded="${line#*=}"
	if [ "$name" = "$line" ] || [ -z "$encoded" ]; then
		echo "error: missing base64 value for $name" >&2
		exit 2
	fi
	set_runtime_env "$name" "$encoded"
done

if [ "$restart" -eq 1 ]; then
	systemctl restart "$service_name"
	cleanup_manager_env
	systemctl --no-pager --lines="$status_lines" status "$service_name"
fi
