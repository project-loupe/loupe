#!/usr/bin/env sh
set -eu

export_secret() {
	name="$1"
	value="$2"

	case "$name" in
		LOUPE_MASTER_KEY | \
		LOUPE_SERVER_CERT_PEM | LOUPE_SERVER_CERT_PEM_B64 | \
		LOUPE_SERVER_KEY_PEM | LOUPE_SERVER_KEY_PEM_B64 | \
		LOUPE_CA_CERT_PEM | LOUPE_CA_CERT_PEM_B64 | \
		LOUPE_CA_KEY_PEM | LOUPE_CA_KEY_PEM_B64 | \
		LOUPE_ADMIN_CERT_PEM | LOUPE_ADMIN_CERT_PEM_B64 | \
		LOUPE_ADMIN_KEY_PEM | LOUPE_ADMIN_KEY_PEM_B64 | \
		LOUPE_SERVER_URL | \
		LOUPE_WORKER_CA_CERT_PEM | LOUPE_WORKER_CA_CERT_PEM_B64 | \
		LOUPE_WORKER_CERT_PEM | LOUPE_WORKER_CERT_PEM_B64 | \
		LOUPE_WORKER_KEY_PEM | LOUPE_WORKER_KEY_PEM_B64 | \
		ANTHROPIC_API_KEY | OPENAI_API_KEY | CODEX_API_KEY)
			;;
		*)
			echo "error: unsupported secret env variable: $name" >&2
			exit 64
			;;
	esac

	export "$name=$value"
}

secret_env_file="${LOUPE_SECRET_ENV_FILE:-/run/loupe/secrets.env}"

if [ -f "$secret_env_file" ]; then
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
			'' | \#*) continue ;;
		esac
		name="${line%%=*}"
		value="${line#*=}"
		if [ "$name" = "$line" ] || [ -z "$value" ]; then
			echo "error: malformed secret env line for $name" >&2
			exit 64
		fi
		export_secret "$name" "$value"
	done <"$secret_env_file"
fi

exec "$@"
