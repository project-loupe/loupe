#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
	echo "error: run as root or with sudo" >&2
	exit 1
fi

apt-get update
apt-get install -y --no-install-recommends ca-certificates podman

install -d -m 0755 /etc/loupe-container /usr/local/lib/loupe-container
install -d -o 10001 -g 10001 -m 0700 /var/lib/loupe-container/server
install -d -o 10002 -g 10002 -m 0700 /var/cache/loupe-worker-container
