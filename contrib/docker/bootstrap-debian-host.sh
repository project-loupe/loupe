#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ] || [[ "$1" != server && "$1" != worker ]]; then
	echo "usage: bootstrap-debian-host.sh server|worker" >&2
	exit 2
fi
host_role="$1"

if [ "$(id -u)" -ne 0 ]; then
	echo "error: run as root or with sudo" >&2
	exit 1
fi

packages=(ca-certificates podman)
if [ "$host_role" = worker ]; then
	packages+=(kmod)
fi
apt-get update
apt-get install -y --no-install-recommends "${packages[@]}"

if [ "$host_role" = worker ]; then
	install -d -m 0755 /etc/modules-load.d
	printf 'tun\nnf_tables\nnf_conntrack\n' >/etc/modules-load.d/loupe-worker.conf
	for module in tun nf_tables nf_conntrack; do
		modprobe "$module" 2>/dev/null || true
	done
fi

install -d -m 0755 /etc/loupe-container /usr/local/lib/loupe-container
if [ "$host_role" = server ]; then
	install -d -o 10001 -g 10001 -m 0700 /var/lib/loupe-container/server
else
	install -d -o 10002 -g 10002 -m 0700 /var/cache/loupe-worker-container
fi
