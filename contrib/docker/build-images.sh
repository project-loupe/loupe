#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENGINE="${CONTAINER_ENGINE:-}"
if [ -z "$ENGINE" ]; then
	if command -v podman >/dev/null 2>&1; then
		ENGINE=podman
	elif command -v docker >/dev/null 2>&1; then
		ENGINE=docker
	else
		echo "error: install podman or docker, or set CONTAINER_ENGINE" >&2
		exit 127
	fi
fi

TAG="${LOUPE_IMAGE_TAG:-$(git -C "$ROOT" rev-parse --short HEAD)}"
SERVER_IMAGE="${LOUPE_SERVER_IMAGE:-localhost/loupe-server:$TAG}"
WORKER_IMAGE="${LOUPE_WORKER_IMAGE:-localhost/loupe-worker:$TAG}"
DOCKERFILE="${LOUPE_DOCKERFILE:-$ROOT/contrib/docker/Dockerfile}"
RUST_VERSION="${LOUPE_RUST_VERSION:-}"

build_args=()
if [ -n "$RUST_VERSION" ]; then
	build_args+=(--build-arg "RUST_VERSION=$RUST_VERSION")
fi

"$ENGINE" build "${build_args[@]}" -f "$DOCKERFILE" --target loupe-server -t "$SERVER_IMAGE" "$ROOT" >&2
"$ENGINE" build "${build_args[@]}" -f "$DOCKERFILE" --target loupe-worker -t "$WORKER_IMAGE" "$ROOT" >&2

printf 'export LOUPE_SERVER_IMAGE=%q\n' "$SERVER_IMAGE"
printf 'export LOUPE_WORKER_IMAGE=%q\n' "$WORKER_IMAGE"
