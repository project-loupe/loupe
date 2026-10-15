#!/bin/sh
# Regression checks for generator output and fail-closed corpus replay.
# Uses a private copy so missing-seed fixtures never touch the real corpus.
set -eu
cd "$(dirname "$0")"
CASE=${1:-all}
SCRATCH=$(mktemp -d /tmp/loupe-fuzz-harness-test.XXXXXX)
trap 'rm -rf "$SCRATCH"' EXIT HUP INT TERM
cp -R . "$SCRATCH/fuzz"
# Preserve workspace inheritance and product path dependencies in the copy.
cp ../Cargo.toml "$SCRATCH/Cargo.toml"
ln -s "$(cd ../crates && pwd)" "$SCRATCH/crates"
# The fixture embeds its manifest directory in the runner. A shared product
# target directory can otherwise reuse that binary after the fixture is gone.
export CARGO_TARGET_DIR="${LOUPE_HARNESS_TARGET_DIR:-${CARGO_TARGET_DIR:-/tmp/cargo-target-loupe-harness-tests}/harness-selftest}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-6}"
export RUSTFLAGS=--cfg=fuzzing
check() {
	case "$1" in
	header)
		(cd "$SCRATCH/fuzz/src/bin" && sh ./gen_target.sh)
		cc -x c -fsyntax-only "$SCRATCH/fuzz/targets.h"
		;;
	stale)
		cp "$SCRATCH/fuzz/runners/src/bin/smoke_target.rs" "$SCRATCH/fuzz/runners/src/bin/obsolete_target.rs"
		(cd "$SCRATCH/fuzz/src/bin" && sh ./gen_target.sh)
		[ ! -e "$SCRATCH/fuzz/runners/src/bin/obsolete_target.rs" ] || {
			echo 'generator retained obsolete target' >&2; exit 1;
		}
		;;
	missing)
		# Cargo can reuse a copied path package's fingerprint across scratch
		# directories; rebuild this runner so its embedded corpus path is current.
		touch "$SCRATCH/fuzz/runners/src/bin/smoke_target.rs"
		cargo test --manifest-path "$SCRATCH/fuzz/runners/Cargo.toml" --features stdin_fuzz --bin smoke_target > "$SCRATCH/replay.log" 2>&1 || { cat "$SCRATCH/replay.log"; exit 1; }
		mv "$SCRATCH/fuzz/test_cases/smoke" "$SCRATCH/saved-seeds"
		if cargo test --manifest-path "$SCRATCH/fuzz/runners/Cargo.toml" --features stdin_fuzz --bin smoke_target > "$SCRATCH/replay.log" 2>&1; then
			echo 'replay accepted a missing seed directory' >&2; exit 1
		fi
		grep -q 'could not read seed directory' "$SCRATCH/replay.log" || { cat "$SCRATCH/replay.log"; exit 1; }
		mv "$SCRATCH/saved-seeds" "$SCRATCH/fuzz/test_cases/smoke"
		;;
	*) echo "unknown harness test: $1" >&2; exit 2 ;;
	esac
}
if [ "$CASE" = all ]; then
	for test in header stale missing; do check "$test"; done
else
	check "$CASE"
fi
