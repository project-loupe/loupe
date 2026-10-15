#!/usr/bin/env bash
# Takes a machine-wide lock so one campaign runs at a time beside a
# Kani run, caps the fuzzer's RSS and the wall time, and runs libFuzzer
# through cargo-fuzz.
#
#   ci/fuzz.sh <target> [seconds]      (from any worktree)
#
# <target> is a runner name such as `core_text_bounded_target`. Seconds
# default to 120. Crashes land in fuzz/runners/artifacts/.
set -euo pipefail
cd "$(dirname "$0")/.."
. ci/env.sh
. ci/process.sh
TARGET=${1:?usage: ci/fuzz.sh target [seconds]}
SECS=${2:-120}
positive_integer seconds "$SECS"
LOCK="${LOUPE_FUZZ_LOCK:-$LOUPE_LOCK_DIR/fuzz.lock}"
mkdir -p "$(dirname "$LOCK")"
exec 9>"$LOCK"
echo "waiting for the fuzz lock" >&2
flock 9
CORPUS=$(mktemp -d)
trap 'stop_child; rm -rf "$CORPUS"' EXIT
SEEDS="fuzz/test_cases/${TARGET%_target}"
[ -d "$SEEDS" ] && cp -r "$SEEDS"/. "$CORPUS"/
cd fuzz/runners
export CARGO_PROFILE_RELEASE_LTO=false RUSTFLAGS="--cfg=fuzzing"
run_child timeout -k 30 --foreground $((SECS + 600)) rustup run nightly cargo fuzz run --fuzz-dir . -s none \
	--features libfuzzer_fuzz "$TARGET" "$CORPUS" -- \
	-max_total_time="$SECS" -rss_limit_mb=2048 -artifact_prefix=./artifacts/
