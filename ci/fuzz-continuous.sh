#!/usr/bin/env bash
# One low-priority, CPU-pinned campaign per repository. Short campaigns use a
# separate lock. Corpus and rotation survive restarts; failures are never clean.
set -euo pipefail
SELF=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
cd "$(dirname "$SELF")/.."
BRANCH=${1:-main}
export LOUPE_BUILD_KIND=fuzz-continuous LOUPE_BUILD_BRANCH=$BRANCH
. ci/env.sh
. ci/process.sh
ROOT=$LOUPE_LOCAL/fuzz-continuous
WT=$LOUPE_LOCAL/wt/fuzz-$BRANCH
SECS=${LOUPE_FUZZ_SLICE:-300}
RETRY=${LOUPE_FUZZ_RETRY:-30}
positive_integer LOUPE_FUZZ_SLICE "$SECS"
positive_integer LOUPE_FUZZ_RETRY "$RETRY"
export CARGO_BUILD_JOBS=1 CARGO_PROFILE_RELEASE_LTO=false RUSTFLAGS=--cfg=fuzzing
CPU=${LOUPE_FUZZ_CPU:-$(($(nproc) - 1))}
if [[ ${LOUPE_FUZZ_PINNED:-0} != 1 ]]; then
	LOUPE_FUZZ_PINNED=1 exec taskset -c "$CPU" nice -n 19 "$SELF" "$@"
fi
campaign_lock fuzz "$BRANCH"
mkdir -p "$ROOT/corpus" "$ROOT/crashes" "$LOUPE_LOCAL/wt"
[[ -d $WT ]] || git worktree add --detach "$WT" "$BRANCH" >/dev/null
while :; do
	if ! (cd "$WT" && git checkout -q --detach "$BRANCH"); then
		echo "$(date -Is) ERROR checkout $BRANCH" >> "$ROOT/FAILED.log"
		run_child sleep "$RETRY"
		continue
	fi
	rev=$(cd "$WT" && git rev-parse --short HEAD)
	mapfile -t targets < <(sed -n 's/^GEN_TEST \([a-z0-9_]*\).*/\1/p' "$WT/fuzz/src/bin/gen_target.sh" | sed '/^smoke$/d')
	if (( ${#targets[@]} == 0 )); then
		echo "$(date -Is) $rev ERROR no fuzz targets" >> "$ROOT/FAILED.log"
		run_child sleep "$RETRY"
		continue
	fi
	next=$(cat "$ROOT/next" 2>/dev/null || true)
	start=0
	for i in "${!targets[@]}"; do
		if [[ ${targets[i]} == "$next" ]]; then start=$i; break; fi
	done
	for ((offset=0; offset<${#targets[@]}; offset++)); do
		i=$(((start + offset) % ${#targets[@]}))
		t=${targets[i]}
		echo "$t" > "$ROOT/next"
		[[ $(cd "$WT" && git rev-parse "$BRANCH") == $(cd "$WT" && git rev-parse HEAD) ]] || break
		corpus=$ROOT/corpus/$t
		crashes=$ROOT/crashes/$t
		mkdir -p "$corpus" "$crashes"
		if [[ -d $WT/fuzz/test_cases/$t ]]; then
			# GNU cp --update=none is newer than several supported hosts.
			for seed in "$WT/fuzz/test_cases/$t"/*; do
				[[ -f $seed ]] || continue
				[[ -e $corpus/${seed##*/} ]] || cp "$seed" "$corpus/"
			done
		fi
		log=$ROOT/last-$t.log
		status=0
		pushd "$WT/fuzz/runners" >/dev/null
		run_child timeout -k 30 --foreground "$((SECS + 900))" \
			rustup run nightly cargo fuzz run --fuzz-dir . -s none \
			--features libfuzzer_fuzz "${t}_target" "$corpus" -- \
			-max_total_time="$SECS" -rss_limit_mb=2048 -artifact_prefix="$crashes/" \
			> "$log" 2>&1 || status=$?
		popd >/dev/null
		found=0
		for artifact in "$crashes"/*; do
			[[ -f $artifact ]] || continue
			if ! grep -qF " $artifact" "$ROOT/FOUND.log" 2>/dev/null; then
				echo "$(date -Is) $rev $t $artifact" >> "$ROOT/FOUND.log"
				found=1
			fi
		done
		if (( found )); then
			result=FOUND
		elif (( status == 0 )); then
			result=CLEAN
		elif (( status == 124 || status == 137 )); then
			result=TIMEOUT
			echo "$(date -Is) $rev $t TIMEOUT exit $status log $log" >> "$ROOT/FAILED.log"
		else
			echo "$(date -Is) $rev $t ERROR exit $status log $log" >> "$ROOT/FAILED.log"
			# Preserve this target and retry after refreshing the branch tip.
			run_child sleep "$RETRY"
			break
		fi
		echo "$(date -Is) $rev $t $result exit $status log $log" >> "$ROOT/progress.log"
		echo "${targets[$(((i + 1) % ${#targets[@]}))]}" > "$ROOT/next"
		# Finds and early timeouts may return immediately; avoid a hot loop.
		if (( status != 0 )); then run_child sleep "$RETRY"; fi
	done
done
