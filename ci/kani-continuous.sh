#!/usr/bin/env bash
# Recheck a branch on each new tip. Kani's wrapper owns memory and slot limits;
# this loop owns the session, worktree, status records and retry interval.
set -euo pipefail
SELF=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
cd "$(dirname "$SELF")/.."
BRANCH=${1:-main}
export LOUPE_BUILD_KIND=kani-continuous LOUPE_BUILD_BRANCH=$BRANCH
. ci/env.sh
. ci/process.sh
ROOT=$LOUPE_LOCAL/kani-continuous
WT=$LOUPE_LOCAL/wt/kani-$BRANCH
POLL=${LOUPE_KANI_POLL:-120}
positive_integer LOUPE_KANI_POLL "$POLL"
campaign_lock kani "$BRANCH"
mkdir -p "$ROOT" "$LOUPE_LOCAL/wt"
[[ -d $WT ]] || git worktree add --detach "$WT" "$BRANCH" >/dev/null
last=
while :; do
	tip=$(git rev-parse "$BRANCH")
	if [[ $tip == "$last" ]]; then
		run_child sleep "$POLL"
		continue
	fi
	if ! (cd "$WT" && git checkout -q --detach "$tip"); then
		echo "$(date -Is) ERROR checkout $BRANCH" >> "$ROOT/FAILED.log"
		run_child sleep "$POLL"
		continue
	fi
	rev=$(cd "$WT" && git rev-parse --short HEAD)
	start=$(date +%s)
	log=$ROOT/last-$rev.log
	status=0
	pushd "$WT" >/dev/null
	# The wrapper cleans each harness group before starting the next and traps
	# campaign shutdown to terminate that group before our own grace expires.
	run_child env LOUPE_KANI_MANAGED=1 nice -n 10 ci/kani.sh --workspace > "$log" 2>&1 || status=$?
	popd >/dev/null
	grep -E ' (VERIFICATION|TIMEOUT|FAILED|OUT OF MEMORY|ERROR|SKIPPED)' "$log" |
		sed "s/^/$(date -Is) $rev /" >> "$ROOT/results.log" || true
	grep -E ' (FAILED|TIMEOUT|OUT OF MEMORY|ERROR)' "$log" |
		sed "s/^/$(date -Is) $rev /" >> "$ROOT/FAILED.log" || true
	if (( status != 0 )) && ! grep -qE ' (TIMEOUT|FAILED|OUT OF MEMORY|ERROR)' "$log"; then
		echo "$(date -Is) $rev ERROR wrapper exit $status log $log" >> "$ROOT/FAILED.log"
	fi
	echo "$(date -Is) $rev whole workspace exit $status $(( $(date +%s) - start ))s log $log" >> "$ROOT/results.log"
	# Successful tips sleep until changed; unsuccessful tips retry after polling.
	if (( status == 0 )); then last=$tip; fi
	run_child sleep "$POLL"
done
