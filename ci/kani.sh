#!/usr/bin/env bash
# CBMC can take tens of gigabytes on an unbounded harness, and several
# Kani runs at once can exhaust a host. This wrapper: takes one of
# LOUPE_KANI_SLOTS machine-wide slots (default and maximum 2), so at most that many
# Kani runs exist at once, across every project that points its lock
# directory at the same place; caps the address space of everything it
# spawns (default and maximum 12 GiB per run, so two runs fit beside builds); runs
# one harness per cargo invocation so a failure names its harness;
# applies a per-harness timeout; and writes verdicts under LOUPE_LOCAL.
#
#   ci/kani.sh -p <crate> [--exact --harness kani::<name>]  [--mem-gb N] [--timeout S]
#   ci/kani.sh --workspace
set -eu
cd "$(dirname "$0")/.."
. ci/env.sh
. ci/process.sh
# Every harness needs its own group, even under a continuous campaign, so a
# timeout cannot leave solvers running alongside the next harness. Our traps
# clean that group on campaign shutdown; finish before the parent's 5s grace.
if [[ ${LOUPE_KANI_MANAGED:-0} == 1 ]]; then child_grace_ticks=20; fi
MEM_GB=${LOUPE_KANI_MEM_GB:-12}
SLOTS=${LOUPE_KANI_SLOTS:-2}
TIMEOUT=${LOUPE_KANI_TIMEOUT:-1800}
ARGS=""
while [ $# -gt 0 ]; do
	case "$1" in
	--mem-gb) MEM_GB=$2; shift 2 ;;
	--timeout) TIMEOUT=$2; shift 2 ;;
	*) ARGS="$ARGS $1"; shift ;;
	esac
done
positive_integer LOUPE_KANI_MEM_GB "$MEM_GB"
positive_integer LOUPE_KANI_SLOTS "$SLOTS"
positive_integer LOUPE_KANI_TIMEOUT "$TIMEOUT"
# Overrides may tighten these limits, never raise them. Match the small
# allowed values directly so oversized numeric strings cannot overflow.
case "$SLOTS" in
1|2) ;;
*) echo "LOUPE_KANI_SLOTS must not exceed 2" >&2; exit 2 ;;
esac
case "$MEM_GB" in
[1-9]|1[0-2]) ;;
*) echo "Kani memory must not exceed 12 GiB" >&2; exit 2 ;;
esac
# Slot 0 shares the plain lock name so single-lock callers also count
# against the limit. LOUPE_KANI_LOCK_DIR lets several projects
# on one host share the slots.
LOCK_DIR="${LOUPE_KANI_LOCK_DIR:-$LOUPE_LOCK_DIR}"
LOCK_BASE="$LOCK_DIR/kani.lock"
LOG_DIR="$LOUPE_LOCAL/kani-logs"
mkdir -p "$LOG_DIR" "$LOCK_DIR"
command -v cargo-kani >/dev/null 2>&1 || { echo "kani not installed (cargo install --locked kani-verifier && cargo kani setup)"; exit 2; }
# Take a free slot; wait rather than fail, so queued runs proceed.
slot_file() { if [ "$1" -eq 0 ]; then echo "$LOCK_BASE"; else echo "$LOCK_BASE.$1"; fi; }
while :; do
	i=0; got=""
	while [ "$i" -lt "$SLOTS" ]; do
		exec 9>"$(slot_file "$i")"
		if flock -n 9; then got=$i; break; fi
		exec 9>&-
		i=$((i + 1))
	done
	[ -n "$got" ] && break
	sleep 5
done
# Address-space cap for this shell and every child, including cbmc.
ulimit -v $((MEM_GB * 1024 * 1024))
# Enumerate harnesses per crate from its kani/mod.rs (cargo kani has
# no listing that takes -p), as crate:name pairs, so each runs in its
# own bounded invocation scoped to its crate and a failure names it.
case "$ARGS" in
*--workspace*) CRATES=$(for d in crates/loupe-*/kani; do [ -d "$d" ] && basename "$(dirname "$d")"; done) ;;
*) CRATES=$(echo "$ARGS" | tr ' ' '\n' | sed -n '/^-p$/{n;p}') ;;
esac
harnesses_of() {
	awk '/#\[kani::proof\]/ { want = 1 }
		want && match($0, /fn [A-Za-z0-9_]+/) { print substr($0, RSTART + 3, RLENGTH - 3); want = 0 }' "crates/$1/kani/mod.rs"
}
LIST=$(for c in $CRATES; do [ -f "crates/$c/kani/mod.rs" ] || continue; harnesses_of "$c" | sed "s/^/$c:/"; done)
# Known no-verdict harnesses (ci/kani-no-verdict.txt) are skipped
# unless LOUPE_KANI_ALL=1; an entry naming no harness is an error.
NOVERDICT=ci/kani-no-verdict.txt
if [ -f "$NOVERDICT" ]; then
	grep -vE '^[[:space:]]*(#|$)' "$NOVERDICT" | while read -r c h; do
		[ -f "crates/$c/kani/mod.rs" ] && harnesses_of "$c" | grep -qx "$h" ||
			{ echo "$NOVERDICT names no harness: $c $h"; exit 1; }
	done || exit 2
fi
no_verdict() { [ -f "$NOVERDICT" ] && grep -qE "^$1[[:space:]]+$2([[:space:]]|\$)" "$NOVERDICT"; }
# A caller that names its own harness gets exactly that one run; adding
# our own --harness on top would make cargo kani run both. Callers
# should pass `--exact --harness kani::<name>` for the same reason as
# below.
case " $ARGS " in *" --harness "*) LIST="__all__" ;; esac
# Name the log after the requested harness; the process id keeps two
# runs that start in the same second (one queued behind the other)
# from writing the same file.
NAMED=$(echo "$ARGS" | tr ' ' '\n' | sed -n '/^--harness$/{n;p}' | tr '\n:' '+_' | sed 's/+$//')
[ -n "$LIST" ] || LIST="__all__"
STAMP=$(date +%Y%m%d-%H%M%S)
SUMMARY="$LOG_DIR/summary-$STAMP-$$.log"
rc=0
for entry in $LIST; do
	# --exact with the module path: plain --harness matches substrings,
	# so `strip` would also run `strip_never_panics_and_shrinks`.
	if [ "$entry" = "__all__" ]; then
		RUN="$ARGS"; name=${NAMED:-all}
	else
		crate=${entry%%:*}; h=${entry#*:}; name="$crate::$h"
		if [ "${LOUPE_KANI_ALL:-0}" != 1 ] && no_verdict "$crate" "$h"; then
			echo "$name SKIPPED (known no verdict; see ci/kani-no-verdict.txt)" | tee -a "$SUMMARY"
			continue
		fi
		RUN="-p $crate --exact --harness kani::$h"
	fi
	start=$(date +%s)
	log="$LOG_DIR/$STAMP-$$-$(echo "$name" | tr ':' '_').log"
	set +e
	# RUN contains the wrapper's whitespace-separated Cargo arguments.
	# shellcheck disable=SC2086
	# Enable explicit per-proof stubs, including panic sentinels proving
	# expensive processing is unreachable before an admission check.
	run_child timeout -k 30 --foreground "$TIMEOUT" cargo kani -Z stubbing $RUN > "$log" 2>&1
	status=$?
	set -e
	# Tell the three ways a harness can fail apart: they need different
	# remedies (lower the bound, or fix the code).
	if [ "$status" -eq 124 ]; then
		rc=1; verdict="TIMEOUT after ${TIMEOUT}s (bound too large)"
	# A real counterexample is listed under "Failed Checks:" and must
	# never be hidden behind another label, so it is checked first.
	elif grep -q 'Failed Checks:' "$log"; then
		rc=1; verdict="FAILED: counterexample or unwinding assertion; see $log"
	# CBMC says "Out of memory" when symbolic execution runs out and
	# "Solver ran out of memory" when the solver does; it then also
	# prints VERIFICATION:- FAILED, without a Failed Checks list.
	elif grep -qi 'out of memory\|std::bad_alloc' "$log"; then
		rc=1; verdict="OUT OF MEMORY at the ${MEM_GB} GB cap (bound too large)"
	elif grep -qE '^VERIFICATION:[[:space:]]*-?[[:space:]]*FAILED([[:space:]]|$)' "$log"; then
		rc=1; verdict="FAILED: counterexample or unwinding assertion; see $log"
	elif [ "$status" -eq 0 ] && grep -qE '^VERIFICATION:[[:space:]]*-?[[:space:]]*SUCCESSFUL[[:space:]]*$' "$log"; then
		# Kani can report SUCCESSFUL even when every cover is unreachable.
		# Require a nonempty set of satisfied witnesses for every invocation.
		if awk '
			$1 == "**" && $3 == "of" && $5 == "cover" && $6 == "properties" && $7 == "satisfied" {
				seen = 1
				if ($2 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/ || $4 == 0 || $2 != $4) bad = 1
			}
			END { exit (!seen || bad) }
		' "$log"; then
			verdict="VERIFICATION:- SUCCESSFUL"
		else
			rc=1; verdict="FAILED: missing or unsatisfied cover properties; see $log"
		fi
	elif [ "$status" -eq 0 ]; then
		rc=1; verdict="ERROR (exit 0, no successful verification verdict); see $log"
	else
		rc=1; verdict="ERROR (exit $status, build or tool failure); see $log"
	fi
	echo "$name $verdict $(( $(date +%s) - start ))s" | tee -a "$SUMMARY"
done
echo "summary: $SUMMARY"
exit $rc
