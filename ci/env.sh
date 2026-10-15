# shellcheck shell=sh
# Sourced by the ci/ scripts. Keeps build output out of the working
# tree (target directories grow to gigabytes per branch) and gives
# each branch its own, so parallel worktrees do not collide. Anything
# the caller already set wins.
if [ -z "${CARGO_TARGET_DIR:-}" ]; then
	branch=${LOUPE_BUILD_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}
	branch=$(printf '%s' "$branch" | tr '/ ' '--')
	CARGO_TARGET_DIR="/tmp/cargo-target-loupe-${LOUPE_BUILD_KIND:+$LOUPE_BUILD_KIND-}${branch:-detached}"
	export CARGO_TARGET_DIR
fi
# Local, git-ignored state for the long-running tools (continuous fuzz
# corpus, Kani logs, lock files). Several projects on one host may
# point this at one directory to share logs and corpus files. Locks live elsewhere.
: "${LOUPE_LOCAL:=$(git rev-parse --show-toplevel)/.local}"
export LOUPE_LOCAL
: "${LOUPE_LOCK_DIR:=/tmp/loupe-locks-$(id -u)}"
export LOUPE_LOCK_DIR
# Bound compiler concurrency even on hosts with hundreds of CPUs.
: "${CARGO_BUILD_JOBS:=6}"
case "$CARGO_BUILD_JOBS" in
''|*[!0-9]*|0) echo "CARGO_BUILD_JOBS must be a positive integer" >&2; exit 2 ;;
esac
if [ "$CARGO_BUILD_JOBS" -gt 6 ]; then CARGO_BUILD_JOBS=6; fi
export CARGO_BUILD_JOBS
