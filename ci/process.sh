# shellcheck shell=bash
# Every managed command has its own session/process group. Killing a cargo
# parent alone leaves compiler or solver descendants running and holding locks.
active_child=
child_grace_ticks=50
stop_child() {
	[[ -n $active_child ]] || return 0
	local child=$active_child i
	kill -TERM -- "-$child" 2>/dev/null || true
	for ((i=0; i<child_grace_ticks; i++)); do
		kill -0 -- "-$child" 2>/dev/null || break
		sleep 0.1
	done
	kill -KILL -- "-$child" 2>/dev/null || true
	wait "$child" 2>/dev/null || true
	active_child=
}
trap 'exit 130' INT
trap 'exit 143' TERM
trap stop_child EXIT

run_child() {
	local status=0
	setsid "$@" &
	active_child=$!
	wait "$active_child" || status=$?
	# Also clean up descendants left behind by a command that already exited.
	stop_child
	return "$status"
}

positive_integer() {
	if [[ ! $2 =~ ^[1-9][0-9]*$ ]]; then
		echo "$1 must be a positive integer" >&2
		exit 2
	fi
}

campaign_lock() {
	local kind=$1 branch=$2 common repo_key branch_key
	common=$(git rev-parse --path-format=absolute --git-common-dir)
	repo_key=$(printf '%s' "$common" | cksum | cut -d ' ' -f 1)
	branch_key=$(printf '%s' "$branch" | cksum | cut -d ' ' -f 1)
	mkdir -p "$LOUPE_LOCK_DIR"
	if [[ $kind == fuzz ]]; then
		exec 8> "$LOUPE_LOCK_DIR/fuzz-continuous-$repo_key.lock"
		flock -n 8 || { echo 'continuous fuzz campaign already running' >&2; exit 3; }
	fi
	exec 9> "$LOUPE_LOCK_DIR/$kind-continuous-$repo_key-$branch_key.lock"
	flock -n 9 || { echo "$kind campaign already running for $branch" >&2; exit 3; }
}
