#!/usr/bin/env bash
# Behavioral checks use disposable repositories and fake compiler/fuzzer tools.
# Each case runs in a separate invocation; subshell setup cannot affect another.
# shellcheck disable=SC2031
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SOURCE=${LOUPE_TOOLING_SOURCE:-$SCRIPT_DIR}
TEST_ROOT=$(mktemp -d /tmp/loupe-tooling-selftest.XXXXXX)
PIDS=()
cleanup() {
	for pid in "${PIDS[@]}"; do
		kill -TERM -- "-$pid" 2>/dev/null || true
		kill -KILL -- "-$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	done
	rm -rf "$TEST_ROOT"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
wait_for() {
	local i
	for ((i=0; i<150; i++)); do
		if "$@"; then return 0; fi
		sleep 0.02
	done
	fail "timed out waiting for $*"
}
fixture() {
	CASE=$TEST_ROOT/$1
	mkdir -p "$CASE/repo" "$CASE/bin" "$CASE/state" "$CASE/local" "$CASE/locks"
	cp -a "$SOURCE" "$CASE/repo/ci"
	# These tests exercise check.sh's orchestration with fake compiler tools.
	# The real compiler bypass probes run separately in ci/gate-selftest.sh.
	# shellcheck disable=SC2016 # The generated script expands its own FIXTURE.
	printf '#!/bin/sh\n: > "$FIXTURE/state/minting-selftest"\n' > "$CASE/repo/ci/gate-selftest.sh"
	printf '#!/bin/sh\nexit 0\n' > "$CASE/repo/ci/production-lint-selftest.sh"
	printf '# No unsafe files in this fixture.\n' > "$CASE/repo/ci/unsafe-allow.txt"
	printf '# No build scripts in this fixture.\n' > "$CASE/repo/ci/build-scripts.txt"
	printf '# No no-verdict harnesses in this fixture.\n' > "$CASE/repo/ci/kani-no-verdict.txt"
	mkdir -p "$CASE/repo/crates/loupe-worker/src"
	mkdir -p "$CASE/repo/fuzz/src/bin" "$CASE/repo/fuzz/runners" "$CASE/repo/fuzz/test_cases/alpha"
	for manifest in "$CASE/repo/Cargo.toml" "$CASE/repo/fuzz/Cargo.toml"; do
		printf '[workspace.lints.rust]\nunsafe_code = "deny"\n' > "$manifest"
	done
	for member in loupe-cli loupe-core loupe-unrelated; do
		mkdir -p "$CASE/repo/crates/$member"
		printf '[lints]\nworkspace = true\n' > "$CASE/repo/crates/$member/Cargo.toml"
	done
	printf 'GEN_TEST alpha\nGEN_TEST beta\n' > "$CASE/repo/fuzz/src/bin/gen_target.sh"
	: > "$CASE/repo/fuzz/test_cases/alpha/empty"
	cat > "$CASE/bin/git" <<'STUB'
#!/usr/bin/env bash
set -eu
if [[ ${1:-} == -C ]]; then cd "$2"; shift 2; fi
case "$1 $2" in
'rev-parse --abbrev-ref') echo main ;;
'rev-parse --show-toplevel') echo "$FIXTURE/repo" ;;
'rev-parse --git-common-dir') echo "$FIXTURE/repo/.git" ;;
'rev-parse --path-format=absolute') echo "$FIXTURE/repo/.git" ;;
'rev-parse --short') echo abc123 ;;
'rev-parse '* ) echo abc123 ;;
'worktree add') dest=$4; mkdir -p "$dest"; cp -a "$FIXTURE/repo/." "$dest/" ;;
'checkout '* ) : ;;
'status '* ) if [[ ${STAGED_GENERATED:-0} == 1 ]]; then echo 'A  runners/src/bin/alpha_target.rs'; fi ;;
'diff '* ) [[ ${CI_GENERATED_DIFF:-0} == 0 ]] ;;
'ls-files '* ) : ;;
*) echo "unexpected git call $*" >&2; exit 2 ;;
esac
STUB
	cat > "$CASE/bin/rustup" <<'STUB'
#!/usr/bin/env bash
set -eu
shift 2
exec "$@"
STUB
	cat > "$CASE/bin/taskset" <<'STUB'
#!/usr/bin/env bash
shift 2
exec "$@"
STUB
	cat > "$CASE/bin/nice" <<'STUB'
#!/usr/bin/env bash
shift 2
exec "$@"
STUB
	printf '#!/bin/sh\nexit 0\n' > "$CASE/bin/cargo-kani"
	cat > "$CASE/bin/cargo" <<'STUB'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$FIXTURE/state/cargo-args"
if [[ $1 == metadata ]]; then
	if [[ ${METADATA_FAIL:-0} != 0 ]]; then
		echo 'fixture dependency resolution failed' >&2
		exit 17
	fi
	if [[ " $* " != *' --no-deps '* ]]; then
		if [[ ${METADATA_UNCACHED:-0} == 1 && " $* " == *' --offline '* ]]; then
			echo 'fixture platform dependency needs a download' >&2
			exit 17
		fi
		if [[ -n ${METADATA_TOOL:-} ]]; then
			printf '{"packages":[{"name":"%s"}]}\n' "$METADATA_TOOL"
			exit 0
		fi
	fi
	printf '{"packages":[{"id":"a","name":"loupe-cli","manifest_path":"%s/repo/crates/loupe-cli/Cargo.toml","targets":[{"kind":["bin"]}]},{"id":"b","name":"loupe-core","manifest_path":"%s/repo/crates/loupe-core/Cargo.toml","targets":[{"kind":["lib"]}]},{"id":"outside","name":"loupe-unrelated","manifest_path":"%s/repo/crates/loupe-unrelated/Cargo.toml","targets":[{"kind":["lib"]}]}],"workspace_members":["a","b"]}\n' "$FIXTURE" "$FIXTURE" "$FIXTURE"
	exit 0
fi
if [[ $1 == check && "$*" == *'loupe-cli --lib'* ]]; then exit 18; fi
[[ $1 == fuzz || $1 == kani ]] || exit 0
printf '%s\n' "$CARGO_TARGET_DIR" >> "$FIXTURE/state/targets"
printf '%s\n' "$CARGO_BUILD_JOBS" >> "$FIXTURE/state/jobs"
ulimit -v >> "$FIXTURE/state/memory"
case ${FUZZ_MODE:-clean} in
hold)
	printf '%s\n' "$$" > "$FIXTURE/state/child"
	# Descendant remains in the fuzzer's process group.
	sleep 30 &
	grandchild=$!
	printf '%s\n' "$grandchild" > "$FIXTURE/state/grandchild"
	trap 'kill "$grandchild" 2>/dev/null || true; wait "$grandchild" 2>/dev/null || true; exit 0' TERM INT
	wait "$grandchild"
	;;
fail) exit 23 ;;
find)
	for arg in "$@"; do
		case "$arg" in -artifact_prefix=*) mkdir -p "${arg#*=}"; : > "${arg#*=}crash-one";; esac
	done
	exit 77 ;;
timeout) exit 124 ;;
no_verdict) echo '0 harnesses selected' ;;
failed_verdict) echo 'VERIFICATION:- FAILED' ;;
success_then_failure) printf 'VERIFICATION:- SUCCESSFUL\nVERIFICATION:- FAILED\n' ;;
no_covers) echo 'VERIFICATION:- SUCCESSFUL' ;;
unsatisfied_cover) printf ' ** 1 of 2 cover properties satisfied\nVERIFICATION:- SUCCESSFUL\n' ;;
unreachable_cover) printf 'Check 1: sample.cover.1\n - Status: UNREACHABLE\n ** 0 of 1 cover properties satisfied\nVERIFICATION:- SUCCESSFUL\n' ;;
empty_covers) printf ' ** 0 of 0 cover properties satisfied\nVERIFICATION:- SUCCESSFUL\n' ;;
stubborn)
	trap '' TERM INT
	printf '%s\n' "$$" > "$FIXTURE/state/child"
	sleep 30 &
	printf '%s\n' "$!" > "$FIXTURE/state/grandchild"
	wait
	;;
leaking_harness)
	if [[ $* == *kani::first* ]]; then
		sleep 30 &
		printf '%s\n' "$!" > "$FIXTURE/state/leftover"
		wait
	else
		old=$(cat "$FIXTURE/state/leftover")
		state=$(ps -o stat= -p "$old" || true)
		case "$state" in ''|Z*) : ;; *) : > "$FIXTURE/state/overlap" ;; esac
		: > "$FIXTURE/state/second-ran"
		echo 'VERIFICATION:- SUCCESSFUL'
	fi
	;;
clean) sleep 0.1; printf ' ** 2 of 2 cover properties satisfied\nVERIFICATION:- SUCCESSFUL\n' ;;
esac
STUB
	chmod +x "$CASE/bin/"* "$CASE/repo/ci/"*.sh
	export FIXTURE=$CASE PATH="$CASE/bin:$ORIGINAL_PATH"
	export LOUPE_LOCAL=$CASE/local LOUPE_LOCK_DIR=$CASE/locks
	export LOUPE_FUZZ_CPU=0 LOUPE_FUZZ_SLICE=1 LOUPE_FUZZ_RETRY=1 LOUPE_KANI_POLL=1
	export CARGO_BUILD_JOBS=1
	unset CARGO_TARGET_DIR LOUPE_FUZZ_PINNED LOUPE_KANI_MANAGED
}
start_fuzz() {
	setsid "$CASE/repo/ci/fuzz-continuous.sh" main > "$CASE/output" 2>&1 &
	PID=$!; PIDS+=("$PID")
}
start_kani() {
	mkdir -p "$CASE/repo/crates/loupe-core/kani"
	printf '#[kani::proof]\nfn sample() {}\n' > "$CASE/repo/crates/loupe-core/kani/mod.rs"
	setsid "$CASE/repo/ci/kani-continuous.sh" main > "$CASE/output" 2>&1 &
	PID=$!; PIDS+=("$PID")
}
generation_fixture() {
	mkdir -p "$CASE/repo/fuzz/runners/src/bin"
	printf 'current runner\n' > "$CASE/repo/fuzz/runners/src/bin/alpha_target.rs"
	printf 'current header\n' > "$CASE/repo/fuzz/targets.h"
	printf '#!/bin/sh\nexit 0\n' > "$CASE/repo/fuzz/test-harness.sh"
	cat > "$CASE/repo/fuzz/src/bin/gen_target.sh" <<'STUB'
#!/bin/sh
case "${GENERATION_MODE:-unchanged}" in
edit) printf 'regenerated runner\n' > ../../runners/src/bin/alpha_target.rs ;;
add) printf 'new runner\n' > ../../runners/src/bin/beta_target.rs ;;
delete) rm ../../runners/src/bin/alpha_target.rs ;;
header) printf 'regenerated header\n' > ../../targets.h ;;
esac
STUB
	chmod +x "$CASE/repo/fuzz/src/bin/gen_target.sh"
	export LOUPE_KANI=0 CI=false
}
stop_fuzz() {
	kill -TERM "$PID"
	local rc=0
	wait "$PID" || rc=$?
	[[ $rc == 143 || $rc == 0 ]] || fail "unexpected shutdown status $rc"
}
ORIGINAL_PATH=$PATH
case ${1:-all} in
env)
	fixture env
	unset LOUPE_LOCK_DIR
	(cd "$CASE/repo"; . ci/env.sh; [[ ${LOUPE_LOCK_DIR:-} == "/tmp/loupe-locks-$(id -u)" ]]) || fail 'default lock directory is not machine-wide'
	;;
metadata)
	fixture metadata
	(cd "$CASE/repo"; ci/check.sh) > "$CASE/output" 2>&1 || fail 'gate rejected bin-only member'
	grep -q '^check --quiet -p loupe-core --lib$' "$CASE/state/cargo-args" || fail 'library member omitted'
	grep -q '^check --quiet -p loupe-cli --all-targets$' "$CASE/state/cargo-args" || fail 'binary member omitted'
	! grep -q '^check .*loupe-unrelated' "$CASE/state/cargo-args" || fail 'nonmember checked'
	;;
metadata_error)
	fixture metadata_error
	if (cd "$CASE/repo"; METADATA_FAIL=1 ci/check.sh) > "$CASE/output" 2>&1; then fail 'metadata failure passed gate'; fi
	;;
metadata_uncached)
	fixture metadata_uncached
	if ! (cd "$CASE/repo"; . ci/gates.sh; METADATA_UNCACHED=1 gate_no_tool_deps .) > "$CASE/output" 2>&1; then
		cat "$CASE/output"
		fail 'dependency gate rejected an uncached platform dependency'
	fi
	;;
metadata_dependency_error)
	fixture metadata_dependency_error
	if (cd "$CASE/repo"; . ci/gates.sh; METADATA_FAIL=1 gate_no_tool_deps .) > "$CASE/output" 2>&1; then
		fail 'dependency metadata failure passed gate'
	fi
	grep -q 'fixture dependency resolution failed' "$CASE/output" || fail 'dependency metadata diagnostic was hidden'
	;;
metadata_tools)
	fixture metadata_tools
	for tool in loupe-fuzz loupe-fuzz-runners; do
		if (cd "$CASE/repo"; . ci/gates.sh; METADATA_TOOL=$tool gate_no_tool_deps .) > "$CASE/output" 2>&1; then
			fail "dependency gate accepted $tool"
		fi
		grep -q "a product crate depends on a tool crate:.*$tool" "$CASE/output" || fail 'tool dependency failed for an unrelated reason'
	done
	;;
production_lints)
	fixture production_lints
	"$CASE/repo/ci/check.sh" > "$CASE/output" 2>&1 || fail 'production lint fixture rejected'
	production=$(grep '^clippy --workspace --lib --bins --all-features -- ' "$CASE/state/cargo-args" || true)
	[[ -n $production ]] || fail 'production lint pass is missing'
	for lint in unwrap_used expect_used string_slice mem_forget dbg_macro todo unimplemented disallowed_methods; do
		[[ $production == *"-D clippy::$lint"* ]] || fail "production pass omitted $lint"
	done
	grep -q '^clippy --workspace --all-targets --all-features -- -D warnings$' "$CASE/state/cargo-args" || fail 'test lint policy changed'
	;;
minting_default)
	fixture minting_default
	unset LOUPE_GATE_UNSAFE
	"$CASE/repo/ci/check.sh" > "$CASE/output" 2>&1 || fail 'clean minting fixture rejected'
	printf 'pub unsafe fn unlisted() {}\n' > "$CASE/repo/crates/loupe-worker/src/unlisted.rs"
	for setting in unset zero; do
		if [[ $setting == zero ]]; then export LOUPE_GATE_UNSAFE=0; fi
		if "$CASE/repo/ci/check.sh" > "$CASE/output" 2>&1; then
			fail "default gate accepted unlisted unsafe code ($setting)"
		fi
		grep -q 'not in ci/unsafe-allow.txt: crates/loupe-worker/src/unlisted.rs' "$CASE/output" || {
			cat "$CASE/output"
			fail 'minting gate failed for an unrelated reason'
		}
	done
	rm "$CASE/repo/crates/loupe-worker/src/unlisted.rs"
	"$CASE/repo/ci/check.sh" > "$CASE/output" 2>&1 || fail 'clean fixture rejected with legacy opt-out'
	[[ -f $CASE/state/minting-selftest ]] || fail 'compiler bypass self-tests were omitted'
	;;
debug_default)
	fixture debug_default
	unset LOUPE_DEBUG_GATE_CRATES
	"$CASE/repo/ci/check.sh" > "$CASE/output" 2>&1 || fail 'clean debug fixture rejected'
	printf '#[derive(Debug)]\nstruct Payload(String);\n' > "$CASE/repo/crates/loupe-worker/src/lib.rs"
	for setting in unset empty unrelated; do
		case "$setting" in
		empty) export LOUPE_DEBUG_GATE_CRATES='' ;;
		unrelated) export LOUPE_DEBUG_GATE_CRATES=loupe-core ;;
		esac
		if "$CASE/repo/ci/check.sh" > "$CASE/output" 2>&1; then
			fail "default gate accepted unreviewed derived Debug ($setting)"
		fi
		grep -q 'derived Debug without a debug-ok reason' "$CASE/output" || {
			cat "$CASE/output"
			fail 'derived Debug gate failed for an unrelated reason'
		}
	done
	;;
debug_raw_comment_position|debug_block_comment_position)
	fixture "$1"
	case "$1" in
	debug_raw_comment_position)
		cat > "$CASE/repo/crates/loupe-worker/src/lib.rs" <<'RUST'
const TEXT: &str = r#"
// debug-ok: this is still raw-string content"#; // unrelated real comment
#[derive(Debug)]
pub struct Payload(String);
RUST
		;;
	debug_block_comment_position)
		cat > "$CASE/repo/crates/loupe-worker/src/lib.rs" <<'RUST'
/*
// debug-ok: this is still a block comment */ // unrelated real comment
#[derive(Debug)]
pub struct Payload(String);
RUST
		;;
	esac
	if "$CASE/repo/ci/check.sh" > "$CASE/output" 2>&1; then
		fail "gate accepted literal Debug reason with unrelated trailing comment ($1)"
	fi
	grep -q 'derived Debug without a debug-ok reason' "$CASE/output" || {
		cat "$CASE/output"
		fail 'derived Debug gate failed for an unrelated reason'
	}
	;;
debug_multiline)
	fixture debug_multiline
	export LOUPE_DEBUG_GATE_CRATES=loupe-worker
	for form in plain multiline empty_reason string_reason block_reason raw_reason; do
		case "$form" in
		plain) code='#[derive(Debug)]\nstruct Payload(String);' ;;
		multiline) code='#[derive(\n    Clone,\n    Debug,\n)]\nstruct Payload(String);' ;;
		empty_reason) code='// debug-ok:   \n#[derive(Debug)]\nstruct Payload(String);' ;;
		string_reason) code='const TEXT: &str = "// debug-ok: this is not a comment";\n#[derive(Debug)]\nstruct Payload(String);' ;;
		raw_reason) code='const TEXT: &str = r#"\n// debug-ok: this is raw string content"#;\n#[derive(Debug)]\nstruct Payload(String);' ;;
		block_reason) code='/*\n// debug-ok: this is a block comment, not the required line comment */\n#[derive(Debug)]\nstruct Payload(String);' ;;
		esac
		printf '%b\n' "$code" > "$CASE/repo/crates/loupe-worker/src/lib.rs"
		if "$CASE/repo/ci/check.sh" > "$CASE/output" 2>&1; then
			fail "gate accepted unreviewed derived Debug ($form)"
		fi
		grep -q 'derived Debug without a debug-ok reason' "$CASE/output" || {
			cat "$CASE/output"
			fail 'derived Debug gate failed for an unrelated reason'
		}
	done
	cat > "$CASE/repo/crates/loupe-worker/src/lib.rs" <<'RUST'
// A comment mentioning #[derive(Debug)] is not an attribute.
const TEXT: &str = "#[derive(Debug)]";
// debug-ok: a scalar counter contains no input content.
#[derive(
    Clone,
    Debug,
)]
struct Count(u64);
#[derive(Debug)] // debug-ok: closed unit variants contain no input content.
enum Category { One, Two }
RUST
	"$CASE/repo/ci/check.sh" > "$CASE/output" 2>&1 || {
		cat "$CASE/output"
		fail 'reviewed scalars or non-code Debug mentions were rejected'
	}
	;;
forward_env)
	fixture forward_env
	cat > "$CASE/repo/crates/loupe-worker/src/lib.rs" <<'RUST'
impl SandboxBuilder {
    pub fn forward_env(self, name: &str) -> Self { self }
}
// A mention of .forward_env("ignored") is not a call.
const MESSAGE: &str = ".forward_env(\"ignored\")";
#[cfg(test)]
mod tests {
    fn explicit_forwarding() { builder.forward_env("TEST_ONLY"); }
}
fn after_tests() {}
RUST
	"$CASE/repo/ci/check.sh" > "$CASE/output" 2>&1 || fail 'environment-forwarding gate rejected its definition or test call'
	for form in method multiline qualified reference after_tests; do
		case "$form" in
		method) code='fn production() { builder.forward_env("SECRET"); }' ;;
		multiline) code='fn production() { builder.\nforward_env\n("SECRET"); }' ;;
		qualified) code='fn production() { SandboxBuilder::forward_env(builder, "SECRET"); }' ;;
		reference) code='fn production() { let forward = SandboxBuilder::forward_env; forward(builder, "SECRET"); }' ;;
		after_tests) code='#[cfg(test)]\nmod tests { fn test() { let text = "}"; } }\nfn production() { builder.forward_env("SECRET"); }' ;;
		esac
		printf '%b\n' "$code" > "$CASE/repo/crates/loupe-worker/src/caller.rs"
		if "$CASE/repo/ci/check.sh" > "$CASE/output" 2>&1; then
			fail "gate accepted production environment forwarding ($form)"
		fi
		grep -q 'production environment forwarding' "$CASE/output" || {
			cat "$CASE/output"
			fail 'environment-forwarding gate failed for an unrelated reason'
		}
	done
	;;
generated_staged)
	fixture generated_staged
	generation_fixture
	STAGED_GENERATED=1 "$CASE/repo/ci/check.sh" --full > "$CASE/output" 2>&1 || fail 'correct staged generated files rejected'
	;;
generated_changes)
	for mode in edit add delete header; do
		fixture "generated_$mode"
		generation_fixture
		if GENERATION_MODE=$mode "$CASE/repo/ci/check.sh" --full > "$CASE/output" 2>&1; then
			fail "generation $mode went undetected"
		fi
		grep -q 'generated fuzz targets are stale' "$CASE/output" || fail "generation $mode failed for an unrelated reason"
	done
	;;
generated_ci)
	fixture generated_ci
	generation_fixture
	if CI=true CI_GENERATED_DIFF=1 "$CASE/repo/ci/check.sh" --full > "$CASE/output" 2>&1; then
		fail 'CI accepted generated output differing from HEAD'
	fi
	;;
short_lock)
	fixture short_lock
	exec 8> "$LOUPE_LOCK_DIR/fuzz.lock"
	flock 8
	FUZZ_MODE=clean timeout -k 1 0.4 "$CASE/repo/ci/fuzz.sh" alpha_target 1 > "$CASE/output" 2>&1 || true
	[[ ! -f $CASE/state/targets ]] || fail 'short campaign bypassed shared lock'
	;;
kill_after)
	fixture kill_after
	cat > "$CASE/bin/timeout" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$FIXTURE/state/timeout-args"
exit 0
STUB
	chmod +x "$CASE/bin/timeout"
	"$CASE/repo/ci/fuzz.sh" alpha_target 1 > "$CASE/output" 2>&1
	grep -q -- '-k 30' "$CASE/state/timeout-args" || fail 'short fuzz lacks forced kill'
	start_fuzz
	wait_for test -f "$CASE/state/timeout-args"
	sleep 0.1
	grep -q -- '-k 30' "$CASE/state/timeout-args" || fail 'continuous fuzz lacks forced kill'
	;;
target_dir)
	fixture target_dir
	export FUZZ_MODE=hold CARGO_TARGET_DIR=/tmp/loupe-explicit-selftest
	start_fuzz
	wait_for test -f "$CASE/state/targets"
	[[ $(head -1 "$CASE/state/targets") == "$CARGO_TARGET_DIR" ]] || fail 'continuous fuzz overrides target directory'
	stop_fuzz
	;;
default_targets)
	fixture default_targets
	export FUZZ_MODE=hold
	start_fuzz
	wait_for test -s "$CASE/state/targets"
	[[ $(head -1 "$CASE/state/targets") == /tmp/cargo-target-loupe-fuzz-continuous-main ]] || fail 'fuzz default build path is not under /tmp'
	stop_fuzz
	rm "$CASE/state/targets"
	start_kani
	wait_for test -s "$CASE/state/targets"
	[[ $(head -1 "$CASE/state/targets") == /tmp/cargo-target-loupe-kani-continuous-main ]] || fail 'Kani default build path is not under /tmp'
	stop_fuzz
	;;
empty_targets)
	fixture empty_targets
	printf 'GEN_TEST smoke\n' > "$CASE/repo/fuzz/src/bin/gen_target.sh"
	start_fuzz
	wait_for test -s "$LOUPE_LOCAL/fuzz-continuous/FAILED.log"
	grep -q 'ERROR no fuzz targets' "$LOUPE_LOCAL/fuzz-continuous/FAILED.log" || fail 'empty campaign not reported'
	[[ ! -f $CASE/state/targets ]] || fail 'empty campaign ran a target'
	sleep 0.2
	[[ $(wc -l < "$LOUPE_LOCAL/fuzz-continuous/FAILED.log") -le 2 ]] || fail 'empty campaign spins'
	stop_fuzz
	;;
singleton)
	fixture singleton
	export FUZZ_MODE=hold
	start_fuzz
	wait_for test -f "$CASE/state/child"
	first=$PID
	for branch in main another; do
		rc=0
		timeout -k 1 0.5 "$CASE/repo/ci/fuzz-continuous.sh" "$branch" >> "$CASE/duplicate-output" 2>&1 || rc=$?
		[[ $rc == 3 ]] || fail "duplicate campaign on $branch exited $rc instead of 3"
	done
	PID=$first; stop_fuzz
	;;
cleanup)
	fixture cleanup
	export FUZZ_MODE=hold
	start_fuzz
	wait_for test -f "$CASE/state/grandchild"
	child=$(cat "$CASE/state/child"); grandchild=$(cat "$CASE/state/grandchild")
	stop_fuzz
	! kill -0 "$child" 2>/dev/null || fail 'fuzzer survived campaign shutdown'
	! kill -0 "$grandchild" 2>/dev/null || fail 'fuzzer descendant survived campaign shutdown'
	;;
failure)
	fixture failure
	export FUZZ_MODE=fail
	start_fuzz
	wait_for test -s "$LOUPE_LOCAL/fuzz-continuous/FAILED.log"
	grep -q 'ERROR.*exit 23' "$LOUPE_LOCAL/fuzz-continuous/FAILED.log" || fail 'build failure lacks status'
	[[ $(cat "$LOUPE_LOCAL/fuzz-continuous/next") == alpha ]] || fail 'failed build advanced rotation'
	[[ $(wc -l < "$CASE/state/targets") -le 2 ]] || fail 'failed build retries without backoff'
	stop_fuzz
	;;
find)
	fixture find
	export FUZZ_MODE=find
	start_fuzz
	wait_for test -s "$LOUPE_LOCAL/fuzz-continuous/FOUND.log"
	grep -q 'alpha.*crash-one' "$LOUPE_LOCAL/fuzz-continuous/FOUND.log" || fail 'artifact missing target/path'
	stop_fuzz
	;;
timeout)
	fixture timeout
	export FUZZ_MODE=timeout
	start_fuzz
	wait_for test -s "$LOUPE_LOCAL/fuzz-continuous/FAILED.log"
	grep -q 'TIMEOUT' "$LOUPE_LOCAL/fuzz-continuous/FAILED.log" || fail 'timeout misclassified'
	stop_fuzz
	;;
kani)
	fixture kani
	cat > "$CASE/repo/ci/kani.sh" <<'STUB'
#!/usr/bin/env bash
echo "$CARGO_TARGET_DIR" > "$FIXTURE/state/targets"
exit 23
STUB
	export CARGO_TARGET_DIR=/tmp/loupe-kani-explicit-selftest
	setsid "$CASE/repo/ci/kani-continuous.sh" main > "$CASE/output" 2>&1 &
	PID=$!; PIDS+=("$PID")
	wait_for test -s "$CASE/state/targets"
	[[ $(cat "$CASE/state/targets") == "$CARGO_TARGET_DIR" ]] || fail 'continuous Kani overrides target directory'
	wait_for test -s "$LOUPE_LOCAL/kani-continuous/FAILED.log"
	grep -q 'ERROR.*exit 23' "$LOUPE_LOCAL/kani-continuous/FAILED.log" || fail 'silent Kani setup failure'
	stop_fuzz
	;;
kani_failure)
	fixture kani_failure
	printf '#!/bin/sh\nexit 23\n' > "$CASE/repo/ci/kani.sh"
	start_kani
	wait_for test -s "$LOUPE_LOCAL/kani-continuous/FAILED.log"
	grep -q 'ERROR.*exit 23' "$LOUPE_LOCAL/kani-continuous/FAILED.log" || fail 'Kani setup error was not classified'
	stop_fuzz
	;;
kani_cleanup)
	fixture kani_cleanup
	export FUZZ_MODE=hold
	start_kani
	wait_for test -f "$CASE/state/grandchild"
	child=$(cat "$CASE/state/child"); grandchild=$(cat "$CASE/state/grandchild")
	stop_fuzz
	! kill -0 "$child" 2>/dev/null || fail 'Kani child survived campaign shutdown'
	! kill -0 "$grandchild" 2>/dev/null || fail 'Kani descendant survived campaign shutdown'
	;;
kani_singleton)
	fixture kani_singleton
	export FUZZ_MODE=hold
	start_kani
	wait_for test -f "$CASE/state/child"
	rc=0
	timeout -k 1 0.5 "$CASE/repo/ci/kani-continuous.sh" main >> "$CASE/duplicate-output" 2>&1 || rc=$?
	[[ $rc == 3 ]] || fail "duplicate Kani campaign exited $rc instead of 3"
	stop_fuzz
	;;
kani_slots)
	fixture kani_slots
	exec 7> "$LOUPE_LOCK_DIR/kani.lock"
	exec 8> "$LOUPE_LOCK_DIR/kani.lock.1"
	flock 7; flock 8
	FUZZ_MODE=clean timeout -k 1 0.4 "$CASE/repo/ci/kani.sh" -p loupe-core --exact --harness kani::sample > "$CASE/output" 2>&1 || true
	[[ ! -f $CASE/state/targets ]] || fail 'Kani bypassed shared slots'
	;;
kani_slot_cap|kani_memory_cap|kani_memory_arg_cap)
	fixture "$1"
	args=(-p loupe-core --exact --harness kani::sample)
	case $1 in
	kani_slot_cap) export LOUPE_KANI_SLOTS=3 ;;
	kani_memory_cap) export LOUPE_KANI_MEM_GB=13 ;;
	kani_memory_arg_cap) args+=(--mem-gb 13) ;;
	esac
	rc=0
	"$CASE/repo/ci/kani.sh" "${args[@]}" > "$CASE/output" 2>&1 || rc=$?
	[[ $rc == 2 ]] || fail "Kani accepted excessive resource override ($1; exit $rc)"
	[[ ! -f $CASE/state/targets ]] || fail 'Kani spawned a tool above its resource ceiling'
	;;
kani_required)
	fixture kani_required
	generation_fixture
	rm "$CASE/bin/cargo-kani"
	if BASH_ENV='' PATH="$CASE/bin:/usr/bin:/bin" LOUPE_KANI=1 "$CASE/repo/ci/check.sh" --full > "$CASE/output" 2>&1; then
		fail 'full gate accepted a missing required verifier'
	fi
	grep -q 'kani not installed.*required' "$CASE/output" || {
		cat "$CASE/output"
		fail 'missing verifier failed for an unrelated reason'
	}
	;;
kani_lower_limits)
	fixture kani_lower_limits
	LOUPE_KANI_SLOTS=1 LOUPE_KANI_MEM_GB=1 "$CASE/repo/ci/kani.sh" -p loupe-core --exact --harness kani::sample > "$CASE/output" 2>&1 || fail 'Kani rejected lower resource limits'
	[[ $(cat "$CASE/state/memory") == 1048576 ]] || fail 'Kani did not apply lower memory limit'
	;;
kani_stubbing)
	fixture kani_stubbing
	"$CASE/repo/ci/kani.sh" -p loupe-core --exact --harness kani::sample > "$CASE/output" 2>&1
	grep -q '^kani -Z stubbing -p loupe-core --exact --harness kani::sample$' "$CASE/state/cargo-args" ||
		fail 'Kani wrapper omitted explicit proof stubbing support'
	;;
kani_verdict)
	for mode in no_verdict failed_verdict success_then_failure no_covers unsatisfied_cover unreachable_cover empty_covers; do
		fixture "kani_$mode"
		rc=0
		FUZZ_MODE=$mode "$CASE/repo/ci/kani.sh" -p loupe-core --exact --harness kani::sample > "$CASE/output" 2>&1 || rc=$?
		[[ $rc != 0 ]] || fail "Kani accepted exit 0 with $mode"
		grep -qE ' (ERROR|FAILED)' "$CASE/output" || fail "Kani $mode lacks failure summary"
	done
	;;
kani_harness_cleanup)
	fixture kani_harness_cleanup
	mkdir -p "$CASE/repo/crates/loupe-core/kani"
	printf '#[kani::proof]\nfn first() {}\n#[kani::proof]\nfn second() {}\n' > "$CASE/repo/crates/loupe-core/kani/mod.rs"
	FUZZ_MODE=leaking_harness LOUPE_KANI_MANAGED=1 setsid "$CASE/repo/ci/kani.sh" --workspace --timeout 1 > "$CASE/output" 2>&1 &
	PID=$!; PIDS+=("$PID")
	rc=0; wait "$PID" || rc=$?
	[[ $rc != 0 ]] || fail 'timed out first harness reported success'
	[[ -f $CASE/state/second-ran ]] || fail 'second harness did not execute'
	[[ ! -f $CASE/state/overlap ]] || fail 'first harness descendant overlapped second harness'
	;;
kani_cleanup_stubborn)
	fixture kani_cleanup_stubborn
	export FUZZ_MODE=stubborn
	start_kani
	wait_for test -f "$CASE/state/grandchild"
	child=$(cat "$CASE/state/child"); grandchild=$(cat "$CASE/state/grandchild")
	stop_fuzz
	for pid in "$child" "$grandchild"; do
		state=$(ps -o stat= -p "$pid" || true)
		case "$state" in ''|Z*) : ;; *) fail 'TERM-resistant Kani descendant survived campaign shutdown' ;; esac
	done
	;;
all)
	for name in env metadata metadata_error metadata_uncached metadata_dependency_error metadata_tools production_lints minting_default debug_default debug_multiline debug_raw_comment_position debug_block_comment_position forward_env generated_staged generated_changes generated_ci short_lock kill_after target_dir default_targets empty_targets singleton cleanup failure find timeout kani kani_failure kani_cleanup kani_singleton kani_slots kani_slot_cap kani_memory_cap kani_memory_arg_cap kani_required kani_lower_limits kani_stubbing kani_verdict kani_harness_cleanup kani_cleanup_stubborn; do
		"$SCRIPT_DIR/tooling-selftest.sh" "$name"
	done
	;;
*) fail "unknown test $1" ;;
esac
echo "PASS: ${1:-all}"
