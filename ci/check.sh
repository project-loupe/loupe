#!/bin/sh
# The gate. `ci/check.sh` runs what every commit must pass; `--full`
# adds the slow parts that run per section of work and in CI.
#
# The derived-Debug gate is enabled as the source-labelled holders land.
set -eu
cd "$(dirname "$0")/.."
. ci/env.sh
. ci/gates.sh
FULL=0; [ "${1:-}" = "--full" ] && FULL=1
export CARGO_TERM_COLOR=always
# Scratch space private to this run, so parallel worktrees cannot race.
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT

say() { printf '\n== %s\n' "$*"; }

say "fmt (nightly)"
rustup run nightly cargo fmt --all -- --check
(cd fuzz && rustup run nightly cargo fmt --all -- --check)

say "no production environment forwarding"
gate_no_forward_env . || exit 1

say "clippy (stable, warnings are errors)"
cargo clippy --workspace --all-targets --all-features -- -D warnings
# The runner binaries have a main only when a backend feature is chosen.
(cd fuzz && RUSTFLAGS="--cfg=fuzzing" cargo clippy --workspace --all-targets --features loupe-fuzz-runners/stdin_fuzz -- -D warnings)

say "per-crate checks (no feature unification)"
# A workspace build unifies features; checking each crate alone shows
# that its library builds without the features its tests enable.
command -v jq >/dev/null 2>&1 || { echo "jq is required for workspace checks" >&2; exit 2; }
cargo metadata --format-version 1 --no-deps > "$SCRATCH/metadata.json"
jq -r '.workspace_members as $members | .packages[] |
	select(.id as $id | $members | index($id)) |
	[.name, (any(.targets[]; .kind | index("lib") != null))] | @tsv' \
	"$SCRATCH/metadata.json" > "$SCRATCH/packages"
while read -r m has_lib; do
	if [ "$has_lib" = true ]; then cargo check --quiet -p "$m" --lib; fi
	cargo check --quiet -p "$m" --all-targets
	cargo check --quiet -p "$m" --all-targets --all-features
done < "$SCRATCH/packages"

say "unsafe code only where listed"
# Minting a provenance label is `unsafe` (loupe-provenance practice P3):
# the compiler finds every site, and this decides where they may be.
gate_unsafe_allow . || { echo "unsafe code outside ci/unsafe-allow.txt"; exit 1; }
gate_lints ./Cargo.toml ./fuzz/Cargo.toml || { echo "a package does not deny unsafe code"; exit 1; }
gate_no_tool_deps . || exit 1
gate_sources . || { echo "a source the checks cannot see"; exit 1; }
# The gates above must reject every known bypass form on every check.
ci/gate-selftest.sh

say "no derived Debug on content-holding types without a reason"
# Types that may hold agent, repository, sandbox or secret bytes
# implement Debug by hand. A derive is allowed only with
# `// debug-ok: <reason>` on the line above it (or on the derive line),
# stating why the type holds no such content.
if [ -n "${LOUPE_DEBUG_GATE_CRATES:-}" ]; then
	bad=0
	for c in $LOUPE_DEBUG_GATE_CRATES; do
		[ -d "crates/$c/src" ] || continue
		if find "crates/$c/src" -name '*.rs' -exec awk '
			/derive\([^)]*Debug/ && $0 !~ /debug-ok:/ && prev !~ /debug-ok:/ { print FILENAME ":" FNR ": " $0; found=1 }
			{ prev=$0 }
			END { exit found ? 0 : 1 }' {} + ; then bad=1; fi
	done
	[ "$bad" -eq 0 ] || { echo "derived Debug without a debug-ok reason"; exit 1; }
else
	echo "not enabled yet (set LOUPE_DEBUG_GATE_CRATES to the crates under the rule)"
fi

say "docs build without warnings"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --quiet

say "unit tests (stable)"
cargo test --workspace --all-targets

say "compile-fail error codes (nightly doctests)"
# Stable rustdoc ignores the error code on a `compile_fail,E....`
# fence, so a snippet that fails for an unrelated reason (a renamed
# type, a broken path) would pass silently. Nightly checks the code.
rustup run nightly cargo test --quiet --workspace --doc

if [ "$FULL" -eq 1 ]; then
	say "fuzz harness regression checks"
	sh fuzz/test-harness.sh
	say "fuzz corpus replay"
	(cd fuzz && RUSTFLAGS="--cfg=fuzzing" cargo test --lib && RUSTFLAGS="--cfg=fuzzing" cargo test --manifest-path runners/Cargo.toml --features stdin_fuzz --bins)
	# A pre-commit check compares current files with regeneration, so staged
	# additions and edits pass when they are already generated correctly.
	mkdir -p "$SCRATCH/generated"
	cp -a fuzz/runners/src/bin "$SCRATCH/generated/bin"
	cp -a fuzz/targets.h "$SCRATCH/generated/targets.h"
	if ! (cd fuzz/src/bin && ./gen_target.sh) ||
		! diff -r "$SCRATCH/generated/bin" fuzz/runners/src/bin ||
		! cmp -s "$SCRATCH/generated/targets.h" fuzz/targets.h; then
		echo "generated fuzz targets are stale"
		exit 1
	fi
	if [ "${CI:-false}" = true ]; then
		# CI also verifies the checked-in candidate, including staged changes
		# and untracked generated files that plain git diff would miss.
		git diff --exit-code HEAD -- fuzz/runners/src/bin fuzz/targets.h
		[ -z "$(git ls-files --others --exclude-standard -- fuzz/runners/src/bin fuzz/targets.h)" ] ||
			{ echo "generated fuzz targets are not committed"; exit 1; }
	fi

	say "kani harnesses"
	if [ "${LOUPE_KANI:-1}" = 0 ]; then
		echo "skipped (LOUPE_KANI=0): the caller runs ci/kani.sh separately"
	elif command -v cargo-kani >/dev/null 2>&1; then
		ci/kani.sh --workspace
	else
		echo "kani not installed; required for --full (see README.md)" >&2
		exit 2
	fi

	say "integration tests (bubblewrap, pinned CLIs)"
	# These skip themselves when bwrap or a CLI is absent; the gate
	# still runs them so the skips are visible in the output.
	cargo test --workspace --all-targets -- --ignored
fi

say "ok"
