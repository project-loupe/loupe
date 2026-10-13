# shellcheck shell=sh
# Gate checks shared by ci/check.sh and ci/gate-selftest.sh. Sourced;
# each function prints what it rejects and returns non-zero.
#
# Unchecked provenance construction requires unsafe code. These lexical
# checks keep unsafe code and lint exceptions in explicitly listed files.
# Deliberately obscured macro or name resolution still requires code review.

GATES_DIR=$(cd "$(dirname "${GATES_SH:-ci/gates.sh}")" 2>/dev/null && pwd)

# Every production crate is covered by default; an environment variable cannot
# narrow the set. Derives in literal examples and comments are not Rust items.
gate_derived_debug() {
	root=$1
	debug_rc=0
	debug_tmp=$(mktemp -d)
	for debug_file in $(rust_files "$root/crates"); do
		case "$debug_file" in */src/*.rs) ;; *) continue ;; esac
		: > "$debug_tmp/comments"
		awk -v line_comments="$debug_tmp/comments" -f "$GATES_DIR/strip-rust.awk" "$root/crates/$debug_file" > "$debug_tmp/code"
		if ! awk -v line_comments="$debug_tmp/comments" -f "$GATES_DIR/derived-debug.awk" "$debug_tmp/code" "$root/crates/$debug_file"; then
			debug_rc=1
		fi
	done
	rm -r "$debug_tmp"
	return "$debug_rc"
}

# Rust source files under $1, relative paths, sorted.
rust_files() {
	(cd "$1" && find . \( -name target -o -name .local -o -name .git \) -prune -o -name '*.rs' -type f -print | sed 's|^\./||' | sort)
}

# Host environment forwarding is forbidden in production. This lexical gate
# catches ordinary calls and references;
# deliberately obscured macro/name resolution remains a code-review concern.
gate_no_forward_env() {
	root=$1
	rc=0
	for f in $(rust_files "$root/crates"); do
		case "$f" in */src/*.rs) ;; *) continue ;; esac
		if awk -f "$GATES_DIR/strip-rust.awk" "$root/crates/$f" | awk '
			{ source = source " " $0 }
			END {
				# Skip only explicitly test-gated items, balancing their body so
				# production items after a test module are still inspected.
				while (match(source, /#[[:space:]]*\[[[:space:]]*cfg[[:space:]]*\([[:space:]]*test[[:space:]]*\)[[:space:]]*\]/)) {
					production = production substr(source, 1, RSTART - 1)
					source = substr(source, RSTART + RLENGTH)
					depth = 0; opened = 0
					for (i = 1; i <= length(source); i++) {
						c = substr(source, i, 1)
						if (c == "{") { depth++; opened = 1 }
						if (c == "}" && --depth == 0 && opened) break
						if (c == ";" && !opened) break
					}
					source = substr(source, i + 1)
				}
				production = production source
				gsub(/fn[[:space:]]+forward_env[[:space:]]*\(/, "fn forwarding_definition(", production)
				print production
			}' | grep -qE '(^|[^[:alnum:]_])forward_env[[:space:]]*\(|::[[:space:]]*forward_env([^[:alnum:]_]|$)'; then
			echo "$f: production environment forwarding is forbidden"
			rc=1
		fi
	done
	return "$rc"
}

# Files that can carry unsafe code: every .rs file whose code (comments,
# strings and character literals stripped) contains the `unsafe`
# keyword, so a macro body that expands to `unsafe` counts where it is
# written; every .rs file that names `unsafe_code` other than to forbid
# or deny it; and every manifest or cargo config (`.cargo/config.toml`
# and the legacy `.cargo/config`) that names the lint other than at deny
# or forbid, rustflags included. One path per line, relative to $1.
unsafe_code_files() {
	root=$1
	rust_files "$root" | while read -r f; do
		code=$(awk -f "$GATES_DIR/strip-rust.awk" "$root/$f")
		if printf '%s\n' "$code" | grep -qE '(^|[^A-Za-z0-9_])unsafe([^A-Za-z0-9_]|$)'; then echo "$f"; continue; fi
		if printf '%s\n' "$code" | sed -E 's/(forbid|deny)[[:space:]]*\([[:space:]]*unsafe_code[[:space:]]*\)//g' | grep -q 'unsafe_code'; then echo "$f"; fi
	done
	(cd "$root" && find . \( -name target -o -name .local -o -name .git \) -prune -o \( -name '*.toml' -o -path '*/.cargo/config' \) -type f -print | sed 's|^\./||' | sort | while read -r f; do
		if sed -E '/^[[:space:]]*#/d; s/unsafe_code[[:space:]]*=[[:space:]]*"(deny|forbid)"//g' "$f" | grep -q 'unsafe_code'; then echo "$f"; fi
	done)
}

# Every file that can carry unsafe code must be listed, with a reason,
# in $2 (default ci/unsafe-allow.txt); a listed file that no longer does
# is stale.
gate_unsafe_allow() {
	root=$1; list=${2:-$1/ci/unsafe-allow.txt}
	tmp=$(mktemp -d)
	unsafe_code_files "$root" | sort -u > "$tmp/found"
	grep -v '^[[:space:]]*#' "$list" | grep -v '^[[:space:]]*$' | awk '{print $1}' | sort > "$tmp/listed"
	rc=0
	missing=$(grep -vxF -f "$tmp/listed" "$tmp/found" || true)
	stale=$(grep -vxF -f "$tmp/found" "$tmp/listed" || true)
	noreason=$(grep -v '^[[:space:]]*#' "$list" | awk 'NF == 1 {print $1}')
	if [ -n "$missing" ]; then echo "$missing" | sed 's|^|not in ci/unsafe-allow.txt: |'; rc=1; fi
	if [ -n "$stale" ]; then echo "$stale" | sed 's|^|stale entry in ci/unsafe-allow.txt: |'; rc=1; fi
	if [ -n "$noreason" ]; then echo "$noreason" | sed 's|^|entry without a reason: |'; rc=1; fi
	rm -rf "$tmp"
	return $rc
}

# The value of `unsafe_code` in a TOML table ($2, e.g. `lints.rust` or
# `workspace.lints.rust`) of manifest $1, or nothing.
lint_level() {
	awk -v want="[$2]" '
		/^[[:space:]]*\[/ { gsub(/[[:space:]]/, ""); inside = ($0 == want); next }
		inside && /^[[:space:]]*unsafe_code[[:space:]]*=/ {
			v = $0; sub(/^[^=]*=[[:space:]]*/, "", v); gsub(/"/, "", v); gsub(/[[:space:]].*/, "", v); print v; exit }' "$1"
}

# Whether manifest $1 has `[lints]` with `workspace = true`.
inherits_lints() {
	awk '/^[[:space:]]*\[/ { inside = ($0 ~ /^[[:space:]]*\[lints\][[:space:]]*$/); next }
		inside && /^[[:space:]]*workspace[[:space:]]*=[[:space:]]*true/ { found = 1 }
		END { exit found ? 0 : 1 }' "$1"
}

# Every package of the workspaces whose root manifests are given must
# lint unsafe code at deny or forbid: by inheriting a workspace table
# that does, or by its own `[lints.rust]`. Fails closed when cargo
# metadata fails.
gate_lints() {
	rc=0
	for ws in "$@"; do
		if ! meta=$(cargo metadata --quiet --offline --format-version 1 --no-deps --manifest-path "$ws" 2>/dev/null); then
			echo "cargo metadata failed for $ws"; rc=1; continue
		fi
		wslevel=$(lint_level "$ws" workspace.lints.rust)
		for m in $(printf '%s' "$meta" | grep -o '"manifest_path":"[^"]*"' | sed 's/^"manifest_path":"//; s/"$//'); do
			own=$(lint_level "$m" lints.rust)
			if inherits_lints "$m"; then level=$wslevel; else level=$own; fi
			case $level in
			deny | forbid) ;;
			*) echo "$m does not lint unsafe code at deny or forbid (level: ${level:-none})"; rc=1 ;;
			esac
		done
	done
	return $rc
}

# No product crate (the workspace at $1) depends on the fuzz harness,
# which mints labels freely.
gate_no_tool_deps() {
	# Metadata includes dependencies for other platforms that a host build
	# may not have fetched. Keep downloads enabled and expose Cargo errors.
	if ! meta=$(cargo metadata --quiet --format-version 1 --manifest-path "$1/Cargo.toml"); then
		echo "cargo metadata failed for $1"; return 1
	fi
	bad=$(printf '%s' "$meta" | grep -oE '"name":"(loupe-fuzz|loupe-fuzz-runners)"' | sort -u)
	if [ -n "$bad" ]; then echo "a product crate depends on a tool crate: $bad"; return 1; fi
	return 0
}

# Every file the compiler sees is a file the checks above scan: an
# `include!` or `#[path]` must name a .rs file, and a build script in a
# product crate, `build.rs` or whatever a manifest's `build = "..."`
# names, must be listed in ci/build-scripts.txt.
gate_sources() {
	root=$1; rc=0
	odd=$(cd "$root" && rust_files . | while read -r f; do
		awk -f "$GATES_DIR/strip-rust.awk" "$f" | grep -q 'include!' && echo "$f: include! (use a module)"
		grep -oE '#\[path[[:space:]]*=[[:space:]]*"[^"]*"' "$f" | grep -vE '\.rs"$' | sed "s|^|$f: |"
	done)
	if [ -n "$odd" ]; then echo "$odd"; rc=1; fi
	listed="$root/ci/build-scripts.txt"
	scripts=$(cd "$root" && {
		find crates -name build.rs -type f 2>/dev/null
		find crates -name Cargo.toml -type f 2>/dev/null | while read -r m; do
			sed -nE 's/^[[:space:]]*build[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' "$m" | sed "s|^|$(dirname "$m")/|"
		done
	} | sort -u)
	for b in $scripts; do
		grep -qxF "$b" "$listed" 2>/dev/null || { echo "$b: build script not in ci/build-scripts.txt"; rc=1; }
	done
	return $rc
}
