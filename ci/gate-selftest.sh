#!/bin/sh
# Unchecked provenance construction, weakened lint settings and hidden source
# paths must fail compilation or the gate, including through aliases and macros.
set -eu
cd "$(dirname "$0")/.."
. ci/env.sh
. ci/gates.sh
ROOT=$(pwd)
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}/gate-selftest"
failures=0
fail() { echo "SELFTEST HOLE: $*"; failures=$((failures + 1)); }

# A one-crate workspace with the project's lints, depending on the real
# crates. $1: extra [dependencies] lines; $2: extra manifest text.
probe() {
	rm -rf "$SCRATCH/ws"; mkdir -p "$SCRATCH/ws/probe/src"
	cat > "$SCRATCH/ws/Cargo.toml" <<EOF
[workspace]
resolver = "3"
members = ["probe"]
[workspace.lints.rust]
unsafe_code = "deny"
EOF
	cat > "$SCRATCH/ws/probe/Cargo.toml" <<EOF
[package]
name = "probe"
version = "0.0.0"
edition = "2024"
publish = false
[lints]
workspace = true
[dependencies]
$1
$2
EOF
}

# Expect `cargo check` of the probe to fail with error code $1.
expect_error() {
	code=$1; what=$2
	if out=$(cargo check --quiet --offline --manifest-path "$SCRATCH/ws/Cargo.toml" 2>&1); then
		fail "$what compiled"
	elif ! printf '%s' "$out" | grep -q "$code"; then
		echo "$out" | head -20; fail "$what failed without $code"
	fi
}

MINT_DEPS="loupe-provenance = { path = \"$ROOT/crates/loupe-provenance\", features = [\"ingress\"] }"

# 1. Minting without `unsafe`: E0133 for every way of naming it.
for form in alias ufcs type_alias turbofish split macro; do
	probe "$MINT_DEPS" ""
	# shellcheck disable=SC2016 # Rust macro metavariables must stay literal.
	case $form in
	alias) body='use loupe_provenance::{Ingress as I, Worker}; pub fn f() -> I<Worker> { I::<Worker>::new() }' ;;
	ufcs) body='use loupe_provenance::{Ingress, Worker}; pub fn f() -> Ingress<Worker> { <Ingress<Worker>>::new() }' ;;
	type_alias) body='use loupe_provenance::{Ingress, Worker}; type T = Ingress<Worker>; pub fn f() -> T { T::new() }' ;;
	turbofish) body='pub fn f() -> loupe_provenance::Ingress<loupe_provenance::Worker> { loupe_provenance::Ingress::<loupe_provenance::Worker>::new() }' ;;
	split) body='use loupe_provenance::{Ingress, Worker};
pub fn f() -> Ingress<Worker> {
    Ingress
        ::<Worker>
        ::new()
}' ;;
	macro) body='use loupe_provenance::{Ingress, Worker};
macro_rules! m { ($t:ty) => { <$t>::new() } }
pub fn f() -> Ingress<Worker> { m!(Ingress<Worker>) }' ;;
	esac
	printf '%s\n' "$body" > "$SCRATCH/ws/probe/src/lib.rs"
	expect_error E0133 "minting ($form)"
done

# 2. Minting inside `unsafe` but without allowing unsafe code: the lint.
probe "$MINT_DEPS" ""
printf '%s\n' 'pub fn f() -> loupe_provenance::Ingress<loupe_provenance::Worker> { unsafe { loupe_provenance::Ingress::new() } }' > "$SCRATCH/ws/probe/src/lib.rs"
expect_error 'unsafe.code' "minting in an unsafe block without allow"

# 3. Allowing unsafe code in a file not on the list: the allow-list gate.
probe "$MINT_DEPS" ""
printf '%s\n' '# empty' > "$SCRATCH/allow.txt"
for variant in plain split expect cfg_attr; do
	case $variant in
	plain) attr='#[allow(unsafe_code)]' ;;
	split) attr='#[allow(
    unsafe_code
)]' ;;
	expect) attr='#[expect(unsafe_code)]' ;;
	cfg_attr) attr='#[cfg_attr(all(), allow(unsafe_code))]' ;;
	esac
	printf '%s\n%s\n' "$attr" 'pub fn f() -> loupe_provenance::Ingress<loupe_provenance::Worker> { unsafe { loupe_provenance::Ingress::new() } }' > "$SCRATCH/ws/probe/src/lib.rs"
	if gate_unsafe_allow "$SCRATCH/ws" "$SCRATCH/allow.txt" > /dev/null; then fail "unlisted allow ($variant) passed the gate"; fi
done
# A manifest that lowers the lint is caught too.
probe "$MINT_DEPS" "[lints.rust]
unsafe_code = \"allow\""
sed -i '/^\[lints\]$/,/^workspace = true$/d' "$SCRATCH/ws/probe/Cargo.toml"
printf '%s\n' 'pub fn f() {}' > "$SCRATCH/ws/probe/src/lib.rs"
if gate_unsafe_allow "$SCRATCH/ws" "$SCRATCH/allow.txt" > /dev/null; then fail "a manifest allowing unsafe code passed the gate"; fi
# So is a cargo config that lowers it through rustflags, in either
# file name cargo reads.
probe "$MINT_DEPS" ""
mkdir -p "$SCRATCH/ws/.cargo"
for cfg in config.toml config; do
	rm -f "$SCRATCH/ws/.cargo/config.toml" "$SCRATCH/ws/.cargo/config"
	printf '%s\n' '[build]' 'rustflags = ["-A", "unsafe_code"]' > "$SCRATCH/ws/.cargo/$cfg"
	if gate_unsafe_allow "$SCRATCH/ws" "$SCRATCH/allow.txt" > /dev/null; then fail "a .cargo/$cfg allowing unsafe code passed the gate"; fi
done

# 4. A package that does not deny unsafe code: no [lints] table, or a
# workspace table that does not set it.
printf '%s\n' 'pub fn f() {}' > "$SCRATCH/lib.rs"
probe "" ""
sed -i '/^\[lints\]$/,/^workspace = true$/d' "$SCRATCH/ws/probe/Cargo.toml"
cp "$SCRATCH/lib.rs" "$SCRATCH/ws/probe/src/lib.rs"
if gate_lints "$SCRATCH/ws/Cargo.toml" > /dev/null; then fail "a crate without [lints] passed the gate"; fi
probe "" ""
sed -i '/^unsafe_code = "deny"$/d' "$SCRATCH/ws/Cargo.toml"
if gate_lints "$SCRATCH/ws/Cargo.toml" > /dev/null; then fail "a workspace without unsafe_code passed the gate"; fi

# 5. A macro in another crate whose body expands to `unsafe`: the file
# that writes it is found, whoever calls it.
rm -rf "$SCRATCH/ws"; mkdir -p "$SCRATCH/ws/a/src" "$SCRATCH/ws/b/src"
printf '%s\n' '[workspace]' 'resolver = "3"' 'members = ["a", "b"]' > "$SCRATCH/ws/Cargo.toml"
printf '%s\n' '#[macro_export]' 'macro_rules! mint { () => { unsafe { loupe_provenance::Ingress::<loupe_provenance::Worker>::new() } } }' > "$SCRATCH/ws/a/src/lib.rs"
printf '%s\n' 'pub fn f() { let _ = a::mint!(); }' > "$SCRATCH/ws/b/src/lib.rs"
if gate_unsafe_allow "$SCRATCH/ws" "$SCRATCH/allow.txt" > /dev/null; then fail "a cross-crate macro expanding unsafe passed the gate"; fi
# A raw byte string or raw C string ends at its closing quote and hashes,
# not at a backslash, so the code after it is still read.
for lit in 'br"C:\"' 'br#"C:\"#' 'cr#"C:\"#'; do
	printf '%s\n' "pub fn f() { let a = $lit; unsafe { mint() } let z = \"\"; }" > "$SCRATCH/ws/a/src/lib.rs"
	if gate_unsafe_allow "$SCRATCH/ws" "$SCRATCH/allow.txt" > /dev/null; then fail "unsafe after $lit passed the gate"; fi
done
# ...and comments or strings that say `unsafe` are not code.
printf '%s\n' '// unsafe' '/* unsafe */' 'pub const S: &str = "unsafe";' 'pub const R: &str = r#"unsafe"#;' > "$SCRATCH/ws/a/src/lib.rs"
printf '%s\n' 'pub fn f() {}' > "$SCRATCH/ws/b/src/lib.rs"
if ! gate_unsafe_allow "$SCRATCH/ws" "$SCRATCH/allow.txt" > /dev/null; then fail "comments and strings were read as unsafe code"; fi

# 6. Sources the scan would not see: include! and a #[path] to a file
# that is not .rs, and an unlisted build script.
mkdir -p "$SCRATCH/ws/ci"; : > "$SCRATCH/ws/ci/build-scripts.txt"
printf '%s\n' 'include!("gen.txt");' > "$SCRATCH/ws/a/src/lib.rs"
if gate_sources "$SCRATCH/ws" > /dev/null; then fail "include! passed the gate"; fi
printf '%s\n' '#[path = "hidden.txt"]' 'mod hidden;' > "$SCRATCH/ws/a/src/lib.rs"
if gate_sources "$SCRATCH/ws" > /dev/null; then fail "a #[path] to a non-.rs file passed the gate"; fi
printf '%s\n' 'pub fn f() {}' > "$SCRATCH/ws/a/src/lib.rs"
mkdir -p "$SCRATCH/ws/crates/x"; printf '%s\n' 'fn main() {}' > "$SCRATCH/ws/crates/x/build.rs"
if gate_sources "$SCRATCH/ws" > /dev/null; then fail "an unlisted build script passed the gate"; fi
# ...under any name a manifest gives it.
rm "$SCRATCH/ws/crates/x/build.rs"
printf '%s\n' '[package]' 'name = "x"' 'build = "gen/make.rs"' > "$SCRATCH/ws/crates/x/Cargo.toml"
if gate_sources "$SCRATCH/ws" > /dev/null; then fail "an unlisted build = \"...\" script passed the gate"; fi

if [ "$failures" -ne 0 ]; then echo "$failures gate self-test hole(s)"; exit 1; fi
echo "gate self-test: every bypass form is rejected"
