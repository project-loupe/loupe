#!/bin/sh
# Compile actual violations, including aliases, against the production policy.
# A fresh workspace member deliberately has no crate attributes: CI must cover
# future targets even before an author copies the local production lint block.
set -eu
cd "$(dirname "$0")/.."
. ci/env.sh
. ci/production-lints.sh
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT
export CARGO_TARGET_DIR="$CARGO_TARGET_DIR/production-lint-selftest"
mkdir -p "$SCRATCH/member/src"
cat > "$SCRATCH/Cargo.toml" <<'EOF'
[workspace]
members = ["member"]
resolver = "3"
[workspace.lints.clippy]
disallowed_methods = "allow"
EOF
cat > "$SCRATCH/member/Cargo.toml" <<'EOF'
[package]
name = "production-lint-probe"
version = "0.0.0"
edition = "2024"
[lints]
workspace = true
EOF
printf '\n[dependencies]\n' >> "$SCRATCH/member/Cargo.toml"
sed -n '/^reqwest = /p; /^tokio = /p' Cargo.toml >> "$SCRATCH/member/Cargo.toml"
cp Cargo.lock "$SCRATCH/Cargo.lock"
if [ -f clippy.toml ]; then cp clippy.toml "$SCRATCH/clippy.toml"; fi
failures=0
reject() {
	lint=$1; body=$2
	printf '%s\n' "$body" > "$SCRATCH/member/src/lib.rs"
	if (cd "$SCRATCH"; production_clippy --workspace --lib --bins --offline) > "$SCRATCH/output" 2>&1; then
		echo "SELFTEST HOLE: production $lint compiled"; failures=$((failures + 1))
	elif ! grep -q "index.html#$lint" "$SCRATCH/output"; then
		cat "$SCRATCH/output"
		echo "SELFTEST HOLE: $lint failed for another reason"; failures=$((failures + 1))
	fi
}
reject unwrap_used 'pub fn f(x: Option<u8>) -> u8 { x.unwrap() }'
reject expect_used 'pub fn f(x: Option<u8>) -> u8 { x.expect("present") }'
reject string_slice 'pub fn f(x: &str) -> &str { &x[1..] }'
reject mem_forget 'pub fn f(x: String) { std::mem::forget(x); }'
reject dbg_macro 'pub fn f(x: u8) -> u8 { dbg!(x) }'
reject todo 'pub fn f() { todo!() }'
reject unimplemented 'pub fn f() { unimplemented!() }'
reject disallowed_methods 'use std::fs::read as read_alias; pub fn f() { let _ = read_alias("input"); }'
reject disallowed_methods 'use std::process::Command as C; pub fn f() { let _ = C::new("program"); }'
reject disallowed_methods 'pub fn f() { let _ = <std::fs::File>::open("input"); }'
reject disallowed_methods 'use tokio::fs::read as read_alias; pub async fn f() { let _ = read_alias("input").await; }'
reject disallowed_methods 'use tokio::process::Command as C; pub fn f() { let _ = C::new("program"); }'
reject disallowed_methods 'use reqwest::Client as Http; pub fn f() { let _ = Http::new(); }'
reject disallowed_methods 'pub async fn f(request: reqwest::RequestBuilder) { let _ = request.send().await; }'
# A reviewed call is accepted locally; an adjacent call still fails.
reviewed='#[allow(clippy::disallowed_methods, reason = "fixture models an explicitly reviewed file ingress")]
pub fn reviewed() { let _ = std::fs::read("input"); }'
reject disallowed_methods "$reviewed
pub fn other() { let _ = std::fs::read(\"other\"); }"
printf '%s\n' "$reviewed" > "$SCRATCH/member/src/lib.rs"
if ! (cd "$SCRATCH"; production_clippy --workspace --lib --bins --offline) > "$SCRATCH/output" 2>&1; then
	cat "$SCRATCH/output"; echo 'SELFTEST HOLE: reviewed call rejected'; failures=$((failures + 1))
fi
# Test fixtures may use panicking assertions and direct filesystem calls.
cat > "$SCRATCH/member/src/lib.rs" <<'EOF'
#[cfg(test)]
mod tests {
    #[test]
    fn fixture() {
        let value = std::hint::black_box(Some(1));
        assert_eq!(value.unwrap(), 1);
        let value = std::hint::black_box(Some(2));
        assert_eq!(value.expect("fixture"), 2);
        let _ = std::fs::read("fixture");
    }
}
EOF
if ! (cd "$SCRATCH"; cargo clippy --workspace --all-targets --offline -- -D warnings) > "$SCRATCH/output" 2>&1; then
	cat "$SCRATCH/output"; echo 'SELFTEST HOLE: deferred tests rejected'; failures=$((failures + 1))
fi
if [ "$failures" -ne 0 ]; then echo "$failures production lint self-test hole(s)"; exit 1; fi
echo 'production lint self-test: violations rejected, reviewed calls and tests accepted'
