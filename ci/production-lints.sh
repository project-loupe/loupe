# shellcheck shell=sh
# Sourced by the production check and its compiler self-test. Test targets
# permit panicking assertions and direct I/O for fixture setup.
production_clippy() {
	cargo clippy "$@" -- -D warnings \
		-D clippy::unwrap_used -D clippy::expect_used \
		-D clippy::string_slice -D clippy::mem_forget \
		-D clippy::dbg_macro -D clippy::todo -D clippy::unimplemented \
		-D clippy::disallowed_methods
}
