#!/bin/sh
# Regenerate the complete set of runner binaries and standalone C declarations.
set -eu
cd "$(dirname "$0")"
GENERATED=$(mktemp -d)
trap 'rm -rf "$GENERATED"' EXIT HUP INT TERM
printf '#include <stdint.h>\n#include <stddef.h>\n' > "$GENERATED/targets.h"
GEN_TEST() {
	target_name=$1
	target_mod=${2:-}
	sed "s/TARGET_NAME/$target_name/g; s|TARGET_MOD|$target_mod$target_name|g" \
		target_template.txt > "$GENERATED/${target_name}_target.rs"
	printf 'void %s_run(const unsigned char* data, size_t data_len);\n' "$target_name" >> "$GENERATED/targets.h"
}
# One line per target, alphabetical. Optional second argument: module prefix.
GEN_TEST cli_config_input
GEN_TEST cli_ingress_response
GEN_TEST cli_render
GEN_TEST core_canonical
GEN_TEST core_json_string
GEN_TEST core_state_machine
GEN_TEST core_text_bounded
GEN_TEST core_text_exact
GEN_TEST core_text_ident
GEN_TEST core_text_json
GEN_TEST core_text_repo_path
GEN_TEST proto_dto
GEN_TEST proto_version
GEN_TEST server_capability_header
GEN_TEST server_config
GEN_TEST server_github_response
GEN_TEST server_ingress_requests
GEN_TEST server_report_email
GEN_TEST server_report_github
GEN_TEST server_request_parsers
GEN_TEST smoke
GEN_TEST storage_identity
GEN_TEST storage_policy_snapshot
GEN_TEST storage_source_refs
GEN_TEST tls_fingerprint
GEN_TEST tls_input
GEN_TEST tls_pem
GEN_TEST web_api
GEN_TEST worker_broker_policy
GEN_TEST worker_broker_usage
GEN_TEST worker_config
GEN_TEST worker_extract_json
GEN_TEST worker_mcp_rpc
GEN_TEST worker_mcp_submission
GEN_TEST worker_network_host
GEN_TEST worker_network_parsers
GEN_TEST worker_regex_secrets
GEN_TEST worker_repo_cache
GEN_TEST worker_sandbox_args
GEN_TEST worker_server_response
GEN_TEST worker_source_discovery
mkdir -p ../../runners/src/bin
for old in ../../runners/src/bin/*_target.rs; do
	[ -e "$old" ] || continue
	[ -e "$GENERATED/$(basename "$old")" ] || rm "$old"
done
cp "$GENERATED/"*_target.rs ../../runners/src/bin/
cp "$GENERATED/targets.h" ../../targets.h
