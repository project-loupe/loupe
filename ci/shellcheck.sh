#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."

scripts=()
while IFS= read -r -d '' path; do
	case "$path" in
		*.sh | *.bash | *.bats) scripts+=("$path") ;;
		*)
			# Scripts without an extension are identified by their interpreter.
			IFS= read -r -n 256 first_line < "$path" || true
			if [[ "$first_line" =~ ^\#![[:space:]]*(/usr/bin/env[[:space:]]+(-S[[:space:]]+)?|/[^[:space:]]*/)(bash|dash|ksh|sh)([[:space:]]|$) ]]; then
				scripts+=("$path")
			fi
			;;
	esac
done < <(git ls-files -z)

exec shellcheck --external-sources "${scripts[@]}"
