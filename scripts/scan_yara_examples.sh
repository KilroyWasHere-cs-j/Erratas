#!/usr/bin/env bash
# Runs every fixture in resources/yara_examples/ through erratas' YARA
# rules (via the `yara_scan_file` example binary) and checks that each
# one still trips the rule its filename is named after.
#
# Fixtures are named after the rule they're meant to trigger, except for
# the two listed in OVERRIDES below, where the rule's own identifier
# doesn't match its filename 1:1.
#
# Usage: ./scan_yara_examples.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES_DIR="$REPO_ROOT/resources/yara_examples"

if [ ! -d "$FIXTURES_DIR" ]; then
    echo "No fixtures found at $FIXTURES_DIR" >&2
    exit 1
fi

echo "Building erratas + yara_scan_file example ..."
(cd "$REPO_ROOT" && cargo build --quiet --example yara_scan_file)
BIN="$REPO_ROOT/target/debug/examples/yara_scan_file"

declare -A OVERRIDES=(
    ["elf_reverse_shell.txt"]="elf_reverse_shell_strings"
    ["script_lolbin_certutil.txt"]="script_lolbin_download_execute"
)

GREEN='\033[0;32m'
RED='\033[0;31m'
RESET='\033[0m'

any_failed=0

for f in "$FIXTURES_DIR"/*; do
    name="$(basename "$f")"
    base="${name%.*}"
    expected="${OVERRIDES[$name]:-$base}"

    # Run from REPO_ROOT, not wherever this script was invoked from --
    # build_yara_rules() reads the "rules" directory relative to the
    # process's cwd, not the repo root.
    matches="$(cd "$REPO_ROOT" && "$BIN" "$f")"

    if echo "$matches" | grep -qxF "$expected"; then
        color="$GREEN"
        status="OK"
    else
        color="$RED"
        status="FAIL"
        any_failed=1
    fi

    joined="$(echo "$matches" | tr '\n' ',' | sed 's/,$//')"
    printf "%b%-4s %-45s expected=%-40s matched=[%s]%b\n" \
        "$color" "$status" "$name" "$expected" "$joined" "$RESET"
done

exit "$any_failed"
