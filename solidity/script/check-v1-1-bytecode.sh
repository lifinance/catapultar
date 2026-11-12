#!/usr/bin/env bash
# Asserts that CATValidatorV1_1 and CATValidatorV1_1Tron still compile to the pinned creation bytecode and that
# their own source files still hash to the pinned git blob ids. CATValidatorV1_1 subclasses CATValidator, so a
# change to the base moves its hash and fails this check.
#
# Usage, from solidity/:
#   ./script/check-v1-1-bytecode.sh            compare against snapshots/v1-1-bytecode.json
#   ./script/check-v1-1-bytecode.sh --update   rewrite the pins (deliberate change or toolchain bump)
set -euo pipefail

cd "$(dirname "$0")/.."
export FOUNDRY_PROFILE=default
pin="snapshots/v1-1-bytecode.json"
contracts=(CATValidatorV1_1 CATValidatorV1_1Tron)

hash_of() {
    forge inspect "$1" bytecode | tr -d '\n' | cast keccak
}

if [[ "${1:-}" == "--update" ]]; then
    json=$(cat "$pin")
    for c in "${contracts[@]}"; do
        json=$(jq --arg k "$c" --arg v "$(hash_of "$c")" '.[$k] = $v' <<<"$json")
    done
    while IFS= read -r f; do
        json=$(jq --arg f "$f" --arg v "$(git hash-object "$f")" '.files[$f] = $v' <<<"$json")
    done < <(jq -r '.files | keys[]' <<<"$json")
    printf '%s\n' "$json" >"$pin"
    echo "updated $pin"
    exit 0
fi

status=0
for c in "${contracts[@]}"; do
    expected=$(jq -r --arg k "$c" '.[$k]' "$pin")
    actual=$(hash_of "$c")
    if [[ "$expected" == "$actual" ]]; then
        echo "ok       $c $actual"
    else
        echo "MISMATCH $c expected $expected got $actual" >&2
        status=1
    fi
done
while IFS= read -r f; do
    expected=$(jq -r --arg f "$f" '.files[$f]' "$pin")
    actual=$(git hash-object "$f")
    if [[ "$expected" == "$actual" ]]; then
        echo "ok       $f $actual"
    else
        echo "MISMATCH $f expected $expected got $actual" >&2
        status=1
    fi
done < <(jq -r '.files | keys[]' "$pin")
exit $status
