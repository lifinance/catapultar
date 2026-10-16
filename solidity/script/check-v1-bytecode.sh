#!/usr/bin/env bash
# Asserts that the audited v1 validators still compile to the pinned creation
# bytecode. CATValidatorV2 subclasses CATValidator, so v1 carries `virtual`
# hooks; this check proves those hooks (and any later v1 edit) leave the
# deployed bytes, and therefore the CREATE2 address and audit status, unchanged.
#
# Usage, from solidity/:
#   ./script/check-v1-bytecode.sh            compare against snapshots/v1-bytecode.json
#   ./script/check-v1-bytecode.sh --update   rewrite the pin (deliberate v1 change or toolchain bump)
set -euo pipefail

cd "$(dirname "$0")/.."
# The pins were taken with the default profile; CI exports FOUNDRY_PROFILE=ci,
# so fix the profile here instead of inheriting whatever the caller set.
export FOUNDRY_PROFILE=default
pin="snapshots/v1-bytecode.json"
contracts=(CATValidator CATValidatorTron)

hash_of() {
    forge inspect "$1" bytecode | tr -d '\n' | cast keccak
}

if [[ "${1:-}" == "--update" ]]; then
    comment=$(jq -r '._comment' "$pin")
    json=$(jq -n --arg c "$comment" '{_comment: $c}')
    for c in "${contracts[@]}"; do
        json=$(jq --arg k "$c" --arg v "$(hash_of "$c")" '. + {($k): $v}' <<<"$json")
    done
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
exit $status
