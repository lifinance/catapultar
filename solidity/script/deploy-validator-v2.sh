#!/usr/bin/env bash
#
# deploy-validator-v2.sh
#
# Deploys CATValidatorV2 to every chain Composer serves. Each chain gets its own
# `forge script deploy --sig 'runValidatorV2(string[])' '[<chain>]'` process, and all chains run in
# parallel. The deployment is CREATE2 through the deterministic deployer with salt 0, so every
# chain gets the same address, and the forge script skips a chain that already has code there.
#
#   ERPC_SECRET=... ./script/deploy-validator-v2.sh --account deployer               # simulate only
#   ERPC_SECRET=... ./script/deploy-validator-v2.sh --account deployer --broadcast   # deploy
#   CHAINS="base tempo" ./script/deploy-validator-v2.sh --account deployer --broadcast
#
# Every argument goes to `forge script`: wallet flags, --broadcast, -vvvv, ... Without --broadcast
# forge only simulates. A keystore (--account or --keystore) without --password or --password-file
# gets one password prompt, and every chain's process reads it from a temporary password file.
#
# After the forge processes finish, the script reads the code at the expected address on every
# chain, so the summary reports what is on-chain, not what forge printed.
#
# Environment:
#   ERPC_SECRET     Develop eRPC key (1Password "[Yggdrasil] eRPC develop key"). A chain without
#                   RPC_URL_<NAME> uses https://erpc-dev.li.finance/yggdrasil/evm/<chainId>.
#   RPC_URL_<NAME>  RPC for one chain, e.g. RPC_URL_BASE. deploy.s.sol forks the same variable.
#   CHAINS          Space-separated subset of the chain names below (default: every chain).
#   FORGE_TEMPO     forge for Tempo (default: ~/.foundry-tempo/bin/forge). Tempo has no native gas
#                   coin: each transaction names a TIP-20 fee token, which stock forge cannot send.
#   LOG_DIR         Per-chain forge logs (default: cache/deploy-validator-v2/<timestamp>).

set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

# The chains in yggdrasil's rs/slot-finder/config.composer.production.json, which is zap-backend's
# candidate chain list. Flare (14) is in that list but has no VirtualMachine, so Composer does not
# serve it and deployCATValidatorV2 would revert CanonicalVmMissing.
#
# name chainId [extra forge args]. The extra args come from the VM repo's chains.json.
CHAIN_TABLE='
ethereum 1
optimism 10
bsc 56
gnosis 100
unichain 130
polygon 137
monad 143
sonic 146
xlayer 196
fraxtal 252
worldchain 480
hyperevm 999
lisk 1135
pharos 1672
soneium 1868
tempo 4217 --tempo.fee-token 0x20C0000000000000000000000000000000000000
megaeth 4326 --legacy --with-gas-price 5000000
robinhood 4663
mantle 5000
arc 5042
base 8453
plasma 9745
immutable 13371
mode 34443
arbitrum 42161
celo 42220
avalanche 43114
ink 57073
linea 59144
berachain 80094
plume 98866
scroll 534352
katana 747474
'

CREATE2_DEPLOYER=0x4e59b44847b379578588920ca78fbf26c0b4956c
CANONICAL_VM=0xA9f22b951d5A9CBBD0eC8d2741EA44BFDD2D11fd # deploy.s.sol CANONICAL_VM
ERPC_BASE=https://erpc-dev.li.finance/yggdrasil/evm
FORGE_TEMPO=${FORGE_TEMPO:-"$HOME/.foundry-tempo/bin/forge"}
LOG_DIR=${LOG_DIR:-"cache/deploy-validator-v2/$(date +%Y%m%d-%H%M%S)"}

chain_row() {
  # chain_row NAME — prints NAME's table row, or nothing when NAME is unknown.
  awk -v n="$1" '$1 == n' <<<"$CHAIN_TABLE"
}

rpc_var() {
  echo "RPC_URL_$(echo "$1" | tr '[:lower:]' '[:upper:]')"
}

resolve_rpc() {
  # resolve_rpc NAME CHAIN_ID — prints the chain's RPC: RPC_URL_<NAME>, else the develop eRPC.
  local var
  var=$(rpc_var "$1")
  if [ -n "${!var:-}" ]; then
    echo "${!var}"
  elif [ -n "${ERPC_SECRET:-}" ]; then
    echo "$ERPC_BASE/$2?secret=$ERPC_SECRET"
  else
    return 1
  fi
}

if [ -n "${CHAINS:-}" ]; then
  SELECTED=$CHAINS
else
  SELECTED=$(awk 'NF { print $1 }' <<<"$CHAIN_TABLE")
fi

for name in $SELECTED; do
  if [ -z "$(chain_row "$name")" ]; then
    echo "Error: unknown chain '$name'. Known chains: $(awk 'NF { printf "%s ", $1 }' <<<"$CHAIN_TABLE")"
    exit 1
  fi
  read -r _ id _ <<<"$(chain_row "$name")"
  if ! resolve_rpc "$name" "$id" >/dev/null; then
    echo "Error: no RPC for $name. Set ERPC_SECRET or $(rpc_var "$name")."
    exit 1
  fi
done

BROADCAST=0
NEEDS_PASSWORD=0
for arg in "$@"; do
  case $arg in
    --broadcast) BROADCAST=1 ;;
    --account | --account=* | --accounts | --accounts=* | --keystore | --keystore=* | --keystores | --keystores=*) NEEDS_PASSWORD=1 ;;
    --password | --password=* | --password-file | --password-file=*) NEEDS_PASSWORD=0; break ;;
  esac
done
FORGE_ARGS=("$@")

mkdir -p "$LOG_DIR"
if [ "$NEEDS_PASSWORD" = 1 ] && [ -z "${ETH_PASSWORD:-}" ]; then
  # Parallel processes cannot share one terminal prompt, so the password goes to a file that only
  # this user can read, and the file is removed on exit.
  PASSWORD_FILE=$(mktemp)
  trap 'rm -f "$PASSWORD_FILE"' EXIT
  chmod 600 "$PASSWORD_FILE"
  read -rsp "Keystore password: " password </dev/tty
  echo
  printf '%s' "$password" >"$PASSWORD_FILE"
  unset password
  FORGE_ARGS+=(--password-file "$PASSWORD_FILE")
fi

# Build once before the fan-out, so the parallel forge processes read a fresh cache instead of
# compiling into the same out/ directory at once.
echo "Building..."
forge build >"$LOG_DIR/build.log" 2>&1 || { echo "Build failed, see $LOG_DIR/build.log"; exit 1; }

INIT_CODE="$(jq -r '.bytecode.object' out/CATValidatorV2.sol/CATValidatorV2.json)$(cast abi-encode 'f(address)' "$CANONICAL_VM" | cut -c3-)"
EXPECTED=$(cast compute-address "$CREATE2_DEPLOYER" --salt "$(cast to-uint256 0)" --init-code "$INIT_CODE" | awk '{ print $NF }')
echo "CATValidatorV2 expected at $EXPECTED"
echo "Logs: $LOG_DIR"
[ "$BROADCAST" = 1 ] || echo "No --broadcast: simulating only."

PIDS=()
NAMES=()
for name in $SELECTED; do
  read -r _ id extra <<<"$(chain_row "$name")"
  # shellcheck disable=SC2206 # split the table's extra args into words
  extra_args=($extra)
  forge_bin=forge
  if [ "$name" = tempo ]; then
    forge_bin=$FORGE_TEMPO
    # A different forge build must not share out/ and cache/ with the stock forge processes.
    extra_args+=(--out "$LOG_DIR/tempo-out" --cache-path "$LOG_DIR/tempo-cache")
  fi
  (
    export "$(rpc_var "$name")=$(resolve_rpc "$name" "$id")"
    "$forge_bin" script script/deploy.s.sol:deploy --sig 'runValidatorV2(string[])' "[$name]" \
      ${extra_args[@]+"${extra_args[@]}"} ${FORGE_ARGS[@]+"${FORGE_ARGS[@]}"}
  ) >"$LOG_DIR/$name.log" 2>&1 </dev/null &
  PIDS+=($!)
  NAMES+=("$name")
  echo "  started $name ($id)"
done

onchain_status() {
  # onchain_status RPC — prints "deployed", "no code" or "code check failed" for EXPECTED. Right
  # after a broadcast the RPC can answer from a node that has not seen the new block yet (Tempo
  # once answered "no code" right after a successful deploy), so a broadcast run polls for up to
  # a minute before it reports "no code".
  local code attempt=1 attempts=1
  [ "$BROADCAST" = 1 ] && attempts=12
  while :; do
    code=$(cast code "$EXPECTED" --rpc-url "$1" 2>/dev/null)
    case $code in
      0x?*) echo deployed; return ;;
      0x) [ "$attempt" -ge "$attempts" ] && { echo "no code"; return; } ;;
      *) [ "$attempt" -ge "$attempts" ] && { echo "code check failed"; return; } ;;
    esac
    attempt=$((attempt + 1))
    sleep 5
  done
}

FAILED=0
SUMMARY=()
for i in "${!PIDS[@]}"; do
  name=${NAMES[$i]}
  if wait "${PIDS[$i]}"; then forge_status=ok; else forge_status=FAIL; FAILED=1; fi
  read -r _ id _ <<<"$(chain_row "$name")"
  onchain=$(onchain_status "$(resolve_rpc "$name" "$id")")
  if [ "$BROADCAST" = 1 ] && [ "$onchain" != deployed ]; then FAILED=1; fi
  SUMMARY+=("$(printf '%-11s %-8s forge %-5s %s' "$name" "$id" "$forge_status" "$onchain")")
  echo "  finished $name: forge $forge_status, $onchain"
done

echo ""
echo "==================== CATValidatorV2 $EXPECTED ===================="
printf '%s\n' "${SUMMARY[@]}"
[ "$FAILED" = 1 ] && echo "" && echo "Failures: see $LOG_DIR/<chain>.log"
exit "$FAILED"
