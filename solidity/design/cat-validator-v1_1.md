# CATValidatorV1_1

`CATValidatorV1_1` is a subclass of `CATValidator` (`src/CATValidator.sol`), which holds the outcome tokens the executor delivers during the call and forwards each held balance after checking it against `Outcome.amount`. It adds a nine-argument `entry` that commits the execution target and payload in the signed constraint, and publishes what the entry pulled and which entry is running, so a contract called during the entry can read both. `CATValidator` gains `virtual` on `entry`, `_domainNameAndVersion` and `_call`, which leaves its bytecode unchanged (see Deployment and pins); `CATValidatorV1_1Tron` is the Tron variant.

| File | Role |
|---|---|
| `src/CATValidatorV1_1.sol` | The validator, `is CATValidator` |
| `src/CATValidatorV1_1.tron.sol` | `CATValidatorV1_1Tron`, the same contract with the Tron payout path |
| `src/interfaces/ICATValidatorV1_1.sol` | The v1.1 surface. `entry` is overloaded by the base's `entry`, so the contract name cannot select it in `abi.encodeCall` or `.selector` |
| `src/libs/LibExecutionConstraintV1_1.sol` | The v1.1 EIP-712 struct hash |

## What it inherits

Everything not listed below comes from `CATValidator` unchanged: nonce handling (`spentNonces`, `_checkNonce`), `_validatePayment`, the call proxy, `receive()` and `BalanceOfFailed`. The nine-argument `entry` replaces the base's reentrancy guard with a transient lock (see **Transient storage**).

- **Settlement.** Outcomes are settled by the inherited `_validatePayment`. The executor delivers outcome tokens to the validator during the call; `_validatePayment` checks the validator's own balance against each `Outcome.amount` and forwards the full balance to `Outcome.destination`, or to the signer when it is `address(0)`.
- **Base `entry`.** The base's seven-argument `entry` reverts `V1EntryDisabled`; the nine-argument `entry` is the only way in.

## What it adds

**Committed target and payload.** The signed `ExecutionConstraint` gains `address executionTarget` and `bytes32 payloadHash` after `nonce`:

```
ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,address executionTarget,bytes32 payloadHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)
```

- `executionTarget != 0` must equal `execTarget`, else `TargetNotCommitted`. Zero is unconstrained.
- `payloadHash != 0` must equal `keccak256(execPayload)`, else `PayloadNotCommitted`. Zero is unconstrained.
- On the reusable nonce `0`, a zero `executionTarget` reverts `ZeroDestination`. Without it, a zero refund address would let the executor sweep to any target.
- On nonce `0` with a zero `payloadHash`, the executor may call the committed `executionTarget` with any calldata through the call proxy. A constraint that may only sweep commits `keccak256("")`.

**Domain.** Name `"CAT Validator"`, version `"1.1"`; the base's version is `"1"`. A v1 signature never verifies here and a v1.1 signature never verifies on v1: the verifying contract and the version both differ. `@custom:version 1.1.0` matches this domain version; the base's `@custom:version` is `0.1.0`. `_domainNameAndVersion` is overridden; Solady's `EIP712` caches the separator and recomputes it on a fork.

**`pulled(token)`.** The amount of `token` moved out of the signer by the `entry` currently executing, summed over the allowances. It is written to transient storage once, after the last transfer of the loop, so a token hook that runs during the loop reads zero, never a partial sum. It is cleared after the call and before the outcomes are paid, so it is zero during the payout and outside `entry`. `pulled` reports the spend, not the amount received: a fee-on-transfer token reports the full spend.

**`entryId()`.** 1, 2, 3, ... for the nine-argument entries of a transaction. The counter is transient and never reset within the transaction, so a settled entry's id is not reused. Zero outside the nine-argument `entry`. A reverted entry rolls its increment back, so the next entry takes the same id.

**Strict balance read.** `SPEND_BALANCE_OF_MAGIC` reads the signer's balance through the same `checkBalanceOf` the base uses and reverts `BalanceOfFailed` on a failed or short read.

**Zero-skipping payout.** `_transfer` is overridden to skip a zero amount, so a `{token, 0, refund}` refund outcome does not revert on tokens that reject zero transfers. `CATValidatorV1_1Tron` overrides `_transfer` again with the same zero check and its own payout path.

**No value to the call.** `_call` is overridden to call the proxy with value 0, so a force-fed native balance does not reach a non-payable execution target.

**Transient storage.** `pulled` and the entry id use EIP-1153 only. A non-zero entry id is also the nine-argument `entry`'s reentrancy lock: a nested entry reverts `Reentrancy()`, and the base's storage guard is not used. The constructor probes `tstore`/`tload` and reverts on a chain without it. The probe slot is cleared. The `pulled` slot of a token is `keccak256(token, PULLED_SEED)`, where `PULLED_SEED` is an arbitrary fixed constant; the entry counter and the entry id sit at the keccak256 of their namespaced names.

## Tron

`CATValidatorV1_1Tron` pays through `SafeTransferLibTron.safeTransfer` (approve self, `transferFrom` self) so a token with a broken `transfer()` return value, such as Tron USDT, settles. `typescript/scripts/tron/deploy-catapultar.ts` deploys it with `--step CATValidatorV1_1Tron`; it is not in the default set.

## Residuals

Inherited from the base, not introduced here:

- The validator holds funds within a transaction. A stray balance of an outcome token is forwarded with the outcome, and a blocklisted validator blocks settlement.
- A fee-on-transfer outcome token pays the fee on the delivery to the validator and again on the forward, so the recipient can receive less than `outcome.amount`.
- Anything sent to the validator outside an entry, native value through `receive()` included, can be claimed by any signer through an outcome. The address is not safe for direct transfers.
- Two outcomes of the same token in one entry are unsupported.

## Deployment and pins

`script/deployV1_1.s.sol` deploys through the deterministic deployer (`0x4e59b44847b379578588920cA78FbF26c0B4956C`, salt 0), so the address is a function of the creation code and therefore of the compiler. At solc 0.8.35 and `evm_version` cancun, the default profile, it is `0xA1d38c83e842ebA863238845Dc4fF14F5668041A`. The script reverts unless the creation code hashes to the pin in `snapshots/v1-1-bytecode.json`. It does not check the chain for EIP-1153. On a chain without it, forge's local simulation passes and the broadcast deployment reverts on chain, spending its gas.

`script/check-v1-1-bytecode.sh` pins the creation hashes of `CATValidatorV1_1` and `CATValidatorV1_1Tron` and the git blob id of each v1.1 source file (`snapshots/v1-1-bytecode.json`). A change to the base moves the hashes and fails the check. `script/check-v1-bytecode.sh` pins the creation hashes of `CATValidator` and `CATValidatorTron` (`snapshots/v1-bytecode.json`), so the base's `virtual` keywords are proven bytecode-neutral.

## Tests

| File | Covers |
|---|---|
| `test/CATValidatorV1_1.t.sol` | Domain and signature binding, committed target and payload, `pulled` and `entryId`, refunds on nonce 0, outcomes held then forwarded, reentrancy, constructor probe, gas |
| `test/CATValidatorV1_1.differential.t.sol` | The nine-argument entry against the base's `entry`: identical results except the three documented deltas (native forwarding, zero payouts, `pulled` and entry id) |
| `test/CATValidatorV1_1.equivalence.t.sol` | Differential fuzz of the subclass against `test/reference/CATValidatorV1_1Standalone.sol`, a standalone implementation of the same specification |
| `test/CATValidatorV1_1.AllowanceParity.t.sol` | The allowance loop against the base's transfers, balances and revert data |
| `test/Tron/CATValidatorV1_1.tron.t.sol` | The Tron payout path against a Tron-style USDT mock |
| `test/vc/ScaParity.t.sol` | Struct hashes, digests and account addresses against `test/vc/fixtures/sca-parity/sca-parity.v1_1.vectors.json` |
| `typescript/src/protocol/validatorV1_1.spec.ts` | The same vectors recomputed with viem and the SDK's factory salt, and the ABI selectors |

`test_reference_is_pinned` pins the creation hash of the standalone reference. It depends on the compiler version and changes with it.
