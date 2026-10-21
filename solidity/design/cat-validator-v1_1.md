# CATValidatorV1_1

`CATValidatorV1_1` is a subclass of the hold-and-forward `CATValidator` (`src/CATValidator.sol`). It adds a nine-argument `entry` that commits the execution target and payload in the signed constraint, and publishes what the entry pulled and which entry is running, so a contract called during the entry can read both. `CATValidator` is not modified; `CATValidatorV1_1Tron` is the Tron variant.

| File | Role |
|---|---|
| `src/CATValidatorV1_1.sol` | The validator, `is CATValidator` |
| `src/CATValidatorV1_1.tron.sol` | `CATValidatorV1_1Tron`, the same contract with the Tron payout path |
| `src/interfaces/ICATValidatorV1_1.sol` | The v1.1 surface. `entry` is overloaded by the base's `entry`, so the contract name cannot select it in `abi.encodeCall` or `.selector` |
| `src/libs/LibExecutionConstraintV1_1.sol` | The v1.1 EIP-712 struct hash |

## What it inherits

Everything not listed below comes from `CATValidator` unchanged: nonce handling (`spentNonces`, `_checkNonce`), `_validatePayment`, the call proxy, `receive()`, `BalanceOfFailed`, and the reentrancy guard.

- **Settlement.** Outcomes are settled by the inherited `_validatePayment`. The executor delivers outcome tokens to the validator during the call; `_validatePayment` checks the validator's own balance against each `Outcome.amount` and forwards the full balance to `Outcome.destination`, or to the signer when it is `address(0)`.
- **Inherited `entry`.** The base's seven-argument `entry` stays callable. It follows the base's flow under this contract's `"1.1"` domain, with the zero-skipping payout below. It publishes neither `pulled` nor an entry id, and it still forwards the validator's native balance to the call as the base does. A v1.1 escrow never signs its digest, since the v1 type string differs.

## What it adds

**Committed target and payload.** The signed `ExecutionConstraint` gains `address executionTarget` and `bytes32 payloadHash` after `nonce`:

```
ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,address executionTarget,bytes32 payloadHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)
```

- `executionTarget != 0` must equal `execTarget`, else `TargetNotCommitted`. Zero is unconstrained.
- `payloadHash != 0` must equal `keccak256(execPayload)`, else `PayloadNotCommitted`. Zero is unconstrained.
- On the reusable nonce `0`, a zero `executionTarget` reverts `ZeroDestination`. Without it, a zero refund address would let the executor sweep to any target.

**Domain.** Name `"CAT Validator"`, version `"1.1"`. A v1 signature never verifies here and a v1.1 signature never verifies on v1. The base fixes its version and its `_domainNameAndVersion` is not virtual, so `_domainSeparator`, `_hashTypedData` and `eip712Domain` are overridden. The separator is cached against `block.chainid` and `address(this)` and recomputed on a fork.

**`pulled(token)`.** The amount of `token` moved out of the signer by the `entry` currently executing, summed over the allowances. It is written to transient storage after every transfer of the loop, so a token hook that runs during the loop reads zero, never a partial sum. It is cleared after the call and before the outcomes are paid, so it is zero inside `_payout` and outside `entry`. `pulled` reports the spend, not the amount received: a fee-on-transfer token reports the full spend.

**`entryId()`.** 1, 2, 3, ... within a transaction, never reused, because the counter is not reset. Zero outside the nine-argument `entry` and inside the inherited seven-argument one. The id rolls back with a reverted entry.

**Strict balance read.** `SPEND_BALANCE_OF_MAGIC` reads the signer's balance through the same `checkBalanceOf` the base uses and reverts `BalanceOfFailed` on a failed or short read.

**Zero-skipping payout.** `_transfer` is overridden to skip a zero amount, so a `{token, 0, refund}` refund outcome does not revert on tokens that reject zero transfers. Non-zero payouts go through `_payout`, which calls the base `_transfer`. `CATValidatorV1_1Tron` overrides `_payout` only.

**No value to the call.** The nine-argument `entry` calls the proxy with value 0, so a force-fed native balance does not reach a non-payable execution target.

**Transient storage.** `pulled` and the entry id use EIP-1153 only. The constructor probes `tstore`/`tload` and reverts on a chain without it. The probe slot is cleared.

## Tron

`CATValidatorV1_1Tron` pays through `SafeTransferLibTron.safeTransfer` (approve self, `transferFrom` self) so a token with a broken `transfer()` return value, such as Tron USDT, settles. `typescript/scripts/tron/deploy-catapultar.ts` deploys it with `--step CATValidatorV1_1Tron`; it is not in the default set.

## Residuals

Inherited from the hold-and-forward base, not introduced here:

- The validator holds funds within a transaction. A stray balance of an outcome token is forwarded with the outcome, and a blocklisted validator blocks settlement.
- A fee-on-transfer outcome token pays the fee on both legs.
- Native value sent through `receive()` can strand.
- Two outcomes of the same token in one entry are unsupported.

Specific to v1.1:

- The inherited seven-argument `entry` forwards the validator's native balance to the call. Use the nine-argument `entry`.

## Deployment and pins

`script/deployV1_1.s.sol` deploys through the deterministic deployer (`0x4e59b44847b379578588920cA78FbF26c0B4956C`, salt 0), so the address is a function of the creation code and therefore of the compiler. At solc 0.8.35, the default profile, it is `0xd7f0DA58b8574d29aF3424b4B4a157AF0F0F4552`.

`script/check-v1-1-bytecode.sh` pins the creation hashes of `CATValidatorV1_1` and `CATValidatorV1_1Tron` and the git blob id of each v1.1 source file (`snapshots/v1-1-bytecode.json`). A change to the base moves the hashes and fails the check.

## Tests

| File | Covers |
|---|---|
| `test/CATValidatorV1_1.t.sol` | Domain and signature binding, committed target and payload, `pulled` and `entryId`, refunds on nonce 0, outcomes held then forwarded, reentrancy, constructor probe, gas |
| `test/CATValidatorV1_1.differential.t.sol` | The nine-argument entry against the base's `entry`: identical results except the three documented deltas (native forwarding, zero payouts, `pulled` and entry id) |
| `test/CATValidatorV1_1.equivalence.t.sol` | Differential fuzz of the subclass against `test/reference/CATValidatorV1_1Standalone.sol`, a standalone hold-and-forward implementation |
| `test/CATValidatorV1_1.AllowanceParity.t.sol` | The allowance loop against the base's transfers, balances and revert data |
| `test/Tron/CATValidatorV1_1.tron.t.sol` | The Tron payout path against a Tron-style USDT mock |
| `test/vc/ScaParity.t.sol` | Struct hashes, digests and escrow addresses against `test/vc/fixtures/sca-parity/sca-parity.v1_1.vectors.json` |
| `typescript/src/protocol/validatorV1_1.spec.ts` | The same vectors recomputed with viem and the SDK's factory salt, and the ABI selectors |

`test_reference_is_pinned` pins the creation hash of the standalone reference. It depends on the compiler version and changes with it.
