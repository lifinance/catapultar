# Plan: bind the V2 refund to its target (option E)

Status: revised after adversarial review (see the last section). Branch `feat/cat-validator-v2-on-v1` (PR #43, not audited).

## Problem

`CATValidatorV2.entry` signs allowances, outcomes, executor, nonce, `validationProgramHash` and `paramsHash`. It does not sign `execTarget` or `execPayload`. A refund constraint shaped as a balance sweep (allowance `allocated = maxUint256`, spend `SPEND_BALANCE_OF_MAGIC`, outcome `{token, 0, refundWallet}`, no program) can therefore be called with `execTarget = attacker`: `_handleAllowances` moves the whole escrow balance to the attacker, and `_validatePayment` checks `>= 0` and passes. The sweep shape must stay (under-funded deposits, deposits above the allowance, amount-flexible allowances, stETH-style 1-2 wei loss), so the fix binds the destination, not the amount.

## Design

Same pattern as intent-factory's audited `CATValidatorV1_1` (lines 85-103, 140-150): the constraint commits `executionTarget` and `payloadHash`; zero means unconstrained.

### EIP-712 type string

```
ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,address executionTarget,bytes32 payloadHash,bytes32 validationProgramHash,bytes32 paramsHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)
```

Struct hash: `keccak256(abi.encode(TYPEHASH, allowancesHash, outcomesHash, executor, nonce, executionTarget, payloadHash, validationProgramHash, paramsHash))`.

**Field order.** The two binding fields sit right after `nonce`, which is where V1_1 puts them. The V2 field list is then the V1_1 field list followed by the program commitment. The order has three effects:

- An SDK that already encodes V1_1 (intent-factory) builds the V2 struct by appending two words to the V1_1 encoding.
- The program fields stay together as the V2-only tail.
- V2 digests still never collide with v1 or V1_1 digests. The type strings differ, and so do the domain versions ("2" against "1" and "1.1").

### `entry`

```solidity
struct ExecutionBinding { address executionTarget; bytes32 payloadHash; }

function entry(
    address execTarget,
    bytes calldata execPayload,
    address account,
    uint256 nonce,
    AllowanceSpend[] calldata allowances,
    Outcome[] calldata outcomes,
    ExecutionBinding calldata binding,
    VMCommand[] calldata validationProgram,
    bytes32[] calldata validationParams,
    bytes calldata signature
) external nonReentrant
```

ABI signature `entry(address,bytes,address,uint256,(address,uint256,uint256)[],(address,uint256,address)[],(address,bytes32),(uint8,bytes32)[],bytes32[],bytes)`, selector `0x9b998f63`, which replaces `0x62551d8f`.

`entry` runs these steps in order:

1. `_checkBinding(binding, execTarget, execPayload)` reverts `TargetNotCommitted()` if `executionTarget != 0 && executionTarget != execTarget`. It reverts `PayloadNotCommitted()` if `payloadHash != 0 && payloadHash != keccak256(execPayload)`.
2. Program and params hashes are derived as before.
3. `_checkNonce` runs.
4. `_validateApprovalV2` signs over the binding fields.
5. The rest is unchanged.

All of these steps run before `_handleAllowances`, so a mismatch moves no funds. The two errors are declared in `CATValidatorV2`, not in v1.

### Stack and coverage (measured)

| `entry` shape | `forge build` (default, via-IR) | `forge coverage --ir-minimum` (CI) |
| --- | --- | --- |
| 11 flat args (`address executionTarget, bytes32 payloadHash`) | compiles | **fails**: "Cannot swap Variable var_signature_length with Slot RET[modifier_nonReentrant]: too deep in the stack by 1 slots" |
| 10 args, `ExecutionBinding calldata` (static struct = 1 calldata-offset slot) | compiles | compiles |

The flat shape fails CI coverage by one slot, so the binding is passed as a calldata struct. The struct is ABI packaging only; the EIP-712 type keeps two flat fields. The struct variant has 17 stack items at function entry, which is the reachable limit (SWAP16), so it has zero spare slots. A future `entry` argument needs another struct.

### Constraint shapes

| Constraint | `executionTarget` | `payloadHash` | Behaviour |
| --- | --- | --- | --- |
| Execute (fill) | `0` | `0` | Unchanged: any target, any payload. The outcome floor stays its only bound (the brief's general rule; out of scope here). |
| Refund | refund wallet | `keccak256("")` = `0xc5d2…a470` | The executor must pass `execTarget = refund wallet` and an empty payload. `_handleAllowances` moves funds escrow → refund wallet in one hop; `_call` is skipped (empty payload), so the refund wallet's code never runs. |

The refund keeps sharing the execute constraint's nonce (decision E1).

### v1 neutrality

`CATValidator.sol`, `LibExecutionConstraint.sol` and the Tron files stay untouched. `script/check-v1-bytecode.sh` must report `ok` for both pins.

## TypeScript SDK (`../typescript`)

| File | Change |
| --- | --- |
| `src/types/types.ts` | Add `ExecutionBinding = { executionTarget, payloadHash }` and set `ExecutionConstraintV2 = ExecutionConstraint & ExecutionBinding & ValidationCommitment`. In `ExecutionConstraintV2Typed`, insert `executionTarget: address, payloadHash: bytes32` after `nonce`. |
| `src/protocol/constraint.ts` | Add an `UNBOUND_EXECUTION` constant (zero, zero) and a `refundBinding(refund)` helper that returns `{ executionTarget: refund, payloadHash: keccak256("0x") }` and rejects a zero refund. Digest code follows from the type table. |
| `src/abi/CATValidatorV2.ts` | Regenerate the V2 `entry` ABI from the forge artifact. The existing artifact-parity spec guards it. |
| `src/transaction/constrainedtransaction.ts` | The V2 execute constraint signs `UNBOUND_EXECUTION`. The V2 refund constraint signs `refundBinding(refund)`, **no outcomes** (revised, see C6), and zero program hashes. On V2, `asRefundCall` targets `refund`, passes payload `0x`, the same binding and no outcomes, and keeps spend = allowance amount. `asExecuteCall` passes `UNBOUND_EXECUTION`. Each V2 refund path rejects `refund == 0x0` (through `refundBinding`), because a zero target would be unconstrained. The v1 paths stay unchanged. |
| `src/index.ts` | Export `ExecutionBinding`, `refundBinding` and `UNBOUND_EXECUTION`. |
| `README.md` | Update the V2 entry signature and the refund paragraph. |
| specs | Re-pin the V2 digest vectors (`protocol.spec.ts`), add a bound-refund vector, update the reference struct hash and the type string literal, and update the V2 refund expectations in `constrainedtransaction.v2.spec.ts`. |

**Why the V2 refund drops its outcomes.** With `execTarget = refund wallet`, the tokens never reach the validator, so a floor of `allowance.amount` on the validator's balance would always revert. The target binding replaces the floor as the bound on where funds go. A zero-amount outcome would still make `_validatePayment` call `transfer(refund, 0)` for each token, which reverts on tokens that reject zero-value transfers (C6). With no outcomes, `_validatePayment` makes no call.

**Scope of the catapultar SDK refund.** The SDK refund signs, approves and spends the allowance amount, exactly as before. It refunds that amount and does not sweep: it reverts for an under-funded escrow, and it leaves anything above the allowance in the escrow. Both limits were already there before this change. The sweep shape belongs to intent-factory's vendored producer: `allocated = maxUint256`, approval `maxUint256`, spend `SPEND_BALANCE_OF_MAGIC`. The contract tests exercise that shape directly (C1).

## Solidity tests

Existing tests updated for the new signature:

- `test/CATValidatorV2.t.sol`: the `sign` helper takes the binding; every `entry` call passes it.
- `test/vc/VcTestBase.sol`: the independent digest encoding.
- `test/vc/IntegrationV2.t.sol`: `_entry`.
- `test/libs/LibExecutionConstraintV2.t.sol`: the reference type string, the struct hash, and a fuzz test over both binding fields.

New tests (implemented by the security review step):

1. Brief PoC port: a sweep refund with `execTarget = attacker` reverts `TargetNotCommitted`. A sweep refund with a non-empty payload reverts `PayloadNotCommitted`.
2. The honest sweep refund (`execTarget = refund wallet`, empty payload) pays the wallet when the balance is under the allowance, when it is above a finite allowance with `allocated = max`, and for a stETH-style mock that loses 1-2 wei per transfer. It also succeeds for a zero balance, and for the no-outcome refund the SDK builds.
3. An execute constraint signed with `0`/`0` fills with an arbitrary target and payload.
4. A digest signed for target A does not verify for target B (`BadSignature` when the caller's binding is changed to B and `execTarget = B`). A binding with `payloadHash = 0` does not verify against a signature over `keccak256("")`, and the reverse fails too.
5. Fuzz test: for a refund constraint, every validator-initiated `transferFrom` out of the escrow goes to the committed target. The test asserts the `transferFrom` destination, not only balances (C7). The fuzzer chooses the target, payload and spends.
6. Fuzz: the execute path with `0`/`0` behaves as before, for any target and payload.
7. A zero-spend refund and a partial-spend refund each consume the shared nonce. This documents the residual risk (C5).
8. A callback (ERC-777-style) token whose recipient hook tries a nested `entry` reverts with `Reentrancy` (C3).
9. Sequence tests (C8): a failing program on the execute constraint, then the bound refund on the same nonce; and at nonce 0, bound refunds alternating with independently signed unbound executes.
10. SDK: a zero refund address is rejected by both the approval batch and `asRefundCall`. A digest vector distinguishes `payloadHash = keccak256("0x")` from zero (C7).

## Gas

Measure `entry` gas before and after with `forge test --gas-report`, on two paths:

- a fill with an empty program and one outcome, identical before and after. This isolates the binding overhead.
- an honest refund: before, the PR #43 1:1 refund through the validator; after, the bound refund straight to the wallet. The difference is reported as the **end-to-end refund-shape difference**, not as binding overhead (C10).

## Design doc

Add decision D10, "Bind the fill target and payload". Update R8 (a refund targets the refund wallet, not the validator), section 4 (the Refunds consumer row), the section 7 pseudo-code, the D4 stack note (struct for the binding), the rollout (lockstep consumers, C4), and the risks (K7 residuals below).

## Residual risks (to document)

- **Executor-chosen spend.** The spend is not signed. An untrusted executor can run the refund with spend 0 or with a partial spend. Either call consumes the nonzero nonce shared with the execute constraint, which disables both signed paths at that nonce and leaves the rest of the deposit in the escrow. This is an accepted griefing capability of an untrusted executor, not theft: funds can only move to the signed wallet. Recovery requires the owner's direct call on the escrow (C5).
- **Nonce 0 (perpetual).** A perpetual refund can be replayed, but only to the refund wallet. The executor can sweep each new deposit to the refund wallet, which affects liveness only.
- **Execute constraint.** An unbound fill with a zero outcome floor stays drainable (the brief's general rule). This change does not alter that; such constraints need a real floor.
- **Refund wallet behaviour (C2, C3).** The validator makes no payload call to the wallet, because the payload is empty and `_call` is skipped. The token's `transferFrom` can still run wallet code through a callback-capable token (ERC-777 hooks), and that code can revert or act; a nested `entry` hits `nonReentrant`. The binding guarantees only the destination of the validator's `transferFrom`. Some destinations do not yield a recoverable refund. If the wallet is the validator, the funds stay on the validator, where the next settlement that forwards that token can pick them up. If the wallet is the escrow, the transfer is a self-transfer and only the nonce is consumed. If the wallet is the token contract, recovery depends on that token. Choosing the wallet is the signer's job; the SDK rejects only the zero address, which would be unconstrained. Routing a refund to the validator was already lossy before this change.
- **Lockstep consumers (C4).** The type string and the `entry` selector change. Every producer of V2 digests and every `entry` encoder must cut over together: this SDK, and intent-factory's vendored SDK, which also produces the sweep refund. A digest approved under the old type string cannot authorize a call on the new validator. No V2 escrow exists in production (design doc section 9), so no escrow migrates.

## Adversarial review (plan-critic) and disposition

| # | Finding | Disposition |
| --- | --- | --- |
| C1 | Blocker: the catapultar SDK refund is not a sweep (it signs, approves and spends the allowance amount). | **Rejected for this SDK.** The sweep is intent-factory's refund shape; the catapultar SDK refund was a fixed-amount refund before this change, and the brief scopes the SDK work to the new ABI, typehash, encoder and refund target. A change to the signed allocation and approval would alter the execute constraint's approval too, so it is a feature. The contract supports the sweep, and the Solidity tests exercise it (tests 2 and 5). The scope note above documents the SDK limits. |
| C2 | A bound target is not always a usable wallet (validator, escrow, token). | **Folded as documentation** (residual risks). No guard is added beyond the zero address: these cases predate the change, and the escrow address is not known when the approval batch is built. |
| C3 | "No code runs at the wallet" is false for callback tokens. | **Folded.** The claim is narrowed, and test 8 is added. |
| C4 | The rollout omits intent-factory's producer and old-digest migration. | **Folded** into the residual risks and the design doc rollout. Changes to intent-factory are out of scope for this repository. |
| C5 | The liveness wording understates an untrusted executor. | **Folded.** The wording is fixed and a partial-spend test is added (test 7). |
| C6 | A zero-amount outcome makes a 0-value transfer, which some tokens reject; the invariant needs a precise boundary. | **Folded.** The SDK refund drops its outcomes, and test 2 adds the zero-balance and no-outcome cases. |
| C7 | Sentinel enforcement is sound; zero-refund rejection and an empty-hash-vs-zero vector are missing. | **Folded** (tests 4 and 10). Test 5 asserts the `transferFrom` destination. |
| C8 | Nonce 0 and program isolation are sound; sequence tests are missing. | **Folded** (test 9). |
| C9 | Type order, ABI packaging and the v1 boundary are sound. | No change. |
| C10 | The refund gas comparison conflates the binding with the route change. | **Folded** (Gas section). |
