# CATValidatorV2 on top of the audited CATValidator

Status: accepted 2026-10-08. Supersedes the port in catapultar PR #42 (closed).

## 1. Summary

CATValidatorV2 lets a signed execution constraint commit a validation program. The validator runs that program on the LI.FI VirtualMachine (VM) after the fill. A failed program reverts the settlement, and the escrow then refunds. The program hash is part of the signed digest, so the escrow's CREATE2 address commits to the program.

The current V2 is a copy of the pre-audit CATValidator (v1) with the program added. That copy has three structural problems:

- It drifted from the audited v1 and needed three catch-up fixes.
- Its pre-balance registers serve only a check that the outcome floor already makes.
- It passes two hashes that the contract can compute itself, and the extra arguments break the coverage build.

This PRD proposes a smaller V2:

- V2 is a **subclass** of the audited v1 on catapultar `main`. It inherits the pay-the-validator settlement.
- V2 adds one step after the payment check: run the committed program.
- V2 **derives** both commitment hashes from the calldata.
- The register file replaces destination pre-balances with **flow registers** that the validator measures itself: the amount spent from the escrow per allowance, and the amount paid per outcome (D2).

Section 8 records the decisions.

## 2. Background and current state

### Why V2 exists

The v1 validator checks one thing about a fill: each committed token reached its destination with at least the committed amount (the "outcome floor"). It cannot express relational, multi-asset or third-party post-conditions. For deferred compose continuations, the executor is therefore trusted for everything above the floor (PRD risk R8, the "comprehensive-outcome gap"). V2 closes that gap: the compose compiler derives a program from the user's authored invariants, the escrow commits to it, and the validator runs it on-chain. Yggdrasil PRD `2026-07-verified-continuations-validation-programs.md` §3 L84-90, G1-G8.

The owner's stated direction (2026-09-25): "0 signature user interactions with arbitrary fills that satisfy user intents for arbitrary actions". The program is "essentially signed by using the specific escrow, address is postimage of the committed verification program". Archived session 01a0d322.

### Current state

| Item | State |
| --- | --- |
| Source of truth today | The intent-factory vendored copy (`external/catapultar`). It was forked from pre-audit v1 at `cba622b`. The fixes are mirrored on branch `catv2-pre-audit`. |
| Upstream | Draft PR catapultar#42: the verbatim port, four catch-up fixes, and the TypeScript SDK. Its coverage job fails ("stack too deep"). |
| Audit | No audit has covered V2, `LibExecutionConstraintV2` or `LibValidationVM`. The validator fixes we call "Zenith 6.1.1/6.2.1" come from `2026.04.23_Catapultar.pdf` (Holterhus and Somraaj, commit `b2583cfc`). The Zenith-branded report (2025.11.19) never covered the validator. |
| Deployments | Base `0x48789d54…1359` (pre-audit, VM v1.0) and `0xc626…dcd7` (VM v1.2, per `docs/runbook/tempo-continuations.md`). Both need replacing. |
| Production use | None. The NCBF product does not use V2 (NCBF PRD D21). intent-factory enables V2 only in develop. `continuation.*` ops are disabled in production compose. The owner expected production "in about 2 weeks" on 2026-09-25. |
| In-flight work that changes V2's contract | Yggdrasil#2006 and intent-factory#422 (open): programs stop emitting balance-delta checks, so the outcome floor becomes the only outcome check. intent-factory#435 (open): move to VM v1.2. |

## 3. Goals

| # | Goal | Status in this PRD |
| --- | --- | --- |
| G1 | Verify a deferred fill on-chain against the user's authored invariants, beyond the per-token floor, without pinning the re-quoted fill calldata. | Kept. |
| G2 | Commit the program through the escrow address (typehash → digest → CREATE2 salt). No new trust root; the executor cannot swap or strip the program. | Kept. |
| G3 | Re-quote safety: the program asserts the end state, never the route. | Kept. |
| G4 | Sandboxed by construction: STATICCALL means a program can only read and revert, so safety does not depend on auditing each program. | Kept. The gas cap is not part of the sandbox (D9). |
| G5 | Add-only over the floor: the outcome check stays mandatory; a bad program can only cause a refund. | Kept for transferable outcomes. See D1 for results that cannot be paid to the validator. |
| G6 | Body sharing: per-user values go in `params`, so users of one operation share one body hash. | Kept. |
| G7 | Additive versioning: v1 bundles, digests and escrow addresses stay untouched. | Kept, and strengthened: v1 bytecode stays byte-identical (section 7). |
| G8 (new) | One settlement implementation. V2 inherits every audited v1 behaviour, so a v1 fix reaches V2 without a manual port. | Added by this PRD. |
| G9 (new) | Smallest audit surface: the auditor reviews only the program step, the V2 digest and the register encoding. | Added by this PRD. |

G1-G7: Yggdrasil PRD G1-G8, D1-D5. Threat model (PRD D9): "settlement is trustless, derivation is trusted". The executor is untrusted. The compose backend and compiler are trusted (risk R-VP9 accepted, client-side re-derivation is non-goal N7).

## 4. Consumers and what they depend on

| Consumer | Depends on |
| --- | --- |
| Compose compiler (Yggdrasil `derive.ts`, intentFactory provider) | Both hashes in the digest; hash 0 = v1 behaviour; 33-byte tight-packed program hash; params hash rule; STATICCALL `runVM` (the compiler emits only the assert-only command subset); register layout baked into every body; program runs after the floor; generous gas cap (the compiler has no gas model); one outcome per settle node, with `amount = minAmount`. |
| intent-factory backend | `prepare-bundle` builds the V2 digest and CREATE2 address from the hashes. The DB stores hashes, program and params (migration 0030). `execute-bundle` re-checks the solver's program-hash echo. The descriptor discloses asserted predicates to the user (disclosure only; nothing reads it at runtime). |
| intent-factory solver | Encodes `entry`; delivers V2 outcomes to the validator (`v2OutcomeReceiver`); decodes `ValidationFailed`, `BadValidationProgram` and `BadValidationParams` in simulation errors. |
| Refunds (`submit-refund`, SDK) | A zero-hash refund constraint signed in the escrow batch; the refund call targets the validator. |
| COM-1647 observed-exact (PR #354) | Reads the `VALIDATION_GAS_CAP` and `VIRTUAL_MACHINE` getters; one absolute third-party predicate. It needs neither pre-balances nor the account register. The gas-cap read is a pre-check in a drill script (`observed-exact.ts:592`) and changes with D9. |

No consumer reads the hashes from `entry` calldata: off-chain they are identifiers in the digest, the DB and the echo. No emitted program reads the account register. After Yggdrasil#2006, no emitted program reads a pre-balance register. IfConsumersV2 §2, ComposeCompilerV2 §2c-b/c.

## 5. Requirements

**hard**: a live consumer depends on it. **convention**: a choice we can change now, at a known cost. **new**: introduced by this PRD.

### Commitment

| ID | Requirement | Level | Kind |
| --- | --- | --- | --- |
| R1 | The EIP-712 constraint commits `validationProgramHash` and `paramsHash`, so the escrow address commits to both. A separate params hash is required: the program hash alone does not cover addresses and amounts (GD-5, intent-factory#223). | MUST | hard |
| R2 | Program hash = `keccak256` of the tight-packed 33-byte commands. Params hash = `keccak256` of the concatenated `bytes32` words. Both are `0` when empty. The TS SDK, the compiler and Solidity agree byte for byte. | MUST | hard |
| R3 | V2 digests never collide with v1 digests. | MUST | hard property; mechanism is D5 |
| R4 | The contract derives both hashes from the program and params in calldata. `entry` does not take them as arguments. | SHOULD | new (D4) |

### Settlement

| ID | Requirement | Level | Kind |
| --- | --- | --- | --- |
| R5 | Settlement is v1's pay-the-validator model, inherited from `main`: the fill pays the validator, the validator checks its own balance against each outcome amount and forwards its full balance; destination `address(0)` means the signer. Duplicate outcome tokens stay unsupported (audit 6.1.1 note). | MUST | hard |
| R6 | Allowances, executor binding, nonces (including perpetual nonce 0) and `BalanceOfFailed` behave exactly as v1, because V2 calls the v1 code. | MUST | hard |
| R7 | An empty program gives exact v1 behaviour at about v1 gas cost. Non-empty params with an empty program revert with `BadValidationParams`. | MUST | hard (Yggdrasil#2006 commits zero hashes when there are no invariants) |
| R8 | Every V2 escrow can refund through a zero-hash constraint whose call targets the validator. | MUST | hard |
| R9 | The fill call forwards no native value from the validator to the execution target. **Reason:** v1's `_call` forwards `selfbalance()` into the call proxy. Before the fill, the validator never holds native value legitimately: `entry` is not payable, `_handleAllowances` moves ERC-20 only (`safeTransferFrom`), and `_validatePayment` forwards the full balance after each settlement. So the only native balance the call can carry is stray or force-fed ETH. Anyone can send 1 wei through `receive()`; every fill whose target function is not payable then reverts, including `IntentExecutor.executeAndSweep`. Forwarding zero removes that block and loses no legitimate flow. intent-factory's `CATValidatorV1_1._call` already forwards zero for this reason (`CATValidatorV1_1.sol:274`). | SHOULD | new (D6) |

### Program execution

| ID | Requirement | Level | Kind |
| --- | --- | --- | --- |
| R10 | The program runs after the payment check, through STATICCALL to `runVM` on an immutable VM address. Any revert, including out-of-gas, reverts `entry` with `ValidationFailed(bytes)`. | MUST | hard |
| R11 | The VM address is exposed as the `VIRTUAL_MACHINE` getter. The VM call's gas is bounded by the executor's transaction gas limit; an immutable `VALIDATION_GAS_CAP` is optional and is decided in D9. | MUST (getter) | hard for the getter; convention for the cap (D9) |
| R12 | A VM address without code fails closed (a STATICCALL to an address without code succeeds vacuously). | MUST | hard |
| R13 | The register file is `params ++ [account] ++ spent[] ++ paid[]`, then zeroed scratch. `spent[i]` is the amount v1 pulls from the escrow for allowance `i`: a literal spend as written, a `SPEND_BALANCE_OF_MAGIC` spend as the escrow balance that remains when v1 reaches that allowance. `paid[j]` is the amount v1 forwards for outcome `j`, recorded at the moment of the transfer. The prefix ends below the VM's void register (`0x7A`). | MUST | hard for params; account is D3; flow registers are D2 |
| R14 | Malformed inputs revert with `BadValidationProgram` (length not a multiple of 33) or `BadValidationParams` (params without a program, or a prefix too long). `entry` types the params as `bytes32[]`, so a word that is not 32 bytes cannot be encoded. The error names stay, because the solver decodes them. | MUST | hard |

### Non-functional

| ID | Requirement | Level |
| --- | --- | --- |
| N1 | v1 (`CATValidator` and `CATValidatorTron`) creation bytecode stays byte-identical, so its CREATE2 address and audit status hold. Measured: adding `virtual` to v1 functions leaves the bytecode unchanged (solc 0.8.35, via-IR, `bytecode_hash = 'none'`). | MUST |
| N2 | Upstream CI is green, coverage included. | MUST |
| N3 | V2 is audited before production (PRD R-VP8), against the VM version it will run with in production. | MUST |
| N4 | The V2 tests run in CI. Today about 20 of 30 fork tests skip because CI sets no `VC_MAINNET_RPC_URL`. | SHOULD |
| N5 | Deterministic CREATE2 deployment with the same address on every chain that has the VM. | SHOULD |

## 6. Non-goals

- **CATValidatorV1_1 and the NCBF lane.** They are separate products with their own validator.
- **Cross-chain composer fills.** V2 is same-chain only (the owner's decision, 2026-08-14 Q10).
- **Deployed or registry program mode** (`validationProgramRef`, PRD FR-R2b). It was never built. This PRD drops it formally.
- **Client-side re-derivation of programs** (N7). The compiler stays trusted for "program matches intent".
- **Validators that are not VM programs** (N2).
- **Negative space and `dustBound`** (removed 2026-07-03, griefing risk R-VP10).
- **Pre-fill program section** (a program that runs before the fill and fills registers). It is the owner's stated future direction for triggers and X-ii, and is out of scope for this V2. The `spent[]` registers (D2) are measured by the validator, not by a program, and already cover "relative to what the user deposited".
- **The off-chain echo as a safety check.** It is a drift canary; COM-1432 removes it.

## 7. Proposed design

```text
contract CATValidatorV2 is CATValidator, Tstorish {  // inherits main v1, audited
  immutable VIRTUAL_MACHINE                          // no gas cap: see D9

  entry(execTarget, execPayload, account, nonce,
        allowances, outcomes, program, bytes32[] params, signature)   // 9 args
    programHash = program.length == 0 ? 0 : keccak256(program)
    paramsHash  = params.length == 0 ? 0 : keccak256(abi.encodePacked(params))
    if nonce != 0: _checkNonce(account, nonce)        // v1
    check signature over the V2 typehash(…, programHash, paramsHash)
    if programHash != 0: spent[] = replay of the v1 allowance order (literal spend, or
                                   remaining escrow balance for a MAGIC spend)
    _handleAllowances(execTarget, account, allowances) // v1
    if execPayload not empty: _call(execTarget, execPayload)   // V2 override: zero value
    if programHash != 0: start recording in a transient slot (Tstorish)
    _validatePayment(account, outcomes)                // v1: pay the validator, forward
      _transfer(token, amount, dest)                   // V2 override: paid[j] = amount
    if programHash != 0:
      paid[] = take and clear the record
      STATICCALL VM.runVM(program, registers = params ++ [account] ++ spent ++ paid ++ zero scratch)
        any failure → ValidationFailed(ret)

  entry(7-arg, inherited)  → overridden to revert    // V2 escrows never sign v1 digests
```

| Change vs current V2 | Why | Cost |
| --- | --- | --- |
| Subclass of v1 instead of a copy | G8: v1 fixes reach V2 automatically. The audit scope shrinks to the program step. | Add `virtual` to `_domainNameAndVersion`, `entry` and `_call` in v1 (bytecode-neutral, pinned by `script/check-v1-bytecode.sh`). |
| Derive hashes on-chain (9-arg `entry`) | The supplied hashes are enforced equalities today, so they carry no information. Removes 2 stack slots and the duplicate checks in the SDK. | The `entry` ABI and selector change; SDK, solver and backend encoders update. No program body changes. |
| Params as `bytes32[]`, not `bytes[]` | The type guarantees 32-byte words, so the params hash is one `keccak256` of the packed array and the "word is not 32 bytes" check disappears. Registers stay `bytes[]` because the VM's `VMState` sets them; `buildRegisters` wraps each word, as it already does for `spent` and `paid`. | Encoders pass `bytes32[]`; a word of the wrong size fails at ABI encoding instead of on-chain. The params hash rule and every committed hash are unchanged. |
| Replace `preBalances` with `spent[]` and `paid[]` | Destination pre-balances measure the wrong thing: under pay-the-validator their delta equals the forwarded amount, which the floor already checks, and they carry no information about the deposit. Flow registers give programs the two amounts that relational checks need (D2). | Every program body hash changes, so fixtures and the compiler re-pin in lockstep. One extra `balanceOf` per magic-spend allowance, only when a program is committed. No v1 change. |
| `paid[]` recorded by a `_transfer` hook in transient storage | v1's `_transfer` is already `virtual`. Recording the amount v1 forwards, at the iteration it forwards it, is the only reading that cannot drift from v1: a pre-read of the validator's balance before `_validatePayment` is wrong when an earlier outcome's transfer changes a later outcome's balance (a native outcome whose destination mints the next outcome's token in `receive()`). | One `TLOAD` per outcome on the empty-program path. Tstorish (`TSTORE` with an `SSTORE` fallback) keeps the contract deployable on chains without Cancun. |
| `spent[]` replayed in memory, not hooked | v1 `_handleAllowances` has no hook, and adding one (`_transferFrom`) changes v1 bytecode. The replay mirrors v1's loop: a literal spend as written, a magic spend as the escrow balance less earlier spends of the same token. | One `balanceOf` per magic-spend allowance. |
| Fill forwards zero native value | See R9 and risk K2. | Needs `virtual` on v1 `_call` (bytecode-neutral) and a V2 override. |
| Test set: unit tests with a stub VM, hash-parity vectors, one fork integration test | Drops `derivation/` (no test reads it) and the 918-line program table. | Fork tests need an RPC secret in CI, or a locally deployed VM. |

**Stack budget.** v1 `entry` uses 11 stack slots, the current V2 uses 17. Measured on scratch copies:

- V2 fails both coverage modes.
- Derived hashes (15 slots) and a validation struct (12 slots) compile only with `--ir-minimum`.
- Only an ABI that packs the order into one struct (6 slots) compiles under the legacy coverage that upstream CI runs.

D4 chooses between those options. Measured on the shipped contract: `forge build` and `forge coverage --ir-minimum` compile, legacy coverage does not, so CI runs coverage with `--ir-minimum` (D4-A). The `spent[]` and `paid[]` arrays live in memory and are built in helpers, so they add no `entry` stack slots.

## 8. Decisions

### D1. What is the outcome of a continuation whose result cannot be paid to the validator?

Pay-the-validator works for any transferable token: aTokens and ERC-4626 shares can be minted to the validator and forwarded. It does not work for results that cannot move: debt repayment, positions credited directly to the user, NFTs that are not transferable, locked stakes. Today's uc1 fill supplies to Aave with `onBehalfOf = delivery`, so under 6.1.1 it reverts with `InvalidTokenAmount`. No Yggdrasil design exists for this case.

- **A (chosen).** V2 supports transferable results only. The compiler routes every result through the validator; for Aave, `onBehalfOf = validator`. Programs add checks the floor cannot express.
- **B.** Allow outcomes with `amount = 0` and let a program check the result at the delivery address. This needs pre-fill state, which reopens the 6.1.1 inflation risk at the program layer.
- **C.** Add a pre-fill program section now (the owner's stated future direction).

> Decision: A for this V2. B and C are recorded as the next version's scope.

**Is there a pre-fill section today?** No. No version of V2 runs any program before the fill. Before the fill, the validator does three things:

1. It checks the nonce and the signature.
2. `_handleAllowances` checks `allocated ≥ spend` for each allowance and pulls `spend` from the escrow. With `SPEND_BALANCE_OF_MAGIC` the spend is the escrow's whole balance. This is an upper bound on what the fill may take, not a check that the user deposited enough.
3. The pre-audit v1 and the original V2 read each destination's balance before the fill (`_recordBalances`). That was a read for the later delta, not a check, and audit 6.1.1 removed it.

The check that the deposit is large enough happens off-chain: intent-factory's detector arms a bundle only when the escrow balance reaches `detect_at_least` (`services/detector/src/detect.ts`). A pre-fill program was prototyped once in intent-factory#350 (V′, a committed probe program that filled registers) and closed unmerged.

### D2. Replace the pre-balance registers with flow registers?

**Why destination pre-balances are not needed.** They let a program compute "the destination's balance went up by at least N". Under pay-the-validator, the validator itself measures what it forwards: its own balance after the fill. That balance is exactly the increase it causes at the destination, so the delta check repeats the outcome floor (except for outbound fee-on-transfer and rebasing tokens). A destination pre-balance is also a weak input: a third party can change the destination's balance during the fill, which is the 6.1.1 bug class.

**What pre-balances cannot do either.** "User X received 90% of the deposited token Y" needs the deposited amount. A destination pre-balance does not contain it. When the deposit is known at signing (a fixed-amount bundle), no program is needed: set the outcome to `{token: Y, amount: 0.9 × D, destination: X}`. When the deposit is unknown at signing, the outcome amount cannot scale with it. intent-factory's solve-time (amount-flexible) bundles hit this today: they carry no on-chain outcome, and the solver enforces the signed rate off-chain (`solve-time-quote.ts:260-261`, "Trusted mode enforces the signed rate off-chain").

**Flow registers make that check on-chain.** The validator already measures both sides of the flow. V2 exposes them as registers:

```text
allowance  {token: Y, allocated: MAX, spend: SPEND_BALANCE_OF_MAGIC}   → spent[0] = Y the validator pulled from the escrow
outcome    {token: Z, amount: hard floor or 0, destination: X}          → paid[0]  = Z the validator forwarded to X
params     [num, den]   e.g. [9000, 10000], or the signed minDestinationRate
program    assert paid[0] * den ≥ spent[0] * num
```

With Z = Y this is "X received at least 90% of the deposit". With Z ≠ Y it is the signed minimum rate. The validator measures both values itself, so the executor cannot misreport them. A donation to the validator only raises `paid`, and the donation also reaches X. A donation to the escrow only raises `spent`, which makes the check stricter. `num` and `den` sit in params, so all users of the rule share one body hash (G6). If the spend is not the magic value, the ratio holds for what was spent, and the rest stays in the escrow for a refund. A program that must also prove the escrow is empty reads the account register (D3).

> Decision: replace `preBalances` with `spent[]` and `paid[]`, together with Yggdrasil#2006 and one lockstep re-pin of the body hashes. This also gives the compiler and intent-factory a path to move the solve-time rate on-chain later.

### D3. Keep the account register?

No emitted program reads it. It exists because the escrow address depends on the program hash, so a program cannot contain that address as a literal (PRD Q4). Keeping it costs one register write.

> Decision: keep. Escrow-side checks (for example "the escrow holds nothing after the fill", D2) need it, and removing it later would cost another re-pin.

### D4. ABI shape and the coverage fix

- **A.** Derive hashes on-chain (9 arguments) and run coverage with `--ir-minimum` in CI (a one-flag workflow change for the whole repository).
- **B.** Pack the order into one calldata struct. Legacy coverage passes, but the ABI looks different from v1's.

> Decision: A. The ABI stays close to v1, and the CI flag is the documented Foundry workaround.

### D5. Keep EIP-712 domain version "2"?

Collision safety does not need it: the type string and `verifyingContract` already differ. Keeping "2" needs `virtual` on v1's `_domainNameAndVersion`, and that change is bytecode-neutral.

> Decision: keep "2". Wallets and tools show the version, and the cost is zero.

### D6. The 1-wei denial of service on main v1

Main v1 has a public `receive()` and forwards `selfbalance()` into the call proxy. Anyone can send 1 wei to the validator. Every fill whose target function is not payable then reverts, including `IntentExecutor.executeAndSweep`. A scratch forge test reproduces this. No audit reports it. intent-factory's V1_1 already forwards zero value for this reason.

- **A.** Fix it in V2 only (override `_call`) and report it upstream as a v1 finding.
- **B.** Fix v1 too. This changes v1 bytecode and its CREATE2 address, so v1 needs a redeploy.

> Decision: A now. The repository has GitHub issues disabled, so the v1 finding is recorded here and in the V2 pull request instead of a separate issue. The test `test_entry_strayNativeBalanceDoesNotBlockNonPayableFill` pins the V2 behaviour.

### D7. Which VM version does the audit target?

The VM address is immutable, and program bodies embed the InvariantChecker and ArithmeticProcessor addresses. A VM move therefore means a new V2 deployment and new body hashes. intent-factory#435 moves to VM v1.2. Measured uc1 `entry` costs about 437k gas with an invariant-only program.

> Decision: audit against VM v1.2.

### D8. What happens to catapultar#42?

> Decision: close it after the new branch opens. PR #42 is closed. Keep its commits as history, and fix the "Zenith" naming in the new commits to cite `2026.04.23_Catapultar.pdf`.

### D9. Do we need a strict gas cap on the VM call?

No, not for safety. The current V2 forwards at most `VALIDATION_GAS_CAP` (5,000,000, a constructor immutable). The cap gives less protection than its name suggests:

- **Fail-closed holds without it.** STATICCALL already prevents state changes. If the VM runs out of gas, the call returns failure and `entry` reverts, so nothing settles. Without a cap the VM gets all but 1/64 of the remaining gas, and the 1/64 left over only has to revert.
- **Executor cost has a bound without it.** The executor sets the transaction gas limit from its own simulation, so a costly program costs at most that limit. The cap only tightens a bound that already exists.
- **The cap does not stop gas games.** CALL forwards the smaller of the cap and 63/64 of the remaining gas. An executor that sends too little gas can still make a valid program fail, with or without the cap. The result is a revert, and the K3 rule applies: never classify a failure by selector alone.
- **The cap has a real cost.** It sits in the creation code, so it fixes the CREATE2 address. One address on every chain forces one cap for chains with very different gas metering (Tempo meters about 5.1× Ethereum, per the drill notes), the same trade-off as ERC7821LIFI audit 6.1.2. A valid program could then fail only on the expensive chain and refund.

* **A.** No cap: STATICCALL with all available gas. Drop `VALIDATION_GAS_CAP`; COM-1647's drill pre-check drops the getter read.
* **B.** Keep the immutable cap (status quo), with one lowest-common cap or per-chain addresses.
* **C.** Commit a cap per constraint in the signed data. This needs a typehash change and a gas model in the compiler, which does not exist.

> Decision: A. It removes a constructor argument, keeps one address on every chain, and gives up no safety property.

## 9. Rollout and migration

1. **catapultar:** add `virtual` to v1 (bytecode-neutral, CI asserts the bytecode is unchanged); implement V2 as a subclass; port the TypeScript; open a new PR for the audit.
2. **Yggdrasil (lockstep):** merge #2006; replace the pre-balance slots with `spent[]` and `paid[]` (D2); route results to the validator (D1-A); regenerate the hash-parity vectors once.
3. **intent-factory:** vendor the new V2; update the `entry` encoders (9 arguments, params as `bytes32[]`), the solver's receiver, the refund target and the fixtures; fix the descriptor's empty-params hash (`descriptor.ts` says keccak of empty bytes; the contract uses 0).
4. **Audit** V2 against VM v1.2.
5. **Deploy** by CREATE2 on each chain; retire `0x48789d54…` and `0xc626…dcd7`.
6. **Drill** on the Aspire fork: `yarn e2e:vc`, `yarn e2e:observed-exact`, `yarn e2e:compose`.

No V2 bundles exist in production, so no escrow needs migrating.

## 10. Risks and known limits

> **K1. Absolute checks pass on balances the user already had.** A program sees only the state after the fill. "USDC balance of the delivery address ≥ 500" passes if the address already held 500 USDC, whatever the fill did. uc1's second assertion has this shape, and its fork test passes by giving USDC directly to the delivery address. The descriptor must say that a check is a post-state check, not a fill-caused change.

> **K2. 1-wei denial of service** (D6) on main v1 and the current V2.

> **K3. Forged error selectors.** A fill target controls its revert data, so it can revert with bytes that decode as `ValidationFailed` or `InvalidTokenAmount` (same class as the ERC7821LIFI audit 6.1.1). The current V2 NatSpec claims the errors are distinguishable. Off-chain failure classification must not trust the selector alone.

> **K4. Trusted compiler.** A compromised compose backend can disclose a strong predicate and commit a weak one (R-VP9, accepted). The blast radius is the funded amount.

> **K5. Gas cap per chain.** If D9 keeps an immutable cap, one CREATE2 address assumes equal gas metering of the VM on every chain (ERC7821LIFI audit 6.1.2 is the same class). D9-A removes this risk.

> **K6. Validator selection in intent-factory.** No policy rejects a V2 validator without a validation group, and `validator-version.ts` maps the V2 address to version "1". [INFERENCE] Such an escrow could not settle. Fix in the intent-factory migration.

## 11. Sources

- Yggdrasil PRD `2026-07-verified-continuations-validation-programs.md` (recovered from `feat/verified-continuations` 8d766229c), SOC plan, GD-1…GD-8 plans.
- Yggdrasil `origin/main` 58deeee63: `derive.ts`, `provider.ts`, `settle.ts`, `ir0_to_isa.rs`; PR #2006.
- intent-factory `catv2-pre-audit`: backend prepare/execute/submit-refund, solver compose and same-chain paths, `descriptor.ts`, migration 0030, NCBF PRD D21; PRs #212, #223, #350 (closed V′), #354 (COM-1647), #422, #435.
- catapultar `main` bc486a4 and PR #42; audit reports in `solidity/audits/`; scratch experiments for bytecode neutrality, stack budget and the 1-wei test.
