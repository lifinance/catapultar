# Internal review — CATValidatorV2 (catapultar PR #43)

Status: reviewed commit `8d1aed7` on 2026-10-15. Finding 3 is fixed in `b0a9c2e`
(`_replaySpends` is gone; `_handleAllowancesRecorded` records each spend inside
the allowance loop, and `test/CATValidatorV2.AllowanceParity.t.sol` fuzzes its
parity with v1). The five PoCs are committed under `test/audit/` and pass on the
current code. Findings 1, 2, 4 and 5 are open as producer guidance or documented
limits; see design doc §10 K7 and the PR body. The system map, hunt checkpoints
and raw slither/aderyn output that this report cites under `.sc-audit/` are not
committed. Line references in the report point at `8d1aed7`.

The report below is unchanged from its 2026-10-15 text.

---

Method: checkpointed Map→Hunt→Attack→Verify pipeline (`skill://audit-pipeline`): 6 parallel hunt lanes (callback/liveness, accounting, semantic consistency, token/oracle, economic, adversarial-deep) over `.sc-audit/SYSTEM.md`, static analysis via slither 0.11 (89 results, triaged) and aderyn 0.1.9 (10 results, triaged), hypothesis falsification and PoC proofs with forge 1.7.1 (solc 0.8.35, via-IR), independent skeptic+judge verification per finding. References loaded: `severity.md`, `report-writing.md`, `static-analysis-triage.md`, the refund-binding plan, and the V2 design doc.

## Scope

**Summary.** We reviewed the `catv2-encode` branch of catapultar at commit `8d1aed7` (the new `CATValidatorV2`, its two libraries, the virtual hooks in the audited v1 validator, the deploy script, and the TypeScript SDK's V2 support; 6 source files, ~500 new contract lines). V2 lets a signed constraint commit a validation program that runs on the LI.FI VirtualMachine after the fill, plus a target/payload binding that secures the refund shape. The settlement core is sound: we could not break signature commitment, nonce replay protection, the binding checks, atomicity, or the fail-closed VM call, and the existing 333-test suite passes. We found 1 medium and 3 low issues, all proven with executable PoCs, plus 1 medium-confidence design note (cross-validator nonce invalidation, also proven mechanically). The most actionable item: for same-token round-trip constraints the producer must bind `payloadHash`, because a pass-through fill through the validator itself satisfies any same-token floor. The escrow owner keeps the ability to recover funds through the refund path in every failure we found. This review covers the listed files only and does not certify the code as free of bugs; the LI.FI VirtualMachine itself, the Catapultar escrow contracts, and the compose compiler are out of scope.

| # | Title | Severity | Status | Proof |
|---|-------|----------|--------|-------|
| 1 | Same-token pass-through fill satisfies any floor with zero work (ECON-02) | Medium | verified | `test/audit/PassThroughFill.t.sol` |
| 2 | Cross-validator nonce shadowing: v1 and V2 each settle the same account+nonce (HS-AD-01) | Medium | verified (mechanism); loss is [INFERENCE] | `test/audit/CrossValidatorNonceShadowing.t.sol` |
| 3 | `spent[]` replay diverges from actual pulls for non-1:1 tokens (5 lanes) | Low | verified | `test/audit/SpentReplayDivergence.t.sol` |
| 4 | Outcome tokens with sender-fees/transfer caps brick settlement (AE-02) | Low | verified | `test/audit/LivenessAndSemantics.t.sol` |
| 5 | Committed destination becoming unpayable bricks the constraint (HS-CL-003) | Low | verified | `test/audit/LivenessAndSemantics.t.sol` |

All six candidates went through independent skeptic + Devil's-Advocate verification. Five were sustained with no DA conflict. The sixth (`_replaySpends`'s `_balanceOf` vs v1's `_safeBalanceOf`, HS-SC-02) was degraded by the verify-DA as fully mitigated (the divergent value is memory-only and never observable: `_handleAllowances` reverts `BalanceOfFailed` before the VM step, atomically); per the pipeline's verify-DA precedence for informational findings it moved to Design Tradeoffs below. The full DA chain lives in `.sc-audit/checkpoints/verify-*.json`.

## Finding 1 — Same-token pass-through fill satisfies any floor with zero work

**Status:** verified — `forge test --match-contract PassThroughFillPoC` (passes on current code, demonstrating the issue).

**Location:** `src/CATValidator.sol:197-211` (`_handleAllowances` pulls to `execTarget` without excluding `address(this)`), `src/CATValidator.sol:178-195` (`_validatePayment` floor check), `src/CATValidatorV2.sol:137-160` (0/0 binding path).

**Description.** The outcome floor and the `spent`/`paid` flow registers measure *funds passing through the validator*, not *performance of the committed action*. When the allowance token and the outcome token coincide and the constraint carries the default 0/0 binding, the executor can call `entry(execTarget = address(validator), execPayload = "")`. The pulled allowance lands on the validator, satisfies a nonzero floor, is forwarded in full to the committed destination, and a `paid >= k * spent` flow program sees a perfect ratio. No external action runs; the nonce is consumed.

**Impact.** Direct: griefing — the user's signed action (bridge-back, repay-and-return, claim-then-forward) never executes and the shared execute/refund nonce burns; funds reach the committed destination, so there is no direct theft. Consequential loss from the elided action (e.g. liquidation because a debt was not repaid) is [INFERENCE] and stays out of the rating. Rating line: Impact Moderate (griefing; attacker pays only gas). Likelihood Medium (config interaction: same-token in/out is a natural round-trip shape; the 0/0 binding is the documented execute default). Matrix: **MEDIUM**.

**Attack path (PoC values).** (1) Signer commits allowance `{T, allocated = max}` + outcome `{T, 990 ether, destination}` with 0/0 binding; escrow holds 1000 T. (2) Executor calls `entry(execTarget = validator, payload = "", spend = MAGIC)`. (3) `_handleAllowances` moves 1000 T to the validator; the floor (990) is met by those same funds; `_validatePayment` forwards the full 1000 T to `destination`; `spentNonces[signer][1]` is set. Total external work: zero calls.

```solidity
vm.prank(executor);
validator.entry(address(validator), hex"", signer, 1, alls, outs, unboundBinding, noProgram, noParams, sig);
assertEq(token.balanceOf(destination), 1000 ether); // floor met with no work
assertTrue(validator.spentNonces(signer, 1));       // nonce consumed
```

**Recommendation.** In the SDK/producer: whenever the allowance token set intersects the outcome token set, bind the payload (`payloadHash = keccak256(execPayload)`, and normally `executionTarget` too) so the fill must perform the committed call. On-chain (optional, defense in depth): document in `CATValidatorV2` NatSpec that a same-token constraint with a 0/0 binding carries no work guarantee — the floor measures flow, not action. Regression check: with `payloadHash` bound, the PoC path reverts `PayloadNotCommitted`; the PoC still passes on unbound code.

## Finding 2 — Cross-validator nonce shadowing

**Status:** verified for the mechanism (`forge test --match-contract CrossValidatorNonceShadowingPoC`); the loss scenario is [INFERENCE] on the migration shape.

**Location:** `src/CATValidator.sol:45` (`spentNonces` in per-contract storage), `src/CATValidator.sol:106-111` (`_checkNonce`), `script/deploy.s.sol:44-48` (`runValidatorV2` keeps v1 live).

**Description.** v1 `CATValidator` and `CATValidatorV2` are simultaneously live at canonical CREATE2 addresses by design ("adopt V2 without moving their escrow addresses"). Nonce invalidation is per-contract storage: settling a constraint at nonce N on V2 marks `spentNonces` on V2 only. An escrow holding live approvals and approved digests on *both* validators — the staged-migration shape the SDK produces — can be settled once per validator at the same nonce. The v1 NatSpec promises "invalidating other approvals by nonce" (`src/CATValidator.sol:32`), and the refund design (E1) deliberately shares a nonce between execute and refund constraints so settlement kills the sibling — training integrators to model invalidation as account-scoped. It is contract-scoped.

**Impact.** An executor holding a stale signed constraint on the other validator version can settle it after the user believes the nonce was consumed: the escrow pays twice for what its owner modeled as one intent, bounded by the signed allocations (each settlement still honors its own signed floors — this is an unexpired-offer problem, not forgery). Rating line: Impact Moderate (bounded loss at stale signed terms). Likelihood Medium (config interaction, per the privilege rule: keeping both validators live and reusing nonce 1 — the SDK default — are each valid choices). Matrix: **MEDIUM**. If the reader adopts the strict per-contract reading of INV-2, this finding is a documentation/consistency issue (Low); the write-up stands under the NatSpec+E1 reading.

**Attack path (PoC values).** (1) Escrow approves token T to v1 and V2, approves digests for a v1 constraint and a V2 constraint, both nonce 1, allowance spend 100 T each. (2) V2 settles: `spentNonces[escrow][1]` set on V2, 100 T pulled. (3) v1 settles: `spentNonces[escrow][1]` unset on v1, approvals live → another 100 T pulled. (4) Neither can be replayed within its own contract (`NonceAlreadySpent`).

**Recommendation.** Document the contract-scope of nonce invalidation in the v1/V2 NatSpec and the migration guide (replace "invalidating other approvals by nonce" with "…within this validator contract"). Integrators migrating an escrow from v1 to V2 should revoke the v1 digest approval (`setSignature`) and/or v1 token approvals, or use fresh nonces per validator version. A contract-level fix (shared nonce registry) would change the deployed v1 bytecode and is not recommended; the fix is documentation + migration hygiene.

## Finding 3 — `spent[]` replay diverges from actual pulls for non-1:1 tokens

**Status:** verified — `forge test --match-contract SpentReplayDivergencePoC` (two runs: actual pull 901 ether, register claims 900).

**Location:** `src/CATValidatorV2.sol:230-251` (`_replaySpends`), `src/CATValidator.sol:197-211` (the v1 loop it mirrors).

**Description.** `_replaySpends` reconstructs each `SPEND_BALANCE_OF_MAGIC` spend arithmetically: one `_balanceOf` read before any allowance moves, minus the *nominal* earlier same-token spends (clamped at zero). v1's loop instead reads a fresh balance *inside* the loop, after each earlier `transferFrom` has executed. The two coincide only when every earlier same-token transfer debits the escrow by exactly the nominal spend. Divergence families: (a) stETH-class share rounding (sender debited 1–2 wei less than nominal), (b) Aave aToken-style index accrual triggered by the earlier pull (escrow balance *rises* mid-loop), (c) sender-side fee/burn tokens (balance falls *faster*), (d) callback-capable earlier allowances whose hook moves the later MAGIC token's escrow balance.

**Impact.** Under-reported `spent[i]` weakens committed rate checks of the documented `paid[0] * den >= spent[i] * num` shape: the program passes although more was pulled than the value it priced. Over-reported `spent[i]` reverts honest fills (recoverable DoS). Magnitudes: dust for stETH (1–2 wei per prior same-token pull); the aToken path is bounded by interest accrued since the pool's last interaction — the user's own unaccrued yield. Blast radius is capped by the signed `allocated` per allowance. Rating line: Impact Moderate at the ceiling (bounded loss of unaccrued yield), Minor for the realistic stETH shape (dust). Likelihood Low (requires a same-token multi-allowance constraint with a rate program over the drifted register *and* a drifting token — several realistic states that must coincide). Matrix: **LOW**. Five independent hunt lanes found this; two rated Medium on the hook/accrual variants — the rating here applies the precondition test (executor-funded donation is a wash; accrual is bounded yield). The documentation currently asserts the opposite of the behavior: the NatSpec states a MAGIC spend "is the escrow balance that remains at that point of the order" (`CATValidatorV2.sol:36-38`, `225-228`) and INV-9 states `spent[i]` equals what v1 pulls — the divergence is undocumented, not an accepted limit (verify-DA `by_design` dimension).

**Attack path (PoC values).** Escrow 1000 LOSSY (1%-loss-on-debit mock, stETH mechanics scaled for visibility); allowances `[100 literal, MAGIC]`; committed program. Run A (accepting VM): the literal pull moves 100, the MAGIC pull resolves to the true balance 901 → execTarget receives 1001. Run B (echo VM): the register file the VM receives claims `spent = [100, 900]`. Divergence: 1% of the first spend. On stETH the same shape yields 1–2 wei.

**Recommendation.** Measure, don't simulate: record `spent[i]` the way `paid[j]` is recorded — have `_handleAllowances` (or a V2 override point) measure the escrow balance delta around each pull into transient storage, instead of reconstructing it pre-loop. Short of that, document that `spent[]` is exact only for 1:1 tokens, and have the compiler avoid rate checks over `spent[i]` for stETH/aToken-class tokens (or read the account register and let the program compute emptiness instead). Regression check: after a measurement fix, run B's register file must show 901.

## Finding 4 — Outcome tokens with sender-fees or transfer caps brick settlement

**Status:** verified — `test_cappedTokenOutcome_bricksSettlement` (fill delivers 1000 CAP to the validator; the capped forward reverts; every settlement of the constraint reverts).

**Location:** `src/CATValidator.sol:178-195` (`_validatePayment` single full-balance `_transfer`).

**Description.** The payment step equates "balance held" with "deliverable in one transfer". A token with a per-transfer cap below the delivered balance, or a sender-side fee on top of the amount, makes the forward revert — permanently for that constraint (the revert is deterministic, not state-dependent). Recipient-side fee-on-transfer semantics are documented intent (v1 NatSpec: "Fee on transfer tokens will arrive with the amount minus the fee"); the sender-side and capped sub-cases are not accommodated anywhere, in contrast to the inbound lossy-token sweep that the refund tests pin.

**Impact.** Availability only: the constraint can never settle; escrow funds are safe (INV-5 atomicity) and recoverable via the bound refund or a direct owner call. The verify pass adds two strengthening observations: (1) no sweep/rescue/withdraw function exists anywhere in `src/`, so a capped token balance above the cap is *permanently stuck in the shared validator* once delivered; (2) because INV-6's full-balance forward sweeps donations too, a third party can pre-donate the capped token to the validator and push the balance over the cap, bricking settlements even when the committed floor is at or below the cap. Rating line: Impact Moderate (core-function DoS for this constraint, funds recoverable for the escrow; donated excess is stuck). Likelihood Low (requires committing such a token as an outcome; mainstream outcome tokens don't cap). Matrix: **LOW**.

**Recommendation.** Document the supported-token constraint (outcome tokens must permit full-balance single transfers from the validator) and the donation-over-cap grief vector. A code fix is optional: splitting the forward into cap-sized chunks only helps the cap case and complicates the gross `paid[j]` semantics; the refund path is the intended recovery.

## Finding 5 — A committed destination that becomes unpayable bricks the constraint

**Status:** verified — `test_revertingNativeDestination_bricksSettlement`.

**Location:** `src/CATValidator.sol:178-195` (push loop, no per-outcome isolation; `safeTransferETH` forwards all gas).

**Description.** `_validatePayment` pushes every outcome to its committed destination; one reverting destination (contract wallet that starts reverting on receipt, token pause/blacklist of validator or destination) reverts the whole settlement, including all other outcomes and the program step. Destinations are signer-committed, so this is not attacker-chosen; the risk materializes on post-signature state changes.

**Impact.** Availability only, recoverable as in Finding 4. Rating line: Impact Moderate (constraint bricked), Likelihood Low (committed destination changes behavior post-signature). Matrix: **LOW**.

**Recommendation.** Document; consider pull-over-push forwarding in a future version. No change required for the refund path to remain the recovery route.

## Design Tradeoffs (degraded on verification — mechanism real, harm closed by design)

- **`_replaySpends` uses `_balanceOf` where v1 uses `_safeBalanceOf`** (`src/CATValidatorV2.sol:242` vs `src/CATValidator.sol:206`; HS-SC-02). The replay computes a native balance for a `token == address(0)` MAGIC allowance where the v1 loop reverts `BalanceOfFailed`. The verify-DA degraded this to fully mitigated: call order (`_handleAllowances` runs before `_runValidation`) plus atomic revert means the divergent value is memory-only and never reaches the VM or any register file; settlement outcomes are identical to v1 (PoC `test_nativeMagicAllowance_failsClosed`). The residual is semantic only: the code suggests native-token allowances are supported when they are not (they are unsettleable in both v1 and V2 — also for literal spends, via `TransferFromFailed`). Suggested tidy: use `_safeBalanceOf` in `_replaySpends` for exact mirrored edge semantics, or document that native-token allowances are unsupported by construction.
- **Push-based full-balance forwarding** (Findings 4–5 share this root): single `_transfer` per outcome, no isolation, no sweep. Deliberately inherited from audited v1; the liveness consequences are reported as findings where the token/destination behavior is not among the documented K1–K7 limits.

## Discarded candidates

- Reentrancy into the validator mid-settlement (HS-CL-001 hypothesis): `entry` is `nonReentrant`, `_transfer` is internal, and every reachable callback leaves the settlement atomic; no path survived dry-run.
- `ValidationFailed(bytes)` selector spoofing by fill targets: documented as K3; off-chain classification guidance, not a contract defect.
- Slither/aderyn residual hits (uninitialized-local, missing-zero-check, locks-Ether, yul `return`, unused error): triaged false positives or out of scope in `.sc-audit/raw/`.
- The old v1 1-wei DoS: fixed in V2 (K2/D6) and the v1 bytecode pin holds — checked, not re-reported.

## Informational and gas

| Item | Detail |
|---|---|
| Constants & parity coverage (HS-SC-03) | All derivable constants recomputed and match: `RUN_VM_SELECTOR = 0x00a32e6c`, the V2 typehash/type string, v1 Allowance/Outcome typehashes, domain name/versions, `SPEND_BALANCE_OF_MAGIC`, register constants (123/121/void 122), the prefix bound at `entry` (no off-by-one), PAID_SLOT counter conventions, and the TS `ExecutionConstraintV2Typed` field order. Two undocumented but behavior-neutral assembly idioms remain: `codesize()` as the call's (dead) out-offset (`CATValidator.sol:241`, `CATValidatorV2.sol:325`, `CallProxy.sol:34`) and v1's scratch-space returndata copy (`CATValidator.sol:246-247`, fixed in V2 at `CATValidatorV2.sol:329-332`). |
| Guard scope (HS-CL-002) | Solady `nonReentrant` covers both live entry points; mid-settlement callbacks (ERC-777 hooks, the CallProxy payload, outcome forwards) can still act on *escrow or integrator* contracts outside the guard. No in-scope exploit path exists; integrators reading validator/escrow state mid-settlement should treat it as intermediate. |
| VM trust is address-only (HS-AD-02) | Neither the deploy script nor the runtime pins the VM's bytecode/version, only its address (`0xA9f2...1fd`) and `code.length > 0`. CREATE2 discipline makes a wrong-VM deployment at the canonical address impractical, and program bodies embed VM-auxiliary addresses (D7), so a wrong VM fails closed. Operational note: keep the canonical-address registry per chain. |
| Constructor zero-check (slither) | `VIRTUAL_MACHINE` has no zero-check; the deploy script reverts `CanonicalVmMissing` when codeless and program-bearing settlements fail closed with `InvalidVirtualMachine`; empty-program settlements never touch the VM. Acceptable. |
| Gas | D10 binding measured by the authors at +695 gas on an empty-program fill; no gas findings from this review (no measured deltas of our own to report). |

## Acknowledged non-issues (checked, not findings)

- **K1–K7 documented limits** (`design/cat-validator-v2.md` §10): post-state checks (K1), v1 1-wei DoS fixed in V2 and reported upstream (K2/D6 — v1 bytecode pin verified locally: `script/check-v1-bytecode.sh` reports `ok` for both pins), forged error selectors (K3), trusted compiler (K4), intent-factory validator selection (K6), and the D10 binding residuals (K7a–d). Finding 1 extends K7c to *nonzero* same-token floors and is reported separately.
- **`arbitrary-send-erc20` on `_handleAllowances`** (slither high): the pull model is the design; authorization is the EIP-712 signature over the digest, and D10 binds the destination when committed.
- **Solady EIP712 constructor caching with the virtual `_domainNameAndVersion`**: internal virtual dispatch resolves to the most-derived override even during base construction, and V2's override is `pure`, so the cached separator uses version "2"; pinned by `test_domainSeparator_isVersion2` and `test_entry_v1DigestNotAccepted`.
- **`uninitialized-local` on `entry`'s `spent`** (slither): conditionally assigned and only read under the same `verified` condition (`CATValidatorV2.sol:148-159`).
- **Aderyn "locks Ether" on CATValidator**: native value is transiently held and swept by `address(0)`-token outcomes (`CATValidator.sol:184-189`); V2's `_call` forwards 0 by design (INV-12).
- **v1 scratch-space returndata copy**: pre-existing in audited v1; V2's `_call` copies revert data to the free-memory region instead (`CATValidatorV2.sol:329-332`); no action.
- **Tstorish SSTORE fallback**: transient records are per-transaction atomic (revert wipes them; success clears them via `_takePaid`), and the pseudo-random `PAID_SLOT` cannot collide with `spentNonces` storage.

## Open questions for the developer

1. Should `spent[]` be *measured* (transient-recorded balance deltas around each pull, like `paid[]`) instead of simulated? Finding 3's fix; it would also subsume Finding 6.
2. Should the SDK refuse (or require `payloadHash` binding for) constraints whose allowance and outcome token sets intersect? Finding 1 hinges on the producer emitting same-token round trips with a 0/0 binding.
3. Is the cross-version migration of an escrow (keeping v1 approvals live while adopting V2) a supported flow? If yes, Finding 2 needs the documented migration hygiene (revoke v1 digest/approvals or fresh nonces); if no, it moves to acknowledged non-issues with a doc note.
4. Are sender-fee/transfer-cap tokens in the supported outcome-token set? If yes, Finding 4 wants a documented recovery path beyond "refund with a different constraint".

## Coverage

- **Walked end-to-end:** `CATValidatorV2.sol`, `CATValidator.sol` (branch diff + inherited paths), `LibExecutionConstraintV2.sol`, `LibValidationVM.sol`, `CallProxy.sol`, `script/deploy.s.sol`, Tstorish; TypeScript `constraint.ts` (all V2 paths), `types.ts` (typed data), `constrainedtransaction.ts` (reviewed for parity; the SDK's refund/binding encoding matches the contract rules).
- **Test-base verification:** ran the full suite — 340 passed, 0 failed (7 fork tests skipped: no mainnet RPC in this environment), including the 7 new audit PoC tests. v1 bytecode pin verified.
- **Static analysis:** slither 89 raw results — 3 in-scope hits, all triaged (two design-intended, one false positive); aderyn 10 — 4 high all false positives or out of scope, 6 low style. Triages recorded in `.sc-audit/raw/`.
- **Not covered:** the LI.FI VirtualMachine v1.2 internals (out of scope; the interface is fail-closed staticcall), `Catapultar.sol`/`CatapultarFactory.sol` internals (trust anchor, unchanged), Tron variants (unchanged; V2 has no Tron deployment in this branch), the mainnet-fork tests (skipped offline — CI runs them), `IntentExecutor.sol` (unchanged by the branch).

## Appendix — pipeline artifacts

`.sc-audit/SYSTEM.md` (system map, INV-1..12), `checkpoints/` (lane hotspots, merged clusters, attack/verify JSONs, manifest), `raw/` (slither + aderyn output), PoCs in `test/audit/` (`SpentReplayDivergence`, `PassThroughFill`, `LivenessAndSemantics`, `CrossValidatorNonceShadowing`).
