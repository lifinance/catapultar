# C3 vm-programs fixture (`vectors.json`)

This directory pins the **C3** cross-repo seam: the canonical byte encoding of
committed validation programs for the LI.FI `VirtualMachine`, the frozen opcode
numbering they rely on, and the accept/reject behavior the on-chain sandbox
guarantees. It is the shared authority that keeps the program **producer**
(yggdrasil's `validation` compile profile, which emits these bodies) and the
program **consumer** (`CATValidatorV2.entry()`, which hash-checks a supplied body
and executes it via `staticcall` on the unmodified VM) agreeing on exactly what
bytes mean what.

A validation program is an **assert-only** command stream: reads plus static
calls to the canonical `InvariantChecker` / `ArithmeticProcessor`, and nothing
else. Running the unmodified VM under `staticcall` is therefore a complete
sandbox — any token move (`SAFE_TRANSFER`, `DEPOSIT_APPROVED`), any
state-mutating `CALL`/`VALUECALL`, and any `LOG` reverts at the EVM level,
reverting the whole settlement (funds stay refundable). This fixture proves that
guarantee against the **real deployed VM on a mainnet fork**.

## What `vectors.json` pins

- `schema`: `c3-vm-programs/v1`.
- `runVMSelector`: `0x00a32e6c` — `runVM((uint8,bytes32)[],(bytes[]))` on the
  canonical `VirtualMachine` (left-aligned in a 32-byte word).
- `registerLayoutConvention`: the frozen C1 layout the validator injects —
  `registers = validationParams ++ [account] ++ preBalances`, remaining slots
  32-byte zero words, 123 total. The escrow `account` and `preBalances` are
  validator-injected at settlement; they are never body literals or committed
  params (the escrow address transitively depends on `validationProgramHash`).
- `platform`: the three canonical, deterministically-deployed addresses
  (identical on every supported chain, `vm/DEPLOYMENTS.md`): `virtualMachine`,
  `invariantChecker`, `arithmeticProcessor`.
- `opcodeNumbering`: the full 11-entry `OP` enum → number map from
  `vm/src/DataModel.sol` (a frozen cross-repo fact). The Solidity suite also
  pins several numbers *behaviorally* — it runs a body non-statically and
  observes that op 10 moves tokens (it **is** `SAFE_TRANSFER`), op 9 emits
  (`LOG`), op 8 reads native balance, op 5 returns a register, etc.
- `programs[]`, each hand-authored **zero-based** per the register convention
  above (fully under GD-4's control — unlike the pinned uc1 vector in the
  sibling `hash-parity/` C1 fixture, these are unaffected by the pending GD-7
  re-pin). Per program:
  - `name`, `class` (`accept` | `fail` | `reject`).
  - `body`: the canonical tight-packed program bytes (33 bytes per command,
    `uint8 op ++ bytes32 data`). `keccak256(body)` is the committed
    `validationProgramHash`.
  - `params`: the committed 32-byte parameter words (the `paramsHash` preimage).
  - `preBalanceCount`: how many injected pre-balance words the program expects
    after the account slot (the settlement outcome count it reads).
  - `expect`: `success` (accept), `validationFailed` (fail — a real assertion
    violation), or `staticcallRevert` (reject — a sandbox violation).
  - `innerSelector`: for `fail` programs, the `InvariantChecker` revert selector
    (`AssertGteFailed` / `AssertEqFailed`) that `ValidationFailed(bytes)` wraps.

### The programs

| name             | class  | opcodes exercised                                   |
|------------------|--------|-----------------------------------------------------|
| `erc20-floor`    | accept | `CALLDATA_BUILD` + `STATICCALL` balanceOf / evaluateRPN / assertGTE — the uc1 shape, **corrected**: the RPN word + operand count live in the committed params, not loose register slots (exactly what the GD-7 re-pin must do; building it here proves the corrected shape executes) |
| `assert-fails`   | fail   | same body as `erc20-floor` with an unsatisfiable `min` param → `AssertGteFailed` |
| `native-gte`     | accept | `NATIVE_BALANCE(account) >= threshold` param        |
| `always-revert`  | fail   | `assertEqual(0, 1)` via params → `AssertEqFailed`   |
| `safe-transfer`  | reject | `SAFE_TRANSFER` (op 10) — a token move              |
| `deposit-approved` | reject | `DEPOSIT_APPROVED` (op 3) — pulls an approved deposit |
| `log`            | reject | `LOG` (op 9) — event emission                       |
| `mutating-call`  | reject | `CALL` with `CallType.CALL` — state-mutating external call |
| `valuecall`      | reject | `CALL` with `CallType.VALUECALL` — value-bearing external call |

The reject-class bodies bake **synthetic mock addresses** (`0x…ca7e00xx`) as
their `SAFE_TRANSFER` / `DEPOSIT_APPROVED` / `CALL` targets — the VM has no
register-indirect target, so these must be command literals. The Solidity
harness etches mock code at those addresses so the pinned bodies stay
deterministic. The `mutating-call` and `valuecall` rows exercise `CALL`'s
`CallType.CALL` and `CallType.VALUECALL` variants under `staticcall`.

## Who asserts it

- **Solidity (consumer authority, GD-4):**
  `external/catapultar/solidity/test/vc/VmPrograms.t.sol` in the intent-factory
  worktree. On a mainnet fork it (1) asserts `ProgramBuilder` reproduces every
  pinned `body` byte-for-byte, (2) drives every program through the full
  `CATValidatorV2.entry()` path — accept settles, fail reverts `ValidationFailed`
  wrapping the pinned `innerSelector` (nonce/funds untouched), reject reverts
  `ValidationFailed` under `staticcall` — (3) runs the reject bodies
  non-statically to pin opcode numbering behaviorally, and (4) proves a 50k gas
  cap fails a valid program closed (FR-V5 bounded grief).
- **yggdrasil (producer, GD-1/GD-2):** the `validation` compile profile must emit
  bodies under this exact encoding and the `opcodeNumbering` map; a re-derivation
  that changes either is a versioning event (bump the schema).

## How to regenerate

From `intent-factory-wts/verified-continuations/external/catapultar/solidity`,
with `VC_MAINNET_RPC_URL` set to an Ethereum-mainnet endpoint:

```
VC_REGEN_VM_FIXTURE=true forge test --match-path 'test/vc/VmPrograms.t.sol' --match-test test_fixtureParity
```

The regeneration writes this file from the `ProgramBuilder` output and then
asserts it in the same run. Output has no timestamps or randomness — re-running
is byte-identical. If regeneration ever produces different bytes without a
deliberate program-shape change, stop and diagnose (same drift protocol as the
C1 fixture README): a command packing, an opcode number, or the register
convention has drifted, and the producer/consumer are now disagreeing.

## Version history

- **2026-09-01 — canonical ArithmeticProcessor redeploy.** The canonical LI.FI
  `ArithmeticProcessor` was redeployed from
  `0x46C2c852E6FEfaF173dFe49457f0Fe61Dc3F587a` to
  `0x25407266A1229c83d03ececfff8eD7d92754b285` (verified deployed on Ethereum
  mainnet and Base). Because the address is a command-body literal
  (`ArithmeticProcessor` is the `STATICCALL` target of the RPN-delta programs),
  the `erc20-floor` / `assert-fails` shared body hash was re-pinned; the uc1
  derivation goldens now emit the shared `validationProgramHash`
  `0xd71a5feb2589caa974cee8d91b3420319fed8975bf2c5cccdf3a42ce10eb3c55`. All
  other program bodies (which never reference the processor) are byte-unchanged.
  Re-pinned against the canonical VM at
  `0xb57Ce43Be47DF611C98EB0943e5D36EBDb36cc6D` on a mainnet fork; no opcode,
  packing, or register-convention change.
- **2026-07-03 — initial pin (GD-4 M5).** Nine programs (two accept, two fail,
  five reject) proven against the canonical VM at
  `0xb57Ce43Be47DF611C98EB0943e5D36EBDb36cc6D` on a mainnet fork. All bodies
  hand-authored zero-based per the C1 register convention as written; unaffected
  by the pending GD-7 uc1 re-pin.
