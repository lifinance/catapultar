# vm-programs fixture (`vectors.json`)

This directory pins the canonical byte encoding of committed validation programs
for the LI.FI `VirtualMachine`, the frozen opcode numbering they rely on, and the
accept/reject behavior the on-chain sandbox guarantees. It keeps the program
**producer** (LI.FI's compose compiler, whose `validation` compile profile emits
these bodies) and the program **consumer** (`CATValidatorV2.entry()`, which
hash-checks a supplied body and executes it via `staticcall` on the unmodified
VM) agreeing on exactly what bytes mean what.

A validation program is an **assert-only** command stream: reads plus static
calls to the canonical `InvariantChecker` / `ArithmeticProcessor`, and nothing
else. Running the unmodified VM under `staticcall` is therefore a complete
sandbox — any token move (`SAFE_TRANSFER`, `DEPOSIT_APPROVED`), any
state-mutating `CALL`/`VALUECALL`, and any `LOG` reverts at the EVM level,
reverting the whole settlement (funds stay refundable). This fixture proves that
guarantee against the **real deployed VM on a mainnet fork**.

Unlike the sibling `hash-parity/` fixture, which mirrors compiler output, these
programs are hand-authored in `test/vc/ProgramBuilder.sol` and
`test/vc/VmPrograms.t.sol`, so they are fully under this repo's control.

## What `vectors.json` pins

- `schema`: `c3-vm-programs/v1`.
- `runVMSelector`: `0x00a32e6c` — `runVM((uint8,bytes32)[],(bytes[]))` on the
  canonical `VirtualMachine` (left-aligned in a 32-byte word).
- `registerLayoutConvention`: the frozen register layout the validator injects —
  `registers = validationParams ++ [account] ++ preBalances`, remaining slots
  32-byte zero words, 123 total. The escrow `account` and `preBalances` are
  validator-injected at settlement; they are never body literals or committed
  params (the escrow address transitively depends on `validationProgramHash`).
  Each pre-balance is the outcome destination's balance, read after the fill
  and immediately before the validator forwards that outcome.
- `platform`: the three canonical, deterministically-deployed addresses
  (identical on every supported chain, per the VirtualMachine's
  `DEPLOYMENTS.md`): `virtualMachine`, `invariantChecker`, `arithmeticProcessor`.
- `opcodeNumbering`: the full 11-entry `OP` enum → number map from the VM's
  `src/DataModel.sol` (frozen by the deployed VM). The Solidity suite also pins
  several numbers *behaviorally* — it runs a body non-statically and observes
  that op 10 moves tokens (it **is** `SAFE_TRANSFER`), op 9 emits (`LOG`), op 8
  reads native balance, op 5 returns a register, etc.
- `programs[]`, each hand-authored with **zero-based** register references per
  the register convention above. Per program:
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
| `erc20-floor`    | accept | `CALLDATA_BUILD` + `STATICCALL` balanceOf / evaluateRPN / assertGTE — the uc1 shape, with the RPN word + operand count in the committed params rather than loose register slots |
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

## `derivation/`

The compose compiler's intermediate stages for the uc1 thunk, kept so a reviewer
can trace how the uc1 body is derived: `uc1.thunk.json` (the compiler input:
committed outcomes, invariants, delivery address), `uc1.ir1.json` (the IR
instructions and initial literals) and `uc1.isa.json` (the emitted commands and
the initial register layout). No test in this repo reads them.

## Who asserts it

- **Solidity (consumer):** `test/vc/VmPrograms.t.sol`. It (1) asserts
  `ProgramBuilder` reproduces every pinned `body` byte-for-byte (no fork
  needed), and on a mainnet fork (2) drives every program through the full
  `CATValidatorV2.entry()` path — accept settles, fail reverts
  `ValidationFailed` wrapping the pinned `innerSelector` (nonce/funds
  untouched), reject reverts `ValidationFailed` under `staticcall` — (3) runs
  the reject bodies non-statically to pin opcode numbering behaviorally, and
  (4) proves a 50k gas cap fails a valid program closed (bounded grief).
- **Compiler (producer):** the compose compiler's `validation` compile profile
  must emit bodies under this exact encoding and the `opcodeNumbering` map; a
  change to either is a versioning event (bump the schema).

## How to regenerate

From `solidity/` (no fork RPC is needed; `test_fixtureParity` is not fork-gated):

```
VC_REGEN_VM_FIXTURE=true forge test --match-path 'test/vc/VmPrograms.t.sol' --match-test test_fixtureParity
```

The regeneration writes this file from the `ProgramBuilder` output and then
asserts it in the same run. Output has no timestamps or randomness — re-running
is byte-identical. If regeneration ever produces different bytes without a
deliberate program-shape change, stop and diagnose (same drift rule as the
hash-parity fixture README): a command packing, an opcode number, or the
register convention has drifted, and the producer and consumer now disagree.
