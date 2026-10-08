# C1 hash-parity fixture (`vectors.json`)

This directory pins the **C1** cross-repo seam: the canonical byte encoding of a
validation program and the two `keccak256` content hashes an escrow address
commits to. It is the shared acceptance mechanism — not code review — that keeps
the TypeScript encoding (compose-core, GD-2) and the future Solidity `keccak256`
(intent-factory / Foundry, GD-4) hashing the **same** bytes. If the two sides
ever disagree, a deposit lands at an address nothing can settle and funds are
stranded (risk R-VP5); this fixture exists to make that disagreement impossible
to miss.

## What `vectors.json` pins

- `schema`: `c1-hash-parity/v1`.
- `profile`: `validation-v1` — the `CompileProfile::identifier()` string. The
  profile is part of the hash universe: a different profile is a different set of
  bytes and hashes.
- `httpProfileField`: `validation` — the value the HTTP `/compile` request
  carries (transport only; do not conflate with the profile identifier).
- `compilerAddresses`: the four canonical platform addresses
  (`vm`, `arithmetic_processor`, `invariant_checker`, `proxy_factory`, per
  `vm/DEPLOYMENTS.md`). The program body bakes `arithmetic_processor` /
  `invariant_checker` as CALL targets, so these addresses are part of the
  encoding spec. The generator verifies them against the live compiler's
  `/metadata` before emitting anything.
- `programVectors[]`: for each thunk — the verbatim thunk, the full `runVM`
  `calldata`, the decoded `commands` and `registers`, the canonical tight-packed
  `canonicalBody` (33 bytes per command: `uint8 op ++ bytes32 data`), the
  `validationProgramHash` (`keccak256(canonicalBody)`), the committed `params`
  (each with its 32-byte ABI `word`), the `canonicalParams` concatenation, and
  the `paramsHash`.
- `paramsVectors[]`: standalone params cases — `empty-params` (hashes to
  `bytes32(0)`, per FR-D4 "zero when empty"), `two-words` (an address word and a
  uint word), and `constants-words` (a `bytes32` RPN program word and a `uint8`
  operand count — the two operation-constant solTypes).

Committed params order (the canonical register-layout prefix):
`[deliveryAddress] ++ [outcome minAmounts, committed-outcomes order] ++
[invariant thresholds, invariants order] ++ [rpnProgram, rpnOpsCount — present
iff ≥ 1 committed outcome]`. The trailing pair are the per-operation constants a
delta assertion's RPN evaluation needs (`rpnProgram`, solType `bytes32`, the
packed `evaluateRPN` program word; `rpnOpsCount`, solType `uint8`, the operand
count). **Command register references are zero-based array positions, and the
committed params include these per-operation constants** — so a validator that
rebuilds the register file from committed data alone (`params ++ [account] ++
preBalances`) can execute the program. (GD-7; see the version history below.)

The pair `uc1-user-a` / `uc1-user-b` is the **body-sharing** case (goal G6): the
same operation for two different users produces an identical `canonicalBody` and
`validationProgramHash` but distinct `paramsHash` — per-user values live only in
the params vector, never in the body.

## How to regenerate

Regeneration requires a **canonically-configured** local Rust compiler. Start
one (first build may take minutes):

```
cargo run -p ir1_web_compiler_api -- --port 8123 \
  --vm-address 0xb57Ce43Be47DF611C98EB0943e5D36EBDb36cc6D \
  --arithmetic-processor-address 0x25407266A1229c83d03ececfff8eD7d92754b285 \
  --invariant-checker-address 0xe17006F4DfE8Aa2bf80589E497ad98D470f66fef \
  --proxy-factory-address 0xe174D02351656a883f6626497C86684e849efB35
```

Then, from the yggdrasil worktree, run the generator with the umbrella dir set
to this repo's root:

```
yarn workspace @lifi/compose-core generate:hash-parity \
  --compiler-url http://127.0.0.1:8123 \
  --mainnet-rpc-url <ethereum-mainnet-rpc> \
  --umbrella-dir /path/to/verified-continuations
```

The generator gates on `/metadata` (aborts on a non-canonical instance),
compiles each thunk twice asserting byte-identical calldata, decodes and hashes
via the compose-core encoding module (it never re-encodes commands in TS), and
asserts body-sharing before writing. It then runs the **execution smoke gate**
(GD-7): each program vector is `eth_call`ed against the canonical mainnet VM two
ways — the pinned calldata verbatim, and with the register file rebuilt from
committed data only (`params ++ [account] ++ preBalances`, the C3 convention) —
and the run aborts unless every probe passes (a pass is a successful call or a
revert with `AssertGteFailed`, the genuine business invariant; any
register-machinery revert fails). This is why `--mainnet-rpc-url` is required.
The output has no timestamps or randomness (the live probe result is never
written into `vectors.json`), so re-running against the same compiler is
byte-identical.

## Mirror

The umbrella/yggdrasil workspace's CI cannot reach this directory, so it keeps a
byte-identical mirror at
`ts/packages/compose-core/src/compiler/validation/__fixtures__/hash-parity.vectors.json`.
The single generator writes both copies; an env-gated test (`VC_CONTRACT_DIR`,
the umbrella repo root) asserts byte-identity when this repo is available. The
intent-factory side keeps its own byte-identity guards against this same file
(the `external/catapultar` C2 specs + the Foundry `VcTestBase.sol` loader, with
a `catapultar-utils` mirror in a later PR of this stack); those read
**`VC_UMBRELLA_DIR`**, not `VC_CONTRACT_DIR` (same path, per-repo
name — see the umbrella workspace's `CONTRACT.md`, "Env var naming").

## Coupling: regenerating C1 requires regenerating C4

The `uc1-user-a` `validationProgramHash` here is the **same** value the
umbrella workspace's C4 `descriptor/` fixture pins for its `uc1` vector. If this fixture is ever
regenerated with different bytes for the unchanged `uc1` thunk, regenerate the
umbrella workspace's C4 descriptor fixture afterwards (`yarn workspace @lifi/compose-core
generate:descriptor --umbrella-dir <path>`) so the shared hash stays in sync. A
`VC_CONTRACT_DIR`-gated compose-core continuity spec catches this if forgotten.

## Regeneration is a versioning event

If regeneration ever produces **different bytes for an unchanged thunk**, stop.
That is encoding drift (R-VP5) — the "what we hash" and "what the VM executes"
have diverged. Diagnose before committing: check the compiler instance's
`/metadata` addresses and the profile plumbing. Do not commit a silently changed
hash; treat it as a deliberate version bump only after understanding the cause.

## Version history

- **2026-09-01 — canonical ArithmeticProcessor redeploy.** The canonical LI.FI
  `ArithmeticProcessor` was redeployed from
  `0x46C2c852E6FEfaF173dFe49457f0Fe61Dc3F587a` to
  `0x25407266A1229c83d03ececfff8eD7d92754b285` (verified deployed on Ethereum
  mainnet and Base). The address is a `STATICCALL` target baked into
  validation-program command bodies, so every content hash downstream of it
  changes: the shared uc1 body hash moved from
  `0xde52503d208770487df75880bf8c9901999641e96e88de076048c0888ac0791e` to
  `0xd71a5feb2589caa974cee8d91b3420319fed8975bf2c5cccdf3a42ce10eb3c55`. Params
  carry no processor address, so both `uc1-user-a` / `uc1-user-b` `paramsHash`
  values are unchanged, and body-sharing still holds. Regenerated against a
  canonically-configured compiler pinned to the new address; no encoding,
  opcode, or register-convention change.
- **2026-07-03 — deliberate re-pin (GD-7, register convention).** Two coupled
  encoder fixes landed (Option A of the umbrella workspace's defect note
  `docs/2026-07-03-gd4-c1-register-convention-defect.md`): (a) command register
  references are now emitted **zero-based** (the sequential ISA allocator was
  one-based while the on-chain register file is a zero-based positional array —
  a compiler-encoder defect; the frozen register-layout convention text is
  unchanged), and (b) the RPN operation constants (program word + operand count)
  moved out of uncommitted scratch and into the committed params vector, so a
  conforming validator can rebuild and execute the register file from committed
  data alone. The `validation-v1` profile string is unchanged (a deliberate
  re-pin, per the dustBound precedent). Shared uc1 body hash moved from
  `0x17fc589a…09bd24c` to
  `0xde52503d208770487df75880bf8c9901999641e96e88de076048c0888ac0791e`. A
  producer-side execution smoke gate was added (see "How to regenerate") so
  "byte-asserted but never executed" cannot ship again.
- **2026-07-03 — deliberate re-pin (dustBound removal).** The negative-space
  residual clause and the `dustBound` param were removed from derivation (PRD
  D10/Q3; umbrella workspace migration note `docs/2026-07-03-dustbound-removal.md`). Program bodies
  lost their residual asserts; the committed-params order is now
  `[deliveryAddress] ++ [outcome minAmounts] ++ [invariant thresholds]` (no
  trailing dustBound). Shared uc1 body hash moved from `0x53c65d6e…2122f9` to
  `0x17fc589a…09bd24c`. The encoding spec (packing, profile, register-layout
  convention incl. the injected escrow slot) is unchanged.
