# Hash-parity fixture (`vectors.json`)

This directory pins the canonical byte encoding of a validation program and the
two `keccak256` content hashes an escrow address commits to. It is the shared
acceptance mechanism that keeps LI.FI's compose compiler (which emits validation
programs and computes their hashes off-chain) and `CATValidatorV2` (which hashes
the supplied bytes on-chain) hashing the **same** bytes. If the two sides ever
disagree, a deposit lands at an address nothing can settle and funds are
stranded; this fixture exists to make that disagreement impossible to miss.

`vectors.json` is produced by the compose compiler's generator and mirrored here
byte-for-byte. Never hand-edit it.

## What `vectors.json` pins

- `schema`: `c1-hash-parity/v1`.
- `profile`: `validation-v1` — the compiler's `CompileProfile::identifier()`
  string. The profile is part of the hash universe: a different profile is a
  different set of bytes and hashes.
- `httpProfileField`: `validation` — the value the compiler's HTTP `/compile`
  request carries (transport only; do not conflate with the profile identifier).
- `compilerAddresses`: the four canonical platform addresses
  (`vm`, `arithmetic_processor`, `invariant_checker`, `proxy_factory`, per the
  VirtualMachine's `DEPLOYMENTS.md`). The program body bakes
  `arithmetic_processor` / `invariant_checker` as CALL targets, so these
  addresses are part of the encoding spec: redeploying either changes every
  body hash. The generator verifies them against the live compiler's
  `/metadata` before emitting anything.
- `programVectors[]`: for each thunk (the compiler input: committed outcomes,
  invariants and delivery address) — the verbatim thunk, the full `runVM`
  `calldata`, the decoded `commands` and `registers`, the canonical tight-packed
  `canonicalBody` (33 bytes per command: `uint8 op ++ bytes32 data`), the
  `validationProgramHash` (`keccak256(canonicalBody)`), the committed `params`
  (each with its 32-byte ABI `word`), the `canonicalParams` concatenation, and
  the `paramsHash`.
- `paramsVectors[]`: standalone params cases — `empty-params` (hashes to
  `bytes32(0)`: zero when empty), `two-words` (an address word and a uint word),
  and `constants-words` (a `bytes32` RPN program word and a `uint8` operand
  count — the two operation-constant solTypes).

Committed params order (the canonical register-layout prefix):
`[deliveryAddress] ++ [outcome minAmounts, committed-outcomes order] ++
[invariant thresholds, invariants order] ++ [rpnProgram, rpnOpsCount — present
iff ≥ 1 committed outcome]`. The trailing pair are the per-operation constants a
delta assertion's RPN evaluation needs (`rpnProgram`, solType `bytes32`, the
packed `evaluateRPN` program word; `rpnOpsCount`, solType `uint8`, the operand
count). **Command register references are zero-based array positions, and the
committed params include these per-operation constants**, so a validator that
rebuilds the register file from committed data alone (`params ++ [account] ++
preBalances`) can execute the program.

The pair `uc1-user-a` / `uc1-user-b` is the **body-sharing** case: the same
operation for two different users produces an identical `canonicalBody` and
`validationProgramHash` but distinct `paramsHash` — per-user values live only in
the params vector, never in the body.

## Who asserts it

- `test/vc/HashParity.t.sol` recomputes every body hash and params hash, checks
  the decoded `commands` against the body, and re-encodes the `runVM` calldata
  through `LibValidationVM.encodeRunVM` byte-for-byte. It needs no fork.
- `test/vc/Uc1Fork.t.sol` and `test/vc/IntegrationV2.t.sol` execute the
  `uc1-user-a` program on the canonical VM on a mainnet fork, both verbatim and
  through `CATValidatorV2.entry()`.

## How to regenerate

The LI.FI compose compiler regenerates these vectors; they are not produced in
this repository. The compiler must run with the canonical platform addresses
(VM `0xb57Ce43Be47DF611C98EB0943e5D36EBDb36cc6D`, arithmetic processor
`0x25407266A1229c83d03ececfff8eD7d92754b285`, invariant checker
`0xe17006F4DfE8Aa2bf80589E497ad98D470f66fef`, proxy factory
`0xe174D02351656a883f6626497C86684e849efB35`); the generator refuses a
non-canonical instance. It compiles each thunk twice and requires
byte-identical calldata, decodes and hashes with the compiler's own encoding
(it never re-encodes commands separately), and asserts body sharing before
writing.

The generator then runs an **execution smoke gate**: each program vector is
`eth_call`ed against the canonical mainnet VM two ways — the pinned calldata
verbatim, and with the register file rebuilt from committed data only
(`params ++ [account] ++ preBalances`) — and the run aborts unless every probe
passes (a pass is a successful call or a revert with `AssertGteFailed`, the
genuine business invariant; any register-machinery revert fails). The output has
no timestamps or randomness (the live probe result is never written into
`vectors.json`), so re-running against the same compiler is byte-identical.

Copy the regenerated file here unchanged, then run the suites above.

## Regeneration is a versioning event

If regeneration ever produces **different bytes for an unchanged thunk**, stop.
That is encoding drift — "what we hash" and "what the VM executes" have
diverged. Diagnose before committing: check the compiler instance's `/metadata`
addresses and the profile plumbing. Do not commit a silently changed hash; treat
it as a deliberate version bump only after understanding the cause.
