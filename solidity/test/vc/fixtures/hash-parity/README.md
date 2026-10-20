# Hash-parity fixture (`vectors.json`)

This directory pins the canonical byte encoding of a validation program and the
two `keccak256` content hashes an escrow address commits to. It is the shared
acceptance mechanism that keeps LI.FI's compose compiler (which emits validation
programs and computes their hashes off-chain) and `CATValidatorV2` (which hashes
the supplied program and params on-chain) hashing the **same** bytes. If the two
sides ever disagree, a deposit lands at an address nothing can settle and funds
are stranded; this fixture exists to make that disagreement impossible to miss.

`vectors.json` is produced by the compose compiler's generator
(`generateHashParityFixture.ts` in Yggdrasil `ts/packages/compose-core`, written
to `test/validation/__fixtures__/hash-parity.vectors.json`) and mirrored here
byte-for-byte. Never hand-edit it.

## What `vectors.json` pins

- `schema`: `c1-hash-parity/v2`.
- `profile`: `validation-v1`, the compiler's `CompileProfile::identifier()`
  string. The profile is part of the hash universe: a different profile is a
  different set of bytes and hashes.
- `httpProfileField`: `validation`, the value the compiler's HTTP `/compile`
  request carries (transport only; do not conflate with the profile identifier).
- `compilerAddresses`: the four canonical v1.2 platform addresses
  (`vm`, `arithmetic_processor`, `invariant_checker`, `proxy_factory`, per the
  VirtualMachine's `deployments/v1.2.json`). The program bakes
  `arithmetic_processor` and `invariant_checker` as CALL targets, so these
  addresses are part of the encoding spec: redeploying either changes every
  program hash. The generator verifies them against the live compiler's
  `/metadata` before emitting anything.
- `programVectors[]`: for each thunk (the compiler input: committed outcomes,
  invariants and delivery address), the verbatim thunk, the full `runVM`
  `calldata`, the decoded `commands` and `registers`, the `validationProgram`
  (`abi.encode(commands)`, the bytes the compiler sends on the wire), the
  `validationProgramHash` (`keccak256(validationProgram)`, the hash
  `CATValidatorV2` derives from its `VMCommand[]` argument), the committed
  `params` (each with its 32-byte ABI `word`), the `canonicalParams`
  concatenation, and the `paramsHash`.
- `paramsVectors[]`: standalone params cases: `empty-params` (hashes to
  `bytes32(0)`: zero when empty) and `two-words` (an address word and a uint
  word).

The pair `uc1-user-a` / `uc1-user-b` is the **body-sharing** case: the same
operation for two different users produces an identical `validationProgram`
and `validationProgramHash` but distinct `paramsHash`. Per-user values live only
in the params vector, never in the program.

## Register layout

`CATValidatorV2` runs a committed program against the register file
`params ++ [account] ++ spent ++ paid`, then zero words up to 123 registers
(`LibValidationVM.buildRegisters`). `account` is the escrow address, `spent[i]`
the amount the validator pulled from the escrow for allowance `i` (a literal
spend as written, or the remaining escrow balance for a `2**255` spend), and
`paid[j]` the amount the validator forwarded for outcome `j`. Command register
references are zero-based positions in that file, so a program addresses its
committed params first, the escrow at index `params.length`, then the spends
and payments in allowance and outcome order.

The vectors use that layout. Their `registers` arrays hold the committed params
followed by zero words: the compiler knows neither the escrow address nor the
flow amounts, and the uc1 program reads only its params. Their committed params
follow the compiler's order `[deliveryAddress] ++ [invariant thresholds]`. The
uc1 program is invariant-only: the validator's outcome floor checks the
committed outcome, so the program checks only that the delivery address holds
at least 500 USDC after the fill.

## Who asserts it

- `test/vc/HashParity.t.sol` recomputes every params hash, checks that each
  `validationProgram` is `abi.encode(commands)` and hashes to the pinned
  `validationProgramHash` under the validator's rule, and re-encodes the `runVM`
  calldata from the decoded `commands` and `registers` byte for byte. It also
  checks that the two uc1 users share one program hash. It needs no fork.
- `test/vc/IntegrationV2.t.sol` executes the `uc1-user-a` pinned `runVM`
  calldata, with the fixture's own register file, on the canonical v1.2 VM on a
  mainnet fork, and checks that it fails only on its USDC threshold.
- `test/CATValidatorV2.t.sol` pins the program hash rule on a vector computed
  outside both codebases with `cast`; the TS SDK spec pins the same vector.

## How to regenerate

The LI.FI compose compiler regenerates these vectors; they are not produced in
this repository. The compiler must run with the canonical v1.2 platform
addresses (VM `0xA9f22b951d5A9CBBD0eC8d2741EA44BFDD2D11fd`, arithmetic
processor `0x0DC20AF039443DC9A8a193f0f42F0AF2Ea611e8a`, invariant checker
`0xe450D45C03745909e08B5C46A87016c33F16a4A6`, proxy factory
`0xACEB3Bb6C75488b5b806B9de4dCF78814465BdaE`); the generator refuses a
non-canonical instance. It compiles each thunk twice and requires
byte-identical calldata, decodes and hashes with the compiler's own encoding
(it never re-encodes commands separately), and asserts body sharing before
writing.

The generator then runs an **execution smoke gate**: each program vector is
`eth_call`ed against the canonical mainnet VM two ways, the pinned calldata
verbatim and with the register file rebuilt from committed data only, and the
run aborts unless every probe passes (a pass is a successful call or a revert
with `AssertGteFailed`, the genuine business invariant; any register-machinery
revert fails). The output has no timestamps or randomness (the live probe
result is never written into `vectors.json`), so re-running against the same
compiler is byte-identical.

Copy the regenerated file here unchanged, then run the suites above.

## Regeneration is a versioning event

If regeneration ever produces **different bytes for an unchanged thunk**, stop.
That is encoding drift: "what we hash" and "what the VM executes" have
diverged. Diagnose before committing: check the compiler instance's `/metadata`
addresses and the profile plumbing. Do not commit a silently changed hash; treat
it as a deliberate version bump only after understanding the cause. A change of
platform addresses, register layout or program encoding is such a bump: it
changes the programs, and every hash with them.
