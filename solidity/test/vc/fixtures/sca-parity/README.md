# sca-parity fixtures

`sca-parity.v1_1.vectors.json` pins how a `CATValidatorV1_1` `ExecutionConstraint` becomes an escrow address: constraint, EIP-712 digest, `CatapultarFactory.deployWithDigest` salt, then the PUSH0-clone CREATE2 address. `ScaParity.t.sol` asserts it in Solidity and `typescript/src/protocol/validatorV1_1.spec.ts` asserts it in TypeScript, so a client that disagrees with the contracts about an address fails a test instead of funding an escrow nothing can settle.

The vectors are pure math: every address input is explicit and synthetic, so they hold for any deployment that supplies its own.

- `schema`: `c2-sca-parity-v1_1/v1`.
- `domain`: name `CAT Validator`, version `1.1`, `chainId` 1, a synthetic `verifyingContract`.
- `clone`: the synthetic `factory` and `executorImpl` the clone address is predicted from.
- `executor` and `refundAddress`: shared by every vector. `refundAddress` is never zero, since zero is the execute sentinel.
- Each vector carries an `execute` and a `refund` constraint with `nonce`, `executionTarget`, `payloadHash`, `allowances` and `outcomes`:
  - `execute` commits `executionTarget = address(0)` and `payloadHash = 0` on a non-zero nonce.
  - `refund` is derived from the execute allowances: nonce 0, `executionTarget = refundAddress`, `payloadHash = keccak256("")`, and per allowance token an allowance of `type(uint256).max` and an outcome `{ token, 0, refundAddress }`.
- `salt`: the pre-salt passed to the factory. Its first 20 bytes are the owner, which `CatapultarFactory._salt` hashes together with the key type and key array.
- `expected`: both struct hashes and digests under
  `ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,address executionTarget,bytes32 payloadHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)`,
  then `saltWithDigest` (`keccak256(_salt(salt, ktp, owner) ++ digest ++ flavorNonce)`) and `escrow` of the execute digest. `flavorNonce` 1 is the call flavor, 2 the signature flavor.
- Vectors: `empty-outcomes`, `ledger-outcome` (an outcome `{ ledger, 1, commit }` with a full-width nonce) and `two-allowances` (one refund sweep per allowance token).

`ScaParity.t.sol` also checks a deployed `CATValidatorV1_1` domain separator against the formula on any chain, and replays the nonce-0 refund sweep on escrows derived from the fixture.

## Regenerate

From `solidity/`:

```
VC_REGEN_SCA_FIXTURE=true forge test --match-path 'test/vc/ScaParity.t.sol'
```

The run writes the file from the code under test and asserts it in the same run. The output has no timestamps or randomness. If regeneration changes bytes without a deliberate change to the constraint shape, the type string, the domain formula or the salt formula has drifted. Then copy it to the TypeScript mirror and never edit the copy:

```
cp test/vc/fixtures/sca-parity/sca-parity.v1_1.vectors.json ../typescript/test/fixtures/sca-parity.v1_1.vectors.json
```
