## Catapultar Typescript Library

Catapultar is a compact TypeScript library for managing Catapultar smart accounts. It provides a reliable and portable wrapper around account and transaction flows to build, sign, and execute account-level operations reliably.

## Key Features

- Utilities for interacting with the Catapultar smart account
- Ethers and viem compatibility.
- Fluent, chainable transaction building (build, sign, and execute batches).
- Helpers for account and factory interactions to simplify common tasks

### Library Structure

The library is split into a high-level and a low-level surface. Pick the layer
that matches how much control you need; bring your own signing and broadcasting
at either level.

**High level** (`src/catapultar`) — account-aware, validated flows:

- **CatapultarAccount** — Catapultar Smart Account management (deploy/predict,
  on-chain reads, owner/nonce/upgrade/ERC-1271 call builders).
- **CatapultarTx** — Build, sign, and execute a batch for an existing account.
- **MetaCatapultarTx** — Batch-of-batches (retryable sub-batches).

**Low level** (`src/transaction`) — minimal building blocks without account
context:

- **BaseTransaction** — Minimal transaction interface without validation.
- **ConstrainedAssetTransaction** — Constrained Asset Transactions (CAT validator).

Beneath both sit the pure protocol primitives (`src/protocol`) — encoders such as
`callsDigest`, `constraintDigest`, `predictCloneAddress`, `factorySalt`,
`buildOpData`, and the signature/owner codecs — plus the contract ABIs
(`catapultarAbi`, `catapultarFactoryAbi`, `catValidatorAbi`). Use these directly
to integrate without any of the classes.

Dependency direction:

- **CatapultarTx** depends on **BaseTransaction** and **CatapultarAccount**.
- **MetaCatapultarTx** depends on **CatapultarTx**.

## Installation

This repository uses Bun. From the project root, install dependencies with:

```bash
bun install
```

The package ships dual **ESM and CJS** builds with type declarations; `import` and `require` both resolve the same API (only the root `catapultar` entry is published).

## Usage (Overview)

Catapultar is offline by default — it can build, hash, and sign everything without network access. Attach a viem client to unlock on-chain features. Either bring your own client with `account.connect(publicClient)`, or use the `account.connectRpc({ rpc, chainId })` convenience to build one from an RPC URL (pass `chain` to override resolution for an unlisted network). Once connected, the following become available:

- Nonce validation
- Simulation
- EIP-1271 signature validation
- Reading owner / approved digests / upgradeability from the account.

Accounts default to the `0.1.1` EIP-712 domain version (matching the deployed
Catapultar contract); pass `version` to the account constructor to override it.

For the common single-wallet case, `CatapultarTx` already signs and broadcasts a
batch in one call via `tx.execute(walletClient)` (see [Transaction Creation](#transaction-creation)).

### Actionables (Signables and Executables)

While Catapultar uses viem under-the-hood, you need to bring your own execution and signing service / library. Catapultar exports actionable objects as either `Signable`-ish or `Executable` which are directly compatible with viem and almost directly compatible into Ethers. If you are using external signers, you need to port these objects.

Signable objects are exported as:

```typescript
type Signable = {
  domain: {
    name: string;
    version: string;
    chainId?: bigint;
    verifyingContract: `0x${string}`;
  };
  types: { /** Universal typed const */ };
  primaryType: string;
  message: { /** Typed Message */ };
};
```

Note that Ether's "`Signable`" looks like:

```typescript
type EthersSignable = {
  domain: {
    name: string;
    version: string;
    chainId?: bigint;
    verifyingContract: `0x${string}`;
  };
  types: { /** Universal typed const */ };
  data: { /** Typed Message */ };
};
```

Executable objects are exported as:

```typescript
type Executable = {
  to: `0x${string}`;
  value: bigint;
  data: `0x${string}`;
};
```

### Owners

Every account is controlled by an `owner`, a discriminated union — the `type` tag tells the library which key it is, so you don't pass protocol enums around:

```typescript
import type { Owner } from "catapultar";

const ecdsa: Owner = { type: "ecdsa", address: "0x..." }; // EOA or ERC-1271 contract
const p256: Owner = { type: "p256", x: "0x...", y: "0x..." }; // raw P256 key
const passkey: Owner = { type: "webauthn-p256", x: "0x...", y: "0x..." }; // WebAuthn passkey
```

### Account deploy

`CatapultarAccount.deploy` returns the deploy `call` and the `account` object. The account address is deterministic (CREATE2), so it is known before the deploy lands.

```typescript
import { CatapultarAccount } from "catapultar";

const { call, account } = CatapultarAccount.deploy({
  owner: { type: "ecdsa", address: ownerAddress },
  salt, // 32-byte salt
});

// Send the deploy call with your own wallet/relayer.
await viemWalletClient.sendTransaction(call);

// Attach a client for on-chain reads (returns a connected account — use the result).
const connected = account.connect(viemPublicClient);
await connected.validateOwner();
```

You can predict the address without building a call via `CatapultarAccount.predict({ owner, salt })`.

#### Clone strategies (immutable vs upgradeable)

By default the factory mints the cheap, immutable PUSH0 minimal clone. Pass
`upgradeable: true` to mint a durable ERC-1967 proxy the owner can later upgrade
via `upgradeToAndCall` (build the call with `account.buildUpgradeCall`). The
predicted address differs between the two strategies, and an embedded `digest`
is only available for the immutable clone (the type system rejects
`{ upgradeable: true, digest }`).

```typescript
const { call, account } = CatapultarAccount.deploy({
  owner: { type: "ecdsa", address: ownerAddress },
  salt,
  upgradeable: true, // ERC-1967 proxy instead of the PUSH0 clone
});

await connectedAccount.isUpgradeable(); // true once deployed
```

### Sign as account (ERC-1271)

A Catapultar account can act as a smart-contract signer for other protocols. The
account rehashes the payload in a replay envelope bound to its own address
before validating, so reproduce that digest with `getReplayProtectedDigest` and
have the owner sign it. Then hand the verifier the **original** payload hash plus
the signature.

```typescript
// Owner signs the replay-protected digest; verifier calls isValidSignature(hash, sig).
const digest = account.getReplayProtectedDigest(payloadHash);
const signature = await ownerLocalAccount.sign({ hash: digest });

// Verify against the deployed account's on-chain ERC-1271 view (pass the
// ORIGINAL payloadHash — the account rehashes into the replay envelope itself):
const ok = await connectedAccount.isValidAccountSignature({
  payloadHash,
  signature,
});
```

### Transaction Creation

```typescript
import { CatapultarTx, ExecutionMode } from "catapultar";

const tx = new CatapultarTx({
  account: {
    address: smartAccountAddress,
    chainId: 1,
    owner: { type: "ecdsa", address: ownerAddress },
  },
});

const signed = await tx
  .setMode(ExecutionMode.RaiseRevert)
  .setRandomNonce()
  .addCall(...calls)
  .sign((data) => viemWalletClient.signTypedData({ account, ...data }));

const call = await signed.asCall();

await viemWalletClient.sendTransaction({
  account,
  ...call, // unpack call into viem.
});
```

### EstimateGas Preflight

`ExecutionMode.EstimateGas` is intended for simulation. It classifies a failed
call by the gas it leaves behind: an OOG consumes nearly all forwarded gas,
while a genuine logical revert refunds what it did not spend. A failure that
leaves the frame below the starvation threshold (262,144 gas) is re-raised as
`EstimateGasStarved(gasLeft)`; any other failure is skipped and logged. A
parent EstimateGas frame recognizes the `EstimateGasStarved` selector in a
failure's returndata and bubbles it unchanged — propagation between
EstimateGas frames does not depend on remaining gas, so the OOG signal reaches
the top-level estimator from any nesting depth, forcing the estimation up
instead of letting it converge on a cheaper estimate where the OOG is
swallowed.

The selector is intentionally treated as a signal rather than authenticated as
coming from a Catapultar child frame. A callee can therefore return the exact
36-byte `EstimateGasStarved(uint256)` error itself. This cannot change state or
damage the account because the mode is used only for simulation; it can only
make the estimate more conservative or prevent the RPC from finding an
automatic estimate. Allowing the signal can also be beneficial: a nested or
gas-sensitive integration can use it to report that its current gas allowance
is unsafe even when an intermediate contract would otherwise wrap or swallow
the underlying failure. Callers can fall back to a manually selected gas limit
if a target emits the signal unconditionally.

`MetaCatapultarTx.estimateGas` builds
an estimation twin of the meta transaction: the outer mode and skip-policy
sub-batch modes (SkipRevert, SkipRevertMultiChain) are swapped to their
EstimateGas counterparts; atomic (RaiseRevert, or unset) sub-batches become
RaiseRevertEstimate, which bubbles failures exactly like RaiseRevert but runs
the starvation check inside the frame itself. Their on-chain rollback
semantics hold: a failing atomic sub-batch bubbles its exact revert data and
rolls back its partial state before the outer frame skips it — later
sub-batches simulate against the same state the broadcast would see — and is
priced at the gas it burns before failing. An OOG anywhere within the
threshold's bounds (below) reverts the whole estimation, forcing the estimator
up.
Trade-off: a sub-batch that fails at estimation but succeeds at relay (state
changed in between) is priced only up to its failure point, leaving its
remaining calls unpriced — a divergence no fixed margin can bound.
Re-estimate close to broadcast if your atomic sub-batches can flip from
failing to succeeding. Only SkipRevert-outer meta transactions can be
estimated this way.

Bounds of the threshold: the estimate carries the threshold as headroom past
each genuinely failing skip call (the frame must stay above it for the failure
to be skipped), and under the EIP-150 63/64 rule the gas check captures OOGs
at frame budgets up to 64 times the threshold — an OOG consumes everything
forwarded, leaving the frame its `budget / 64` reserve, which must stay below
the threshold — at the 262,144 (2^18) threshold that is 16,777,216, exactly
Ethereum's EIP-7825 per-transaction cap (2^24). Every estimation-twin frame —
EstimateGas and RaiseRevertEstimate alike — classifies its own failures with a
single reserve held, and parents bubble the typed error by selector, so the
bound holds per frame at any nesting depth.

With `useCodeOverride`, the bundled Catapultar account runtime code is injected
at the account address unless `overrideCode` or `overrideCodeAddress` is
provided. Estimation is always sent from the account address itself and uses
Catapultar's unsigned self-call authorization path, so no signer is required.
The returned estimate excludes signature validation, digest hashing, and the
proxy hop — add a signed-path margin before using it as a relay gas limit.

```typescript
import { MetaCatapultarTx, ExecutionMode } from "catapultar";

const metaTx = new MetaCatapultarTx({ account: connectedAccount })
  .setMode(ExecutionMode.SkipRevert) // outer mode; SkipRevert is the default
  .addCalls(
    { calls: batchA, mode: ExecutionMode.RaiseRevert },
    { calls: batchB, mode: ExecutionMode.SkipRevert },
  );

const gas = await metaTx.estimateGas({ useCodeOverride: true });
```

### Embed

In some cases, you may want to execute an action on behalf of another user — they are the primary custodian but a pre-approved call has been configured.
Catapultar can be configured for this use case by embedding a call (or signature) digest.

To create embedded accounts, use **BaseTransaction**.

```typescript
const embeddedCalls: {
  to: `0x${string}`;
  data: `0x${string}`;
  value: bigint;
}[];

const tx = new BaseTransaction();

tx.setRandomNonce();
tx.setMode(ExecutionMode.RaiseRevert);
tx.addCall(...embeddedCalls);

const context = tx.asAccount({ salt, owner: { type: "ecdsa", address } });
// {
//   deployCall // Call to deploy the account. Save, if lost account may not be recoverable.
//   actionCall, // Call to call on the account.
//   callDigest, // Digest of the embedded call. Can be ignored.
//   address, // Address of the contract once deployed.
// }
```

### Constrained Asset Transaction (CAT)

CATs are transactions that can be executed using an account's assets given a certain output. In an intent factory use case, you may want to generate an account with a CAT embedded to later execute arbitrary data against it.

To create a CAT use **ConstrainedAssetTransaction**. You can then convert it to a **BaseTransaction** to get the embedded account.

```typescript
const executor: `0x${string}`;
const allowances: { token: `0x${string}`; amount: bigint }[];
const outcomes: {
  token: `0x${string}`;
  amount: bigint;
  destination: `0x${string}`;
}[];

const cat = new ConstrainedAssetTransaction({ executor, chainId })
  .addAllowances(...allowances)
  .addOutcomes(...outcomes);

// `asExecutionBundle` builds the full ordered sequence in one call:
const { deployCall, actionCall, entryCall, address } = cat.asExecutionBundle({
  salt,
  owner: { type: "ecdsa", address: ownerAddress },
  execute: { executionTarget, executionPayload, spends },
});

// Execute in order: [deployCall, actionCall, entryCall]
```

For finer control, the lower-level pieces are still available: `cat.asCatapultarAllowanceTransaction()` → `BaseTransaction`, `tx.asAccount({ salt, owner })` for the account context, and `cat.asExecuteCall({ address, ... })` for the entry call.

Two on-chain sentinels are exported for advanced constraints:

- `SPEND_FULL_BALANCE` (`1 << 255`) — use as a `spend` to pull the signer's full
  current token balance instead of a fixed amount (e.g. DCA / sweep flows).
- `OUTCOME_TO_SIGNER` (`address(0)`) — use as an outcome `destination` to route
  the outcome back to the signer.

The constraint digest itself is available via `constraintDigest({ chainId, verifyingContract }, constraint)`, and `isConstraintNonceSpent(publicClient, { validator, account, nonce })` reads whether a constraint nonce was already consumed.

See `src/transaction/constrainedtransaction.spec.ts::create account and execute contained constraints` for an example.

## Protocol primitives (unopinionated)

Every class is a thin wrapper over pure, side-effect-free encoders that mirror
the on-chain libraries byte-for-byte. They are exported directly so you can
integrate without any of the classes:

- Calls / EIP-712: `callsDigest`, `callsStructHash`, `callsTypedData`, `isMultichainMode`, `CALL_TYPE_HASH`, `CALLS_TYPE_HASH`, `CallsTyped`.
- Factory / CREATE2: `predictCloneAddress`, `factorySalt`, `factorySaltWithDigest`, `pushZeroCloneInitCode`, `erc1967CloneInitCode`.
- Execution data: `buildOpData`, `buildExecutionData`.
- Signatures: `normalizeSignature`, `compactSignature`, `toCompactSignature`, `fromCompactSignature`, `encodeWebAuthnAuth`, `normalizeP256`.
- Owners: `ownerToKeyArray`, `keyArrayToOwner`, `ownersEqual`, `ownerTypeToEnum`, `enumToOwnerType`, `keyTypeLength`.
- Constraints: `constraintDigest`, `constraintTypedData`, `constraintDomain`.

Contract ABIs are exported as `catapultarAbi`, `catapultarFactoryAbi`, and `catValidatorAbi`; deployment addresses as `factories`, `templates`, and `cat_validator`.

## Project Layout

- `src/catapultar/` — high-level account and transaction logic
- `src/transaction/` — low-level transaction logic
- `src/protocol/` — pure protocol encoders (calls, factory, opdata, signatures, owners, constraints)
- `src/abi/` — Contract ABIs
- `src/types/` — shared TypeScript types
- `src/utils/` — helper utilities
