## Catapultar Typescript Library

Catapultar is a compact TypeScript library for managing Catapultar smart accounts. It provides a reliable and portable wrapper around account and transaction flows to build, sign, and execute account-level operations reliably.

## Key Features
- Utilities for interacting with the Catapultar smart account
- Ethers and viem compatibility.
- Natural language transaction creation.
- Helpers for account and factory interactions to simplify common tasks

### Library Structure

4 Main classes are exported:
- **BaseTransaction** — Minimal transaction interface without validation.
- **CatapultarAccount** — Catapultar Smart Account management.
- **CatapultarTx** — Creating transaction for existing smart accounts.
- **MetaCatapultarTx** — High level batch transactions.

Depending on your use case, you may prefer either a high level or low level transaction creation.

- **CatapultarTx** depends on **BaseTransaction** and **CatapultarAccount**.
- **MetaCatapultarTx** depends on **CatapultarTx**

## Installation
This repository uses Bun. From the project root, install dependencies with:

```bash
bun install
```

## Usage (Overview)
Catapultar is RPC-less by default. If an RPC is provided to the library, validation will be enhanced with on-chain information including:
- Nonce validation
- Account version selection
- Simulation
- EIP-1271 signature validation
- Get deployed transactions in transaction.

Catapultar is verioned, meaning accounts can be versioned to their respective version. Unless an RPC is provided to the library, it is important that the version of the account is provided to explicitly enable or disable flows.

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
  message: { /** Typed Message */};
}
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
  data: { /** Typed Message */};
}
```

Executable objects are exported as: 
```typescript
type Executable = {
  to: `0x${string}`;
  value: bigint;
  data: `0x${string}`;
}
```

### Account deploy

TODO

### Transaction Creation

```typescript
import { CatapultarTx } from "catapultar";

const account = {
  address,
  chainId,
  owner,
}

const tx = new CatapultarTx({account});
const call = (await tx.addCalls(...calls).sign((v) => viemWalletClient.signTypedData({account, ...v}))).asCall();

viemWalletClient.sendTransaction({
  account,
  ...call // unpack call into viem. 
});
```

### Embed

In some cases, you may want to execute an action on behalf of another user — they are the primary custodian but a pre-approved call has been configured.
Catapultar can be configured for this use case by embedding a call (or signature) digest.

To create embedded accounts, use **BaseTransaction**.

```typescript
const embeddedCalls: {to: `0x${string}`, data: `0x${string}`, value: bigint}[];

const tx = new BaseTransaction();

tx.setRandomNonce();
tx.setMode(ExecutionMode.RaiseRevert);
tx.addCalls(...embeddedCalls);


const context = tx.asAccount(...);
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
const allowances: { token: `0x${string}`; amount: bigint; }[];
const outcomes: { token: `0x${string}`; amount: bigint; destination: `0x${string}` }[];

const cat = new ConstrainedAssetTransaction({executor});
cat.addAllowances(...allowances);
cat.addOutcomes(...outcomes);

const tx = cat.asCatapultarAllowanceTransaction();
const context = tx.asAccount(...);

const entryCall = tx.asExecuteCall({address: context.address, ...})

// then you need to execute [context.deployCall, context.actionCall, entryCall]
```

See `src/transaction/constrainedtransaction.spec.ts::create account and execute contained constraints` for an example.

## Project Layout
- `src/catapultar/` — core account and factory logic
- `src/transaction/` — low level transaction logic
- `src/abi/` — Contract ABIs
- `src/types/` — shared TypeScript types
- `src/utils/` — helper utilities
