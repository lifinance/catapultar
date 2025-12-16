## Catapultar Typescript Library

Catapultar is a compact TypeScript library for managing Catapultar smart accounts. It provides a reliable and portable wrapper around account and transaction flows to build, sign, and execute account-level operations reliably.

## Key Features
- Lightweight TypeScript utilities for interacting with the Catapultar smart account
- Ethers and viem compatibility.
- Natural language transaction creation.
- Helpers for account and factory interactions to simplify common tasks

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
const account = {
  address,
  chainId,
  owner,
}
CatapultarTx;

const tx = new CatapultarTx({account});
const call = (await tx.addCalls(...calls).sign((v) => viemWalletClient.signTypedData({account, ...v}))).asCall();

viemWalletClient.sendTransaction({
  account,
  ...call // unpack call into viem. 
});
```




## Project Layout
- `src/catapultar/` — core account and factory logic
- `src/abi/` — Contract ABIs
- `src/types/` — shared TypeScript types
- `src/utils/` — helper utilities

