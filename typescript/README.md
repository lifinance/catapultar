# Catapultar TypeScript Library

Catapultar is a TypeScript library for building and validating Catapultar smart-account calls.

## Runtime support
- Node.js `>=20`
- Bun `>=1.3.5`

## Installation

```bash
npm i catapultar
```

```bash
pnpm add catapultar
```

```bash
yarn add catapultar
```

```bash
bun add catapultar
```

## Exports

- `BaseTransaction` — low-level transaction composer.
- `CatapultarAccount` — account helpers and on-chain validation methods.
- `CatapultarTx` — typed transaction wrapper for account calls.
- `MetaCatapultarTx` — composed multi-transaction wrapper.
- `ConstrainedAssetTransaction` — constrained asset flow helper.

## Quick Start

```ts
import { CatapultarTx, ExecutionMode } from "catapultar";

const tx = new CatapultarTx({
  account: {
    address: "0x...",
    chainId: 1,
    pubkey: "0x...",
  },
});

tx.setMode(ExecutionMode.RaiseRevert);
tx.setNonce(1n);
tx.addCall({ to: "0x...", value: 0n, data: "0x" });
```

## Testing (repository)

Repository tests run against a local Anvil instance started by `prool`.

- Default port: `18545`
