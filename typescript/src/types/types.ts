import type { PublicClient } from "viem";
import type { Owner } from "../protocol/owner";

export type {
  Owner,
  OwnerType,
  OwnerOf,
  EcdsaOwner,
  P256Owner,
  WebAuthnOwner,
} from "../protocol/owner";

/**
 * ERC-7821 execution mode, encoded as the `bytes32` mode word the account
 * decodes. Controls revert behavior and whether the batch is signed for a single
 * chain or across chains.
 *
 * The `MultiChain` variants are signed without a `chainId` in the EIP-712 domain
 * (see {@link isMultichainMode}), so the same signature is valid on every chain.
 */
export enum ExecutionMode {
  /** If a call fails, bubble up the revert and do not spend the nonce. */
  RaiseRevert = "0x0100000000007821000100000000000000000000000000000000000000000000",
  /** If a call fails, skip it and emit an event; the nonce is still spent (unless out of gas). */
  SkipRevert = "0x0101000000007821000100000000000000000000000000000000000000000000",
  /** For gas estimation: skip failures, but re-raise a failure that leaves the frame below the starvation threshold as EstimateGasStarved. */
  EstimateGas = "0x0102000000007821000100000000000000000000000000000000000000000000",
  /** For gas estimation, the twin of {@link RaiseRevert}: bubble failures like RaiseRevert, but re-raise a failure that leaves the frame below the starvation threshold as EstimateGasStarved. */
  RaiseRevertEstimate = "0x0103000000007821000100000000000000000000000000000000000000000000",
  /** {@link RaiseRevert} signed chain-agnostically (multichain domain). */
  RaiseRevertMultiChain = "0x0100010000007821000100000000000000000000000000000000000000000000",
  /** {@link SkipRevert} signed chain-agnostically (multichain domain). */
  SkipRevertMultiChain = "0x0101010000007821000100000000000000000000000000000000000000000000",
  /** {@link EstimateGas} signed chain-agnostically (multichain domain). */
  EstimateGasMultiChain = "0x0102010000007821000100000000000000000000000000000000000000000000",
  /** {@link RaiseRevertEstimate} signed chain-agnostically (multichain domain). */
  RaiseRevertEstimateMultiChain = "0x0103010000007821000100000000000000000000000000000000000000000000",
}

/** Approval flag stored against a digest on the account (`approvedDigest` view). */
export enum DigestApproval {
  /** No approval recorded. */
  Unset = 0,
  /** The digest is an approved `Calls` hash (an embedded call). */
  Call = 1,
  /** The digest is an approved message hash (a pre-approved signature). */
  Signature = 2,
}

/**
 * A WebAuthn (passkey) assertion, as produced by an authenticator. Catapultar
 * ABI-encodes this into the `WebAuthnAuth` struct the account expects.
 */
export type WebAuthnSignature = {
  authenticatorData: `0x${string}`;
  clientDataJSON: string;
  challengeIndex: number;
  typeIndex: number;
  r: bigint;
  s: bigint;
};

/**
 * The output a signer must produce for a given {@link Owner}. ECDSA and P256
 * keys deliver a raw hex signature; WebAuthn delivers a structured object that
 * Catapultar encodes for you.
 */
export type KeyedSignature<O extends Owner = Owner> = O extends {
  type: "webauthn-p256";
}
  ? WebAuthnSignature
  : `0x${string}`;

/**
 * Parameters for constructing a {@link CatapultarAccount}.
 *
 * Connectivity is optional: pass a viem `client` (or an `rpc` + `chainId`
 * convenience pair) to enable on-chain reads, or leave them off for a purely
 * offline account. `chainId` on its own is enough to build single-chain
 * EIP-712 domains without a client.
 */
export type AccountConstructorParams<O extends Owner = Owner> = {
  address: `0x${string}`;
  owner: O;
  name?: string;
  /** EIP-712 domain version. Defaults to `0.1.1` (the deployed contract's domain). */
  version?: string;
  chainId?: number;
  /** Bring-your-own viem client used for on-chain reads. */
  client?: PublicClient;
  /** Convenience: an RPC URL Catapultar uses to build a client (needs `chainId`). */
  rpc?: string;
};

//-- Typehashed Objects --//

// Typehashed Calls

/** A single low-level call: target, native value, and calldata. */
export type Call = {
  to: `0x${string}`;
  value: bigint;
  data: `0x${string}`;
};

/** A single executable call. viem-compatible; alias of {@link Call}. */
export type Executable = Call;

/** Return shape of {@link BaseTransaction.asParameters}. */
export type ExecuteParameters = {
  mode: ExecutionMode | undefined;
  executionData: `0x${string}`;
  metadata: {
    value: bigint;
    signature: `0x${string}` | undefined;
  };
};

/** A nonced batch of {@link Call}s executed under one {@link ExecutionMode}. */
export type Calls = {
  nonce: bigint;
  mode: `0x${string}`;
  calls: Call[];
};

/** EIP-712 type table for {@link Calls} / {@link Call} (mirrors `LibCalls`). */
export const CallsTyped = {
  Calls: [
    { name: "nonce", type: "uint256" },
    { name: "mode", type: "bytes32" },
    { name: "calls", type: "Call[]" },
  ],
  Call: [
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "data", type: "bytes" },
  ],
} as const;

// Typehashed ExecutionConstraint

/** A token + maximum amount the constraint's executor may pull. */
export type Allowance = {
  token: `0x${string}`;
  amount: bigint;
};

/**
 * A spend resolved at execution time: the originally `allocated` allowance and
 * the actual `spend` (use {@link SPEND_FULL_BALANCE} to spend the full balance).
 */
export type AllowanceSpend = {
  token: `0x${string}`;
  allocated: bigint;
  spend: bigint;
};

/**
 * A token amount that must be delivered to `destination` for the constraint to
 * pass. Use {@link OUTCOME_TO_SIGNER} (`address(0)`) to route back to the signer.
 */
export type Outcome = {
  token: `0x${string}`;
  amount: bigint;
  destination: `0x${string}`;
};

/**
 * The CAT Validator constraint: allowances the `executor` may spend in exchange
 * for delivering `outcomes`, bound to a `nonce` (0 = perpetual/reusable).
 */
export type ExecutionConstraint = {
  allowances: Allowance[];
  outcomes: Outcome[];
  executor: `0x${string}`;
  nonce: bigint;
};

/** EIP-712 type table for {@link ExecutionConstraint} (mirrors `LibExecutionConstraint`). */
export const ExecutionConstraintTyped = {
  ExecutionConstraint: [
    { name: "allowances", type: "Allowance[]" },
    { name: "outcomes", type: "Outcome[]" },
    { name: "executor", type: "address" },
    { name: "nonce", type: "uint256" },
  ],
  Allowance: [
    { name: "token", type: "address" },
    { name: "amount", type: "uint256" },
  ],
  Outcome: [
    { name: "token", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "destination", type: "address" },
  ],
} as const;

//-- Factory pattern types --//

/**
 * A factory/template pair used for deployment and CREATE2 address derivation:
 * the `factory` is the deploying contract, the `template` is the implementation
 * cloned from it. Defaults to the library's well-known pair (see `_factory`).
 */
export type Factory = {
  factory: `0x${string}`;
  template: `0x${string}`;
};

/** A digest embedded into an account at deploy time. */
export type EmbeddedDigest = {
  /** The digest to approve: a Calls typehash, or a signing message hash. */
  hash: `0x${string}`;
  /** `true` to approve as a signature, `false` to approve as a call. */
  isSignature: boolean;
};

/**
 * Options for {@link CatapultarAccount.deploy} / {@link CatapultarAccount.predict}.
 *
 * `factory` defaults to the library's well-known factory/template. Provide a
 * `digest` to embed an approved call/signature at deploy time — because these
 * are explicit named fields, a misspelled or partial option fails to compile.
 * `version` only sets the returned account handle's EIP-712 domain version; it
 * does not affect factory calldata or the predicted deployment address.
 *
 * `upgradeable` selects the clone strategy: omitted/`false` mints the cheap
 * immutable PUSH0 clone, `true` mints a durable ERC-1967 proxy the owner can
 * later `upgrade`. The union below makes `{ upgradeable: true, digest }` a
 * compile error — the factory's `deployWithDigest` only mints PUSH0 clones, so
 * an embedded digest and upgradeability are mutually exclusive on-chain.
 */
export type DeployOptions<O extends Owner = Owner> = {
  salt: `0x${string}`;
  owner: O;
  factory?: Factory;
  version?: string;
} & (
  | { upgradeable?: false; digest?: EmbeddedDigest }
  | { upgradeable: true; digest?: never }
);
