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
 * @param RaiseRevert If a call fails, raise the revert message and do not spend the nonce.
 * @param SkipRevert If a call fails, skip the call, emit an event. The nonce will be spent if the transaction does not run out of gas.
 */
export enum ExecutionMode {
  RaiseRevert = "0x0100000000007821000100000000000000000000000000000000000000000000",
  SkipRevert = "0x0101000000007821000100000000000000000000000000000000000000000000",
  RaiseRevertMultiChain = "0x0100010000007821000100000000000000000000000000000000000000000000",
  SkipRevertMultiChain = "0x0101010000007821000100000000000000000000000000000000000000000000",
}

export enum DigestApproval {
  Unset = 0,
  Call = 1,
  Signature = 2,
}

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

export type Version = `0.1.0` | "0.0.1";

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
  version?: Version;
  chainId?: number;
  /** Bring-your-own viem client used for on-chain reads. */
  client?: PublicClient;
  /** Convenience: an RPC URL Catapultar uses to build a client (needs `chainId`). */
  rpc?: string;
};

//-- Typehashed Objects --//

// Typehashed Calls

export type Call = {
  to: `0x${string}`;
  value: bigint;
  data: `0x${string}`;
};

export type Calls = {
  nonce: bigint;
  mode: `0x${string}`;
  calls: Call[];
};

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

export type Allowance = {
  token: `0x${string}`;
  amount: bigint;
};

export type AllowanceSpend = {
  token: `0x${string}`;
  allocated: bigint;
  spend: bigint;
};

export type Outcome = {
  token: `0x${string}`;
  amount: bigint;
  destination: `0x${string}`;
};

export type ExecutionConstraint = {
  allowances: Allowance[];
  outcomes: Outcome[];
  executor: `0x${string}`;
  nonce: bigint;
};

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

export type EmbeddedCall = {
  callDigest: `0x${string}`;
  isSignature: boolean;
};

export type Factory = {
  factory: `0x${string}`;
  template: `0x${string}`;
};

export type MaybeFactory = {} | Factory;
