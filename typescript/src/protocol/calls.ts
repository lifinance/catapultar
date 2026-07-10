import { hashStruct, hashTypedData, keccak256, toBytes } from "viem";
import { CallsTyped, ExecutionMode, type Call } from "../types/types";

/**
 * EIP-712 / typed-data encoding for the `Calls` struct.
 *
 * This is the TypeScript mirror of `LibCalls.typehash` and the digest selection
 * in `Catapultar._validateOpData`. `viem`'s `hashStruct` / `hashTypedData`
 * produce byte-identical results to the on-chain hashing (verified against
 * `LibCalls.sol`), so all `Calls` hashing flows through here.
 */

/** `keccak256("Call(address to,uint256 value,bytes data)")` (mirrors LibCalls). */
export const CALL_TYPE_HASH = keccak256(
  toBytes("Call(address to,uint256 value,bytes data)"),
);

/** `keccak256` of the full `Calls` type string (mirrors LibCalls). */
export const CALLS_TYPE_HASH = keccak256(
  toBytes(
    "Calls(uint256 nonce,bytes32 mode,Call[] calls)Call(address to,uint256 value,bytes data)",
  ),
);

export type CallsMessage = {
  nonce: bigint;
  mode: ExecutionMode | `0x${string}`;
  calls: Call[];
};

/**
 * EIP-712 domain for a Catapultar account. `chainId` is intentionally optional:
 * when it is omitted entirely (not zeroed) `viem` derives the chain-less
 * `EIP712Domain` typehash, matching the contract's `_hashTypedDataSansChainId`
 * used for multichain modes.
 */
export type CatapultarDomain = {
  name: string;
  version: string;
  chainId?: number;
  verifyingContract: `0x${string}`;
};

/** Build the EIP-712 typed-data object for a `Calls` message. */
export function callsTypedData(
  domain: CatapultarDomain,
  message: CallsMessage,
) {
  return {
    domain,
    types: CallsTyped,
    primaryType: "Calls",
    message,
  } as const;
}

/**
 * Struct hash of a `Calls` message without the domain envelope. This is the
 * "call digest" that can be embedded into an account (it must equal
 * `LibCalls.typehash(nonce, mode, calls)`).
 */
export function callsStructHash(message: CallsMessage): `0x${string}` {
  return hashStruct({
    types: CallsTyped,
    primaryType: "Calls",
    data: message,
  });
}

/** Full EIP-712 digest (domain-wrapped) for a `Calls` message. */
export function callsDigest(
  domain: CatapultarDomain,
  message: CallsMessage,
): `0x${string}` {
  return hashTypedData(callsTypedData(domain, message));
}

/**
 * Whether an execution mode carries the multichain flag. Multichain modes are
 * signed without a `chainId` in the domain (see {@link CatapultarDomain}).
 */
export function isMultichainMode(mode: ExecutionMode | undefined): boolean {
  return (
    mode === ExecutionMode.RaiseRevertMultiChain ||
    mode === ExecutionMode.SkipRevertMultiChain ||
    mode === ExecutionMode.EstimateGasMultiChain
  );
}

/**
 * The viem-shaped EIP-712 typed-data object Catapultar asks a signer to sign.
 * This is exactly what {@link CatapultarTx.getSignerData} returns, so an
 * external signer/relayer can type its callback against it.
 */
export type Signable = ReturnType<typeof callsTypedData>;
