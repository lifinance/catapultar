import { encodeAbiParameters } from "viem";
import { CallsTyped, type Call } from "../types/types";
import { asHex } from "../utils/helpers";
import { assertNonce } from "./validation";

/**
 * `opData` and execution-data encoding.
 *
 * Mirrors `Catapultar._validateOpData`, which reads `opData` as
 * `abi.encodePacked(bytes32(nonce), signature)`: the nonce occupies the first
 * 32 bytes and the signature (if any) follows. A bare 32-byte `opData` (no
 * signature) is the self-call / approved-digest form.
 */

/** Pack a nonce and optional signature into `opData`. */
export function buildOpData(
  nonce: bigint | undefined,
  signature?: `0x${string}`,
): `0x${string}` {
  assertNonce(nonce);
  if (signature) {
    return `0x${asHex(nonce, 32)}${signature.replace("0x", "")}`;
  }
  return asHex(nonce, 32, "0x");
}

/**
 * ABI-encode `(Call[] calls, bytes opData)` — the payload `ERC7821.execute`
 * decodes for the Catapultar execution mode.
 */
export function buildExecutionData(
  calls: Call[],
  opData: `0x${string}`,
): `0x${string}` {
  return encodeAbiParameters(
    [{ type: "tuple[]", components: CallsTyped.Call }, { type: "bytes" }],
    [calls, opData],
  );
}
