import { ExecutionMode, type Call } from "../types/types";
import {
  CallsUnsetError,
  ModeUnsetError,
  NonceUnsetError,
  NonceZeroError,
} from "../errors";

/**
 * Shared transaction-field validation. These guards were previously duplicated
 * across `getSignerData`, `getOpData`, and `asDigest`; they now live in one
 * place so the rules (and their error messages) cannot drift.
 */

export const NONCE_ZERO_ERROR =
  "Nonce 0 is not allowed. It cannot be differentiated from an invalid nonce.";

/** Assert a usable nonce is present. Nonce 0 is reserved as "unset" on-chain. */
export function assertNonce(
  nonce: bigint | undefined,
): asserts nonce is bigint {
  if (nonce === 0n) throw new NonceZeroError(NONCE_ZERO_ERROR);
  if (nonce === undefined) throw new NonceUnsetError("Nonce has not been set");
}

/** Assert a valid execution mode is set. */
export function assertMode(
  mode: ExecutionMode | undefined,
): asserts mode is ExecutionMode {
  if (!mode || !Object.values(ExecutionMode).includes(mode))
    throw new ModeUnsetError("Mode has not been set");
}

/** Assert at least one call has been added. */
export function assertCalls(calls: Call[]): void {
  if (calls.length === 0) throw new CallsUnsetError("Calls have not been set");
}
