import {
  compactSignatureToSignature,
  encodeAbiParameters,
  parseAbiParameters,
  parseCompactSignature,
  parseSignature,
  serializeCompactSignature,
  serializeSignature,
  signatureToCompactSignature,
} from "viem";
import type { KeyedSignature, WebAuthnSignature } from "../types/types";
import type { Owner } from "./owner";

/**
 * Keyed-signature encoding for the on-chain wire format.
 *
 * Mirrors `KeyedOwnable._validateSignature`. This is the single place that
 * turns a signer's output into the bytes the account expects, replacing the
 * previously-duplicated `account.parseSignature` and (dead) `asCompatibleSignature`.
 *
 * Dispatch is always on `owner.type` — never on the signature's TypeScript type
 * — because ECDSA and P256 both surface as a hex string yet encode differently
 * (P256 needs a trailing prehash-flag byte; ECDSA passes through).
 */

/** Compress a 65-byte ECDSA signature to its 64-byte EIP-2098 form. */
export function toCompactSignature(signature: `0x${string}`): `0x${string}` {
  const sig = parseSignature(signature);
  return serializeCompactSignature(signatureToCompactSignature(sig));
}

/** Expand a 64-byte EIP-2098 compact signature back to 65 bytes. */
export function fromCompactSignature(signature: `0x${string}`): `0x${string}` {
  const compactSig = parseCompactSignature(signature);
  return serializeSignature(compactSignatureToSignature(compactSig));
}

/**
 * Normalize an ECDSA signature for `opData`: compress 65 bytes to the 64-byte
 * EIP-2098 form (the account accepts either). Non-ECDSA-length signatures are
 * returned untouched so P256/WebAuthn payloads are never accidentally compacted.
 */
export function compactSignature(signature: `0x${string}`): `0x${string}` {
  const raw = signature.replace("0x", "");
  if (raw.length === 64 * 2) return signature;
  if (raw.length !== 65 * 2) return signature;
  return toCompactSignature(signature);
}

const WEBAUTHN_AUTH_PARAMS = parseAbiParameters([
  "WebAuthnAuth auth",
  "struct WebAuthnAuth { bytes authenticatorData; string clientDataJSON; uint256 challengeIndex; uint256 typeIndex; uint256 r; uint256 s;}",
]);

/** ABI-encode a WebAuthn signature into the `WebAuthnAuth` struct bytes. */
export function encodeWebAuthnAuth(sig: WebAuthnSignature): `0x${string}` {
  return encodeAbiParameters(WEBAUTHN_AUTH_PARAMS, [
    {
      ...sig,
      typeIndex: BigInt(sig.typeIndex),
      challengeIndex: BigInt(sig.challengeIndex),
    },
  ]);
}

/**
 * Pad a raw P256 signature to 65 bytes and append the prehash-flag byte (`00`,
 * meaning "no SHA-256 prehash"). Signatures already longer than 65 bytes (i.e.
 * already carrying a flag byte) are returned unchanged.
 */
export function normalizeP256(signature: `0x${string}`): `0x${string}` {
  let raw = signature.replace("0x", "");
  if (raw.length <= 65 * 2) {
    raw = `${raw.padEnd(65 * 2, "0")}00`;
  }
  return `0x${raw}`;
}

/**
 * Encode a keyed signature into the on-chain wire format for the given owner.
 * - `ecdsa`: returned as-is (compaction happens later, in `opData`).
 * - `p256`: padded to 65 bytes + `00` prehash flag.
 * - `webauthn-p256`: ABI-encoded `WebAuthnAuth` struct + `00` prehash flag.
 */
export function normalizeSignature(
  owner: Owner,
  signature: KeyedSignature<Owner>,
): `0x${string}` {
  if (owner.type === "ecdsa") return signature as `0x${string}`;
  if (owner.type === "p256") return normalizeP256(signature as `0x${string}`);
  // webauthn-p256
  return `${encodeWebAuthnAuth(signature as WebAuthnSignature)}00`;
}
