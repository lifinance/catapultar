import {
  compactSignatureToSignature,
  decodeAbiParameters,
  encodeAbiParameters,
  isAddressEqual,
  parseAbiParameters,
  parseCompactSignature,
  parseSignature,
  recoverAddress,
  serializeCompactSignature,
  serializeSignature,
  sha256,
  signatureToCompactSignature,
} from "viem";
import { P256, PublicKey, WebAuthnP256 } from "ox";
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

/** Decode `WebAuthnAuth` struct bytes back into its fields (inverse of {@link encodeWebAuthnAuth}). */
export function decodeWebAuthnAuth(hex: `0x${string}`) {
  return decodeAbiParameters(WEBAUTHN_AUTH_PARAMS, hex)[0];
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

/**
 * Verify an on-chain-wire signature against an owner key, offline. The inverse
 * of {@link normalizeSignature}: dispatch is on `owner.type` (never the JS type
 * of `signature`), and the P256/WebAuthn wire format — the trailing prehash-flag
 * byte, the `r`/`s` split, and the `WebAuthnAuth` struct — is decoded here in the
 * one module that also encodes it, so encode and decode cannot drift.
 *
 * Mirrors the owner-key half of `KeyedOwnable._validateSignature`: a non-zero
 * prehash flag re-hashes the digest with SHA-256 before verification.
 *
 * For an `ecdsa` owner this only checks ECDSA recovery against the owner address
 * — a smart-contract (ERC-1271) owner returns `false` here and must be verified
 * on-chain by the caller.
 */
export async function verifyKeyedSignature(
  owner: Owner,
  hash: `0x${string}`,
  signature: `0x${string}`,
): Promise<boolean> {
  if (owner.type === "ecdsa") {
    // Only recover ECDSA-sized signatures (65 bytes, or a 64-byte EIP-2098
    // compact signature). Any other length is a contract signature: return
    // false and let the caller defer to ERC-1271. The try/catch also covers
    // correctly-sized but unrecoverable signatures (e.g. invalid v/yParity).
    if (signature.length !== 65 * 2 + 2 && signature.length !== 64 * 2 + 2)
      return false;
    try {
      const signer = await recoverAddress({
        hash,
        signature:
          signature.length === 64 * 2 + 2
            ? fromCompactSignature(signature)
            : signature,
      });
      return isAddressEqual(owner.address, signer);
    } catch {
      return false;
    }
  }

  const raw = signature.replace("0x", "");
  if (raw.length <= 65 * 2) return false;
  const publicKey = PublicKey.from({ x: BigInt(owner.x), y: BigInt(owner.y) });
  // Trailing byte is the prehash flag; the rest is the signature body.
  const prehash = raw.slice(-2) !== "00";
  const body = raw.slice(0, -2);

  if (owner.type === "p256") {
    const r = BigInt(`0x${body.slice(0, 64)}`);
    const s = BigInt(`0x${body.slice(64, 128)}`);
    // `hash: prehash` makes ox SHA-256 the payload first, mirroring the
    // on-chain `sha256(digest)` path when the flag is set.
    return P256.verify({
      payload: hash,
      hash: prehash,
      publicKey,
      signature: { r, s },
    });
  }

  // webauthn-p256
  const auth = decodeWebAuthnAuth(`0x${body}`);
  return WebAuthnP256.verify({
    metadata: {
      authenticatorData: auth.authenticatorData,
      clientDataJSON: auth.clientDataJSON,
      challengeIndex: Number(auth.challengeIndex),
      typeIndex: Number(auth.typeIndex),
    },
    // On-chain the challenge is `abi.encode(digest)` (the possibly-prehashed
    // digest), so SHA-256 the hash when the flag is set.
    challenge: prehash ? sha256(hash) : hash,
    publicKey,
    signature: { r: auth.r, s: auth.s },
  });
}
