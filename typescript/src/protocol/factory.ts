import { encodePacked, keccak256 } from "viem";

/**
 * CREATE2 salt derivation for the Catapultar factory.
 *
 * Mirrors `CatapultarFactory._salt`:
 * `keccak256(preSalt || ktp(1 byte) || numOwners(1 byte) || key[0] || ... || key[n])`,
 * and the digest variant appended for `deployWithDigest`.
 */

/**
 * Inner factory salt over the key array.
 * @param preSalt Caller-provided salt.
 * @param ktp Numeric `PublicKeyType` enum value.
 * @param keyArray Owner key encoded as `bytes32[]` (see `ownerToKeyArray`).
 */
export function factorySalt(
  preSalt: `0x${string}`,
  ktp: number,
  keyArray: `0x${string}`[],
): `0x${string}` {
  const numOwners = keyArray.length;
  const types = [
    "bytes32",
    "uint8",
    "uint8",
    ...keyArray.map((): "bytes32" => "bytes32"),
  ] as const;
  const values = [preSalt, ktp, numOwners, ...keyArray] as const;
  return keccak256(
    encodePacked(types as unknown as string[], values as unknown as unknown[]),
  );
}

/**
 * Final salt for an account deployed with an embedded digest:
 * `keccak256(internalSalt || digest || uint256(isSignature ? 2 : 1))`.
 */
export function factorySaltWithDigest(
  internalSalt: `0x${string}`,
  callDigest: `0x${string}`,
  isSignature: boolean,
): `0x${string}` {
  return keccak256(
    encodePacked(
      ["bytes32", "bytes32", "uint256"],
      [internalSalt, callDigest, isSignature ? 2n : 1n],
    ),
  );
}
