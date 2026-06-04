import {
  AccountPublicKeyType,
  type AccountPublicVar,
  type Pubkey,
} from "../types/types";

/**
 * Pads a string such that it has an even length OR until a specific minimum.
 * @param s String to pad.
 * @param minimal Optional length. Default 2.
 * @param pad Value to pad with. Default: 0
 */
export function padEven(s: string, minimal = 2, pad: string = "0") {
  return s.padStart(((Math.max(s.length + 1, minimal) / 2) | 0) * 2, pad);
}

/**
 * Converts a number into a hex string.
 * @param num Number to convert into hex. Takes Number or BigInt
 * @param bytes How many bytes to pad the number to. Default: 1
 * @param prefix Value to prefix the hex string with. Default: ''
 * @returns Returns the provided value as a hex string.
 */
export function asHex<T extends string = "">(
  num: number | bigint,
  bytes: number = 1,
  prefix?: T,
): `${T}${string}` {
  const p = (prefix ?? "") as T;
  return `${p}${padEven(num.toString(16), bytes * 2)}` as `${T}${string}`;
}

/**
 * Returns a random hex value.
 * @param length Number of bytes to get.
 */
export const random = (length: number): `0x${string}` =>
  `0x${Array.from(crypto.getRandomValues(new Uint8Array(length)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("")}`;

/**
 * Takes an pubkey array of a key type and pubkey structure and after validation returns it as an array.
 * @param options AccountPublicKeyType and pubkey. if ECDSA or smart contract, pubkey is provided as a 20 or 32 bytes string otherwise as an array.
 */
export function pubkeyAsArray<AKT extends AccountPublicKeyType>(
  options: Pubkey<AKT>,
) {
  if (options.keyType === AccountPublicKeyType.ECDSAOrSmartContract) {
    if (typeof options.pubkey !== "string")
      throw new Error(`PublicKeyType not expected ${typeof options.pubkey}`);
    // Check pubkey is formatted correctly. Either 20 bytes or 32 bytes with first 12 bytes empty.
    const pubkeyAddress = options.pubkey.replace("0x", "");
    if (
      !(
        pubkeyAddress.length === 20 * 2 ||
        (pubkeyAddress.length === 32 * 2 &&
          pubkeyAddress.slice(0, 12 * 2) === "000000000000000000000000")
      )
    )
      throw new Error(`Pubkey address incorrectly formatted: ${pubkeyAddress}`);

    // Validate that pubkey is `0x${string}`
    return [`0x${padEven(pubkeyAddress, 64)}`] as [`0x${string}`];
  } else if (
    options.keyType === AccountPublicKeyType.P256 ||
    options.keyType === AccountPublicKeyType.WebAuthnP256
  ) {
    if (options.pubkey.length !== 2)
      throw new Error(
        `Invalid pubkey array ${options.pubkey}, length ${options.pubkey.length} !== 2`,
      );
    return options.pubkey as AccountPublicVar<
      AccountPublicKeyType.P256 | AccountPublicKeyType.WebAuthnP256
    >;
  } else {
    throw new Error(`PublicKeyType not supported ${options.keyType}`);
  }
}
