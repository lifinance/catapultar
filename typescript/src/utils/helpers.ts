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
