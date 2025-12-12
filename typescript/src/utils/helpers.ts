/**
 * Pads a string such that it has an even length OR until a specific minimum.
 * @param s String to pad.
 * @param minimal Optional length. Default 2.
 * @param pad Value to pad with. Default: 0
 */
export function padEven(s: string, minimal = 2, pad: string = '0') {
  return s.padStart(((Math.max(s.length + 1, minimal) / 2) | 0) * 2, pad);
}

/**
 * Converts a number into a hex string.
 * @param num Number to convert into hex. Takes Number or BigInt
 * @param bytes How many bytes to pad the number to. Default: 1
 * @param prefix Value to prefix the hex string with. Default: ''
 * @returns Returns the provided value as a hex string.
 */
export function toHex<T extends string = ''>(
  num: number | bigint,
  bytes: number = 1,
  prefix?: T,
): `${T}${string}` {
  const p = (prefix ?? '') as T;
  return `${p}${padEven(num.toString(16), bytes * 2)}` as `${T}${string}`;
}

/**
 * Validate whether an a salt value contains a specific address as the initial values.
 */
export function saltContainsAddress(
  address: `0x${string}`,
  salt: `0x${string}`,
): boolean {
  const saltSlice = salt.slice(0, 42);
  if (saltSlice === '0x0000000000000000000000000000000000000000') return true;
  return saltSlice === address;
}

/**
 * Returns a random hex value.
 * @param length Number of bytes to get.
 */
export const random = (length: number): `0x${string}` =>
  `0x${Array.from(
    crypto.getRandomValues(new Uint8Array(Math.ceil((length * 2) / 2))),
    (b) => b.toString(16).padStart(2, '0'),
  )
    .join('')
    .slice(0, length * 2)}`;
