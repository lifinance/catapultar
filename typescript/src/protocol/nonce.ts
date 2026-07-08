/**
 * Unordered-nonce bitmap math (mirrors `BitmapNonce`).
 *
 * A nonce is split into a 248-bit word position (the upper bits) and an 8-bit
 * position within that word's 256-bit bitmap (the lower byte). These primitives
 * are the single definition of that split, shared by every place that reads or
 * builds a nonce bitmap so the shift/mask rules cannot drift.
 */

/** Bitmap word a nonce lives in: the nonce shifted right by 8 bits. */
export function nonceWord(nonce: bigint): bigint {
  return nonce >> 8n;
}

/** Bit position of a nonce within its word: the low byte (`0`–`255`). */
export function nonceBit(nonce: bigint): bigint {
  return nonce & 255n;
}

/**
 * Group nonces into per-word bitmap masks, OR-ing each nonce's bit into its
 * word. The result maps `wordPos -> mask`, ready for `invalidateUnorderedNonces`
 * or a batched `nonceBitmap` lookup.
 */
export function groupNoncesByWord(nonces: bigint[]): Map<bigint, bigint> {
  const words = new Map<bigint, bigint>();
  for (const nonce of nonces) {
    const word = nonceWord(nonce);
    words.set(word, (words.get(word) ?? 0n) | (1n << nonceBit(nonce)));
  }
  return words;
}
