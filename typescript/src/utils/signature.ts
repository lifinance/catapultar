import {
  compactSignatureToSignature,
  parseCompactSignature,
  parseSignature,
  serializeCompactSignature,
  serializeSignature,
  signatureToCompactSignature,
} from "viem";

export function toCompactSignature(signature: `0x${string}`) {
  const sig = parseSignature(signature);
  return serializeCompactSignature(signatureToCompactSignature(sig));
}

export function fromCompactSignature(signature: `0x${string}`) {
  const compactSig = parseCompactSignature(signature);
  return serializeSignature(compactSignatureToSignature(compactSig));
}
