import { ValidationError } from "../errors";
import type { Owner, OwnerType } from "../types/types";

/**
 * Proportional code-override margin, in percent (ceiling-rounded by
 * {@link applyCodeOverrideMargin}, which `MetaCatapultarTx.estimateGas`
 * applies whenever the estimate ran with an RPC code override).
 *
 * The code-override estimate runs the account's runtime bytecode directly at
 * the account address, without the clone's delegatecall frames, and each extra
 * real frame retains 1/64 of gas (EIP-150) — roughly 5% at typical batch
 * scale. On the tested shape its headroom also absorbs the signed path's
 * EIP-712 `Calls` struct hashing, which every unsigned estimate skips
 * (override or not) and which grows with batch calldata — non-override
 * estimates lean on the flat {@link SIGNED_PATH_GAS_OVERHEAD} for it. A fixed
 * percent covers the tested shape (a code-override estimate broadcast through
 * a single clone proxy hop); every additional nesting boundary (e.g. a
 * Catapultar self-call) compounds another ~64/63 and is NOT covered.
 */
export const ESTIMATE_GAS_MARGIN_PERCENT = 10n;

/**
 * Add the proportional {@link ESTIMATE_GAS_MARGIN_PERCENT} (ceiling-rounded)
 * to a raw code-override estimate. Applied automatically by
 * `MetaCatapultarTx.estimateGas` when the estimation ran with an RPC code
 * override, compensating for the clone's delegatecall frame and other
 * proportional costs the override path skips.
 */
export function applyCodeOverrideMargin(estimate: bigint): bigint {
  if (estimate < 0n)
    throw new ValidationError(`Estimate must be non-negative: ${estimate}`);
  return estimate + (estimate * ESTIMATE_GAS_MARGIN_PERCENT + 99n) / 100n;
}

/**
 * Flat signed-path overhead per owner type, in gas, assuming the chain has NO
 * RIP-7212 P256 precompile — Solady's `P256.verifySignature` then falls back
 * to its deployed verifier contract (~200-330k gas). This is the conservative
 * default; on precompile chains the unused gas is simply refunded.
 *
 * Besides signature validation the overhead absorbs the signature's opData
 * calldata and the EIP-712 digest hashing the unsigned estimate skips (the
 * hashing grows with batch calldata; very large batches without a
 * code-override estimate may outgrow the flat cover).
 *
 * `ecdsa` means an EOA owner (ecrecover). An ERC-1271 smart-contract owner
 * shares the same wire type but its `isValidSignature` cost is unbounded and
 * unknowable to the SDK — pass its cost via
 * {@link EstimateGasMarginOptions.signatureValidationGas}.
 *
 * These are tested policy defaults (validated by the estimate→signed-broadcast
 * suite against Solady's fallback verifier), not mathematically sufficient
 * bounds.
 */
export const SIGNED_PATH_GAS_OVERHEAD = {
  ecdsa: 50_000n,
  p256: 350_000n,
  "webauthn-p256": 420_000n,
} as const satisfies Readonly<Record<OwnerType, bigint>>;

/**
 * Flat signed-path overhead per owner type when the executing chain has the
 * RIP-7212 P256 precompile (3,450 gas per verification). Analytic values
 * derived from the precompile's fixed cost plus the WebAuthn envelope
 * (SHA-256s, clientDataJSON checks, ~500-650 bytes of signature calldata) —
 * not yet integration-tested on a precompile-enabled chain.
 */
export const SIGNED_PATH_GAS_OVERHEAD_WITH_P256_PRECOMPILE = {
  ecdsa: 50_000n,
  p256: 65_000n,
  "webauthn-p256": 135_000n,
} as const satisfies Readonly<Record<OwnerType, bigint>>;

export type EstimateGasMarginOptions = {
  /**
   * The executing chain implements the RIP-7212 P256 precompile, so p256 /
   * webauthn-p256 validation costs ~3.5k instead of the ~300k fallback
   * verifier. Defaults to false (conservative).
   */
  p256Precompile?: boolean;
  /**
   * REPLACES the owner-type default flat overhead with a caller-supplied
   * budget for the ENTIRE signed path — not just signature validation but
   * also the signature's opData calldata and the EIP-712 digest hashing the
   * table entries otherwise cover. Required for ERC-1271 smart-contract
   * owners (wire type `ecdsa`), whose `isValidSignature` cost the SDK cannot
   * know: budget that cost plus the base signed-path costs (the `ecdsa` table
   * entry is a reasonable floor to add on top of).
   */
  signatureValidationGas?: bigint;
};

/**
 * Turn an unsigned {@link MetaCatapultarTx.estimateGas} result into a
 * recommended gas limit for the signed broadcast.
 *
 * The unsigned estimate runs on the self-call path, so it excludes signature
 * validation, the signature's opData calldata, and the EIP-712 digest
 * hashing. This helper adds a flat
 * per-owner-type overhead for those ({@link SIGNED_PATH_GAS_OVERHEAD}, or
 * {@link SIGNED_PATH_GAS_OVERHEAD_WITH_P256_PRECOMPILE} when
 * `options.p256Precompile` is set). The proportional code-override margin is
 * NOT added here — `MetaCatapultarTx.estimateGas` already applies
 * {@link applyCodeOverrideMargin} to estimates that ran with a code override.
 *
 * The result is a recommended budget, not a guaranteed bound: it does not
 * cover arbitrary Catapultar nesting depth, state divergence between
 * estimation and inclusion, unusually large WebAuthn assertions, or ERC-1271
 * owners without an explicit `signatureValidationGas`. It may also exceed a
 * chain's transaction or block gas cap — cap it yourself where relevant.
 *
 * @param estimate The unsigned estimate returned by `estimateGas()`.
 * @param owner The account owner (or its `type` tag) controlling which flat
 *   overhead applies.
 */
export function applyEstimateGasMargin(
  estimate: bigint,
  owner: Owner | OwnerType,
  options?: EstimateGasMarginOptions,
): bigint {
  if (estimate < 0n)
    throw new ValidationError(`Estimate must be non-negative: ${estimate}`);
  if (
    options?.signatureValidationGas !== undefined &&
    options.signatureValidationGas < 0n
  )
    throw new ValidationError(
      `signatureValidationGas must be non-negative: ${options.signatureValidationGas}`,
    );
  const type = typeof owner === "string" ? owner : owner.type;
  const table = options?.p256Precompile
    ? SIGNED_PATH_GAS_OVERHEAD_WITH_P256_PRECOMPILE
    : SIGNED_PATH_GAS_OVERHEAD;
  const flat = options?.signatureValidationGas ?? table[type];
  if (flat === undefined)
    throw new ValidationError(`Unknown owner type: ${String(type)}`);
  return estimate + flat;
}
