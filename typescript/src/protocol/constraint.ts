import {
  concat,
  hashTypedData,
  keccak256,
  size,
  zeroAddress,
  zeroHash,
  type PublicClient,
} from "viem";
import {
  ExecutionConstraintTyped,
  ExecutionConstraintV2Typed,
  type ExecutionConstraint,
  type ExecutionConstraintV2,
  type ValidationCommitment,
} from "../types/types";
import { ValidationError } from "../errors";
import { CAT_VALIDATOR_ABI } from "../abi/CATValidator";

/**
 * EIP-712 encoding for the CAT Validator's `ExecutionConstraint`.
 *
 * This is the TypeScript mirror of `LibExecutionConstraint.typehash` plus the
 * `CATValidator` EIP-712 domain. `viem`'s `hashTypedData` produces a
 * byte-identical digest to the on-chain `_hashTypedData(typehash(...))`, so all
 * constraint hashing flows through here (it replaces the inline encoding that
 * previously lived in `ConstrainedAssetTransaction`).
 */

/** Domain name of the deployed `CATValidator` (mirrors `_domainNameAndVersion`). */
export const CAT_VALIDATOR_DOMAIN_NAME = "CAT Validator";
/** Domain version of the deployed `CATValidator`. */
export const CAT_VALIDATOR_DOMAIN_VERSION = "1";

/**
 * Outcome destination sentinel: `address(0)` routes the outcome to the signer
 * (the account whose assets back the constraint). Mirrors the `destination ==
 * address(0) ? signer : destination` branch in `CATValidator._validatePayment`.
 */
export const OUTCOME_TO_SIGNER = zeroAddress;

/**
 * Spend sentinel: `1 << 255` tells the validator to spend the signer's *full
 * current balance* of the token instead of a fixed amount. Mirrors
 * `CATValidator.SPEND_BALANCE_OF_MAGIC`. Useful for "sweep everything" flows
 * (e.g. DCA) where the exact balance is unknown at signing time.
 */
export const SPEND_FULL_BALANCE = 1n << 255n;

/** EIP-712 domain for the CAT Validator on a given chain. */
export type CatValidatorDomain = {
  chainId: number;
  verifyingContract: `0x${string}`;
};

/** Build the EIP-712 domain object for the CAT Validator. */
export function constraintDomain(domain: CatValidatorDomain) {
  return {
    name: CAT_VALIDATOR_DOMAIN_NAME,
    version: CAT_VALIDATOR_DOMAIN_VERSION,
    chainId: domain.chainId,
    verifyingContract: domain.verifyingContract,
  } as const;
}

/** Build the EIP-712 typed-data object for an `ExecutionConstraint`. */
export function constraintTypedData(
  domain: CatValidatorDomain,
  constraint: ExecutionConstraint,
) {
  return {
    domain: constraintDomain(domain),
    types: ExecutionConstraintTyped,
    primaryType: "ExecutionConstraint",
    message: constraint,
  } as const;
}

/**
 * Full EIP-712 digest (domain-wrapped) for an `ExecutionConstraint`. This is the
 * value approved via `setSignature(..., DigestApproval.Signature)` so the
 * validator's empty-signature ERC-1271 path accepts the constraint.
 */
export function constraintDigest(
  domain: CatValidatorDomain,
  constraint: ExecutionConstraint,
): `0x${string}` {
  return hashTypedData(constraintTypedData(domain, constraint));
}

/**
 * Read whether a constraint `nonce` has already been spent for `account` on a
 * CAT validator (`spentNonces` view, identical on `CATValidator` and
 * `CATValidatorV2`). Nonce 0 is the perpetual constraint and is never marked
 * spent, so this always returns `false` for it.
 */
export async function isConstraintNonceSpent(
  client: PublicClient,
  options: {
    validator: `0x${string}`;
    account: `0x${string}`;
    nonce: bigint;
  },
): Promise<boolean> {
  if (options.nonce === 0n) return false;
  return client.readContract({
    address: options.validator,
    abi: CAT_VALIDATOR_ABI,
    functionName: "spentNonces",
    args: [options.account, options.nonce],
  });
}

// --- CATValidatorV2 --- //

/** Domain version of `CATValidatorV2`. The domain name is {@link CAT_VALIDATOR_DOMAIN_NAME}. */
export const CAT_VALIDATOR_V2_DOMAIN_VERSION = "2";

/** Size of one canonical validation-program command: `uint8 op ++ bytes32 data` (mirrors `LibValidationVM.COMMAND_SIZE`). */
export const VALIDATION_COMMAND_SIZE = 33;

/** Build the EIP-712 domain object for `CATValidatorV2`. */
export function constraintV2Domain(domain: CatValidatorDomain) {
  return {
    name: CAT_VALIDATOR_DOMAIN_NAME,
    version: CAT_VALIDATOR_V2_DOMAIN_VERSION,
    chainId: domain.chainId,
    verifyingContract: domain.verifyingContract,
  } as const;
}

/** Build the EIP-712 typed-data object for an {@link ExecutionConstraintV2}. */
export function constraintV2TypedData(
  domain: CatValidatorDomain,
  constraint: ExecutionConstraintV2,
) {
  return {
    domain: constraintV2Domain(domain),
    types: ExecutionConstraintV2Typed,
    primaryType: "ExecutionConstraint",
    message: constraint,
  } as const;
}

/**
 * Full EIP-712 digest for an {@link ExecutionConstraintV2}, the mirror of
 * `CATValidatorV2._hashTypedData(LibExecutionConstraintV2.typehash(...))`. This
 * is the value an account approves so `CATValidatorV2.entry` accepts the
 * constraint with an empty signature.
 */
export function constraintV2Digest(
  domain: CatValidatorDomain,
  constraint: ExecutionConstraintV2,
): `0x${string}` {
  return hashTypedData(constraintV2TypedData(domain, constraint));
}

/**
 * The committed `validationProgramHash` of a canonical program body: `keccak256`
 * of the tight-packed commands. An empty body has no program and commits
 * `bytes32(0)`.
 */
export function hashValidationProgram(program: `0x${string}`): `0x${string}` {
  return size(program) === 0 ? zeroHash : keccak256(program);
}

/**
 * The committed `paramsHash` of a params vector, the mirror of
 * `LibValidationVM.paramsHashOf`: `bytes32(0)` when empty, else `keccak256` of
 * the concatenated words. Throws if any word is not exactly 32 bytes, which the
 * validator rejects as `BadValidationParams`.
 */
export function hashValidationParams(params: `0x${string}`[]): `0x${string}` {
  if (params.length === 0) return zeroHash;
  params.forEach((word, i) => {
    if (size(word) !== 32)
      throw new ValidationError(
        `validationParams[${i}] is ${size(word)} bytes; every param word must be exactly 32 bytes.`,
      );
  });
  return keccak256(concat(params));
}

/**
 * Assert that the program and params supplied to `CATValidatorV2.entry` hash to
 * the commitment. The validator derives both hashes from the calldata and
 * checks the signature over them, so mismatching inputs produce a digest the
 * account never approved and the call reverts with `BadSignature`. The
 * remaining format checks (`BadValidationProgram`, `BadValidationParams`) are
 * the contract's; `hashValidationParams` still throws on a non-32-byte word.
 */
export function assertValidationInputs(
  commitment: ValidationCommitment,
  validationProgram: `0x${string}`,
  validationParams: `0x${string}`[],
): void {
  // Hex digits may arrive in either case; keccak256 and zeroHash are lowercase.
  if (
    hashValidationProgram(validationProgram) !==
    commitment.validationProgramHash.toLowerCase()
  )
    throw new ValidationError(
      "validationProgram does not hash to the committed validationProgramHash, so CATValidatorV2 would reject the call with BadSignature (the digest commits a different hash); pass the committed program body (empty when the hash is zero).",
    );
  if (
    hashValidationParams(validationParams) !==
    commitment.paramsHash.toLowerCase()
  )
    throw new ValidationError(
      "validationParams do not hash to the committed paramsHash, so CATValidatorV2 would reject the call with BadSignature (the digest commits a different hash); pass the committed param words (none when the hash is zero).",
    );
}
