import { hashTypedData, zeroAddress, type PublicClient } from "viem";
import {
  ExecutionConstraintTyped,
  type ExecutionConstraint,
} from "../types/types";
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
 * Read whether a constraint `nonce` has already been spent for `account` on the
 * `CATValidator` (`spentNonces` view). Nonce 0 is the perpetual constraint and
 * is never marked spent, so this always returns `false` for it.
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
