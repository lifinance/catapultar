/**
 * Catapultar — a TypeScript interface for the Catapultar ERC-7821 smart account.
 *
 * The library is layered so you can opt into as much abstraction as you need,
 * and is offline by default (build/hash/sign with no network; attach a viem
 * client to unlock on-chain reads):
 *
 * - **High level** ({@link CatapultarAccount}, {@link CatapultarTx},
 *   {@link MetaCatapultarTx}) — account-aware, validated build/sign/execute flows.
 * - **Low level** ({@link BaseTransaction}, {@link ConstrainedAssetTransaction})
 *   — minimal batch primitives without account context.
 * - **Protocol primitives** (`callsDigest`, `constraintDigest`,
 *   `predictCloneAddress`, the owner/signature codecs, …) — pure, side-effect-free
 *   encoders that mirror the on-chain libraries byte-for-byte, plus the contract
 *   ABIs and deployment addresses — for integrating without any of the classes.
 *
 * Bring your own signing and broadcasting at every layer.
 *
 * @packageDocumentation
 */

// --- High-level classes (src/catapultar) --- //

export { CatapultarAccount } from "./catapultar/account";
export { CatapultarTx, MetaCatapultarTx } from "./catapultar/catapultar";

// --- Low-level transaction primitives (src/transaction) --- //

export { BaseTransaction } from "./transaction/transaction";
export { ConstrainedAssetTransaction } from "./transaction/constrainedtransaction";

// --- Enums & wire constants --- //

export { ExecutionMode, DigestApproval } from "./types/types";
export { REPLAY_PROTECTION, ERC1271_MAGIC_VALUE } from "./catapultar/account";
export {
  CAT_VALIDATOR_DOMAIN_NAME,
  CAT_VALIDATOR_DOMAIN_VERSION,
  OUTCOME_TO_SIGNER,
  SPEND_FULL_BALANCE,
} from "./protocol/constraint";

// --- Errors --- //

export {
  CatapultarError,
  ValidationError,
  NonceZeroError,
  NonceUnsetError,
  ModeUnsetError,
  CallsUnsetError,
  NonceCollisionError,
  DuplicateNonceError,
  OwnerMismatchError,
  InvalidSignatureError,
  InvalidChainError,
  NotConnectedError,
} from "./errors";

// --- Contract ABIs --- //

export { default as catapultarAbi } from "./abi/catapultar";
export { default as catapultarFactoryAbi } from "./abi/catapultarFactory";
export { CAT_VALIDATOR_ABI as catValidatorAbi } from "./abi/CATValidator";

// --- Deployment addresses --- //

export { defaultFactory, cat_validator } from "./config";

// --- Unopinionated protocol primitives --- //
// Pure encoders/decoders that mirror the on-chain libraries. Use these to
// integrate without the class wrappers.

export {
  CALL_TYPE_HASH,
  CALLS_TYPE_HASH,
  callsTypedData,
  callsStructHash,
  callsDigest,
  isMultichainMode,
} from "./protocol/calls";
export {
  factorySalt,
  factorySaltWithDigest,
  predictCloneAddress,
  pushZeroCloneInitCode,
  erc1967CloneInitCode,
} from "./protocol/factory";
export { buildOpData, buildExecutionData } from "./protocol/opdata";
export {
  toCompactSignature,
  fromCompactSignature,
  compactSignature,
  encodeWebAuthnAuth,
  decodeWebAuthnAuth,
  normalizeP256,
  normalizeSignature,
  verifyKeyedSignature,
} from "./protocol/signature";
export {
  ownerToKeyArray,
  keyArrayToOwner,
  ownersEqual,
  ownerTypeToEnum,
  enumToOwnerType,
  keyTypeLength,
} from "./protocol/owner";
export {
  constraintTypedData,
  constraintDomain,
  constraintDigest,
  isConstraintNonceSpent,
} from "./protocol/constraint";

// EIP-712 type tables (shared with the contracts).
export { CallsTyped, ExecutionConstraintTyped } from "./types/types";

// --- Types --- //

export type {
  Owner,
  OwnerType,
  OwnerOf,
  EcdsaOwner,
  P256Owner,
  WebAuthnOwner,
  KeyedSignature,
  Call,
  Calls,
  Executable,
  ExecuteParameters,
  Allowance,
  AllowanceSpend,
  Outcome,
  ExecutionConstraint,
  WebAuthnSignature,
  Factory,
  EmbeddedDigest,
  DeployOptions,
  AccountConstructorParams,
} from "./types/types";

export type { DeployKind } from "./protocol/factory";
export type {
  Signable,
  CallsMessage,
  CatapultarDomain,
} from "./protocol/calls";
export type { CatValidatorDomain } from "./protocol/constraint";
export type {
  CatExecuteOptions,
  CatRefundOptions,
} from "./transaction/constrainedtransaction";
