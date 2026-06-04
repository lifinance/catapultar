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

export { default as catapultarAbi } from "./abi/catapultarV0.1.0";
export { default as catapultarFactoryAbi } from "./abi/catapultarFactoryV0.1.0";
export { CAT_VALIDATOR_ABI as catValidatorAbi } from "./abi/CATValidator";

// --- Deployment addresses --- //

export { factories, templates, cat_validator } from "./config";

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
  normalizeP256,
  normalizeSignature,
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
  Version,
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
