/**
 * Typed error hierarchy. Every Catapultar-thrown error extends
 * {@link CatapultarError}, so a consumer can branch with a single
 * `catch (e) { if (e instanceof CatapultarError) ... }` and narrow further by
 * subclass instead of string-matching messages.
 */

export class CatapultarError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "CatapultarError";
  }
}

/** Base for invalid-input / unset-field failures (mode/nonce/calls/etc). */
export class ValidationError extends CatapultarError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ValidationError";
  }
}

/** Nonce 0 was supplied; it is indistinguishable from an unset nonce on-chain. */
export class NonceZeroError extends ValidationError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "NonceZeroError";
  }
}

/** A nonce was required but none was set. */
export class NonceUnsetError extends ValidationError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "NonceUnsetError";
  }
}

/** A valid execution mode was required but none was set. */
export class ModeUnsetError extends ValidationError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ModeUnsetError";
  }
}

/** At least one call was required but none was added. */
export class CallsUnsetError extends ValidationError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "CallsUnsetError";
  }
}

/** A requested nonce has already been spent on-chain. */
export class NonceCollisionError extends CatapultarError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "NonceCollisionError";
  }
}

/** The same nonce was used more than once within a batch. */
export class DuplicateNonceError extends CatapultarError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "DuplicateNonceError";
  }
}

/** The on-chain owner does not match the account's configured owner. */
export class OwnerMismatchError extends CatapultarError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "OwnerMismatchError";
  }
}

/** A signature failed validation. */
export class InvalidSignatureError extends CatapultarError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "InvalidSignatureError";
  }
}

/** A chain could not be resolved (e.g. an rpc was given without a chainId). */
export class InvalidChainError extends CatapultarError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "InvalidChainError";
  }
}

/** An on-chain read was attempted on an account with no attached client. */
export class NotConnectedError extends CatapultarError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "NotConnectedError";
  }
}
