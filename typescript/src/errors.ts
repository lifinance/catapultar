/**
 * Typed error hierarchy. Every Catapultar-thrown error extends
 * {@link CatapultarError}, so a consumer can branch with a single
 * `catch (e) { if (e instanceof CatapultarError) ... }` and narrow further by
 * subclass instead of string-matching messages.
 *
 * Subclasses are empty on purpose: the base constructor sets `name` from
 * `new.target` (the concrete class being instantiated), so each `name` stays in
 * sync with its class automatically and cannot drift from a hand-typed string.
 */

export class CatapultarError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** Base for invalid-input / unset-field failures (mode/nonce/calls/etc). */
export class ValidationError extends CatapultarError {}

/** Nonce 0 was supplied; it is indistinguishable from an unset nonce on-chain. */
export class NonceZeroError extends ValidationError {}

/** A nonce was required but none was set. */
export class NonceUnsetError extends ValidationError {}

/** A valid execution mode was required but none was set. */
export class ModeUnsetError extends ValidationError {}

/** At least one call was required but none was added. */
export class CallsUnsetError extends ValidationError {}

/** A requested nonce has already been spent on-chain. */
export class NonceCollisionError extends CatapultarError {}

/** The same nonce was used more than once within a batch. */
export class DuplicateNonceError extends CatapultarError {}

/** The on-chain owner does not match the account's configured owner. */
export class OwnerMismatchError extends CatapultarError {}

/** A signature failed validation. */
export class InvalidSignatureError extends CatapultarError {}

/** A chain could not be resolved (e.g. an rpc was given without a chainId). */
export class InvalidChainError extends CatapultarError {}

/** An on-chain read was attempted on an account with no attached client. */
export class NotConnectedError extends CatapultarError {}
