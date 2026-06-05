import type { Account, Hex, WalletClient } from "viem";
import { random } from "../utils/helpers";
import {
  ExecutionMode,
  type AccountConstructorParams,
  type Call,
  type KeyedSignature,
  type Owner,
} from "../types/types";
import { callsDigest, callsTypedData } from "../protocol/calls";
import { assertCalls, assertMode, assertNonce } from "../protocol/validation";
import {
  DuplicateNonceError,
  InvalidSignatureError,
  ValidationError,
} from "../errors";
import { CatapultarAccount } from "./account";
import { BaseTransaction } from "../transaction/transaction";

/**
 * Account-aware transaction builder: turns a list of {@link Call}s into a single
 * signed Catapultar batch for a specific account.
 *
 * It extends {@link BaseTransaction} with the account context needed to build the
 * EIP-712 domain, normalize signatures for the owner's key type, and (when
 * connected) validate the nonce/owner/signature on-chain.
 *
 * The builder is fluent — each setter mutates and returns `this`, so calls
 * chain:
 *
 * ```typescript
 * const signed = await new CatapultarTx({ account })
 *   .setMode(ExecutionMode.RaiseRevert)
 *   .setNonce(12n)
 *   .addCall(...calls)
 *   .sign((data) => walletClient.signTypedData({ account, ...data }));
 * const call = await signed.asCall();
 * ```
 *
 * To batch batches, build sub-transactions, convert each to a call, and add them
 * to an outer transaction (or use {@link MetaCatapultarTx}):
 *
 * ```typescript
 * const inner = await new CatapultarTx({ account }).addCall(...).asCall();
 * await new CatapultarTx({ account }).addCall(inner).sign(...);
 * ```
 *
 * @typeParam O The owner variant controlling the account (drives signature shape).
 * @typeParam Connected Whether the underlying account has a viem client attached
 *   (required for {@link validateUsingProvider}).
 */
export class CatapultarTx<
  O extends Owner = Owner,
  Connected extends boolean = false,
> extends BaseTransaction {
  /** The account this batch is built for (offline or connected). */
  account: CatapultarAccount<O, Connected>;

  /**
   * Create a new Catapultar transaction batch.
   */
  constructor(options: {
    account: AccountConstructorParams<O> | CatapultarAccount<O, Connected>;
    mode?: ExecutionMode;
    nonce?: bigint;
    calls?: Call[];
    signature?: `0x${string}`;
  }) {
    super(options);
    this.account =
      options.account instanceof CatapultarAccount
        ? options.account
        : (new CatapultarAccount<O>(options.account) as CatapultarAccount<
            O,
            Connected
          >);
  }

  // --- Export the transaction for saving --- //

  /**
   * @returns Constructor parameters for a new (identical) CatapultarTx
   */
  export(): ConstructorParameters<typeof CatapultarTx>[0] {
    return {
      account: {
        address: this.account.address,
        owner: this.account.owner,
        chainId: this.account.chainId,
        name: this.account.name,
        version: this.account.version,
      },
      mode: this.mode,
      nonce: this.nonce,
      signature: this.signature,
      calls: this.calls,
    };
  }

  /**
   * Sets a signature along with its type. If non-ecdsa signatures are being set, this provides additional aids with encoding
   */
  setSignature(signature: KeyedSignature<O>): this {
    this.signature = this.account.normalizeSignature(signature);
    return this;
  }

  /**
   * Sign the transaction using a Ethers compatible signer function.
   * @dev The callback function will be called with a typeset compatible with ether.Signer._signTypedData.
   * An alternative way to sign this function is to set it manually as .signature.
   */
  async sign(
    callback: (
      options: ReturnType<typeof this.getSignerData>,
    ) => Promise<KeyedSignature<O>>,
    options?: { ignoreNoCalls?: boolean },
  ) {
    const signerData = this.getSignerData(options);

    this.signature = this.account.normalizeSignature(
      await callback(signerData),
    );
    return this;
  }

  // --- Validation --- //

  /**
   * Whether the currently-set signature is valid for this batch's digest.
   *
   * Checks the set signature against the account owner (ECDSA recovery, or P256 /
   * WebAuthn verification; an ERC-1271 contract owner is checked on-chain when the
   * account is connected). The digest is computed with `ignoreNoCalls: true`, so
   * an empty batch can still be checked.
   *
   * @param options.noSignatureIsValid Value to return when no signature has been
   *   set yet. Default `false`.
   */
  async hasValidSignature(options?: {
    noSignatureIsValid?: boolean;
  }): Promise<boolean> {
    const { noSignatureIsValid = false } = options ?? {};
    if (this.signature === undefined) return noSignatureIsValid;
    return this.account.isSignatureValid({
      signature: this.signature,
      hash: this.getTypeHashDigest({ ignoreNoCalls: true }),
    });
  }

  /**
   * Assert the set signature is valid (see {@link hasValidSignature}), returning
   * `this` for chaining.
   * @throws {InvalidSignatureError} If the signature does not verify.
   */
  async validateSignature(options?: { noSignatureIsValid?: boolean }) {
    if (!(await this.hasValidSignature(options)))
      throw new InvalidSignatureError(`Invalid Signer`);
    return this;
  }

  /**
   * On-chain pre-flight for a connected account: assert the nonce has not been
   * spent and the configured owner matches the deployed account, returning `this`.
   * Requires a connected account.
   * @throws {NonceZeroError | NonceUnsetError | NonceCollisionError} On a bad nonce.
   * @throws {OwnerMismatchError} If the on-chain owner differs from the configured one.
   */
  async validateUsingProvider(this: CatapultarTx<O, true>) {
    await this.account.validateNonce({ nonce: this.nonce });
    await this.account.validateOwner();

    return this;
  }

  // --- Order Creation --- //

  /**
   * Returns an Ethers compatible typed dict.
   * @param options.ignoreNoCalls Do not throw an error if no calls have been configured. Default: false
   */
  getSignerData(options?: { ignoreNoCalls?: boolean }) {
    const { ignoreNoCalls = false } = options ?? {};
    const { nonce, mode, calls } = this;
    assertNonce(nonce);
    assertMode(mode);
    if (!ignoreNoCalls) assertCalls(calls);

    return callsTypedData(
      this.account.getDomainSeparator({
        chain: !this.hasMultichainMode(),
      }),
      { nonce, mode, calls },
    );
  }

  /**
   * The full EIP-712 digest the owner signs for this batch (domain-wrapped
   * `Calls` hash). This is the value recovered against in {@link hasValidSignature}.
   * @param options.ignoreNoCalls Do not throw if no calls have been added. Default false.
   */
  getTypeHashDigest(options?: { ignoreNoCalls?: boolean }) {
    const signerData = this.getSignerData(options);
    return callsDigest(signerData.domain, signerData.message);
  }

  // --- Convert the transaction object into actionable items --- //

  /**
   * @return As a call for further scheduling or manual transaction signing. If used for manual transaction.
   */
  async asCall(): Promise<Call> {
    return {
      ...this.asCallData(),
      to: this.account.address,
    };
  }

  /**
   * Sign (if needed) and broadcast in one call via a viem `WalletClient`.
   *
   * If a signature is already set (e.g. from a relayer or a manual `sign()`),
   * re-signing is skipped and the transaction is just sent. The signing account
   * defaults to the wallet client's account; override it via `options.account`.
   * Returns the transaction hash. For an external signer, keep using `sign()`.
   */
  async execute(
    walletClient: WalletClient,
    options?: { account?: Account | Hex; ignoreNoCalls?: boolean },
  ): Promise<Hex> {
    const account = options?.account ?? walletClient.account;
    if (!account)
      throw new ValidationError(
        "execute() requires an account on the WalletClient or in options.account.",
      );
    if (this.signature === undefined) {
      // A WalletClient produces an ECDSA hex signature, so this path is for
      // ECDSA/EOA owners. The signature is normalized for the account's owner.
      const data = this.getSignerData({
        ignoreNoCalls: options?.ignoreNoCalls,
      });
      const signature = await walletClient.signTypedData({
        account,
        ...data,
      } as Parameters<typeof walletClient.signTypedData>[0]);
      this.signature = this.account.normalizeSignature(
        signature as KeyedSignature<O>,
      );
    }
    const call = await this.asCall();
    return walletClient.sendTransaction({
      account,
      chain: walletClient.chain,
      ...call,
    } as Parameters<typeof walletClient.sendTransaction>[0]);
  }
}

/**
 * A batch-of-batches: a meta transaction composed of several independently-nonced sub-batches.
 *
 * Each sub-batch becomes its own inner {@link CatapultarTx} (executed with a
 * dedicated nonce), and they are wrapped in one outer batch executed with
 * {@link ExecutionMode.SkipRevert} by default — so a failed sub-batch is skipped
 * (and can be retried later) rather than reverting the whole transaction.
 *
 * Typical flow:
 *
 * ```typescript
 * const outer = await new MetaCatapultarTx({ account })
 *   .addCalls({ calls: batchA }, { calls: batchB })
 *   .asCatapultarTx(); // -> a normal CatapultarTx you then sign + send
 * ```
 *
 * @typeParam O The owner variant controlling the account.
 * @typeParam Connected Whether the underlying account has a viem client attached.
 */
export class MetaCatapultarTx<
  O extends Owner = Owner,
  Connected extends boolean = false,
> {
  /** Execution mode of the outer (wrapping) batch. Defaults to SkipRevert when converted. */
  mode?: ExecutionMode;
  /** Unused reserved field carried from constructor options. */
  nonce?: bigint;
  /** The queued sub-batches, each with an optional explicit nonce/mode. */
  calls: { calls: Call[]; nonce?: bigint; mode?: ExecutionMode }[] = [];

  /** Nonce of the outer batch. Random by default. */
  outerNonce: bigint;
  /** Base nonce for sub-batches; sub-batch `i` defaults to `innerNonce + i`. */
  innerNonce: bigint;

  /** The account every sub-batch (and the outer batch) is built for. */
  account: CatapultarAccount<O, Connected>;

  /**
   * @param options.account Account params or an existing {@link CatapultarAccount}.
   * @param options.outerNonce Nonce for the wrapping batch. Defaults to a random value.
   * @param options.innerNonce Base nonce for sub-batches. Defaults to `outerNonce + 1`.
   */
  constructor(options: {
    account: AccountConstructorParams<O> | CatapultarAccount<O, Connected>;
    mode?: ExecutionMode;
    nonce?: bigint;
    signature?: `0x${string}`;
    outerNonce?: bigint;
    innerNonce?: bigint;
  }) {
    this.account =
      options.account instanceof CatapultarAccount
        ? options.account
        : (new CatapultarAccount<O>(options.account) as CatapultarAccount<
            O,
            Connected
          >);
    // Random bytes with rightmost byte empty.
    const randomNonce = BigInt(random(31)) << 8n;
    const {
      mode,
      nonce,
      outerNonce = randomNonce,
      innerNonce = randomNonce + 1n,
    } = options;

    // Transaction Definition
    this.mode = mode;
    this.nonce = nonce;

    this.outerNonce = outerNonce;
    this.innerNonce = innerNonce;
  }

  /** Set the execution mode of the outer (wrapping) batch. */
  setMode(mode: ExecutionMode) {
    this.mode = mode;
    return this;
  }

  /**
   * Queue one or more sub-batches. Each entry is a group of {@link Call}s with an
   * optional explicit `nonce`/`mode`; omitted values are resolved when converted
   * (nonce -> `innerNonce + index`, mode -> RaiseRevert).
   */
  addCalls(
    ...calls: { calls: Call[]; nonce?: bigint; mode?: ExecutionMode }[]
  ) {
    for (const call of calls) {
      this.calls.push(call);
    }
    return this;
  }

  /**
   * Resolves the effective nonce of every sub-call: the explicitly provided
   * nonce, or the generated `innerNonce + index` when omitted (0n counts as
   * omitted, matching getSignerData/setNonce which reject nonce 0). Single
   * source of truth so checkNonces and getCallsAsTxs cannot diverge.
   */
  private resolvedNonces(): bigint[] {
    return this.calls.map((c, i) =>
      c.nonce ? c.nonce : this.innerNonce + BigInt(i),
    );
  }

  /**
   * Assert no two sub-batches share a nonce (after resolving omitted nonces),
   * returning `this`.
   * @throws {DuplicateNonceError} If any resolved nonce appears more than once.
   */
  checkNonces() {
    // Validate the resolved set so an explicit nonce that collides with a
    // generated `innerNonce + i` value is caught too, not just explicit-vs-explicit.
    const nonces = this.resolvedNonces();
    const counts = new Map<bigint, number>();
    for (const n of nonces) counts.set(n, (counts.get(n) ?? 0) + 1);
    const duplicates = nonces.filter((n) => counts.get(n)! > 1);
    if (duplicates.length > 0)
      throw new DuplicateNonceError(
        `Duplicate nonces were found: ${duplicates}`,
      );
    return this;
  }

  /**
   * Materialize each queued sub-batch as its own unsigned {@link CatapultarTx}
   * (with its resolved nonce and mode). Useful if you want to sign sub-batches
   * individually rather than through {@link asCatapultarTx}.
   */
  getCallsAsTxs() {
    const nonces = this.resolvedNonces();
    return this.calls.map((c, i) => {
      return new CatapultarTx({
        account: this.account,
      })
        .setMode(c.mode ? c.mode : ExecutionMode.RaiseRevert)
        .setNonce(nonces[i]!)
        .addCall(...c.calls);
    });
  }

  /**
   * Collapse all sub-batches into a single outer {@link CatapultarTx}: each
   * sub-batch is encoded as a self-call carrying its own nonce/mode, then wrapped
   * in one batch (defaulting to {@link ExecutionMode.SkipRevert} so a failed
   * sub-batch is skipped). Validates nonces first. The returned transaction is
   * unsigned — sign and send it like any other {@link CatapultarTx}.
   */
  async asCatapultarTx() {
    this.checkNonces();
    return new CatapultarTx({
      account: this.account,
    })
      .setNonce(this.outerNonce)
      .setMode(this.mode ?? ExecutionMode.SkipRevert)
      .addCall(
        ...(await Promise.all(this.getCallsAsTxs().map((c) => c.asCall()))),
      );
  }
}
