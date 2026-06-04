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
 * A Catapultar transaction wrapper. Is intended to be used to convert a list of calls into a single Catapultar batch.
 * @dev The class is intended to be used through modifiers, meaning each property should be set iteratively on the object:
 * const tx = new CatapultarTx(options).setMode(ExecutionMode.RaiseRevert).setNonce(12n).addCall(...[]).sign(() => ...).asParameters();
 * To batch batches, multiple sub CatapultarTx can be created and then converted into calls like:
 * calls.push(await new CatapultarTx(options).addCall(...[]).asCall());
 * new CatapultarTx(options).addCall(...calls).sign(() => ...).asParameters();
 */
export class CatapultarTx<
  O extends Owner = Owner,
  Connected extends boolean = false,
> extends BaseTransaction {
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

  async validateSignature(options?: { noSignatureIsValid?: boolean }) {
    if (!(await this.hasValidSignature(options)))
      throw new InvalidSignatureError(`Invalid Signer`);
    return this;
  }

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
 * This defines a meta transaction composed of several smaller transactions.
 * Intended usecase: Wrapping multiple transactions (that can later be retried) into a single batch.
 */
export class MetaCatapultarTx<
  O extends Owner = Owner,
  Connected extends boolean = false,
> {
  mode?: ExecutionMode;
  nonce?: bigint;
  calls: { calls: Call[]; nonce?: bigint; mode?: ExecutionMode }[] = [];

  outerNonce: bigint;
  innerNonce: bigint;

  account: CatapultarAccount<O, Connected>;

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

  setMode(mode: ExecutionMode) {
    this.mode = mode;
    return this;
  }

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
