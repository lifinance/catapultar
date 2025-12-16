import { encodeAbiParameters, encodeFunctionData, hashTypedData } from "viem";
import { random, asHex } from "../utils/helpers";
import {
  AccountKeyType,
  CallsTyped,
  ExecutionMode,
  type AccountConstructorParams,
  type Call,
  type KeyedSignature,
  type Version,
} from "../types/types";
import { CatapultarAccount } from "./account";
import CATAPULTAR_V0_1_0_ABI from "../abi/catapultarV0.1.0";

// const abiencoder = AbiCoder.defaultAbiCoder();

/**
 * A Catapultar transaction wrapper. Is intended to be used to convert a list of calls into a single Catapultar batch.
 * @dev The class is intended to be used through modifiers, meaning each property should be set iteratively on the object:
 * const tx = new CatapultarTx(options).setMode(ExecutionMode.RaiseRevert).setNonce(12n).addCalls(...[]).sign(() => ...).asParameters();
 * To batch batches, multiple sub CatapultarTx can be created and then converted into calls like:
 * calls.push(new CatapultarTx(options).addCalls(...[]).asCall());
 * new CatapultarTx(options).addCalls(...calls).sign(() => ...).asParameters();
 */
export class CatapultarTx<
  V extends Version = "0.1.0",
  RPC extends string | undefined = undefined,
  AKT extends AccountKeyType = AccountKeyType.ECDSAOrSmartContract,
> extends CatapultarAccount<V, RPC, AKT> {
  /** Signature for the transaction. */
  signature?: `0x${string}`;

  /** Transaction ExecutionMode, defines transaction behavior for call reverts. */
  mode?: ExecutionMode;
  /** Transaction nonce. Only 1 transaction can be executed for each nonce. */
  nonce?: bigint;
  /** List of calls the transaction contains. */
  calls: Call[] = [];

  /**
   * Create a new Catapultar transaction batch.
   */
  constructor(options: {
    account:
      | AccountConstructorParams<V, RPC, AKT>
      | CatapultarAccount<V, RPC, AKT>;
    mode?: ExecutionMode;
    nonce?: bigint;
    calls?: Call[];
    signature?: `0x${string}`;
    // provider?: Provider;
  }) {
    super(options.account);
    const { mode, nonce, calls = [], signature } = options;

    // Transaction Definition
    this.mode = mode;
    this.nonce = nonce;
    this.calls = calls;

    this.signature = signature;

    // this.provider = provider;
  }

  // --- Export the transaction for saving --- //

  /**
   * @returns Constructor parameters for a new (identical) CatapultarTx
   */
  export(): ConstructorParameters<typeof CatapultarTx>[0] {
    return {
      account: {
        address: this.address,
        chainId: this.chainId,
        owner: this.owner,
        name: this.name,
        version: this.version,
      },
      mode: this.mode,
      nonce: this.nonce,
      signature: this.signature,
      calls: this.calls,
    };
  }

  // --- Modify the existing transaction. This allows you to change how it has been defined --- //

  /**
   * Set the transaction nonce for the Catapultar transaction. Only 1 transaction can ever be executed for each nonce.
   */
  setNonce(nonce: bigint) {
    if (nonce === 0n)
      throw new Error(
        `Nonce 0 is not allowed. It cannot be differentiated from an invalid nonce.`,
      );
    this.nonce = nonce;
    return this;
  }

  /**
   * Generates a random uint256 nonce and sets it.
   */
  setRandomNonce() {
    return this.setNonce(BigInt(random(32)));
  }

  /**
   * Sets the Catapultar transaction mode.
   */
  setMode(mode: ExecutionMode) {
    if (
      this.version === "0.0.1" &&
      (mode === ExecutionMode.RaiseRevertMultiChain ||
        mode === ExecutionMode.SkipRevertMultiChain)
    )
      throw new Error(`Version 0.0.1 does not support multichain execution`);
    this.mode = mode;
    return this;
  }

  /**
   * Sets a signature along with its type. If non-ecdsa signatures are being set, this provides additional aids with encoding
   */
  setSignature(signature: KeyedSignature<AKT>) {
    this.signature = this.parseSignature(signature)!;
  }

  /**
   * Adds list of calls to the Catapultar transaction. The calls will be executed with the configured mode.
   */
  addCall(...calls: Call[]) {
    for (const call of calls) {
      this.calls.push(call);
    }
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
    ) => Promise<string>,
    options?: { ignoreNoCalls?: boolean },
  ) {
    const signerData = this.getSignerData(options);

    this.signature = (await callback(signerData)) as `0x${string}`;
    return this;
  }

  // --- Validation --- //

  hasValidMode() {
    if (this.mode === undefined) return false;
    return Object.values(ExecutionMode).includes(this.mode);
  }

  /**
   * @returns Whether the a multichain execution mode is set.
   */
  hasMultichainMode(): boolean {
    return (
      this.mode === ExecutionMode.RaiseRevertMultiChain ||
      this.mode === ExecutionMode.SkipRevertMultiChain
    );
  }

  async hasValidSignature(options?: {
    noSignatureIsValid?: boolean;
  }): Promise<boolean> {
    const { noSignatureIsValid = false } = options ?? {};
    if (this.signature === undefined) return noSignatureIsValid;
    return this.isSignatureValid({
      signature: this.signature,
      hash: this.getTypeHash({ ignoreNoCalls: true }),
    });
  }

  async validateSignature(options?: { noSignatureIsValid?: boolean }) {
    if (!(await this.hasValidSignature(options)))
      throw new Error(`Invalid Signer`);
    return this;
  }

  async validateUsingProvider(this: CatapultarTx<V, string>) {
    await this.validateNonce({ nonce: this.nonce });
    await this.validateOwner();

    return this;
  }

  // --- Read objects relating to its construction --- ///

  /**
   * @returns Total value of all contained calls.
   */
  getTotalValue(): bigint {
    return this.calls.map((c) => c.value).reduce((a, b) => a + b, 0n);
  }

  // --- Order Creation --- //

  /**
   * Returns an Ethers compatible typed dict.
   * @param options.ignoreNoCalls Do not throw an error if no calls have been configured. Default: false
   */
  getSignerData(options?: { ignoreNoCalls?: boolean }) {
    const { ignoreNoCalls = false } = options ?? {};
    if (this.nonce === 0n)
      throw new Error(
        `Nonce 0 is not allowed. It cannot be differentiated from an invalid nonce.`,
      );
    if (!this.nonce) throw new Error("Nonce has not been set");
    if (!this.mode || !this.hasValidMode())
      throw new Error("Mode has not been set");
    if (!ignoreNoCalls && this.calls.length === 0)
      throw new Error("Calls have not been set");

    return {
      domain: this.getDomainSeparator({ chain: !this.hasMultichainMode() }),
      types: CallsTyped,
      primaryType: "Calls",
      message: {
        nonce: this.nonce,
        mode: this.mode,
        calls: this.calls,
      },
    } as const;
  }

  getTypeHash(options?: { ignoreNoCalls?: boolean }) {
    const signerData = this.getSignerData(options);

    return hashTypedData(signerData);
  }

  /**
   * Returns the signature as a compact signature of 64 bytes instead of 65 bytes.
   *
   * @param signature Signature. If already compact, returns as is.
   */
  asCompactSignature(): `0x${string}` {
    if (!this.signature) throw new Error("A signature has to be provided");
    if (this.signature.replace("0x", "").length === 64 * 2)
      return this.signature;
    // If this is not an ECDSA sig, lets not touch it.
    if (this.signature.replace("0x", "").length !== 65 * 2)
      return this.signature;

    const r = BigInt(`0x${this.signature.slice(2, 2 + 64)}`);
    const s = BigInt(`0x${this.signature.slice(2 + 64, 2 + 64 + 64)}`);
    const v = BigInt(`0x${this.signature.slice(2 + 64 + 64, 2 + 64 + 64 + 2)}`);
    const normV = v >= 27 ? v - 27n : v;
    const vAndS = (normV << 255n) | s;
    return `0x${asHex(r, 32)}${asHex(vAndS, 32)}`;
  }

  /**
   * @dev Opdata is nonce + signature packed.
   * If no signature has been provided to the object, it will create the transaction without a signatures. This can be used to sub-batch the transaction.
   */
  async getOpData(options?: {
    compactSignature: boolean;
  }): Promise<`0x${string}`> {
    if (this.nonce === 0n)
      throw new Error(
        "Nonce 0 is not allowed. It cannot be differentiated from an invalid nonce.",
      );
    if (!this.nonce) throw new Error("No nonce has been set");
    const { compactSignature = true } = options ?? {};
    await this.validateSignature({ noSignatureIsValid: true });
    if (this.signature) {
      const sig = compactSignature ? this.asCompactSignature() : this.signature;
      return `0x${asHex(this.nonce, 32)}${sig.replace("0x", "")}`;
    } else {
      return asHex(this.nonce, 32, "0x");
    }
  }

  async getExecutionData() {
    return encodeAbiParameters(
      [{ type: "tuple[]", components: CallsTyped.Call }, { type: "bytes" }],
      [this.calls, await this.getOpData()],
    );
  }

  // --- Convert the transaction object into actionable items --- //

  /** @return As parameters for an execute call. */
  async asParameters() {
    return {
      mode: this.mode,
      executionData: await this.getExecutionData(),
      metadata: {
        value: this.getTotalValue(),
        signature: this.signature,
      },
    };
  }

  /**
   * @return As a call for further scheduling or manual transaction signing. If used for manual transaction.
   */
  async asCall(): Promise<Call> {
    if (!this.hasValidMode())
      throw new Error(`Mode incorrectly set: ${this.mode}`);
    const executionData = await this.getExecutionData();
    const data = encodeFunctionData({
      abi: CATAPULTAR_V0_1_0_ABI,
      functionName: "execute",
      args: [this.mode!, executionData],
    });
    return {
      to: this.address,
      value: 0n,
      data,
    };
  }
}

/**
 * This defines a meta transaction composed of several smaller transactions.
 * Intended usecase: Wrapping multiple transactions (that can later be retried) into a single batch.
 */
export class MetaCatapultarTx<
  V extends Version = "0.1.0",
  RPC extends string | undefined = undefined,
  AKT extends AccountKeyType = AccountKeyType.ECDSAOrSmartContract,
> extends CatapultarAccount<V, RPC, AKT> {
  mode?: ExecutionMode;
  nonce?: bigint;
  calls: { calls: Call[]; nonce?: bigint; mode?: ExecutionMode }[] = [];

  outerNonce: bigint;
  innerNonce: bigint;

  constructor(options: {
    account:
      | AccountConstructorParams<V, RPC, AKT>
      | CatapultarAccount<V, RPC, AKT>;
    mode?: ExecutionMode;
    nonce?: bigint;
    signature?: `0x${string}`;
    outerNonce?: bigint;
    innerNonce?: bigint;
  }) {
    // Random bytes with rightmost byte empty.
    const randomNonce = BigInt(random(31)) << 8n;
    const {
      mode,
      nonce,
      outerNonce = randomNonce,
      innerNonce = randomNonce + 1n,
    } = options;
    super(options.account);

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

  checkNonces() {
    const nonces = this.calls.map((tx) => tx.nonce).filter((n) => !!n);
    if ([...new Set(nonces)].length != nonces.length)
      throw new Error(`Duplicate nonces were found: ${nonces}`);
    return this;
  }

  getCallsAsTxs() {
    return this.calls.map((c, i) => {
      return new CatapultarTx({
        account: this,
      })
        .setMode(c.mode ? c.mode : ExecutionMode.RaiseRevert)
        .setNonce(c.nonce ? c.nonce : this.innerNonce + BigInt(i))
        .addCall(...c.calls);
    });
  }

  async asCatapultarTx() {
    this.checkNonces();
    return new CatapultarTx({
      account: this,
    })
      .setNonce(this.outerNonce)
      .setMode(this.mode ?? ExecutionMode.SkipRevert)
      .addCall(
        ...(await Promise.all(this.getCallsAsTxs().map((c) => c.asCall()))),
      );
  }
}
