import { encodeFunctionData, hashTypedData } from "viem";
import { random } from "../utils/helpers";
import {
  AccountPublicKeyType,
  CallsTyped,
  ExecutionMode,
  type AccountConstructorParams,
  type Call,
  type KeyedSignature,
  type Version,
} from "../types/types";
import { CatapultarAccount } from "./account";
import CATAPULTAR_V0_1_0_ABI from "../abi/catapultarV0.1.0";
import { BaseTransaction } from "../transaction/transaction";

/**
 * A Catapultar transaction wrapper. Is intended to be used to convert a list of calls into a single Catapultar batch.
 * @dev The class is intended to be used through modifiers, meaning each property should be set iteratively on the object:
 * const tx = new CatapultarTx(options).setMode(ExecutionMode.RaiseRevert).setNonce(12n).addCalls(...[]).sign(() => ...).asParameters();
 * To batch batches, multiple sub CatapultarTx can be created and then converted into calls like:
 * calls.push(new CatapultarTx(options).addCalls(...[]).asCall());
 * new CatapultarTx(options).addCalls(...calls).sign(() => ...).asParameters();
 */
export class CatapultarTx<
  V extends Version,
  RPC extends string | undefined = undefined,
  AKT extends AccountPublicKeyType = AccountPublicKeyType.ECDSAOrSmartContract,
> extends BaseTransaction {
  account: CatapultarAccount<V, RPC, AKT>;

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
    super(options);
    // TODO: If given an object, assign object instead of recreating account.
    this.account = new CatapultarAccount<V, RPC, AKT>(
      options.account as AccountConstructorParams<V, RPC, AKT>,
    );
  }

  // --- Export the transaction for saving --- //

  /**
   * @returns Constructor parameters for a new (identical) CatapultarTx
   */
  export(): ConstructorParameters<typeof CatapultarTx>[0] {
    return {
      account: {
        address: this.account.address,
        chainId: this.account.chainId,
        pubkey: this.account.pubkey,
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
  setSignature(signature: KeyedSignature<AKT>) {
    this.signature = this.account.parseSignature(signature)!;
  }

  /**
   * Sign the transaction using a Ethers compatible signer function.
   * @dev The callback function will be called with a typeset compatible with ether.Signer._signTypedData.
   * An alternative way to sign this function is to set it manually as .signature.
   */
  async sign(
    callback: (
      options: ReturnType<typeof this.getSignerData>,
    ) => Promise<KeyedSignature<AKT>>,
    options?: { ignoreNoCalls?: boolean },
  ) {
    const signerData = this.getSignerData(options);

    this.signature = this.account.parseSignature(await callback(signerData));
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
      throw new Error(`Invalid Signer`);
    return this;
  }

  async validateUsingProvider(this: CatapultarTx<V, string>) {
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
      domain: this.account.getDomainSeparator({
        chain: !this.hasMultichainMode(),
      }),
      types: CallsTyped,
      primaryType: "Calls",
      message: {
        nonce: this.nonce,
        mode: this.mode,
        calls: this.calls,
      },
    } as const;
  }

  getTypeHashDigest(options?: { ignoreNoCalls?: boolean }) {
    const signerData = this.getSignerData(options);

    return hashTypedData(signerData);
  }

  /**
   * Returns the signature as a on-chain compatible signature with an indicator byte.
   * For ECDSA / Smart contracts returns as is.
   * For P256, pads to 65. Then adds 00.
   *
   * @param Signature If provided, will act on the provided signature instead.
   */
  asCompatibleSignature(signature?: `0x${string}`): `0x${string}` {
    const sig = signature ?? this.signature;
    if (!sig) throw new Error("A signature has to be provided");
    if (
      this.account.accountPublicKeyType ===
      AccountPublicKeyType.ECDSAOrSmartContract
    )
      return sig;

    if (
      this.account.accountPublicKeyType === AccountPublicKeyType.P256 ||
      this.account.accountPublicKeyType === AccountPublicKeyType.WebAuthnP256
    ) {
      // If length >= 66, return as is.
      if (sig.replace("0x", "").length >= 66 * 2) return sig;
      // Pad end to 65. Then add 00.
      return `0x${sig.replace("0x", "").padEnd(65 * 2, "0")}00`;
    }
    throw new Error(`Unknown key scheme ${this.account.accountPublicKeyType}`);
  }

  // --- Convert the transaction object into actionable items --- //

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
      to: this.account.address,
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
  V extends Version,
  RPC extends string | undefined = undefined,
  AKT extends AccountPublicKeyType = AccountPublicKeyType.ECDSAOrSmartContract,
> {
  mode?: ExecutionMode;
  nonce?: bigint;
  calls: { calls: Call[]; nonce?: bigint; mode?: ExecutionMode }[] = [];

  outerNonce: bigint;
  innerNonce: bigint;

  account: CatapultarAccount<V, RPC, AKT>;

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
    // TODO: If given an object, assign object instead of recreating account.
    this.account = new CatapultarAccount<V, RPC, AKT>(
      options.account as AccountConstructorParams<V, RPC, AKT>,
    );
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

  checkNonces() {
    const nonces = this.calls.map((tx) => tx.nonce).filter((n) => !!n);
    if ([...new Set(nonces)].length != nonces.length)
      throw new Error(`Duplicate nonces were found: ${nonces}`);
    return this;
  }

  getCallsAsTxs() {
    return this.calls.map((c, i) => {
      return new CatapultarTx({
        account: this.account,
      })
        .setMode(c.mode ? c.mode : ExecutionMode.RaiseRevert)
        .setNonce(c.nonce ? c.nonce : this.innerNonce + BigInt(i))
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
