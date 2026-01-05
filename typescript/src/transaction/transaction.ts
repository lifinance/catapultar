import { encodeAbiParameters, encodeFunctionData, hashStruct } from "viem";
import {
  AccountPublicKeyType,
  CallsTyped,
  ExecutionMode,
  type Call,
  type Factory,
  type Pubkey,
} from "../types/types";
import { asHex, pubkeyAsArray, random } from "../utils/helpers";
import { toCompactSignature } from "../utils/signature";
import { CatapultarAccount } from "../catapultar/account";
import CATAPULTAR_FACTORY_V0_1_0_ABI from "../abi/catapultarFactoryV0.1.0";

export class BaseTransaction {
  /** Transaction ExecutionMode, defines transaction behavior for call reverts. */
  mode?: ExecutionMode;
  /** Transaction nonce. Only 1 transaction can be executed for each nonce. */
  nonce?: bigint;
  /** List of calls the transaction contains. */
  calls: Call[];

  signature?: `0x${string}`;

  constructor(opt?: {
    mode?: ExecutionMode;
    nonce?: bigint;
    calls?: Call[];
    signature?: `0x${string}`;
  }) {
    const { mode, nonce, calls = [], signature } = opt ?? {};
    this.mode = mode;
    this.nonce = nonce;
    this.calls = calls;
    this.signature = signature;
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
    this.mode = mode;
    return this;
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

  // --- Read objects relating to its construction --- ///

  /**
   * @returns Total value of all contained calls.
   */
  getTotalValue(): bigint {
    return this.calls.map((c) => c.value).reduce((a, b) => a + b, 0n);
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

  /**
   * Returns the signature as a compact signature of 64 bytes instead of 65 bytes.
   *
   * @param Signature If provided, will act on the provided signature instead.
   */
  asCompactSignature(signature?: `0x${string}`): `0x${string}` {
    const sig = signature ?? this.signature;
    if (!sig) throw new Error("A signature has to be provided");
    if (sig.replace("0x", "").length === 64 * 2) return sig;
    // If this is not an ECDSA sig, lets not touch it.
    if (sig.replace("0x", "").length !== 65 * 2) return sig;

    return toCompactSignature(sig);
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
    if (this.signature) {
      this.signature = compactSignature
        ? this.asCompactSignature()
        : this.signature;
    }
    if (this.signature) {
      return `0x${asHex(this.nonce, 32)}${this.signature.replace("0x", "")}`;
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

  /** Return the calls as an approval diget. This can be used to "embed" the calls into an account */
  asDigest() {
    if (this.nonce === 0n)
      throw new Error(
        `Nonce 0 is not allowed. It cannot be differentiated from an invalid nonce.`,
      );
    if (!this.nonce) throw new Error("Nonce has not been set");
    if (!this.mode || !this.hasValidMode())
      throw new Error("Mode has not been set");
    if (this.calls.length === 0) throw new Error("Calls have not been set");
    return hashStruct({
      types: CallsTyped,
      primaryType: "Calls",
      data: { nonce: this.nonce, mode: this.mode, calls: this.calls },
    });
  }

  /** Generate an account with this action embedded. */
  asAccount<AKT extends AccountPublicKeyType>(
    options: {
      salt: `0x${string}`;
    } & Pubkey<AKT> &
      Factory,
  ) {
    const callDigest = this.asDigest();
    const predictedAddress = CatapultarAccount.predict({
      ...options,
      callDigest,
      isSignature: false,
    });

    const pubkeyArray = pubkeyAsArray(options);
    const call = {
      to: options.factory,
      data: encodeFunctionData({
        abi: CATAPULTAR_FACTORY_V0_1_0_ABI,
        functionName: "deployWithDigest",
        args: [options.keyType, pubkeyArray, options.salt, callDigest, false],
      }),
      value: 0n,
    };

    return {
      call,
      callDigest,
      predictedAddress,
    };
  }
}
