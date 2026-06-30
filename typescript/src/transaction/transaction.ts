import { encodeFunctionData } from "viem";
import {
  ExecutionMode,
  type Call,
  type ExecuteParameters,
  type Factory,
  type Owner,
} from "../types/types";
import { random } from "../utils/helpers";
import { CatapultarAccount } from "../catapultar/account";
import { ownerToKeyArray, ownerTypeToEnum } from "../protocol/owner";
import { callsStructHash, isMultichainMode } from "../protocol/calls";
import { buildExecutionData, buildOpData } from "../protocol/opdata";
import { compactSignature } from "../protocol/signature";
import {
  NONCE_ZERO_ERROR,
  assertCalls,
  assertMode,
  assertNonce,
} from "../protocol/validation";
import { NonceZeroError, ValidationError } from "../errors";
import CATAPULTAR_FACTORY_ABI from "../abi/catapultarFactory";
import CATAPULTAR_ABI from "../abi/catapultar";
import { _factory } from "../config";

/**
 * Minimal, account-agnostic Catapultar batch.
 *
 * `BaseTransaction` is the low-level building block: it holds a mode, a nonce,
 * and a list of {@link Call}s, and encodes them into the `opData` /
 * `executionData` the on-chain `execute` entrypoint decodes. It carries no
 * account context, signer, or EIP-712 domain — bring your own signature (set
 * {@link signature} directly) or leave it unsigned to embed the batch into an
 * account via {@link asAccount}.
 *
 * For account-aware building (domain construction, owner-specific signature
 * normalization, on-chain validation) use {@link CatapultarTx}, which extends
 * this class.
 */
export class BaseTransaction {
  /** Transaction ExecutionMode, defines transaction behavior for call reverts. */
  mode?: ExecutionMode;
  /** Transaction nonce. Only 1 transaction can be executed for each nonce. */
  nonce?: bigint;
  /** List of calls the transaction contains. */
  calls: Call[];

  /**
   * Raw owner signature over the batch digest, in the on-chain wire format.
   * Optional: when unset the batch encodes without a signature (the self-call /
   * embedded-digest form).
   */
  signature?: `0x${string}`;

  /** Construct a batch, optionally pre-seeding mode / nonce / calls / signature. */
  constructor(opt?: {
    mode?: ExecutionMode;
    nonce?: bigint;
    calls?: Call[];
    signature?: `0x${string}`;
  }) {
    const { mode, nonce, calls = [], signature } = opt ?? {};
    // Reject nonce 0 here too (not just in setNonce): it is indistinguishable
    // from an unset nonce on-chain, so fail fast at construction.
    if (nonce === 0n) throw new NonceZeroError(NONCE_ZERO_ERROR);
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
    if (nonce === 0n) throw new NonceZeroError(NONCE_ZERO_ERROR);
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

  /** @returns Whether a recognized {@link ExecutionMode} has been set. */
  hasValidMode() {
    if (this.mode === undefined) return false;
    return Object.values(ExecutionMode).includes(this.mode);
  }

  /**
   * @returns Whether a multichain execution mode is set.
   */
  hasMultichainMode(): boolean {
    return isMultichainMode(this.mode);
  }

  /**
   * Returns the signature as a compact signature of 64 bytes instead of 65 bytes.
   *
   * @param Signature If provided, will act on the provided signature instead.
   */
  asCompactSignature(signature?: `0x${string}`): `0x${string}` {
    const sig = signature ?? this.signature;
    if (!sig) throw new ValidationError("A signature has to be provided");
    return compactSignature(sig);
  }

  /**
   * @dev Opdata is nonce + signature packed.
   * If no signature has been provided to the object, it will create the transaction without a signatures. This can be used to sub-batch the transaction.
   */
  getOpData(options?: { compactSignature: boolean }): `0x${string}` {
    const { compactSignature: useCompact = true } = options ?? {};
    const sig = this.signature
      ? useCompact
        ? this.asCompactSignature()
        : this.signature
      : undefined;
    return buildOpData(this.nonce, sig);
  }

  /**
   * ABI-encoded `(Call[], opData)` payload that `ERC7821.execute` decodes for the
   * Catapultar execution mode. Combines the calls with {@link getOpData}.
   */
  getExecutionData() {
    return buildExecutionData(this.calls, this.getOpData());
  }

  // --- Convert the transaction object into actionable items --- //

  /** @return As parameters for an execute call. */
  asParameters(): ExecuteParameters {
    return {
      mode: this.mode,
      executionData: this.getExecutionData(),
      metadata: {
        value: this.getTotalValue(),
        signature: this.signature,
      },
    };
  }

  /**
   * @return As a call for further scheduling or manual transaction signing. If used for manual transaction.
   */
  asCallData(): Omit<Call, "to"> {
    const { mode } = this;
    assertMode(mode);
    const executionData = this.getExecutionData();
    const data = encodeFunctionData({
      abi: CATAPULTAR_ABI,
      functionName: "execute",
      args: [mode, executionData],
    });
    return {
      value: 0n,
      data,
    };
  }

  /** Return the calls as an approval digest. This can be used to "embed" the calls into an account */
  asDigest() {
    const { nonce, mode, calls } = this;
    assertNonce(nonce);
    assertMode(mode);
    assertCalls(calls);
    return callsStructHash({ nonce, mode, calls });
  }

  /** Generate an account with this action embedded. */
  asAccount(opt: { salt: `0x${string}`; owner: Owner; factory?: Factory }) {
    const callDigest = this.asDigest();
    const { factory } = _factory(opt);
    const address = CatapultarAccount.predict({
      ...opt,
      digest: { hash: callDigest, isSignature: false },
    });

    const keyType = ownerTypeToEnum(opt.owner.type);
    const keyArray = ownerToKeyArray(opt.owner);
    const deployCall = {
      to: factory,
      data: encodeFunctionData({
        abi: CATAPULTAR_FACTORY_ABI,
        functionName: "deployWithDigest",
        args: [keyType, keyArray, opt.salt, callDigest, false],
      }),
      value: 0n,
    };
    const actionCall = { ...this.asCallData(), to: address };

    return {
      deployCall,
      actionCall,
      callDigest,
      address,
    };
  }
}
