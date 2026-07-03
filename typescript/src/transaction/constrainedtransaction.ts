import { encodeFunctionData, erc20Abi, zeroAddress } from "viem";
import {
  DigestApproval,
  ExecutionMode,
  type Allowance,
  type AllowanceSpend,
  type Call,
  type ExecutionConstraint,
  type Factory,
  type Outcome,
  type Owner,
} from "../types/types";
import { ValidationError } from "../errors";
import { BaseTransaction } from "./transaction";
import CATAPULTAR_ABI from "../abi/catapultar";
import { CAT_VALIDATOR_ABI } from "../abi/CATValidator";
import { cat_validator } from "../config";
import { constraintDigest } from "../protocol/constraint";

/** Options for {@link ConstrainedAssetTransaction.asExecuteCall}. */
export type CatExecuteOptions = {
  address: `0x${string}`;
  executionTarget: `0x${string}`;
  executionPayload: `0x${string}`;
  spends: bigint[];
  validator?: `0x${string}`;
};

/** Options for {@link ConstrainedAssetTransaction.asRefundCall}. */
export type CatRefundOptions = {
  address: `0x${string}`;
  refund: `0x${string}`;
  validator?: `0x${string}`;
};

/**
 * Builder for a Constrained Asset Transaction (CAT).
 *
 * A CAT lets a designated `executor` spend an account's assets (the
 * `allowances`) provided a set of `outcomes` is delivered — enforced by the
 * `CATValidator` via an EIP-712 `ExecutionConstraint`. The typical flow embeds
 * the constraint into a freshly-deployed account so arbitrary execution can be
 * run against it later (see {@link asExecutionBundle}).
 *
 * Build the constraint with {@link addAllowances} / {@link addOutcomes}, then
 * convert it: {@link asCatapultarAllowanceTransaction} for the embeddable
 * approval batch, {@link asExecuteCall} for the validator entry call, or
 * {@link asExecutionBundle} for the full deploy -> approve -> execute sequence.
 *
 * Two on-chain sentinels assist advanced flows: {@link SPEND_FULL_BALANCE} as a
 * spend amount, and {@link OUTCOME_TO_SIGNER} (`address(0)`) as an outcome
 * destination.
 */
export class ConstrainedAssetTransaction {
  /** Tokens (and amounts) the executor is permitted to pull from the account. */
  allowances: Allowance[] = [];
  /** Tokens (and amounts) that must be delivered for the constraint to pass. */
  outcomes: Outcome[] = [];

  /** The only address allowed to execute this constraint. */
  executor: `0x${string}`;
  /** Chain the constraint (and its CAT Validator domain) is bound to. */
  chainId: number;

  /** Constraint nonce (Permit2-style). Defaults to 1; `0` is the perpetual/reusable nonce. */
  constraintNonce: bigint = 1n;

  /**
   * @param opt.executor The address permitted to execute the constraint.
   * @param opt.chainId Chain the constraint is bound to.
   */
  constructor(opt: { executor: `0x${string}`; chainId: number }) {
    const { executor, chainId } = opt;
    this.executor = executor;
    this.chainId = chainId;
  }

  /** Add token allowances the executor may pull from the account. */
  addAllowances(...allowances: Allowance[]): this {
    this.allowances.push(...allowances);
    return this;
  }

  /**
   * Add token outcomes to an asset constraint.
   * To add the smart account as the recipient (address unknown at this stage), set address(0).
   */
  addOutcomes(...outcomes: Outcome[]): this {
    this.outcomes.push(...outcomes);
    return this;
  }

  /** Make the constraint reusable by using nonce 0 (a "perpetual" constraint). */
  setPerpetual(): this {
    this.constraintNonce = 0n;
    return this;
  }

  /** Set the constraint nonce explicitly. */
  setConstraintNonce(nonce: bigint): this {
    this.constraintNonce = nonce;
    return this;
  }

  /**
   * Export the constrainted transaction as a BaseTransaction which can be converted to an account.
   * @param opt.addApprove Whether to approve the tokens on the validator. Default True.
   * @param opt.refund If provided, refund allowances to this contract. Default none.
   * @param opt.validator Validator for transaction. Default library validator.
   * @param opt.executor The constrainted transaction can only be executed by this account. Default this.executor.
   * @returns BaseTransaction with calls embedded for a constrainted validator.
   */
  asCatapultarAllowanceTransaction(opt?: {
    addApprove?: boolean;
    refund?: `0x${string}`;
    validator?: `0x${string}`;
    executor?: `0x${string}`;
    /** Nonce for the embedded BaseTransaction. Default 1. */
    nonce?: bigint;
  }) {
    const {
      addApprove = true,
      refund,
      validator = cat_validator,
      executor = this.executor,
      nonce = 1n,
    } = opt ?? {};

    const calls: Call[] = [];
    if (addApprove) {
      // Allow the validator to pull funds. To actually pull funds, the validator requires a signature.
      for (const allowance of this.allowances) {
        calls.push({
          to: allowance.token,
          data: encodeFunctionData({
            abi: erc20Abi,
            functionName: "approve",
            args: [validator, allowance.amount],
          }),
          value: 0n,
        });
      }
    }
    // Set the signature that allows the validator to pull funds. The approval is
    // identical for the main constraint and the optional refund; only `outcomes`
    // differ between them.
    const pushConstraintApproval = (outcomes: Outcome[]) => {
      const executionConstraint: ExecutionConstraint = {
        allowances: this.allowances,
        outcomes,
        executor,
        nonce: this.constraintNonce,
      };
      const digest = constraintDigest(
        { chainId: this.chainId, verifyingContract: validator },
        executionConstraint,
      );
      // `to: zeroAddress` is the ERC-7821 self-call convention — the executor
      // (Solady's `_get`) substitutes `address(this)`, so this approves the
      // constraint digest on the account itself during the embedded batch.
      calls.push({
        to: zeroAddress,
        value: 0n,
        data: encodeFunctionData({
          abi: CATAPULTAR_ABI,
          functionName: "setSignature",
          args: [digest, DigestApproval.Signature],
        }),
      });
    };

    pushConstraintApproval(this.outcomes);

    // If a refund target has been provided, then we add a 1:1 refund.
    if (refund) {
      const refundOutcomes: Outcome[] = this.allowances.map((allowance) => ({
        destination: refund,
        amount: allowance.amount,
        token: allowance.token,
      }));
      pushConstraintApproval(refundOutcomes);
    }

    const tx = new BaseTransaction();
    tx.addCall(...calls);
    tx.setMode(ExecutionMode.RaiseRevert);
    tx.setNonce(nonce);
    return tx;
  }

  /**
   * Encode a `CATValidator.entry` call — the shared shape behind
   * {@link asExecuteCall} and {@link asRefundCall}. Only the execution
   * target/payload, spends, and outcomes differ between them.
   */
  private buildEntryCall(opt: {
    validator: `0x${string}`;
    target: `0x${string}`;
    payload: `0x${string}`;
    account: `0x${string}`;
    spends: AllowanceSpend[];
    outcomes: Outcome[];
  }): Call {
    return {
      to: opt.validator,
      value: 0n,
      data: encodeFunctionData({
        abi: CAT_VALIDATOR_ABI,
        functionName: "entry",
        args: [
          opt.target,
          opt.payload,
          opt.account,
          this.constraintNonce,
          opt.spends,
          opt.outcomes,
          "0x",
        ],
      }),
    };
  }

  /**
   * The call for execution the validation on the account.
   */
  asExecuteCall(opt: CatExecuteOptions): Call {
    const {
      validator = cat_validator,
      executionTarget,
      executionPayload,
    } = opt;

    if (opt.spends.length !== this.allowances.length)
      throw new ValidationError(
        `Spends and allowances not same length: Allowances: ${this.allowances.length}, Spends: ${opt.spends.length}`,
      );
    const allowanceSpends: AllowanceSpend[] = this.allowances.map((a, i) => ({
      token: a.token,
      allocated: a.amount,
      spend: opt.spends[i]!,
    }));

    return this.buildEntryCall({
      validator,
      target: executionTarget,
      payload: executionPayload,
      account: opt.address,
      spends: allowanceSpends,
      outcomes: this.outcomes,
    });
  }

  /**
   * Build the validator entry call that refunds the full allowances 1:1 back to
   * `opt.refund` (each allowance becomes an equal outcome to the refund target).
   * Use this to unwind an embedded constraint without running any execution.
   */
  asRefundCall(opt: CatRefundOptions) {
    const { validator = cat_validator } = opt;

    const allowanceSpends: AllowanceSpend[] = this.allowances.map((a) => ({
      token: a.token,
      allocated: a.amount,
      spend: a.amount,
    }));
    const refundOutcomes: Outcome[] = this.allowances.map((a) => ({
      token: a.token,
      amount: a.amount,
      destination: opt.refund,
    }));

    // Set target to the validator. The validator will forward funds to the user at the end of the call.
    return this.buildEntryCall({
      validator,
      target: validator,
      payload: "0x",
      account: opt.address,
      spends: allowanceSpends,
      outcomes: refundOutcomes,
    });
  }

  /**
   * Build the full ordered call sequence for the common flow: deploy the
   * account with the constraint embedded, run the embedded approval, then
   * execute the constraint. Returns `[deployCall, actionCall, entryCall]` (in
   * execution order) plus the account address.
   */
  asExecutionBundle(opt: {
    salt: `0x${string}`;
    owner: Owner;
    factory?: Factory;
    execute: Omit<CatExecuteOptions, "address">;
  }): {
    deployCall: Call;
    actionCall: Call;
    entryCall: Call;
    address: `0x${string}`;
  } {
    // The embedded approve + setSignature batch must target the SAME validator the
    // entry call (asExecuteCall) executes against, or the custom validator would have
    // neither an ERC20 allowance nor an approved digest. `undefined` re-applies the
    // library default via the destructuring default, preserving the default path.
    const tx = this.asCatapultarAllowanceTransaction({
      validator: opt.execute.validator,
    });
    const { deployCall, actionCall, address } = tx.asAccount({
      salt: opt.salt,
      owner: opt.owner,
      factory: opt.factory,
    });
    const entryCall = this.asExecuteCall({ address, ...opt.execute });
    return { deployCall, actionCall, entryCall, address };
  }
}
