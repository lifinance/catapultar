import { encodeFunctionData, erc20Abi, hashTypedData, zeroAddress } from "viem";
import {
  DigestApproval,
  ExecutionConstraintTyped,
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
import CATAPULTAR_V0_1_0_ABI from "../abi/catapultarV0.1.0";
import { CAT_VALIDATOR_ABI } from "../abi/CATValidator";
import { cat_validator } from "../config";

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
 * Helper class for deploying a Catapultar account with an embedded Constrained Asset Transaction
 */
export class ConstrainedAssetTransaction {
  allowances: Allowance[] = [];
  outcomes: Outcome[] = [];

  executor: `0x${string}`;
  chainId: number;

  constraintNonce: bigint = 1n;

  constructor(opt: { executor: `0x${string}`; chainId: number }) {
    const { executor, chainId } = opt;
    this.executor = executor;
    this.chainId = chainId;
  }

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
      const typehash = hashTypedData({
        types: ExecutionConstraintTyped,
        primaryType: "ExecutionConstraint",
        message: executionConstraint,
        domain: {
          chainId: this.chainId,
          name: "CAT Validator",
          version: "1",
          verifyingContract: validator,
        },
      });
      calls.push({
        to: zeroAddress,
        value: 0n,
        data: encodeFunctionData({
          abi: CATAPULTAR_V0_1_0_ABI,
          functionName: "setSignature",
          args: [typehash, DigestApproval.Signature],
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

    const executeCall: Call = {
      to: validator,
      data: encodeFunctionData({
        abi: CAT_VALIDATOR_ABI,
        functionName: "entry",
        args: [
          executionTarget,
          executionPayload,
          opt.address,
          this.constraintNonce,
          allowanceSpends,
          this.outcomes,
          "0x",
        ],
      }),
      value: 0n,
    };
    return executeCall;
  }

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
    const executeCall: Call = {
      to: validator,
      data: encodeFunctionData({
        abi: CAT_VALIDATOR_ABI,
        functionName: "entry",
        args: [
          validator,
          "0x",
          opt.address,
          this.constraintNonce,
          allowanceSpends,
          refundOutcomes,
          "0x",
        ],
      }),
      value: 0n,
    };
    return executeCall;
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
    const tx = this.asCatapultarAllowanceTransaction();
    const { deployCall, actionCall, address } = tx.asAccount({
      salt: opt.salt,
      owner: opt.owner,
      factory: opt.factory,
    });
    const entryCall = this.asExecuteCall({ address, ...opt.execute });
    return { deployCall, actionCall, entryCall, address };
  }
}
