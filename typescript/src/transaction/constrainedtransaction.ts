import { encodeFunctionData, erc20Abi, hashTypedData, zeroAddress } from "viem";
import {
  DigestApproval,
  ExecutionConstraintTyped,
  ExecutionMode,
  type Allowance,
  type AllowanceSpend,
  type Call,
  type ExecutionConstraint,
  type Outcome,
} from "../types/types";
import { BaseTransaction } from "./transaction";
import CATAPULTAR_V0_1_0_ABI from "../abi/catapultarV0.1.0";
import { CAT_VALIDATOR_ABI } from "../abi/CATValidator";
import { cat_validator } from "../config";

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

  addAllowances(...allowances: Allowance[]) {
    this.allowances.push(...allowances);
  }

  /**
   * Add token outcomes to an asset constraint.
   * To add the smart account as the recipient (address unknown at this stage), set address(0).
   */
  addOutcomes(...outcomes: Outcome[]) {
    this.outcomes.push(...outcomes);
  }

  perpetual(state: boolean) {
    if (state) this.constraintNonce = 0n;
    else if (this.constraintNonce === 0n) this.constraintNonce = 1n;
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
  }) {
    const {
      addApprove = true,
      refund,
      validator = cat_validator,
      executor = this.executor,
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
    tx.setNonce(1n);
    return tx;
  }

  /**
   * The call for execution the validation on the account.
   */
  asExecuteCall(
    opt: { address: `0x${string}` } & {
      executionTarget: `0x${string}`;
      executionPayload: `0x${string}`;
      spends: bigint[];
    } & {
      refund?: `0x${string}`;
      validator?: `0x${string}`;
    },
  ): Call {
    const {
      validator = cat_validator,
      executionTarget,
      executionPayload,
    } = opt;

    if (opt.spends.length !== this.allowances.length)
      throw new Error(
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

  asRefundCall(
    opt: { address: `0x${string}` } & {
      refund: `0x${string}`;
      validator?: `0x${string}`;
    },
  ) {
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
}
