import { encodeFunctionData, erc20Abi, zeroAddress, zeroHash } from "viem";
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
  type ValidationCommitment,
} from "../types/types";
import { ValidationError } from "../errors";
import { BaseTransaction } from "./transaction";
import CATAPULTAR_ABI from "../abi/catapultar";
import { CAT_VALIDATOR_ABI } from "../abi/CATValidator";
import { CAT_VALIDATOR_V2_ABI } from "../abi/CATValidatorV2";
import { cat_validator } from "../config";
import {
  assertValidationInputs,
  constraintDigest,
  constraintV2Digest,
} from "../protocol/constraint";

/** Options for {@link ConstrainedAssetTransaction.asExecuteCall}. */
export type CatExecuteOptions = {
  address: `0x${string}`;
  executionTarget: `0x${string}`;
  executionPayload: `0x${string}`;
  spends: bigint[];
  /**
   * Validator to call. Defaults to the library `CATValidator`; required when a
   * validation commitment is set, since there is no default `CATValidatorV2`.
   */
  validator?: `0x${string}`;
  /**
   * `CATValidatorV2` only: the committed program body (33 bytes per command).
   * Must hash to the commitment's `validationProgramHash`. Default empty.
   */
  validationProgram?: `0x${string}`;
  /**
   * `CATValidatorV2` only: the committed param words, encoded as `bytes32[]`.
   * Must hash to the commitment's `paramsHash`. Default empty.
   */
  validationParams?: `0x${string}`[];
};

/** Options for {@link ConstrainedAssetTransaction.asRefundCall}. */
export type CatRefundOptions = {
  address: `0x${string}`;
  refund: `0x${string}`;
  /**
   * Validator to call. Defaults to the library `CATValidator`; required when a
   * validation commitment is set, since there is no default `CATValidatorV2`.
   */
  validator?: `0x${string}`;
};

/**
 * The refund constraint of a v2 transaction commits no program: refundability
 * is the safety net, so a program that can never pass must not brick it.
 * `CATValidatorV2` settles a zero commitment exactly like v1.
 */
const NO_VALIDATION: ValidationCommitment = {
  validationProgramHash: zeroHash,
  paramsHash: zeroHash,
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
 * {@link setValidationCommitment} targets `CATValidatorV2` instead: the
 * constraint then also commits an LI.FI VirtualMachine validation program, and
 * every digest and entry call it produces is v2. Without a commitment the
 * builder produces exactly the v1 output.
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
   * The committed validation program and params hashes. Presence, not
   * zero-ness, selects `CATValidatorV2`: a zero-hash commitment is a valid v2
   * constraint without a program. Unset means v1.
   */
  validationCommitment?: ValidationCommitment;

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
   * Commit a validation program to the constraint, switching it to
   * `CATValidatorV2`: digests use EIP-712 domain version "2" and commit both
   * hashes, and entry calls use the v2 `entry`. Every call that touches the
   * validator then requires an explicit `validator` address. The refund
   * constraint deliberately commits zero hashes so a failing program can never
   * block a refund.
   */
  setValidationCommitment(commitment: ValidationCommitment): this {
    this.validationCommitment = commitment;
    return this;
  }

  /**
   * Resolve the validator for a call: the caller's, else the library
   * `CATValidator`. A v2 constraint has no library default.
   */
  private resolveValidator(validator?: `0x${string}`): `0x${string}` {
    if (validator) return validator;
    if (this.validationCommitment)
      throw new ValidationError(
        "A constraint with a validation commitment targets CATValidatorV2, which has no default deployment; pass `validator`.",
      );
    return cat_validator;
  }

  /**
   * Export the constrainted transaction as a BaseTransaction which can be converted to an account.
   * @param opt.addApprove Whether to approve the tokens on the validator. Default True.
   * @param opt.refund If provided, refund allowances to this contract. Default none.
   * @param opt.validator Validator for transaction. Default library validator; required with a validation commitment.
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
      executor = this.executor,
      nonce = 1n,
    } = opt ?? {};
    const validator = this.resolveValidator(opt?.validator);

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
    // and, on v2, the committed hashes differ between them.
    const pushConstraintApproval = (
      outcomes: Outcome[],
      commitment: ValidationCommitment | undefined,
    ) => {
      const executionConstraint: ExecutionConstraint = {
        allowances: this.allowances,
        outcomes,
        executor,
        nonce: this.constraintNonce,
      };
      const domain = { chainId: this.chainId, verifyingContract: validator };
      const digest = commitment
        ? constraintV2Digest(domain, { ...executionConstraint, ...commitment })
        : constraintDigest(domain, executionConstraint);
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

    pushConstraintApproval(this.outcomes, this.validationCommitment);

    // If a refund target has been provided, then we add a 1:1 refund.
    if (refund) {
      const refundOutcomes: Outcome[] = this.allowances.map((allowance) => ({
        destination: refund,
        amount: allowance.amount,
        token: allowance.token,
      }));
      pushConstraintApproval(
        refundOutcomes,
        this.validationCommitment && NO_VALIDATION,
      );
    }

    const tx = new BaseTransaction();
    tx.addCall(...calls);
    tx.setMode(ExecutionMode.RaiseRevert);
    tx.setNonce(nonce);
    return tx;
  }

  /**
   * Encode a validator `entry` call — the shared shape behind
   * {@link asExecuteCall} and {@link asRefundCall}. Only the execution
   * target/payload, spends, and outcomes differ between them. With a
   * `validation` the call is the 9-argument `CATValidatorV2.entry`, which
   * derives the committed hashes from the program and params itself;
   * otherwise it is the 7-argument `CATValidator.entry`.
   */
  private buildEntryCall(opt: {
    validator: `0x${string}`;
    target: `0x${string}`;
    payload: `0x${string}`;
    account: `0x${string}`;
    spends: AllowanceSpend[];
    outcomes: Outcome[];
    validation?: {
      validationProgram: `0x${string}`;
      validationParams: `0x${string}`[];
    };
  }): Call {
    const { validation } = opt;
    return {
      to: opt.validator,
      value: 0n,
      data: validation
        ? encodeFunctionData({
            abi: CAT_VALIDATOR_V2_ABI,
            functionName: "entry",
            args: [
              opt.target,
              opt.payload,
              opt.account,
              this.constraintNonce,
              opt.spends,
              opt.outcomes,
              validation.validationProgram,
              validation.validationParams,
              "0x",
            ],
          })
        : encodeFunctionData({
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
   * The call for execution the validation on the account. With a validation
   * commitment, `validationProgram` and `validationParams` must hash to it;
   * otherwise they must be omitted.
   */
  asExecuteCall(opt: CatExecuteOptions): Call {
    const {
      executionTarget,
      executionPayload,
      validationProgram = "0x",
      validationParams = [],
    } = opt;
    const validator = this.resolveValidator(opt.validator);

    if (opt.spends.length !== this.allowances.length)
      throw new ValidationError(
        `Spends and allowances not same length: Allowances: ${this.allowances.length}, Spends: ${opt.spends.length}`,
      );
    const allowanceSpends: AllowanceSpend[] = this.allowances.map((a, i) => ({
      token: a.token,
      allocated: a.amount,
      spend: opt.spends[i]!,
    }));

    const commitment = this.validationCommitment;
    if (commitment)
      assertValidationInputs(commitment, validationProgram, validationParams);
    else if (
      opt.validationProgram !== undefined ||
      opt.validationParams !== undefined
    )
      throw new ValidationError(
        "validationProgram and validationParams require a validation commitment; call setValidationCommitment first.",
      );

    return this.buildEntryCall({
      validator,
      target: executionTarget,
      payload: executionPayload,
      account: opt.address,
      spends: allowanceSpends,
      outcomes: this.outcomes,
      validation: commitment && { validationProgram, validationParams },
    });
  }

  /**
   * Build the validator entry call that refunds the full allowances 1:1 back to
   * `opt.refund` (each allowance becomes an equal outcome to the refund target).
   * Use this to unwind an embedded constraint without running any execution.
   * On a v2 constraint the refund commits zero hashes and no program, matching
   * the refund constraint embedded by {@link asCatapultarAllowanceTransaction}.
   */
  asRefundCall(opt: CatRefundOptions) {
    const validator = this.resolveValidator(opt.validator);

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
      validation: this.validationCommitment && {
        validationProgram: "0x",
        validationParams: [],
      },
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
    // neither an ERC20 allowance nor an approved digest. `undefined` resolves to the
    // library default (or throws on a v2 constraint), preserving the default path.
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
