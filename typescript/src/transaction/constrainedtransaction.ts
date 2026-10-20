import {
  encodeFunctionData,
  erc20Abi,
  isAddressEqual,
  keccak256,
  maxUint256,
  zeroAddress,
  zeroHash,
} from "viem";
import {
  DigestApproval,
  ExecutionMode,
  type Allowance,
  type AllowanceSpend,
  type Call,
  type ExecutionBinding,
  type ExecutionConstraint,
  type Factory,
  type Outcome,
  type Owner,
  type ValidationCommand,
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
  refundBinding,
  SPEND_FULL_BALANCE,
  UNBOUND_EXECUTION,
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
   * `CATValidatorV2` only: the committed program, the `runVM` command array.
   * Must hash to the commitment's `validationProgramHash`. Default empty.
   */
  validationProgram?: readonly ValidationCommand[];
  /**
   * `CATValidatorV2` only: the committed param words, encoded as `bytes32[]`.
   * Must hash to the commitment's `paramsHash`. Default empty.
   */
  validationParams?: readonly `0x${string}`[];
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
 * A binding the SDK signs must commit both fields: zero is the unconstrained
 * sentinel for either, and a half-bound constraint still lets the executor
 * choose the other half.
 */
function assertBoundFill(binding: ExecutionBinding): void {
  if (
    isAddressEqual(binding.executionTarget, zeroAddress) ||
    BigInt(binding.payloadHash) === 0n
  )
    throw new ValidationError(
      "An execution binding must set both executionTarget and payloadHash: zero is the unconstrained sentinel for either field.",
    );
}

/**
 * Fails closed client-side, as for the validation inputs: the validator checks
 * the call against each non-zero binding field before any allowance moves, so
 * a mismatch encodes a call that can only revert.
 */
function assertCallMatchesBinding(
  binding: ExecutionBinding,
  executionTarget: `0x${string}`,
  executionPayload: `0x${string}`,
): void {
  if (!isAddressEqual(executionTarget, binding.executionTarget))
    throw new ValidationError(
      `executionTarget ${executionTarget} is not the bound ${binding.executionTarget}; the validator would revert TargetNotCommitted.`,
    );
  const payloadHash = keccak256(executionPayload);
  if (BigInt(payloadHash) !== BigInt(binding.payloadHash))
    throw new ValidationError(
      `keccak256(executionPayload) ${payloadHash} is not the bound payloadHash ${binding.payloadHash}; the validator would revert PayloadNotCommitted.`,
    );
}

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
   * The committed fill of the execute constraint (`CATValidatorV2` only).
   * Unset means {@link UNBOUND_EXECUTION}. Set via {@link setExecutionBinding}.
   */
  executionBinding?: ExecutionBinding;

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
   * validator then requires an explicit `validator` address. The execute
   * constraint commits an unbound fill ({@link UNBOUND_EXECUTION}) unless
   * {@link setExecutionBinding} binds it. The refund constraint commits zero
   * hashes, so a failing program can never block a refund, and binds its
   * target to the refund address ({@link refundBinding}).
   */
  setValidationCommitment(commitment: ValidationCommitment): this {
    this.validationCommitment = commitment;
    return this;
  }

  /**
   * Bind the execute constraint to one exact fill. `CATValidatorV2.entry` then
   * reverts `TargetNotCommitted()` for any other `execTarget` and
   * `PayloadNotCommitted()` unless `keccak256(execPayload) == payloadHash`,
   * before any allowance moves. The binding is signed into the v2 digest, so
   * it also moves the account address. Both fields must be non-zero: zero is
   * the unconstrained sentinel for either field, and a half-bound constraint
   * still lets the executor choose the other half. Requires a validation
   * commitment, since only the v2 digest carries a binding. The refund
   * constraint keeps its own {@link refundBinding}.
   */
  setExecutionBinding(binding: ExecutionBinding): this {
    assertBoundFill(binding);
    this.executionBinding = binding;
    return this;
  }

  /**
   * The execute constraint's binding: the bound fill, or the unbound sentinels.
   * Checked here, not only in the setter, since the field is public. A binding
   * without a validation commitment throws rather than being dropped from the
   * v1 digest, which has no binding field.
   */
  private executeBinding(): ExecutionBinding {
    if (!this.executionBinding) return UNBOUND_EXECUTION;
    if (!this.validationCommitment)
      throw new ValidationError(
        "An execution binding requires a validation commitment: only the CATValidatorV2 digest signs a binding. Call setValidationCommitment first, or drop the binding.",
      );
    assertBoundFill(this.executionBinding);
    return this.executionBinding;
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
    const binding = this.executeBinding();

    const calls: Call[] = [];
    // The v2 refund sweeps whatever balance the account holds, even more than
    // the signed amount (see `asRefundCall`), so a v2 bundle with a refund
    // approves without limit. Otherwise the approval is the signed amount:
    // the v1 refund delivers exactly the signed amounts.
    const approval =
      refund && this.validationCommitment ? maxUint256 : undefined;
    if (addApprove) {
      // Allow the validator to pull funds. To actually pull funds, the validator requires a signature.
      for (const allowance of this.allowances) {
        calls.push({
          to: allowance.token,
          data: encodeFunctionData({
            abi: erc20Abi,
            functionName: "approve",
            args: [validator, approval ?? allowance.amount],
          }),
          value: 0n,
        });
      }
    }
    // Set the signature that allows the validator to pull funds. The approval is
    // identical for the main constraint and the optional refund; only the
    // allowance amounts, `outcomes` and, on v2, the binding and the committed
    // hashes differ between them.
    const pushConstraintApproval = (
      allowances: Allowance[],
      outcomes: Outcome[],
      v2?: { binding: ExecutionBinding; commitment: ValidationCommitment },
    ) => {
      const executionConstraint: ExecutionConstraint = {
        allowances,
        outcomes,
        executor,
        nonce: this.constraintNonce,
      };
      const domain = { chainId: this.chainId, verifyingContract: validator };
      const digest = v2
        ? constraintV2Digest(domain, {
            ...executionConstraint,
            ...v2.binding,
            ...v2.commitment,
          })
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

    pushConstraintApproval(
      this.allowances,
      this.outcomes,
      this.validationCommitment && {
        binding,
        commitment: this.validationCommitment,
      },
    );

    if (refund) {
      if (this.validationCommitment) {
        // v2: the sweep form. Every allowance is signed at `maxUint256`, since
        // the validator checks `allocated >= spend` with the spend resolved to
        // the account's live balance, and the binding pins the target to
        // `refund`, so the allowances move straight there and no outcome is
        // needed (see `asRefundCall`).
        const refundAllowances: Allowance[] = this.allowances.map((a) => ({
          token: a.token,
          amount: maxUint256,
        }));
        pushConstraintApproval(refundAllowances, [], {
          binding: refundBinding(refund),
          commitment: NO_VALIDATION,
        });
      } else {
        // v1: a 1:1 refund through the validator.
        pushConstraintApproval(this.allowances, this.refundOutcomes(refund));
      }
    }

    const tx = new BaseTransaction();
    tx.addCall(...calls);
    tx.setMode(ExecutionMode.RaiseRevert);
    tx.setNonce(nonce);
    return tx;
  }

  /**
   * The v1 refund outcomes: each allowance, 1:1, to `refund` through the
   * validator. The amount is the floor the validator enforces, which is what
   * keeps the signed executor from diverting the refund: the v1 digest signs
   * no target, so the outcome is the only commitment to `refund`.
   */
  private refundOutcomes(refund: `0x${string}`): Outcome[] {
    return this.allowances.map((a) => ({
      token: a.token,
      amount: a.amount,
      destination: refund,
    }));
  }

  /**
   * Encode a validator `entry` call — the shared shape behind
   * {@link asExecuteCall} and {@link asRefundCall}. Only the execution
   * target/payload, spends, and outcomes differ between them. With a
   * `validation` the call is the 10-argument `CATValidatorV2.entry`, which
   * takes the signed binding and derives the committed hashes from the
   * program and params itself; otherwise it is the 7-argument
   * `CATValidator.entry`.
   */
  private buildEntryCall(opt: {
    validator: `0x${string}`;
    target: `0x${string}`;
    payload: `0x${string}`;
    account: `0x${string}`;
    spends: AllowanceSpend[];
    outcomes: Outcome[];
    validation?: {
      binding: ExecutionBinding;
      validationProgram: readonly ValidationCommand[];
      validationParams: readonly `0x${string}`[];
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
              validation.binding,
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
   * otherwise they must be omitted. With an execution binding
   * ({@link setExecutionBinding}), `executionTarget` and
   * `keccak256(executionPayload)` must equal it; otherwise the call could only
   * revert `TargetNotCommitted()` or `PayloadNotCommitted()`.
   */
  asExecuteCall(opt: CatExecuteOptions): Call {
    const {
      executionTarget,
      executionPayload,
      validationProgram = [],
      validationParams = [],
    } = opt;
    const validator = this.resolveValidator(opt.validator);
    const binding = this.executeBinding();

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

    if (this.executionBinding)
      assertCallMatchesBinding(binding, executionTarget, executionPayload);

    return this.buildEntryCall({
      validator,
      target: executionTarget,
      payload: executionPayload,
      account: opt.address,
      spends: allowanceSpends,
      outcomes: this.outcomes,
      validation: commitment && {
        binding,
        validationProgram,
        validationParams,
      },
    });
  }

  /**
   * Build the validator entry call that refunds the allowances to
   * `opt.refund`. Use this to unwind an embedded constraint without running
   * any execution. It matches the refund constraint embedded by
   * {@link asCatapultarAllowanceTransaction}:
   *
   * - v2: a sweep of the account's whole balance of every allowance token.
   *   Each spend is {@link SPEND_FULL_BALANCE}, which the validator resolves
   *   to the account's live balance, against an `allocated` of `maxUint256`
   *   (the amount the refund allowances are signed at), so it works whether
   *   the account holds less or more than the signed amount. The call targets
   *   `opt.refund` with an empty payload, under the signed
   *   {@link refundBinding}, so the allowances move straight from the account
   *   to `opt.refund`; the validator reverts `TargetNotCommitted()` for any
   *   other target before an allowance moves. It commits no outcomes, zero
   *   hashes and no program.
   * - v1: the signed amounts, exactly. The call targets the validator with
   *   `allocated = spend = amount` per allowance and a 1:1 outcome to
   *   `opt.refund`, which the validator forwards and enforces as a floor. It
   *   reverts once the account holds less than the signed amount, and leaves
   *   any excess behind. The floor is what pins the destination: the v1
   *   digest signs no target, so a sweep (zero floor, full balance) would let
   *   the executor send the balance anywhere. A balance sweep needs
   *   `CATValidatorV2`.
   */
  asRefundCall(opt: CatRefundOptions) {
    const validator = this.resolveValidator(opt.validator);
    // The refund has its own binding, but a builder whose execute binding can
    // never be signed is misconfigured; fail on every flow it produces.
    this.executeBinding();

    if (this.validationCommitment) {
      const binding = refundBinding(opt.refund);
      return this.buildEntryCall({
        validator,
        target: binding.executionTarget,
        payload: "0x",
        account: opt.address,
        spends: this.allowances.map((a) => ({
          token: a.token,
          allocated: maxUint256,
          spend: SPEND_FULL_BALANCE,
        })),
        outcomes: [],
        validation: {
          binding,
          validationProgram: [],
          validationParams: [],
        },
      });
    }

    // Set target to the validator. The validator will forward funds to the user at the end of the call.
    return this.buildEntryCall({
      validator,
      target: validator,
      payload: "0x",
      account: opt.address,
      spends: this.allowances.map((a) => ({
        token: a.token,
        allocated: a.amount,
        spend: a.amount,
      })),
      outcomes: this.refundOutcomes(opt.refund),
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
