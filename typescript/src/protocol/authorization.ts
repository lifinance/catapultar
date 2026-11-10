import {
  decodeAbiParameters,
  decodeFunctionData,
  getAbiItem,
  isAddressEqual,
  keccak256,
  toFunctionSelector,
  type Address,
  type Hex,
} from "viem";
import { CallsTyped, ExecutionMode, type Call } from "../types/types";
import { CAT_VALIDATOR_V2_ABI } from "../abi/CATValidatorV2";
import { INTENT_EXECUTOR_ABI } from "../abi/IntentExecutor";
import CATAPULTAR_ABI from "../abi/catapultar";
import { ExecutorAuthorizationError } from "../errors";
import { cat_validator_v2 } from "../config";
import { isMultichainMode } from "./calls";

/**
 * Batch-shape guard for IntentExecutor authorizations.
 *
 * `IntentExecutor.authorizeCall(h)` adds one transient authorization in its own
 * frame; the validator `entry` that consumes it runs in a later frame. If that
 * `entry` fails inside a batch that skips failures, only the consumption is
 * rolled back and the authorization stays live for the rest of the transaction,
 * where any later code can run the authorized payload. The executor cannot see
 * the batch mode, so the signer must refuse every shape in which `entry` can fail
 * without taking its `authorizeCall` down with it.
 *
 * The only accepted shape: `authorizeCall(h)` immediately followed, in the same
 * chain-specific {@link ExecutionMode.RaiseRevert} batch or sub-batch, by a direct
 * `entry` call to a known CAT validator whose `execTarget` is the executor that
 * was authorized and whose `keccak256(execPayload)` is `h`. Sub-batches
 * (`execute` self-calls to the account running the batch) are checked with their
 * own mode, so the pair may sit in a RaiseRevert sub-batch of a SkipRevert meta
 * transaction. An `execute` call to any other contract is opaque: its failure
 * handling is that contract's own. A sub-batch has no signature of its own, so
 * "chain-specific" covers every enclosing frame up to the signed root: a
 * multichain outer batch is rejected even when the pair's own sub-batch is
 * RaiseRevert.
 *
 * The validator must be known because any other contract with an `entry`
 * function could return success without calling the executor, which leaves the
 * authorization live even in a RaiseRevert batch. The SDK cannot check code
 * offline: a listed address with no code on the target chain also "succeeds".
 *
 * Any other call whose calldata carries the `authorizeCall` selector (a
 * multicall, a router, a packed forwarder, or the paired `entry`'s own payload)
 * is rejected: the guard cannot see how that contract handles a failure, so it
 * fails closed. The scan checks every byte offset, so packed encodings are
 * caught too; unrelated calldata matches the 4 bytes by chance with probability
 * about `length / 2^32`.
 */

/** Validators whose `entry` the guard accepts when the caller passes none. */
export const DEFAULT_AUTHORIZED_VALIDATORS: readonly Address[] = [
  cat_validator_v2,
];

export type ExecutorAuthorizationOptions = {
  /** Validators the paired `entry` may target. Default {@link DEFAULT_AUTHORIZED_VALIDATORS}. */
  validators?: readonly Address[];
};

/** The selector {@link carriesAuthorizeCall} searches calldata for. */
const AUTHORIZE_CALL_SELECTOR = toFunctionSelector(
  getAbiItem({ abi: INTENT_EXECUTOR_ABI, name: "authorizeCall" }),
);

/** Both `entry` overloads (v1 and V2) start with `execTarget, execPayload`. */
const ENTRY_ABI = CAT_VALIDATOR_V2_ABI.filter(
  (item) => item.type === "function" && item.name === "entry",
);

function modeName(mode: Hex | undefined): string {
  if (mode === undefined) return "unset";
  const name = Object.entries(ExecutionMode).find(
    ([, value]) => value === mode,
  )?.[0];
  return name ?? mode;
}

/** The mode and calls of a nested `execute(mode, executionData)` call, if `data` is one. */
function decodeSubBatch(
  data: Hex,
): { mode: Hex; calls: readonly Call[] } | undefined {
  try {
    const decoded = decodeFunctionData({ abi: CATAPULTAR_ABI, data });
    if (decoded.functionName !== "execute") return undefined;
    const [mode, executionData] = decoded.args as readonly [Hex, Hex];
    const [calls] = decodeAbiParameters(
      [{ type: "tuple[]", components: CallsTyped.Call }, { type: "bytes" }],
      executionData,
    );
    return { mode, calls: calls as readonly Call[] };
  } catch {
    return undefined;
  }
}

/** `data` decoded against the IntentExecutor ABI, if it is a well-formed call to it. */
function decodeExecutorCall(data: Hex) {
  try {
    return decodeFunctionData({ abi: INTENT_EXECUTOR_ABI, data });
  } catch {
    return undefined;
  }
}

/** Whether the `authorizeCall` selector appears at any byte offset of `data`. */
function carriesAuthorizeCall(data: Hex): boolean {
  const hex = data.toLowerCase();
  const needle = AUTHORIZE_CALL_SELECTOR.slice(2);
  // Hex index 2 + 2k is byte k; an odd index would straddle two bytes.
  for (let i = hex.indexOf(needle, 2); i !== -1; i = hex.indexOf(needle, i + 1))
    if (i % 2 === 0) return true;
  return false;
}

const NOT_FOLLOWED_BY_ENTRY =
  "authorizeCall must be immediately followed by the validator entry it authorizes.";

function assertPair(
  mode: Hex | undefined,
  insideMultichain: boolean,
  authorize: Call,
  callHash: Hex,
  next: Call | undefined,
  validators: readonly Address[],
): asserts next is Call {
  if (mode !== ExecutionMode.RaiseRevert)
    throw new ExecutorAuthorizationError(
      `authorizeCall must run in a RaiseRevert batch or sub-batch, not ${modeName(mode)}: a skipped entry would leave the authorization live.`,
    );
  // A sub-batch carries no signature of its own: the enclosing signed batch
  // authorizes it, and a multichain signature replays it on chains where the
  // validator may have no code, so `entry` would succeed without consuming.
  if (insideMultichain)
    throw new ExecutorAuthorizationError(
      "authorizeCall must be signed chain-specifically: an enclosing batch uses a multichain mode, which replays it on other chains.",
    );

  if (next === undefined)
    throw new ExecutorAuthorizationError(NOT_FOLLOWED_BY_ENTRY);
  let execTarget: Hex;
  let execPayload: Hex;
  try {
    const decoded = decodeFunctionData({ abi: ENTRY_ABI, data: next.data });
    [execTarget, execPayload] = decoded.args as unknown as readonly [Hex, Hex];
  } catch {
    throw new ExecutorAuthorizationError(NOT_FOLLOWED_BY_ENTRY);
  }

  if (!validators.some((validator) => isAddressEqual(validator, next.to)))
    throw new ExecutorAuthorizationError(
      `entry must call a known CAT validator, not ${next.to}.`,
    );
  if (!isAddressEqual(execTarget, authorize.to))
    throw new ExecutorAuthorizationError(
      `entry.execTarget ${execTarget} is not the authorized executor ${authorize.to}.`,
    );
  if (keccak256(execPayload) !== callHash)
    throw new ExecutorAuthorizationError(
      "authorizeCall hash does not match keccak256(entry.execPayload).",
    );
  // A payload calling anything else (or empty, which the validator does not even
  // forward) returns without consuming, leaving the authorization live.
  const payloadFunction = decodeExecutorCall(execPayload)?.functionName;
  if (
    payloadFunction !== "executeAndSweep" &&
    payloadFunction !== "executeAndSweepNative"
  )
    throw new ExecutorAuthorizationError(
      "entry.execPayload must call executeAndSweep or executeAndSweepNative, the executor functions that consume the authorization.",
    );
}

/**
 * Assert that every IntentExecutor `authorizeCall` in a batch (and in any nested
 * sub-batch) is paired with its validator `entry` inside one RaiseRevert frame.
 * Batches without `authorizeCall` always pass.
 * @param options.validators Validators the paired `entry` may target. Default
 *   {@link DEFAULT_AUTHORIZED_VALIDATORS}.
 * @param options.account The account that executes `calls`. Only `execute` calls
 *   to it are checked as sub-batches; without it, every `execute` call is opaque.
 * @throws {ExecutorAuthorizationError} On any other shape.
 */
export function assertExecutorAuthorizations(
  mode: Hex | undefined,
  calls: readonly Call[],
  options?: ExecutorAuthorizationOptions & { account?: Address },
): void {
  const { validators = DEFAULT_AUTHORIZED_VALIDATORS, account } = options ?? {};
  assertFrame(mode, calls, false, validators, account);
}

/**
 * One batch frame of {@link assertExecutorAuthorizations}. `insideMultichain` is
 * whether any enclosing frame, up to the signed root, uses a multichain mode.
 */
function assertFrame(
  mode: Hex | undefined,
  calls: readonly Call[],
  insideMultichain: boolean,
  validators: readonly Address[],
  account: Address | undefined,
): void {
  for (let i = 0; i < calls.length; i++) {
    const call = calls[i]!;
    const executorCall = decodeExecutorCall(call.data);
    if (executorCall?.functionName === "authorizeCall") {
      const entry = calls[i + 1];
      assertPair(
        mode,
        insideMultichain,
        call,
        executorCall.args[0],
        entry,
        validators,
      );
      if (carriesAuthorizeCall(entry.data))
        throw new ExecutorAuthorizationError(
          "The paired entry's payload carries another authorizeCall; the guard cannot pair it.",
        );
      i++; // The paired entry is not a sub-batch.
      continue;
    }
    const subBatch =
      account !== undefined && isAddressEqual(call.to, account)
        ? decodeSubBatch(call.data)
        : undefined;
    if (subBatch) {
      assertFrame(
        subBatch.mode,
        subBatch.calls,
        insideMultichain || isMultichainMode(mode as ExecutionMode),
        validators,
        account,
      );
      continue;
    }
    if (carriesAuthorizeCall(call.data))
      throw new ExecutorAuthorizationError(
        `Call to ${call.to} carries an authorizeCall the guard cannot inspect. Put authorizeCall directly in the batch, before its entry.`,
      );
  }
}
