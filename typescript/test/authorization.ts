import { encodeFunctionData, keccak256, type Hex } from "viem";
import CATAPULTAR_ABI from "../src/abi/catapultar";
import { CAT_VALIDATOR_V2_ABI } from "../src/abi/CATValidatorV2";
import { INTENT_EXECUTOR_ABI } from "../src/abi/IntentExecutor";
import { cat_validator_v2 } from "../src/config";
import { buildExecutionData, buildOpData } from "../src/protocol/opdata";
import type { Call, ExecutionMode } from "../src/types/types";
import { random } from "../src/utils/helpers";

/** A random `executeAndSweep` payload: an executor call that consumes an authorization. */
export function executeAndSweepPayload(): Hex {
  return encodeFunctionData({
    abi: INTENT_EXECUTOR_ABI,
    functionName: "executeAndSweep",
    args: [
      [],
      [{ target: random(20), allowFailure: false, callData: random(36) }],
      [{ token: random(20), recipient: random(20) }],
    ],
  });
}

/** `IntentExecutor.authorizeCall(callHash, validator)` sent to `executor`. */
export function authorizeCall(
  executor: Hex,
  callHash: Hex,
  validator: Hex = cat_validator_v2,
): Call {
  return {
    to: executor,
    value: 0n,
    data: encodeFunctionData({
      abi: INTENT_EXECUTOR_ABI,
      functionName: "authorizeCall",
      args: [callHash, validator],
    }),
  };
}

/** A V2 `entry` call on `validator` that forwards `execPayload` to `execTarget`. */
export function entryCall(
  execTarget: Hex,
  execPayload: Hex,
  validator: Hex = cat_validator_v2,
): Call {
  return {
    to: validator,
    value: 0n,
    data: encodeFunctionData({
      abi: CAT_VALIDATOR_V2_ABI,
      functionName: "entry",
      args: [
        execTarget,
        execPayload,
        random(20),
        1n,
        [],
        [],
        { executionTarget: execTarget, payloadHash: keccak256(execPayload) },
        [],
        [],
        "0x",
      ],
    }),
  };
}

/** `[authorizeCall, entry]` for `execPayload` on `executor`: the one shape the SDK signs. */
export function authorizeThenEntry(
  executor: Hex,
  execPayload: Hex,
  validator: Hex = cat_validator_v2,
): Call[] {
  return [
    authorizeCall(executor, keccak256(execPayload), validator),
    entryCall(executor, execPayload, validator),
  ];
}

/**
 * An unsigned `execute(mode, calls)` call to `to`: a sub-batch when `to` is the
 * account running the outer batch, any `execute`-shaped wrapper otherwise.
 */
export function executeCall(
  to: Hex,
  mode: ExecutionMode,
  calls: Call[],
  nonce: bigint = 1n,
): Call {
  return {
    to,
    value: 0n,
    data: encodeFunctionData({
      abi: CATAPULTAR_ABI,
      functionName: "execute",
      args: [mode, buildExecutionData(calls, buildOpData(nonce))],
    }),
  };
}
