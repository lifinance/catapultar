import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  createPublicClient,
  createTestClient,
  createWalletClient,
  keccak256,
  decodeFunctionData,
  encodeFunctionData,
  erc20Abi,
  getAddress,
  http,
  maxUint256,
  toFunctionSelector,
  zeroAddress,
  zeroHash,
  type Hex,
} from "viem";
import { anvil } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import {
  ConstrainedAssetTransaction,
  type CatExecuteOptions,
} from "./constrainedtransaction";
import { rpcUrl } from "../../test/setup";
import { random } from "../utils/helpers";
import { token1, token2 } from "../../test/fixtures";
import { MOCKERC20_abi } from "../abi/mockerc20";
import { CAT_VALIDATOR_ABI } from "../abi/CATValidator";
import { CAT_VALIDATOR_V2_ABI } from "../abi/CATValidatorV2";
import CATAPULTAR_ABI from "../abi/catapultar";
import {
  constraintV2Digest,
  constraintV2Domain,
  hashValidationParams,
  hashValidationProgram,
  refundBinding,
  SPEND_FULL_BALANCE,
  UNBOUND_EXECUTION,
} from "../protocol/constraint";
import { ValidationError } from "../errors";
import type { ValidationCommand } from "../types/types";

const WETH: Hex = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
const DEST: Hex = "0x1111111111111111111111111111111111111111";
const EXECUTOR: Hex = "0x2222222222222222222222222222222222222222";
const VALIDATOR: Hex = "0x3333333333333333333333333333333333333333";
const ACCOUNT: Hex = "0x4444444444444444444444444444444444444444";
const TARGET: Hex = "0x5555555555555555555555555555555555555555";

// Two runVM commands and two 32-byte param words.
const PROGRAM: ValidationCommand[] = [
  { op: 1, data: `0x${"aa".repeat(32)}` },
  { op: 2, data: `0x${"bb".repeat(32)}` },
];
const PARAMS: Hex[] = [`0x${"11".repeat(32)}`, `0x${"22".repeat(32)}`];
const COMMITMENT = {
  validationProgramHash: hashValidationProgram(PROGRAM),
  paramsHash: hashValidationParams(PARAMS),
};

function wethTx() {
  return new ConstrainedAssetTransaction({ executor: EXECUTOR, chainId: 1 })
    .addAllowances({ token: WETH, amount: 2000000000000000000n })
    .addOutcomes({
      token: WETH,
      amount: 1000000000000000000n,
      destination: DEST,
    });
}

const execute: CatExecuteOptions = {
  address: ACCOUNT,
  executionTarget: TARGET,
  executionPayload: "0xdeadbeef",
  spends: [2000000000000000000n],
  validator: VALIDATOR,
};

/** The digests a `setSignature` batch approves, in call order. */
function approvedDigests(calls: { data: Hex }[]): Hex[] {
  return calls.flatMap((call) => {
    try {
      const decoded = decodeFunctionData({
        abi: CATAPULTAR_ABI,
        data: call.data,
      });
      return decoded.functionName === "setSignature"
        ? [decoded.args[0] as Hex]
        : [];
    } catch {
      return [];
    }
  });
}

describe("ConstrainedAssetTransaction v2", () => {
  describe("CATValidatorV2 ABI", () => {
    const entries = CAT_VALIDATOR_V2_ABI.filter(
      (i) => i.type === "function" && i.name === "entry",
    );

    it("entry has the 10-argument v2 selector", () => {
      const entry = entries.find(
        (i) => i.type === "function" && i.inputs.length === 10,
      )!;
      expect(toFunctionSelector(entry)).toBe(
        toFunctionSelector(
          "entry(address,bytes,address,uint256,(address,uint256,uint256)[],(address,uint256,address)[],(address,bytes32),(uint8,bytes32)[],bytes32[],bytes)",
        ),
      );
      expect(toFunctionSelector(entry)).toBe("0x9b998f63");
    });

    it("keeps the inherited 7-argument entry, which shares v1's selector", () => {
      expect(entries.map((i) => toFunctionSelector(i)).sort()).toEqual([
        "0x9b998f63",
        "0xe5ce4787",
      ]);
      const v1Entry = CAT_VALIDATOR_ABI.find(
        (i) => i.type === "function" && i.name === "entry",
      )!;
      expect(toFunctionSelector(v1Entry)).toBe("0xe5ce4787");
    });

    it("carries every CATValidatorV2 and Tstorish error, the VM getter and the receive hook", () => {
      const errors = CAT_VALIDATOR_V2_ABI.filter((i) => i.type === "error")
        .map((i) => i.name)
        .sort();
      expect(errors).toEqual([
        "AllocationTooSmall",
        "BadSignature",
        "BadValidationParams",
        "BalanceOfFailed",
        "InvalidTokenAmount",
        "InvalidVirtualMachine",
        "NonceAlreadySpent",
        "OnlyDirectCalls",
        "PayloadNotCommitted",
        "Reentrancy",
        "TStoreAlreadyActivated",
        "TStoreNotSupported",
        "TargetNotCommitted",
        "TloadTestContractDeploymentFailed",
        "V1EntryDisabled",
        "ValidationFailed",
      ]);
      expect(
        CAT_VALIDATOR_V2_ABI.some(
          (i) => i.type === "function" && i.name === "VIRTUAL_MACHINE",
        ),
      ).toBe(true);
      expect(CAT_VALIDATOR_V2_ABI.some((i) => i.type === "receive")).toBe(true);
      const constructor = CAT_VALIDATOR_V2_ABI.find(
        (i) => i.type === "constructor",
      )!;
      expect(constructor.inputs.map((i) => i.type)).toEqual(["address"]);
    });

    // Guards the mirrored ABI against drifting from the contract: it is the
    // artifact's ABI verbatim, in artifact order. Requires `forge build` output
    // in solidity/out; skipped when absent, like the embedded bytecode spec.
    const artifactPath = join(
      import.meta.dir,
      "../../../solidity/out/CATValidatorV2.sol/CATValidatorV2.json",
    );
    test.skipIf(!existsSync(artifactPath))("matches the forge artifact", () => {
      const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
      expect(CAT_VALIDATOR_V2_ABI).toEqual(artifact.abi);
    });
  });

  describe("without a validation commitment", () => {
    // Computed on upstream main before CATValidatorV2 support; any drift means
    // the v1 path is no longer byte-identical.
    const V1_EXECUTE_CALLDATA =
      "0xe5ce4787000000000000000000000000555555555555555555555555555555555555555500000000000000000000000000000000000000000000000000000000000000e000000000000000000000000044444444444444444444444444444444444444440000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000000000000004deadbeef000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000001bc16d674ec800000000000000000000000000000000000000000000000000001bc16d674ec800000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000";
    // The v1 execute digest (the one `setSignature` of the batch without a
    // refund) and keccak256 of that batch, computed before the sweep-form
    // refund and the execution binding were added.
    const V1_EXECUTE_DIGEST =
      "0xd030b6c6d454fbfc04ce03e26b2acb3b0644adfa18c1a6a019776cbc45cbcc32";
    const V1_ACTION_DATA_HASH =
      "0xf9bd79ecb6ac27e218a8aff40c28148b30ab9af90b7c31c30163f5d0190823ff";
    // The v1 refund bundle on the same inputs, computed at 1652038 (before
    // the v2 sweep-form refund and the execution binding were added): the
    // refund digest (the second `setSignature`), keccak256 of the embedded
    // batch, the counterfactual account it deploys to, and the refund
    // calldata. v1 keeps the fixed-amount refund, so none of these may move.
    const V1_REFUND_DIGEST =
      "0x7c9b48dacf8c86bdee8d6d395ea3a43f02c856274d89fa8dd17854d53c63a870";
    const V1_REFUND_ACTION_DATA_HASH =
      "0x622bc9137422d3d9797c15769084b8ca6edb7b179a62c5eec7b8a3eb45ec4ad6";
    const V1_REFUND_ACCOUNT = "0xdD28C1019513fDd13A8AFde9AAc32cB471A5DD65";
    const V1_REFUND_CALLDATA =
      "0xe5ce4787000000000000000000000000333333333333333333333333333333333333333300000000000000000000000000000000000000000000000000000000000000e00000000000000000000000004444444444444444444444444444444444444444000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000180000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000001bc16d674ec800000000000000000000000000000000000000000000000000001bc16d674ec800000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000001bc16d674ec8000000000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000";

    it("encodes the v1 entry byte-identically", () => {
      const exec = wethTx().asExecuteCall(execute);
      expect(exec.data).toBe(V1_EXECUTE_CALLDATA);
      expect(
        decodeFunctionData({ abi: CAT_VALIDATOR_ABI, data: exec.data }).args,
      ).toHaveLength(7);
    });

    it("embeds byte-identically without a refund", () => {
      const tx = wethTx().asCatapultarAllowanceTransaction({
        validator: VALIDATOR,
      });
      expect(approvedDigests(tx.calls)).toEqual([V1_EXECUTE_DIGEST]);
      const { actionCall } = tx.asAccount({
        salt: zeroHash,
        owner: { type: "ecdsa", address: EXECUTOR },
      });
      expect(keccak256(actionCall.data)).toBe(V1_ACTION_DATA_HASH);
    });

    it("embeds the fixed-amount refund byte-identically: signed approval, 1:1 floor", () => {
      const tx = wethTx().asCatapultarAllowanceTransaction({
        refund: DEST,
        validator: VALIDATOR,
      });
      expect(tx.calls).toHaveLength(3);
      expect(
        decodeFunctionData({ abi: erc20Abi, data: tx.calls[0]!.data }),
      ).toEqual({
        functionName: "approve",
        args: [VALIDATOR, 2000000000000000000n],
      });
      expect(approvedDigests(tx.calls)).toEqual([
        V1_EXECUTE_DIGEST,
        V1_REFUND_DIGEST,
      ]);
      const { actionCall, address } = tx.asAccount({
        salt: zeroHash,
        owner: { type: "ecdsa", address: EXECUTOR },
      });
      expect(keccak256(actionCall.data)).toBe(V1_REFUND_ACTION_DATA_HASH);
      expect(address).toBe(V1_REFUND_ACCOUNT);
    });

    it("refunds the signed amounts through the validator, byte-identically", () => {
      const refund = wethTx().asRefundCall({
        address: ACCOUNT,
        refund: DEST,
        validator: VALIDATOR,
      });
      expect(refund.to).toBe(VALIDATOR);
      expect(refund.data).toBe(V1_REFUND_CALLDATA);
      expect(
        decodeFunctionData({ abi: CAT_VALIDATOR_ABI, data: refund.data }).args,
      ).toEqual([
        VALIDATOR,
        "0x",
        ACCOUNT,
        1n,
        [
          {
            token: WETH,
            allocated: 2000000000000000000n,
            spend: 2000000000000000000n,
          },
        ],
        [{ token: WETH, amount: 2000000000000000000n, destination: DEST }],
        "0x",
      ]);
    });

    it("rejects validation inputs, which only a v2 constraint can carry", () => {
      expect(() =>
        wethTx().asExecuteCall({ ...execute, validationProgram: PROGRAM }),
      ).toThrow(ValidationError);
      expect(() =>
        wethTx().asExecuteCall({ ...execute, validationParams: [] }),
      ).toThrow(ValidationError);
    });
  });

  describe("with a validation commitment", () => {
    const v2Tx = () => wethTx().setValidationCommitment(COMMITMENT);
    // The unbound v2 execute digest of `v2Tx()`, computed before the sweep-form
    // refund and the execution binding were added: the default must not move.
    const V2_UNBOUND_EXECUTE_DIGEST =
      "0x6cba9f85852350c0fc3c684204795d096f4bd9b7bd04704d57beefe2c475437e";
    // The v2 sweep-form refund digest on the same inputs: allowances at
    // maxUint256, no outcomes, the refund binding, zero hashes. Computed
    // independently with `cast`.
    const V2_REFUND_DIGEST =
      "0x0c76d0aa3c094f53ca04d68cc5a987e61f94e07a76eb4d22775ed4e9043b1130";

    it("encodes the 10-argument v2 entry, which decodes back to the inputs", () => {
      const exec = v2Tx().asExecuteCall({
        ...execute,
        validationProgram: PROGRAM,
        validationParams: PARAMS,
      });
      expect(exec.to).toBe(VALIDATOR);
      expect(exec.value).toBe(0n);
      expect(exec.data.slice(0, 10)).toBe("0x9b998f63");
      const { functionName, args } = decodeFunctionData({
        abi: CAT_VALIDATOR_V2_ABI,
        data: exec.data,
      });
      expect(functionName).toBe("entry");
      expect(args).toEqual([
        TARGET,
        "0xdeadbeef",
        ACCOUNT,
        1n,
        [
          {
            token: WETH,
            allocated: 2000000000000000000n,
            spend: 2000000000000000000n,
          },
        ],
        [{ token: WETH, amount: 1000000000000000000n, destination: DEST }],
        UNBOUND_EXECUTION,
        PROGRAM,
        PARAMS,
        "0x",
      ]);
    });

    it("approves a v2 digest that differs from the v1 builder's", () => {
      const v2Digests = approvedDigests(
        wethTx()
          .setValidationCommitment({
            validationProgramHash: zeroHash,
            paramsHash: zeroHash,
          })
          .asCatapultarAllowanceTransaction({ validator: VALIDATOR }).calls,
      );
      const v1Digests = approvedDigests(
        wethTx().asCatapultarAllowanceTransaction({ validator: VALIDATOR })
          .calls,
      );
      expect(v2Digests).toHaveLength(1);
      expect(v1Digests).toHaveLength(1);
      expect(v2Digests[0]).not.toBe(v1Digests[0]);
    });

    it("embeds an unbound v2 execute digest and a bound zero-commitment sweep refund digest", () => {
      const tx = v2Tx().asCatapultarAllowanceTransaction({
        refund: DEST,
        validator: VALIDATOR,
      });
      expect(
        decodeFunctionData({ abi: erc20Abi, data: tx.calls[0]!.data }),
      ).toEqual({ functionName: "approve", args: [VALIDATOR, maxUint256] });
      expect(approvedDigests(tx.calls)).toEqual([
        V2_UNBOUND_EXECUTE_DIGEST,
        V2_REFUND_DIGEST,
      ]);
      const domain = { chainId: 1, verifyingContract: VALIDATOR };
      expect(
        constraintV2Digest(domain, {
          allowances: [{ token: WETH, amount: 2000000000000000000n }],
          outcomes: [
            { token: WETH, amount: 1000000000000000000n, destination: DEST },
          ],
          executor: EXECUTOR,
          nonce: 1n,
          ...UNBOUND_EXECUTION,
          ...COMMITMENT,
        }),
      ).toBe(V2_UNBOUND_EXECUTE_DIGEST);
      expect(
        constraintV2Digest(domain, {
          allowances: [{ token: WETH, amount: maxUint256 }],
          outcomes: [],
          executor: EXECUTOR,
          nonce: 1n,
          ...refundBinding(DEST),
          validationProgramHash: zeroHash,
          paramsHash: zeroHash,
        }),
      ).toBe(V2_REFUND_DIGEST);
    });

    it("refunds straight to the bound refund address with an empty payload", () => {
      const refund = v2Tx().asRefundCall({
        address: ACCOUNT,
        refund: DEST,
        validator: VALIDATOR,
      });
      expect(refund.to).toBe(VALIDATOR);
      const { args } = decodeFunctionData({
        abi: CAT_VALIDATOR_V2_ABI,
        data: refund.data,
      });
      expect(args).toEqual([
        DEST,
        "0x",
        ACCOUNT,
        1n,
        [{ token: WETH, allocated: maxUint256, spend: SPEND_FULL_BALANCE }],
        [],
        {
          executionTarget: DEST,
          payloadHash:
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        },
        [],
        [],
        "0x",
      ]);
    });

    it("rejects a zero refund address, which would leave the refund unbound", () => {
      expect(() => refundBinding(zeroAddress)).toThrow(ValidationError);
      expect(() =>
        v2Tx().asCatapultarAllowanceTransaction({
          refund: zeroAddress,
          validator: VALIDATOR,
        }),
      ).toThrow(ValidationError);
      expect(() =>
        v2Tx().asRefundCall({
          address: ACCOUNT,
          refund: zeroAddress,
          validator: VALIDATOR,
        }),
      ).toThrow(ValidationError);
    });

    it("selects v2 on presence: a zero-hash commitment is still v2", () => {
      const exec = wethTx()
        .setValidationCommitment({
          validationProgramHash: zeroHash,
          paramsHash: zeroHash,
        })
        .asExecuteCall(execute);
      const { args } = decodeFunctionData({
        abi: CAT_VALIDATOR_V2_ABI,
        data: exec.data,
      });
      expect(args.slice(6)).toEqual([UNBOUND_EXECUTION, [], [], "0x"]);
    });

    it("requires an explicit validator", () => {
      const { validator: _, ...withoutValidator } = execute;
      expect(() => v2Tx().asCatapultarAllowanceTransaction()).toThrow(
        ValidationError,
      );
      expect(() =>
        v2Tx().asExecuteCall({
          ...withoutValidator,
          validationProgram: PROGRAM,
          validationParams: PARAMS,
        }),
      ).toThrow(ValidationError);
      expect(() =>
        v2Tx().asRefundCall({ address: ACCOUNT, refund: DEST }),
      ).toThrow(ValidationError);
      expect(() =>
        v2Tx().asExecutionBundle({
          salt: zeroHash,
          owner: { type: "ecdsa", address: EXECUTOR },
          execute: { ...withoutValidator, validationProgram: PROGRAM },
        }),
      ).toThrow(ValidationError);
    });

    it("fails closed on program or params that do not match the commitment", () => {
      const cases: {
        validationProgram?: ValidationCommand[];
        validationParams?: Hex[];
        message: RegExp;
      }[] = [
        {
          validationParams: PARAMS,
          message: /BadValidationParams/,
        },
        {
          validationProgram: PROGRAM,
          message: /validationParams.*BadSignature/,
        },
        {
          validationProgram: [{ op: 3, data: `0x${"cc".repeat(32)}` }],
          validationParams: PARAMS,
          message: /validationProgram.*BadSignature/,
        },
        {
          validationProgram: [...PROGRAM, { op: 0, data: zeroHash }],
          validationParams: PARAMS,
          message: /validationProgram.*BadSignature/,
        },
        {
          validationProgram: PROGRAM,
          validationParams: [PARAMS[0]!],
          message: /validationParams.*BadSignature/,
        },
        {
          validationProgram: PROGRAM,
          validationParams: [PARAMS[0]!, `0x${"22".repeat(31)}`],
          message: /validationParams\[1\] is 31 bytes/,
        },
      ];
      for (const { message, ...inputs } of cases) {
        const build = () => v2Tx().asExecuteCall({ ...execute, ...inputs });
        expect(build).toThrow(ValidationError);
        expect(build).toThrow(message);
      }
    });

    it("rejects params without a program, as entry does with BadValidationParams", () => {
      const tx = wethTx().setValidationCommitment({
        validationProgramHash: zeroHash,
        paramsHash: hashValidationParams(PARAMS),
      });
      const build = () =>
        tx.asExecuteCall({ ...execute, validationParams: PARAMS });
      expect(build).toThrow(ValidationError);
      expect(build).toThrow(/BadValidationParams/);
    });
  });

  describe("with an execution binding", () => {
    const PAYLOAD_HASH = keccak256("0xdeadbeef");
    const BINDING = { executionTarget: TARGET, payloadHash: PAYLOAD_HASH };
    const boundTx = () =>
      wethTx().setValidationCommitment(COMMITMENT).setExecutionBinding(BINDING);
    const boundExecute: CatExecuteOptions = {
      ...execute,
      validationProgram: PROGRAM,
      validationParams: PARAMS,
    };

    it("signs the bound fill into the execute digest and carries it in entry argument 7", () => {
      const exec = boundTx().asExecuteCall(boundExecute);
      const { args } = decodeFunctionData({
        abi: CAT_VALIDATOR_V2_ABI,
        data: exec.data,
      });
      expect(args[6]).toEqual(BINDING);

      const domain = { chainId: 1, verifyingContract: VALIDATOR };
      const boundDigest = constraintV2Digest(domain, {
        allowances: [{ token: WETH, amount: 2000000000000000000n }],
        outcomes: [
          { token: WETH, amount: 1000000000000000000n, destination: DEST },
        ],
        executor: EXECUTOR,
        nonce: 1n,
        ...BINDING,
        ...COMMITMENT,
      });
      const bound = approvedDigests(
        boundTx().asCatapultarAllowanceTransaction({
          refund: DEST,
          validator: VALIDATOR,
        }).calls,
      );
      const unbound = approvedDigests(
        wethTx()
          .setValidationCommitment(COMMITMENT)
          .asCatapultarAllowanceTransaction({
            refund: DEST,
            validator: VALIDATOR,
          }).calls,
      );
      // The binding moves the execute digest only; the refund keeps its own.
      expect(bound[0]).toBe(boundDigest);
      expect(bound[0]).not.toBe(unbound[0]);
      expect(bound[1]).toBe(unbound[1]!);

      // A bound bundle predicts another account than the unbound one.
      const account = (tx: ConstrainedAssetTransaction) =>
        tx
          .asCatapultarAllowanceTransaction({ validator: VALIDATOR })
          .asAccount({
            salt: zeroHash,
            owner: { type: "ecdsa", address: EXECUTOR },
          }).address;
      expect(account(boundTx())).not.toBe(
        account(wethTx().setValidationCommitment(COMMITMENT)),
      );
    });

    it("builds the pinned execute-binding digest from the protocol vector's inputs", () => {
      // The same vector `protocol.spec.ts` pins (computed with `cast`), built
      // through the builder: the signed digest is the one LibExecutionConstraintV2
      // derives for a bound fill.
      const tx = new ConstrainedAssetTransaction({
        executor: "0x00000000000000000000000000000000ca7A0003",
        chainId: 1,
      })
        .addAllowances({ token: WETH, amount: 2000000000000000000n })
        .addOutcomes(
          { token: WETH, amount: 1000000000000000000n, destination: DEST },
          {
            token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            amount: 1000000000n,
            destination: DEST,
          },
        )
        .setValidationCommitment({
          validationProgramHash:
            "0xd71a5feb2589caa974cee8d91b3420319fed8975bf2c5cccdf3a42ce10eb3c55",
          paramsHash:
            "0x6f119f4892c1928b59c0cb3f60046c7bfcac7b23db280b459b933bcbc9ac35fc",
        })
        .setExecutionBinding({
          executionTarget: "0x00000000000000000000000000000000cA7A0004",
          payloadHash:
            "0x688f92a80f1a4c0690dac4a85bb16969910bc88f22069813029559887ef6d35d",
        });
      expect(
        approvedDigests(
          tx.asCatapultarAllowanceTransaction({
            validator: "0x00000000000000000000000000000000ca7A0002",
          }).calls,
        ),
      ).toEqual([
        "0xc84818432fd77464920c4aadd93a16fecb9c1fd00daa83ee6500e271a8e5d047",
      ]);
    });

    it("throws before building on a target or payload that is not the bound fill", () => {
      const wrongTarget = () =>
        boundTx().asExecuteCall({ ...boundExecute, executionTarget: DEST });
      expect(wrongTarget).toThrow(ValidationError);
      expect(wrongTarget).toThrow(/TargetNotCommitted/);
      const wrongPayload = () =>
        boundTx().asExecuteCall({
          ...boundExecute,
          executionPayload: "0xdeadbeef00",
        });
      expect(wrongPayload).toThrow(ValidationError);
      expect(wrongPayload).toThrow(/PayloadNotCommitted/);
      // Address and hash casing do not count as a mismatch.
      expect(() =>
        boundTx().asExecuteCall({
          ...boundExecute,
          executionTarget: TARGET.toLowerCase() as Hex,
        }),
      ).not.toThrow();
      expect(() =>
        wethTx()
          .setValidationCommitment(COMMITMENT)
          .setExecutionBinding({
            ...BINDING,
            payloadHash: PAYLOAD_HASH.toUpperCase().replace("0X", "0x") as Hex,
          })
          .asExecuteCall(boundExecute),
      ).not.toThrow();
    });

    it("refuses half a binding, through the setter and the public field", () => {
      expect(() =>
        boundTx().setExecutionBinding({
          ...BINDING,
          executionTarget: zeroAddress,
        }),
      ).toThrow(ValidationError);
      expect(() =>
        boundTx().setExecutionBinding({ ...BINDING, payloadHash: zeroHash }),
      ).toThrow(ValidationError);
      const tx = wethTx().setValidationCommitment(COMMITMENT);
      tx.executionBinding = { ...BINDING, payloadHash: zeroHash };
      expect(() => tx.asExecuteCall(boundExecute)).toThrow(ValidationError);
      expect(() =>
        tx.asCatapultarAllowanceTransaction({ validator: VALIDATOR }),
      ).toThrow(ValidationError);
    });

    it("refuses a binding without a validation commitment on every flow", () => {
      const v1 = wethTx().setExecutionBinding(BINDING);
      const message = /requires a validation commitment/;
      expect(() => v1.asExecuteCall(execute)).toThrow(message);
      expect(() =>
        v1.asCatapultarAllowanceTransaction({ validator: VALIDATOR }),
      ).toThrow(message);
      expect(() =>
        v1.asRefundCall({
          address: ACCOUNT,
          refund: DEST,
          validator: VALIDATOR,
        }),
      ).toThrow(message);
      expect(() =>
        v1.asExecutionBundle({
          salt: zeroHash,
          owner: { type: "ecdsa", address: EXECUTOR },
          execute,
        }),
      ).toThrow(message);
      // The same builder is fine once it commits to v2.
      v1.setValidationCommitment(COMMITMENT);
      expect(() => v1.asExecuteCall(boundExecute)).not.toThrow();
      // And fails again if the commitment is dropped afterwards.
      v1.validationCommitment = undefined;
      expect(() => v1.asExecuteCall(execute)).toThrow(message);
    });

    it("leaves the refund call untouched by the execute binding", () => {
      const refund = boundTx().asRefundCall({
        address: ACCOUNT,
        refund: DEST,
        validator: VALIDATOR,
      });
      const { args } = decodeFunctionData({
        abi: CAT_VALIDATOR_V2_ABI,
        data: refund.data,
      });
      expect(args[0]).toBe(DEST);
      expect(args[6]).toEqual(refundBinding(DEST));
    });
  });

  // End-to-end against a CATValidatorV2 deployed from the forge artifact. The
  // VirtualMachine is a stub whose code the tests swap: `STOP` accepts every
  // program, `REVERT(0, 0)` rejects every program. An empty program never
  // reaches it.
  describe("integration", () => {
    const artifactPath = join(
      import.meta.dir,
      "../../../solidity/out/CATValidatorV2.sol/CATValidatorV2.json",
    );
    const hasArtifact = existsSync(artifactPath);

    const VM_ACCEPT: Hex = "0x00";
    const VM_REJECT: Hex = "0x60006000fd";
    const virtualMachine = random(20);

    const publicClient = createPublicClient({
      chain: anvil,
      transport: http(rpcUrl()),
    });
    const testClient = createTestClient({
      chain: anvil,
      mode: "anvil",
      transport: http(rpcUrl()),
    });
    // Anvil's default account 1, so this file never races account 0's nonces.
    const wallet = privateKeyToAccount(
      "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    );
    const executor = createWalletClient({
      account: wallet,
      chain: anvil,
      transport: http(rpcUrl()),
    });

    let validator: Hex;

    async function send(call: { to: Hex; data: Hex; value?: bigint }) {
      const hash = await executor.sendTransaction(call);
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      expect(receipt.status).toBe("success");
    }

    async function balanceOf(token: Hex, owner: Hex) {
      return publicClient.readContract({
        address: token,
        abi: MOCKERC20_abi,
        functionName: "balanceOf",
        args: [owner],
      });
    }

    /**
     * Deploy an account through the factory embedding a funded v2 constraint
     * (token1 in, token2 out) and build its entry call with `program`/`params`.
     * `funding` is the token1 balance minted to the account (default: the
     * signed allowance); `bound` signs the entry call's target and payload
     * into the execute constraint.
     */
    async function deployFundedAccount(
      recipient: Hex,
      validation: {
        program: ValidationCommand[];
        params: Hex[];
      },
      opt: { funding?: bigint; bound?: boolean } = {},
    ) {
      const amount1 = 10n ** 18n;
      const amount2 = 10n ** 6n;
      const { funding = amount1, bound = false } = opt;
      // The executor delivers the outcome to the validator, which forwards it.
      const executionTarget = token2;
      const executionPayload = encodeFunctionData({
        abi: MOCKERC20_abi,
        functionName: "mint",
        args: [validator, amount2],
      });
      const catx = new ConstrainedAssetTransaction({
        executor: wallet.address,
        chainId: anvil.id,
      })
        .addAllowances({ token: token1, amount: amount1 })
        .addOutcomes({ token: token2, amount: amount2, destination: recipient })
        .setValidationCommitment({
          validationProgramHash: hashValidationProgram(validation.program),
          paramsHash: hashValidationParams(validation.params),
        });
      if (bound)
        catx.setExecutionBinding({
          executionTarget,
          payloadHash: keccak256(executionPayload),
        });
      const account = catx
        .asCatapultarAllowanceTransaction({ refund: recipient, validator })
        .asAccount({
          salt: random(32),
          owner: { type: "ecdsa", address: recipient },
        });
      await send({
        to: token1,
        data: encodeFunctionData({
          abi: MOCKERC20_abi,
          functionName: "mint",
          args: [account.address, funding],
        }),
      });
      await send(account.deployCall);
      await send(account.actionCall);
      const executeCall = catx.asExecuteCall({
        address: account.address,
        executionTarget,
        executionPayload,
        spends: [amount1],
        validator,
        validationProgram: validation.program,
        validationParams: validation.params,
      });
      return { catx, account, executeCall, amount1, amount2 };
    }

    /** The 10 decoded arguments of a v2 entry call. */
    function entryArgs(call: { data: Hex }) {
      const decoded = decodeFunctionData({
        abi: CAT_VALIDATOR_V2_ABI,
        data: call.data,
      });
      if (decoded.args?.length !== 10)
        throw new Error("expected the 10-argument entry");
      return decoded.args;
    }

    beforeAll(async () => {
      if (!hasArtifact) return;
      const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
      await testClient.setCode({
        address: virtualMachine,
        bytecode: VM_ACCEPT,
      });
      const hash = await executor.deployContract({
        abi: CAT_VALIDATOR_V2_ABI,
        bytecode: artifact.bytecode.object,
        args: [virtualMachine],
      });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      validator = getAddress(receipt.contractAddress!);
    });

    it.skipIf(!hasArtifact)(
      "the SDK domain equals the deployed validator's domain",
      async () => {
        const [, name, version, chainId, verifyingContract] =
          await publicClient.readContract({
            address: validator,
            abi: CAT_VALIDATOR_V2_ABI,
            functionName: "eip712Domain",
          });
        expect({
          name,
          version,
          chainId: Number(chainId),
          verifyingContract,
        }).toEqual(
          constraintV2Domain({
            chainId: anvil.id,
            verifyingContract: validator,
          }),
        );
      },
    );

    it.skipIf(!hasArtifact)(
      "the deployed validator reads back its VirtualMachine",
      async () => {
        expect(
          await publicClient.readContract({
            address: validator,
            abi: CAT_VALIDATOR_V2_ABI,
            functionName: "VIRTUAL_MACHINE",
          }),
        ).toBe(getAddress(virtualMachine));
      },
    );

    it.skipIf(!hasArtifact)(
      "settles an empty-program constraint through entry without the VirtualMachine",
      async () => {
        const recipient = random(20);
        const { account, executeCall, amount1, amount2 } =
          await deployFundedAccount(recipient, { program: [], params: [] });
        // A rejecting VM proves the empty program never reaches it.
        await testClient.setCode({
          address: virtualMachine,
          bytecode: VM_REJECT,
        });
        try {
          await send(executeCall);
        } finally {
          await testClient.setCode({
            address: virtualMachine,
            bytecode: VM_ACCEPT,
          });
        }
        expect(await balanceOf(token2, recipient)).toBe(amount2);
        expect(await balanceOf(token2, validator)).toBe(0n);
        expect(await balanceOf(token1, account.address)).toBe(0n);
        expect(await balanceOf(token1, token2)).toBeGreaterThanOrEqual(amount1);
      },
    );

    it.skipIf(!hasArtifact)(
      "reverts BadValidationParams on params without a program",
      async () => {
        const recipient = random(20);
        const { account, executeCall, amount1 } = await deployFundedAccount(
          recipient,
          { program: [], params: [] },
        );
        const [target, payload, address, nonce, spends, outcomes, binding] =
          entryArgs(executeCall);
        // An empty program commits a zero params hash, so the params check
        // runs before the signature check.
        await expect(
          publicClient.simulateContract({
            account: wallet.address,
            address: validator,
            abi: CAT_VALIDATOR_V2_ABI,
            functionName: "entry",
            args: [
              target,
              payload,
              address,
              nonce,
              spends,
              outcomes,
              binding,
              [],
              [PARAMS[0]!],
              "0x",
            ],
          }),
        ).rejects.toThrow(/BadValidationParams/);
        expect(await balanceOf(token1, account.address)).toBe(amount1);
      },
    );

    it.skipIf(!hasArtifact)(
      "reverts V1EntryDisabled on the inherited 7-argument entry",
      async () => {
        // viem resolves `entry` to the 10-argument overload of the v2 ABI, so
        // encode through the v1 entry and decode with the v2 errors.
        const v2Errors = CAT_VALIDATOR_V2_ABI.filter(
          (i): i is Extract<typeof i, { type: "error" }> => i.type === "error",
        );
        await expect(
          publicClient.simulateContract({
            account: wallet.address,
            address: validator,
            abi: [...CAT_VALIDATOR_ABI, ...v2Errors],
            functionName: "entry",
            args: [validator, "0x", wallet.address, 1n, [], [], "0x"],
          }),
        ).rejects.toThrow(/V1EntryDisabled/);
      },
    );

    it.skipIf(!hasArtifact)(
      "executes a committed program and delivers the outcome",
      async () => {
        const recipient = random(20);
        const { executeCall, amount1, amount2 } = await deployFundedAccount(
          recipient,
          {
            program: PROGRAM,
            params: PARAMS,
          },
        );
        await send(executeCall);
        expect(await balanceOf(token1, token2)).toBeGreaterThanOrEqual(amount1);
        expect(await balanceOf(token2, recipient)).toBe(amount2);
      },
    );

    it.skipIf(!hasArtifact)(
      "refunds straight to the bound refund address when the program rejects",
      async () => {
        const recipient = random(20);
        const { catx, account, executeCall, amount1 } =
          await deployFundedAccount(recipient, {
            program: PROGRAM,
            params: PARAMS,
          });

        await testClient.setCode({
          address: virtualMachine,
          bytecode: VM_REJECT,
        });
        try {
          await expect(
            publicClient.simulateContract({
              account: wallet.address,
              address: validator,
              abi: CAT_VALIDATOR_V2_ABI,
              functionName: "entry",
              args: entryArgs(executeCall),
            }),
          ).rejects.toThrow(/ValidationFailed/);

          // The refund is bound to `recipient`: redirecting the sweep reverts
          // before any allowance moves.
          const refundCall = catx.asRefundCall({
            address: account.address,
            refund: recipient,
            validator,
          });
          const [, ...afterTarget] = entryArgs(refundCall);
          await expect(
            publicClient.simulateContract({
              account: wallet.address,
              address: validator,
              abi: CAT_VALIDATOR_V2_ABI,
              functionName: "entry",
              args: [wallet.address, ...afterTarget],
            }),
          ).rejects.toThrow(/TargetNotCommitted/);
          expect(await balanceOf(token1, account.address)).toBe(amount1);

          await send(refundCall);
        } finally {
          await testClient.setCode({
            address: virtualMachine,
            bytecode: VM_ACCEPT,
          });
        }
        expect(await balanceOf(token1, recipient)).toBe(amount1);
        expect(await balanceOf(token1, account.address)).toBe(0n);
      },
    );

    it.skipIf(!hasArtifact)(
      "sweeps an account holding less than the signed allowance to the refund address",
      async () => {
        const recipient = random(20);
        // Half the signed allowance of 1e18.
        const funding = 5n * 10n ** 17n;
        const { catx, account, amount1 } = await deployFundedAccount(
          recipient,
          { program: [], params: [] },
          { funding },
        );
        expect(funding).toBeLessThan(amount1);
        await send(
          catx.asRefundCall({
            address: account.address,
            refund: recipient,
            validator,
          }),
        );
        expect(await balanceOf(token1, recipient)).toBe(funding);
        expect(await balanceOf(token1, account.address)).toBe(0n);
      },
    );

    it.skipIf(!hasArtifact)(
      "sweeps an account holding more than the signed allowance in full",
      async () => {
        const recipient = random(20);
        // Three times the signed allowance of 1e18.
        const funding = 3n * 10n ** 18n;
        const { catx, account, amount1 } = await deployFundedAccount(
          recipient,
          { program: [], params: [] },
          { funding },
        );
        expect(funding).toBeGreaterThan(amount1);
        await send(
          catx.asRefundCall({
            address: account.address,
            refund: recipient,
            validator,
          }),
        );
        expect(await balanceOf(token1, recipient)).toBe(funding);
        expect(await balanceOf(token1, account.address)).toBe(0n);
      },
    );

    it.skipIf(!hasArtifact)(
      "settles a bound fill and rejects any other target or payload",
      async () => {
        const recipient = random(20);
        const { account, executeCall, amount1, amount2 } =
          await deployFundedAccount(
            recipient,
            { program: PROGRAM, params: PARAMS },
            { bound: true },
          );
        const [target, payload, ...rest] = entryArgs(executeCall);
        // The binding is checked before the signature and any allowance move.
        await expect(
          publicClient.simulateContract({
            account: wallet.address,
            address: validator,
            abi: CAT_VALIDATOR_V2_ABI,
            functionName: "entry",
            args: [wallet.address, payload, ...rest],
          }),
        ).rejects.toThrow(/TargetNotCommitted/);
        await expect(
          publicClient.simulateContract({
            account: wallet.address,
            address: validator,
            abi: CAT_VALIDATOR_V2_ABI,
            functionName: "entry",
            args: [target, `${payload}00`, ...rest],
          }),
        ).rejects.toThrow(/PayloadNotCommitted/);
        expect(await balanceOf(token1, account.address)).toBe(amount1);

        // The bound call settles: the account approved the SDK's bound digest,
        // and the validator accepted it, so the two derivations agree.
        await send(executeCall);
        expect(await balanceOf(token2, recipient)).toBe(amount2);
        expect(await balanceOf(token1, account.address)).toBe(0n);
      },
    );

    it.skipIf(!hasArtifact)(
      "the refund leaves no balance on the validator",
      async () => {
        expect(await balanceOf(token1, validator)).toBe(0n);
        expect(await balanceOf(token2, validator)).toBe(0n);
      },
    );
  });
});
