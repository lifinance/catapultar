import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  createPublicClient,
  createTestClient,
  createWalletClient,
  keccak256,
  decodeFunctionData,
  encodeFunctionData,
  getAddress,
  http,
  toFunctionSelector,
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
} from "../protocol/constraint";
import { ValidationError } from "../errors";

const WETH: Hex = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
const DEST: Hex = "0x1111111111111111111111111111111111111111";
const EXECUTOR: Hex = "0x2222222222222222222222222222222222222222";
const VALIDATOR: Hex = "0x3333333333333333333333333333333333333333";
const ACCOUNT: Hex = "0x4444444444444444444444444444444444444444";
const TARGET: Hex = "0x5555555555555555555555555555555555555555";

// Two 33-byte commands (op ++ bytes32) and two 32-byte param words.
const PROGRAM: Hex = `0x01${"aa".repeat(32)}02${"bb".repeat(32)}`;
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
    it("entry has the 11-argument v2 selector", () => {
      const entry = CAT_VALIDATOR_V2_ABI.find(
        (i) => i.type === "function" && i.name === "entry",
      )!;
      expect(toFunctionSelector(entry)).toBe(
        toFunctionSelector(
          "entry(address,bytes,address,uint256,(address,uint256,uint256)[],(address,uint256,address)[],bytes32,bytes32,bytes,bytes[],bytes)",
        ),
      );
      expect(toFunctionSelector(entry)).toBe("0xc461d6f0");
    });

    it("carries every CATValidatorV2 error and the receive hook", () => {
      const errors = CAT_VALIDATOR_V2_ABI.filter((i) => i.type === "error")
        .map((i) => i.name)
        .sort();
      expect(errors).toEqual([
        "AllocationTooSmall",
        "BadSignature",
        "BadValidationParams",
        "BadValidationProgram",
        "BalanceOfFailed",
        "InvalidTokenAmount",
        "InvalidValidationGasCap",
        "InvalidVirtualMachine",
        "NonceAlreadySpent",
        "Reentrancy",
        "ValidationFailed",
      ]);
      expect(CAT_VALIDATOR_V2_ABI.some((i) => i.type === "receive")).toBe(true);
    });

    // Guards the hand-maintained ABI against drifting from the contract.
    // Requires `forge build` output in solidity/out; skipped when absent, like
    // the embedded bytecode spec.
    const artifactPath = join(
      import.meta.dir,
      "../../../solidity/out/CATValidatorV2.sol/CATValidatorV2.json",
    );
    test.skipIf(!existsSync(artifactPath))("matches the forge artifact", () => {
      const key = (i: { type: string; name?: string }) =>
        `${i.type}:${i.name ?? ""}`;
      const sorted = (abi: readonly { type: string; name?: string }[]) =>
        [...abi].sort((a, b) => key(a).localeCompare(key(b)));
      const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
      expect(sorted(CAT_VALIDATOR_V2_ABI)).toEqual(sorted(artifact.abi));
    });
  });

  describe("without a validation commitment", () => {
    // Computed on upstream main before CATValidatorV2 support; any drift means
    // the v1 path is no longer byte-identical.
    const V1_EXECUTE_CALLDATA =
      "0xe5ce4787000000000000000000000000555555555555555555555555555555555555555500000000000000000000000000000000000000000000000000000000000000e000000000000000000000000044444444444444444444444444444444444444440000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000000000000004deadbeef000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000001bc16d674ec800000000000000000000000000000000000000000000000000001bc16d674ec800000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000";
    // keccak256 of the refund entry call and of the embedded approval batch
    // (with refund), on the same inputs.
    const V1_REFUND_CALLDATA_HASH =
      "0x3e933709b53ac6af1eb3defb5518a674ea58f40192a682bd15a12b442487fda9";
    const V1_ACTION_DATA_HASH =
      "0x622bc9137422d3d9797c15769084b8ca6edb7b179a62c5eec7b8a3eb45ec4ad6";

    it("encodes the v1 entry byte-identically", () => {
      const exec = wethTx().asExecuteCall(execute);
      expect(exec.data).toBe(V1_EXECUTE_CALLDATA);
      expect(
        decodeFunctionData({ abi: CAT_VALIDATOR_ABI, data: exec.data }).args,
      ).toHaveLength(7);
    });

    it("embeds and refunds byte-identically", () => {
      const tx = wethTx().asCatapultarAllowanceTransaction({
        refund: DEST,
        validator: VALIDATOR,
      });
      const { actionCall } = tx.asAccount({
        salt: zeroHash,
        owner: { type: "ecdsa", address: EXECUTOR },
      });
      expect(keccak256(actionCall.data)).toBe(V1_ACTION_DATA_HASH);
      const refund = wethTx().asRefundCall({
        address: ACCOUNT,
        refund: DEST,
        validator: VALIDATOR,
      });
      expect(refund.to).toBe(VALIDATOR);
      expect(keccak256(refund.data)).toBe(V1_REFUND_CALLDATA_HASH);
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

    it("encodes the 11-argument v2 entry", () => {
      const exec = v2Tx().asExecuteCall({
        ...execute,
        validationProgram: PROGRAM,
        validationParams: PARAMS,
      });
      expect(exec.to).toBe(VALIDATOR);
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
        COMMITMENT.validationProgramHash,
        COMMITMENT.paramsHash,
        PROGRAM,
        PARAMS,
        "0x",
      ]);
    });

    it("embeds the v2 digest, and a zero-commitment v2 refund digest", () => {
      const tx = v2Tx().asCatapultarAllowanceTransaction({
        refund: DEST,
        validator: VALIDATOR,
      });
      const domain = { chainId: 1, verifyingContract: VALIDATOR };
      const constraint = {
        allowances: [{ token: WETH, amount: 2000000000000000000n }],
        executor: EXECUTOR,
        nonce: 1n,
      };
      expect(approvedDigests(tx.calls)).toEqual([
        constraintV2Digest(domain, {
          ...constraint,
          outcomes: [
            { token: WETH, amount: 1000000000000000000n, destination: DEST },
          ],
          ...COMMITMENT,
        }),
        constraintV2Digest(domain, {
          ...constraint,
          outcomes: [
            { token: WETH, amount: 2000000000000000000n, destination: DEST },
          ],
          validationProgramHash: zeroHash,
          paramsHash: zeroHash,
        }),
      ]);
    });

    it("refunds through the validator with a zero commitment", () => {
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
        zeroHash,
        zeroHash,
        "0x",
        [],
        "0x",
      ]);
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
      expect(args.slice(6)).toEqual([zeroHash, zeroHash, "0x", [], "0x"]);
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
        validationProgram?: Hex;
        validationParams?: Hex[];
        message: RegExp;
      }[] = [
        { validationParams: PARAMS, message: /validationProgram/ },
        { validationProgram: PROGRAM, message: /validationParams/ },
        {
          validationProgram: `0x03${"cc".repeat(32)}`,
          validationParams: PARAMS,
          message: /validationProgram/,
        },
        {
          validationProgram: `${PROGRAM}00`,
          validationParams: PARAMS,
          message: /33-byte/,
        },
        {
          validationProgram: PROGRAM,
          validationParams: [PARAMS[0]!],
          message: /validationParams/,
        },
      ];
      for (const { message, ...inputs } of cases) {
        expect(() => v2Tx().asExecuteCall({ ...execute, ...inputs })).toThrow(
          message,
        );
      }
    });
  });

  // End-to-end against a CATValidatorV2 deployed from the forge artifact. The
  // VirtualMachine is a stub whose code the tests swap: `STOP` accepts every
  // program, `REVERT(0, 0)` rejects every program.
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

    /** Deploy an account embedding a funded v2 constraint (token1 in, token2 out). */
    async function deployFundedAccount(recipient: Hex) {
      const amount1 = 10n ** 18n;
      const amount2 = 10n ** 6n;
      const catx = new ConstrainedAssetTransaction({
        executor: wallet.address,
        chainId: anvil.id,
      })
        .addAllowances({ token: token1, amount: amount1 })
        .addOutcomes({ token: token2, amount: amount2, destination: recipient })
        .setValidationCommitment(COMMITMENT);
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
          args: [account.address, amount1],
        }),
      });
      await send(account.deployCall);
      await send(account.actionCall);
      // The executor delivers the outcome to the validator, which forwards it.
      const executeCall = catx.asExecuteCall({
        address: account.address,
        executionTarget: token2,
        executionPayload: encodeFunctionData({
          abi: MOCKERC20_abi,
          functionName: "mint",
          args: [validator, amount2],
        }),
        spends: [amount1],
        validator,
        validationProgram: PROGRAM,
        validationParams: PARAMS,
      });
      return { catx, account, executeCall, amount1, amount2 };
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
        args: [virtualMachine, 1_000_000n],
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
      "executes a committed program and delivers the outcome",
      async () => {
        const recipient = random(20);
        const { executeCall, amount1, amount2 } =
          await deployFundedAccount(recipient);
        await send(executeCall);
        expect(await balanceOf(token1, token2)).toBeGreaterThanOrEqual(amount1);
        expect(await balanceOf(token2, recipient)).toBe(amount2);
      },
    );

    it.skipIf(!hasArtifact)(
      "refunds through the validator when the program rejects",
      async () => {
        const recipient = random(20);
        const { catx, account, executeCall, amount1 } =
          await deployFundedAccount(recipient);

        await testClient.setCode({
          address: virtualMachine,
          bytecode: VM_REJECT,
        });
        try {
          const decoded = decodeFunctionData({
            abi: CAT_VALIDATOR_V2_ABI,
            data: executeCall.data,
          });
          if (decoded.functionName !== "entry")
            throw new Error("expected an entry call");
          await expect(
            publicClient.simulateContract({
              account: wallet.address,
              address: validator,
              abi: CAT_VALIDATOR_V2_ABI,
              functionName: "entry",
              args: decoded.args,
            }),
          ).rejects.toThrow(/ValidationFailed/);

          await send(
            catx.asRefundCall({
              address: account.address,
              refund: recipient,
              validator,
            }),
          );
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
      "the refund leaves no balance on the validator",
      async () => {
        expect(await balanceOf(token1, validator)).toBe(0n);
        expect(await balanceOf(token2, validator)).toBe(0n);
      },
    );
  });
});
