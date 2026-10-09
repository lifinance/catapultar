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

    it("entry has the 9-argument v2 selector", () => {
      const entry = entries.find(
        (i) => i.type === "function" && i.inputs.length === 9,
      )!;
      expect(toFunctionSelector(entry)).toBe(
        toFunctionSelector(
          "entry(address,bytes,address,uint256,(address,uint256,uint256)[],(address,uint256,address)[],(uint8,bytes32)[],bytes32[],bytes)",
        ),
      );
      expect(toFunctionSelector(entry)).toBe("0x62551d8f");
    });

    it("keeps the inherited 7-argument entry, which shares v1's selector", () => {
      expect(entries.map((i) => toFunctionSelector(i)).sort()).toEqual([
        "0x62551d8f",
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
        "Reentrancy",
        "TStoreAlreadyActivated",
        "TStoreNotSupported",
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

    it("encodes the 9-argument v2 entry, which decodes back to the inputs", () => {
      const exec = v2Tx().asExecuteCall({
        ...execute,
        validationProgram: PROGRAM,
        validationParams: PARAMS,
      });
      expect(exec.to).toBe(VALIDATOR);
      expect(exec.value).toBe(0n);
      expect(exec.data.slice(0, 10)).toBe("0x62551d8f");
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
        [],
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
      expect(args.slice(6)).toEqual([[], [], "0x"]);
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
     */
    async function deployFundedAccount(
      recipient: Hex,
      validation: {
        program: ValidationCommand[];
        params: Hex[];
      },
    ) {
      const amount1 = 10n ** 18n;
      const amount2 = 10n ** 6n;
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
        validationProgram: validation.program,
        validationParams: validation.params,
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
        const decoded = decodeFunctionData({
          abi: CAT_VALIDATOR_V2_ABI,
          data: executeCall.data,
        });
        if (decoded.args?.length !== 9)
          throw new Error("expected the 9-argument entry");
        const [target, payload, address, nonce, spends, outcomes] =
          decoded.args;
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
        // viem resolves `entry` to the 9-argument overload of the v2 ABI, so
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
      "refunds through the validator when the program rejects",
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
          const decoded = decodeFunctionData({
            abi: CAT_VALIDATOR_V2_ABI,
            data: executeCall.data,
          });
          if (decoded.args?.length !== 9)
            throw new Error("expected the 9-argument entry");
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
