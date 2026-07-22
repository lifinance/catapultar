import {
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  http,
  parseEventLogs,
  type Hex,
  type TransactionReceipt,
} from "viem";
import { privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";
import { anvil } from "viem/chains";
import CATAPULTAR_ABI from "../abi/catapultar";
import { defaultFactory } from "../config";
import { ExecutionMode, type Call, type Owner } from "../types/types";
import { asHex, random } from "../utils/helpers";
import { CatapultarAccount } from "./account";
import { MetaCatapultarTx } from "./catapultar";
import { ESTIMATE_GAS_MARGIN_PERCENT, applyEstimateGasMargin } from "./gas";
import { PUBLIC_DEFAULT_ANVIL_ACCOUNT_0 } from "../../test/fixtures";
import { makeOwnerSigner } from "../../test/signers";
import { rpcUrl } from "../../test/setup";
import {
  dirtyStateTargetBytecode,
  gasEstimateTargetBytecode,
} from "../../test/mock-bytecode";

const chainId = 31337;
const anvilAccountVersion = "0.1.0";
const expensiveRounds = 100_000n;
const highGasLimit = 15_000_000n;
const expensiveFailureSelector = "0xf839e66c";

const gasEstimateTargetAbi = [
  {
    type: "function",
    name: "expensiveThenRevert",
    stateMutability: "pure",
    inputs: [{ name: "rounds", type: "uint256" }],
    outputs: [],
  },
  {
    type: "function",
    name: "healthy",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    type: "function",
    name: "healthyCalls",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "event",
    name: "Healthy",
    inputs: [{ name: "calls", type: "uint256", indexed: false }],
    anonymous: false,
  },
] as const;

const intentAlreadyFilledSelector = "0xefece901";

const dirtyStateTargetAbi = [
  {
    type: "function",
    name: "setFlag",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    type: "function",
    name: "revertWithData",
    stateMutability: "pure",
    inputs: [],
    outputs: [],
  },
  {
    type: "function",
    name: "expensiveIfFlagUnset",
    stateMutability: "nonpayable",
    inputs: [{ name: "rounds", type: "uint256" }],
    outputs: [],
  },
  {
    type: "function",
    name: "flag",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "finishedCalls",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
] as const;

describe("Catapultar gas estimation PoC", () => {
  const publicClient = createPublicClient({
    chain: anvil,
    transport: http(rpcUrl()),
  });
  const relayer = privateKeyToAccount(PUBLIC_DEFAULT_ANVIL_ACCOUNT_0);
  const walletClient = createWalletClient({
    account: relayer,
    chain: anvil,
    transport: http(rpcUrl()),
  });

  async function waitForTransaction(hash: Hex): Promise<TransactionReceipt> {
    return publicClient.waitForTransactionReceipt({ hash });
  }

  async function deployGasTarget() {
    const hash = await walletClient.deployContract({
      abi: gasEstimateTargetAbi,
      bytecode: gasEstimateTargetBytecode,
    });
    const receipt = await waitForTransaction(hash);
    if (!receipt.contractAddress) throw new Error("target deployment failed");
    return receipt.contractAddress;
  }

  async function deployCatapultar(owner: Owner) {
    const deployCall = CatapultarAccount.deploy({
      owner,
      salt: `0x${asHex(0n, 20)}${random(12).replace("0x", "")}`,
      factory: defaultFactory,
      version: anvilAccountVersion,
    });
    await waitForTransaction(
      await walletClient.sendTransaction({ ...deployCall.call }),
    );
    return deployCall.account.connectRpc({ chainId, rpc: rpcUrl() });
  }

  async function signedSkipBatchCall(options: {
    account: CatapultarAccount<Owner, true>;
    ownerAccount: PrivateKeyAccount;
    target: `0x${string}`;
    nonceBase: bigint;
  }): Promise<Call> {
    const expensiveCall: Call = {
      to: options.target,
      value: 0n,
      data: encodeFunctionData({
        abi: gasEstimateTargetAbi,
        functionName: "expensiveThenRevert",
        args: [expensiveRounds],
      }),
    };
    const healthyCall: Call = {
      to: options.target,
      value: 0n,
      data: encodeFunctionData({
        abi: gasEstimateTargetAbi,
        functionName: "healthy",
      }),
    };

    const metaTx = new MetaCatapultarTx({
      account: options.account,
      outerNonce: options.nonceBase,
      innerNonce: options.nonceBase + 1n,
    });
    const signedTx = await (
      await metaTx
        .setMode(ExecutionMode.SkipRevert)
        .addCalls(
          { calls: [expensiveCall], mode: ExecutionMode.RaiseRevert },
          { calls: [healthyCall], mode: ExecutionMode.RaiseRevert },
        )
        .asCatapultarTx()
    ).sign((data) => options.ownerAccount.signTypedData(data));

    return signedTx.asCall();
  }

  function callRevertData(receipt: TransactionReceipt) {
    return parseEventLogs({
      abi: CATAPULTAR_ABI,
      logs: receipt.logs,
      eventName: "CallReverted",
    }).map((log) => log.args.revertData);
  }

  async function healthyCalls(target: `0x${string}`) {
    return publicClient.readContract({
      address: target,
      abi: gasEstimateTargetAbi,
      functionName: "healthyCalls",
    });
  }

  it.serial(
    "verifies Anvil can estimate the skip batch far below the high-gas failure path",
    async () => {
      const ownerAccount = privateKeyToAccount(random(32));
      const account = await deployCatapultar({
        type: "ecdsa",
        address: ownerAccount.address,
      });
      const target = await deployGasTarget();
      const nonceBase = BigInt(random(31)) << 8n;

      const estimatedCall = await signedSkipBatchCall({
        account,
        ownerAccount,
        target,
        nonceBase,
      });

      const estimate = await publicClient.estimateGas({
        account: relayer.address,
        ...estimatedCall,
      });

      const lowGasReceipt = await waitForTransaction(
        await walletClient.sendTransaction({ ...estimatedCall, gas: estimate }),
      );
      expect(lowGasReceipt.status).toBe("success");
      expect(await healthyCalls(target)).toBe(1n);
      expect(callRevertData(lowGasReceipt)).toEqual(["0x"]);

      const highGasCall = await signedSkipBatchCall({
        account,
        ownerAccount,
        target,
        nonceBase: nonceBase + 10n,
      });
      const highGasReceipt = await waitForTransaction(
        await walletClient.sendTransaction({
          ...highGasCall,
          gas: highGasLimit,
        }),
      );
      const highGasReverts = callRevertData(highGasReceipt);

      expect(highGasReceipt.status).toBe("success");
      expect(await healthyCalls(target)).toBe(2n);
      expect(highGasReceipt.gasUsed).toBeGreaterThan(estimate * 10n);
      expect(highGasReverts).toHaveLength(1);
      expect(highGasReverts[0]!.startsWith(expensiveFailureSelector)).toBe(
        true,
      );
    },
    30_000,
  );

  // Regression: the estimation twin must keep atomic (RaiseRevert) sub-batch
  // modes so their state changes roll back during estimation exactly as
  // on-chain. Group1 [setFlag, revertWithData] reverts atomically on-chain, so
  // group2's expensiveIfFlagUnset sees a CLEAN flag and runs its expensive
  // path. The old all-frames-to-EstimateGas twin kept group1's setFlag (no
  // rollback on a data-carrying skip), so group2 simulated against a DIRTY
  // flag, reverted cheaply with FlagWasSet, and the estimate never priced the
  // expensive path — a silent starve at broadcast time.
  it.serial(
    "rolls back an atomic sub-batch's state in the estimation twin so later sub-batches see clean state",
    async () => {
      const ownerAccount = privateKeyToAccount(random(32));
      const account = await deployCatapultar({
        type: "ecdsa",
        address: ownerAccount.address,
      });
      const hash = await walletClient.deployContract({
        abi: dirtyStateTargetAbi,
        bytecode: dirtyStateTargetBytecode,
      });
      const receipt = await waitForTransaction(hash);
      if (!receipt.contractAddress) throw new Error("target deployment failed");
      const target = receipt.contractAddress;
      const nonceBase = BigInt(random(31)) << 8n;

      const setFlagCall: Call = {
        to: target,
        value: 0n,
        data: encodeFunctionData({
          abi: dirtyStateTargetAbi,
          functionName: "setFlag",
        }),
      };
      const revertWithDataCall: Call = {
        to: target,
        value: 0n,
        data: encodeFunctionData({
          abi: dirtyStateTargetAbi,
          functionName: "revertWithData",
        }),
      };
      const expensiveIfFlagUnsetCall: Call = {
        to: target,
        value: 0n,
        data: encodeFunctionData({
          abi: dirtyStateTargetAbi,
          functionName: "expensiveIfFlagUnset",
          args: [expensiveRounds],
        }),
      };

      const metaTx = new MetaCatapultarTx({
        account,
        outerNonce: nonceBase,
        innerNonce: nonceBase + 1n,
      })
        .setMode(ExecutionMode.SkipRevert)
        .addCalls(
          {
            calls: [setFlagCall, revertWithDataCall],
            mode: ExecutionMode.RaiseRevert,
          },
          {
            calls: [expensiveIfFlagUnsetCall],
            mode: ExecutionMode.RaiseRevert,
          },
        );

      // Old twin: group2 reverts with FlagWasSet during estimation (dirty
      // flag) and is skipped, so the estimate converges near the batch
      // overhead. New twin: group1 rolls back, group2 runs the expensive path,
      // and an estimate below it OOGs empty and forces the estimator up.
      const estimate = await metaTx.estimateGas({ useCodeOverride: true });
      expect(estimate).toBeGreaterThan(1_000_000n);

      // Broadcast at the estimate (which already carries the proportional
      // code-override margin) plus the SDK's flat signed-path overhead — NOT
      // a 2x buffer — so a partially-underestimating regression starves
      // group2 and fails the finishedCalls assertion below (rationale lives
      // on applyCodeOverrideMargin's and applyEstimateGasMargin's JSDoc).
      const withSignedPathMargin = applyEstimateGasMargin(estimate, "ecdsa");
      const signedTx = await (
        await metaTx.asCatapultarTx()
      ).sign((data) => ownerAccount.signTypedData(data));
      const broadcastReceipt = await waitForTransaction(
        await walletClient.sendTransaction({
          ...(await signedTx.asCall()),
          gas: withSignedPathMargin,
        }),
      );

      expect(broadcastReceipt.status).toBe("success");
      // Group2 actually executed within the estimated budget (old estimate
      // starved it into a swallowed OOG skip).
      const finishedCalls = await publicClient.readContract({
        address: target,
        abi: dirtyStateTargetAbi,
        functionName: "finishedCalls",
      });
      expect(finishedCalls).toBe(1n);
      // Exactly one CallReverted: group1's genuine, data-carrying revert.
      expect(callRevertData(broadcastReceipt)).toEqual([
        intentAlreadyFilledSelector,
      ]);
      // On-chain the atomic group rolled the flag back.
      const flag = await publicClient.readContract({
        address: target,
        abi: dirtyStateTargetAbi,
        functionName: "flag",
      });
      expect(flag).toBe(false);
    },
    30_000,
  );

  // The unsigned estimate skips signature validation, and non-ECDSA owners
  // are where that omission is largest: on this anvil state P256 verification
  // runs through Solady's deployed fallback verifier (no RIP-7212 precompile),
  // the worst case the conservative SIGNED_PATH_GAS_OVERHEAD table must cover.
  for (const ownerType of ["p256", "webauthn-p256"] as const) {
    it.serial(
      `broadcasts a signed ${ownerType} batch within applyEstimateGasMargin of the unsigned estimate`,
      async () => {
        const { owner, signTypedData } = makeOwnerSigner(ownerType);
        const account = await deployCatapultar(owner);
        const target = await deployGasTarget();
        const nonceBase = BigInt(random(31)) << 8n;

        const expensiveCall: Call = {
          to: target,
          value: 0n,
          data: encodeFunctionData({
            abi: gasEstimateTargetAbi,
            functionName: "expensiveThenRevert",
            args: [expensiveRounds],
          }),
        };
        const healthyCall: Call = {
          to: target,
          value: 0n,
          data: encodeFunctionData({
            abi: gasEstimateTargetAbi,
            functionName: "healthy",
          }),
        };
        const buildMetaTx = (base: bigint) =>
          new MetaCatapultarTx({
            account,
            outerNonce: base,
            innerNonce: base + 1n,
          })
            .setMode(ExecutionMode.SkipRevert)
            .addCalls(
              { calls: [expensiveCall], mode: ExecutionMode.RaiseRevert },
              { calls: [healthyCall], mode: ExecutionMode.RaiseRevert },
            );

        const metaTx = buildMetaTx(nonceBase);
        const estimate = await metaTx.estimateGas({ useCodeOverride: true });
        expect(estimate).toBeGreaterThan(1_000_000n);

        const gasLimit = applyEstimateGasMargin(estimate, owner);
        const signedTx = await (
          await metaTx.asCatapultarTx()
        ).sign((...args) => signTypedData(...args));
        const receipt = await waitForTransaction(
          await walletClient.sendTransaction({
            ...(await signedTx.asCall()),
            gas: gasLimit,
          }),
        );

        // Semantic completion, not just tx status: the expensive call reached
        // its genuine business revert (a starved skip logs "0x" instead) and
        // the healthy group actually executed.
        expect(receipt.status).toBe("success");
        const revertData = callRevertData(receipt);
        expect(revertData).toHaveLength(1);
        expect(revertData[0]?.startsWith(expensiveFailureSelector)).toBe(true);
        expect(await healthyCalls(target)).toBe(1n);
        // Informational: the estimate is a minimum gas limit carrying unused
        // starvation headroom, so gasUsed is not a margin measurement.
        console.log(
          `${ownerType}: estimate=${estimate} gasLimit=${gasLimit} gasUsed=${receipt.gasUsed}`,
        );

        // Lower bound: the same signed batch at the raw unsigned estimate —
        // stripped of the built-in code-override margin, and with no
        // owner-type overhead — must NOT fully complete for these owners
        // (fallback P256 validation alone outweighs the estimate's slack),
        // proving the margins do real work rather than being padding.
        const rawEstimate =
          (estimate * 100n) / (100n + ESTIMATE_GAS_MARGIN_PERCENT);
        const controlTx = buildMetaTx(nonceBase + 10n);
        const controlSigned = await (
          await controlTx.asCatapultarTx()
        ).sign((...args) => signTypedData(...args));
        const controlReceipt = await waitForTransaction(
          await walletClient.sendTransaction({
            ...(await controlSigned.asCall()),
            gas: rawEstimate,
          }),
        );
        const controlRevertData = callRevertData(controlReceipt);
        const fullyCompleted =
          controlReceipt.status === "success" &&
          controlRevertData.length === 1 &&
          (controlRevertData[0]?.startsWith(expensiveFailureSelector) ?? false);
        expect(fullyCompleted).toBe(false);
      },
      60_000,
    );
  }
});
