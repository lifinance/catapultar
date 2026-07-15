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
import { PUBLIC_DEFAULT_ANVIL_ACCOUNT_0 } from "../../test/fixtures";
import { rpcUrl } from "../../test/setup";

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

// Deployment bytecode compiled from solidity/test/mocks/DirtyStateTarget.sol.
const dirtyStateTargetBytecode =
  "0x6080806040523460155761024a908161001a8239f35b5f80fdfe60806040526004361015610011575f80fd5b5f3560e01c80635270e9ca146101e757806362548c7b1461018d578063890eba681461014e5780638ace1a91146101135763a03df8a214610050575f80fd5b3461010f5760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261010f5760043560ff5f54166100e7576040515f91906020810190835b8385106100d4577f86954ecc0ae072157fcf7f87a425a1461295a4cc9cc3122d2efc73bf32d98e1a6020600180540180600155604051908152a1005b8152838252600160408220940193610098565b7f25e345dc000000000000000000000000000000000000000000000000000000005f5260045ffd5b5f80fd5b3461010f575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261010f576020600154604051908152f35b3461010f575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261010f57602060ff5f54166040519015158152f35b3461010f575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261010f575f80547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00166001179055005b3461010f575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261010f577fefece901000000000000000000000000000000000000000000000000000000005f5260045ffdfea164736f6c6343000823000a" as const;

// Deployment bytecode compiled from solidity/test/mocks/GasEstimateTarget.sol.
const gasEstimateTargetBytecode =
  "0x6080806040523460155761016f908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c9081637560fdd1146101035750806388f14b431461007b57639ebaf26b1461003d575f80fd5b34610077575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126100775760205f54604051908152f35b5f80fd5b346100775760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc360112610077576004355f90604051905f91602081015b8284106100ed57847ff839e66c000000000000000000000000000000000000000000000000000000005f5260045260245ffd5b93815282845260408120936001909301926100ba565b34610077575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126100775760207fe2c7262c072f15668b0bb466afb96109550708a188a8a0845c275c2fba34bc169160015f5401805f558152a100fea164736f6c6343000823000a" as const;

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

  async function deployCatapultar(ownerAccount: PrivateKeyAccount) {
    const owner: Owner = { type: "ecdsa", address: ownerAccount.address };
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
      const account = await deployCatapultar(ownerAccount);
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
      const account = await deployCatapultar(ownerAccount);
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

      // Broadcast at the estimate plus a tight signed-path margin — NOT a 2x
      // buffer — so a partially-underestimating regression starves group2 and
      // fails the finishedCalls assertion below. The margin is proportional,
      // not constant: the code-override estimate runs without the clone's
      // delegatecall frames, and each extra real frame retains 1/64 of gas
      // (EIP-150), so the signed broadcast needs ~5% more at this scale; 10%
      // + 50k absorbs that plus signature validation and the extra opData
      // calldata while still failing on any >=~5% underestimation.
      const withSignedPathMargin = (estimate * 110n) / 100n + 50_000n;
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
});
