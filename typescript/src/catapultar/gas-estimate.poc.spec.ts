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
});
