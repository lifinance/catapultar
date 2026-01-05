import { createPublicClient, createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { anvil } from "viem/chains";
import { CatapultarAccount } from "./account";
import { random, asHex, pubkeyAsArray } from "../utils/helpers";
import { rpcUrl } from "../../test/setup";
import { AccountPublicKeyType, type Version } from "../types/types";
import { factories, templates } from "../../test/config";
import CATAPULTAR_FACTORY_V0_1_0_ABI from "../abi/catapultarFactoryV0.1.0";

const chainId = 31337;
const PUBLIC_DEFAULT_ANVIL_ACCOUNT_0 =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

async function waitForTransaction(hash: `0x${string}`) {
  await new Promise((resolve) => setTimeout(resolve, 50));
  // We need to wait for the transaction to be finalised.
  const publicClient = createPublicClient({
    chain: anvil,
    transport: http(rpcUrl()),
  });
  await publicClient.getTransactionReceipt({ hash });
}

describe("Catapultar Account", () => {
  const publicClient = createPublicClient({
    chain: anvil,
    transport: http(rpcUrl()),
  });

  describe("Primitives", () => {
    const _getParams = () => {
      const owner = random(20);
      return {
        salt: owner.padEnd(64 + 2, "0") as `0x${string}`,
        factory: factories["0.1.0"],
        template: templates["0.1.0"],
        keyType: AccountPublicKeyType.ECDSAOrSmartContract,
        pubkey: owner,
      };
    };

    it("should predict deployed account", async () => {
      const options = _getParams();
      const predicted = CatapultarAccount.predict(options);
      const pubkeyArray = pubkeyAsArray(options);

      const factoryReturned = await publicClient.readContract({
        address: options.factory,
        abi: CATAPULTAR_FACTORY_V0_1_0_ABI,
        functionName: "predictDeploy",
        args: [
          options.keyType as AccountPublicKeyType,
          pubkeyArray,
          options.salt,
        ],
      });

      expect(predicted).toBe(factoryReturned);
    });

    it("should predict deployed account with digest", async () => {
      const options = {
        ..._getParams(),
        isSignature: false,
        callDigest: random(32),
      };
      const predicted = CatapultarAccount.predict(options);
      const pubkeyArray = pubkeyAsArray(options);
      const factoryReturned = await publicClient.readContract({
        address: options.factory,
        abi: CATAPULTAR_FACTORY_V0_1_0_ABI,
        functionName: "predictDeployWithDigest",
        args: [
          options.keyType as AccountPublicKeyType,
          pubkeyArray,
          options.salt,
          options.callDigest,
          options.isSignature,
        ],
      });

      expect(predicted).toBe(factoryReturned);
    });
  });

  describe("0.1.0 with transactions", () => {
    const pubkey = privateKeyToAccount(random(32));

    const wallet = privateKeyToAccount(PUBLIC_DEFAULT_ANVIL_ACCOUNT_0);
    const executor = createWalletClient({
      account: wallet,
      chain: anvil,
      transport: http(rpcUrl()),
    });

    let deployedAccountV010: CatapultarAccount<
      Version,
      string,
      AccountPublicKeyType
    >;

    beforeAll(async () => {
      const deployCall010 = await CatapultarAccount.deploy({
        keyType: AccountPublicKeyType.ECDSAOrSmartContract,
        pubkey: pubkey.address,
        salt: `0x${asHex(0n, 20)}${random(12).replace("0x", "")}`,
        factory: factories["0.1.0"],
        template: templates["0.1.0"],
      });
      deployedAccountV010 = deployCall010.account.attachRpc({
        chainId,
        rpc: rpcUrl(),
      });
      const tx = await executor.sendTransaction({
        ...deployCall010.call,
      });
      // We need to wait for the transaction to be finalised.
      await waitForTransaction(tx);
    });

    it.serial("should deploy with set pubkey", async () => {
      const publicClientOwner = await publicClient.readContract({
        address: deployedAccountV010.address,
        abi: deployedAccountV010.abi(),
        functionName: "owner",
      });
      const onChainOwner = await deployedAccountV010.getAccountOwner();
      const expectedOwner = pubkey.address;
      expect(publicClientOwner).toBe(expectedOwner);
      expect(onChainOwner).toBe(expectedOwner);
    });

    it.serial("should deploy with digest call", async () => {
      const digest = random(32);

      const deployCall = await CatapultarAccount.deploy({
        keyType: AccountPublicKeyType.ECDSAOrSmartContract,
        pubkey: pubkey.address,
        salt: `0x${asHex(0n, 20)}${random(12).replace("0x", "")}`,
        factory: factories["0.1.0"],
        template: templates["0.1.0"],
        callDigest: digest,
        isSignature: false,
      });
      const tx = await executor.sendTransaction({
        ...deployCall.call,
      });
      // We need to wait for the transaction to be finalised.
      await waitForTransaction(tx);

      const smartAccount = deployCall.account.attachRpc({
        chainId,
        rpc: rpcUrl(),
      });

      const approvalStatus = await publicClient.readContract({
        address: smartAccount.address,
        abi: smartAccount.abi(),
        functionName: "approvedDigest",
        args: [digest],
      });

      expect(approvalStatus).toBe(1);
    });

    it.serial("should deploy with digest signature", async () => {
      const digest = random(32);

      const deployCall = await CatapultarAccount.deploy({
        keyType: AccountPublicKeyType.ECDSAOrSmartContract,
        pubkey: pubkey.address,
        salt: `0x${asHex(0n, 20)}${random(12).replace("0x", "")}`,
        factory: factories["0.1.0"],
        template: templates["0.1.0"],
        callDigest: digest,
        isSignature: true,
      });
      const tx = await executor.sendTransaction({
        ...deployCall.call,
      });
      // We need to wait for the transaction to be finalised.
      await waitForTransaction(tx);

      const smartAccount = deployCall.account.attachRpc({
        chainId,
        rpc: rpcUrl(),
      });

      const approvalStatus = await publicClient.readContract({
        address: smartAccount.address,
        abi: smartAccount.abi(),
        functionName: "approvedDigest",
        args: [digest],
      });

      expect(approvalStatus).toBe(2);
    });
  });
});
