import {
  concatHex,
  createPublicClient,
  createWalletClient,
  http,
  keccak256,
  pad,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { anvil } from "viem/chains";
import { CatapultarAccount, REPLAY_PROTECTION } from "./account";
import { random, asHex } from "../utils/helpers";
import { ownerToKeyArray, ownerTypeToEnum } from "../protocol/owner";
import { rpcUrl } from "../../test/setup";
import type { Owner } from "../types/types";
import { defaultFactory } from "../config";
import CATAPULTAR_FACTORY_ABI from "../abi/catapultarFactory";
import { P256 } from "ox";

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
      const address = random(20);
      const owner: Owner = { type: "ecdsa", address };
      return {
        salt: address.padEnd(64 + 2, "0") as `0x${string}`,
        factory: defaultFactory,
        owner,
      };
    };

    it("should predict deployed account", async () => {
      const options = _getParams();
      const predicted = CatapultarAccount.predict(options);
      const keyArray = ownerToKeyArray(options.owner);

      const factoryReturned = await publicClient.readContract({
        address: options.factory.factory,
        abi: CATAPULTAR_FACTORY_ABI,
        functionName: "predictDeploy",
        args: [ownerTypeToEnum(options.owner.type), keyArray, options.salt],
      });

      expect(predicted).toBe(factoryReturned);
    });

    it("should predict deployed account with digest", async () => {
      const options = {
        ..._getParams(),
        digest: { hash: random(32), isSignature: false },
      };
      const predicted = CatapultarAccount.predict(options);
      const keyArray = ownerToKeyArray(options.owner);
      const factoryReturned = await publicClient.readContract({
        address: options.factory.factory,
        abi: CATAPULTAR_FACTORY_ABI,
        functionName: "predictDeployWithDigest",
        args: [
          ownerTypeToEnum(options.owner.type),
          keyArray,
          options.salt,
          options.digest.hash,
          options.digest.isSignature,
        ],
      });

      expect(predicted).toBe(factoryReturned);
    });

    it("should predict an upgradeable account (matches predictDeployUpgradeable)", async () => {
      const base = _getParams();
      const options = { ...base, upgradeable: true } as const;
      const predicted = CatapultarAccount.predict(options);
      const keyArray = ownerToKeyArray(options.owner);
      const factoryReturned = await publicClient.readContract({
        address: options.factory.factory,
        abi: CATAPULTAR_FACTORY_ABI,
        functionName: "predictDeployUpgradeable",
        args: [ownerTypeToEnum(options.owner.type), keyArray, options.salt],
      });
      expect(predicted).toBe(factoryReturned);
      // The upgradeable address must differ from the immutable clone address
      // for identical owner/salt/factory.
      expect(predicted).not.toBe(CatapultarAccount.predict(base));
    });

    it("computes the ERC-1271 replay-protected digest", () => {
      const account = new CatapultarAccount({
        address: "0x1111111111111111111111111111111111111111",
        owner: {
          type: "ecdsa",
          address: "0x2222222222222222222222222222222222222222",
        },
      });
      const payload = random(32);
      // Independent reconstruction: keccak256(tag || bytes32(address) || payload).
      const expected = keccak256(
        concatHex([REPLAY_PROTECTION, pad(account.address), payload]),
      );
      expect(account.getReplayProtectedDigest(payload)).toBe(expected);

      // Binding to the account address: a different account → different digest.
      const other = new CatapultarAccount({
        address: "0x3333333333333333333333333333333333333333",
        owner: account.owner,
      });
      expect(other.getReplayProtectedDigest(payload)).not.toBe(expected);
    });
  });

  describe("owner wrappers", () => {
    const account = new CatapultarAccount({
      address: "0x1111111111111111111111111111111111111111",
      owner: {
        type: "ecdsa",
        address: "0x2222222222222222222222222222222222222222",
      },
    });

    it("uses the transferOwnership(uint8,bytes32[]) overload for a normal transfer", () => {
      const call = account.buildTransferOwnershipCall({
        newOwner: {
          type: "ecdsa",
          address: "0x3333333333333333333333333333333333333333",
        },
      });
      // selector of transferOwnership(uint8,bytes32[])
      expect(call.data.startsWith("0xe3c21638")).toBe(true);
      expect(call.to).toBe(account.address);
    });

    it("uses the transferOwnership(address) overload to resign to the zero address", () => {
      const call = account.buildTransferOwnershipCall({
        newOwner: {
          type: "ecdsa",
          address: "0x0000000000000000000000000000000000000000",
        },
      });
      // selector of transferOwnership(address)
      expect(call.data.startsWith("0xf2fde38b")).toBe(true);
    });
  });

  describe("with transactions", () => {
    const pubkey = privateKeyToAccount(random(32));

    const wallet = privateKeyToAccount(PUBLIC_DEFAULT_ANVIL_ACCOUNT_0);
    const executor = createWalletClient({
      account: wallet,
      chain: anvil,
      transport: http(rpcUrl()),
    });

    let deployedAccountV010: CatapultarAccount<Owner, true>;

    beforeAll(async () => {
      const deployCall010 = CatapultarAccount.deploy({
        owner: { type: "ecdsa", address: pubkey.address },
        salt: `0x${asHex(0n, 20)}${random(12).replace("0x", "")}`,
        factory: defaultFactory,
      });
      deployedAccountV010 = deployCall010.account.connectRpc({
        chainId,
        rpc: rpcUrl(),
      });
      const tx = await executor.sendTransaction({
        ...deployCall010.call,
      });
      // We need to wait for the transaction to be finalised.
      await waitForTransaction(tx);
    });

    it.serial("should deploy with set owner", async () => {
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

    it.serial("should validate owner for p256 accounts", async () => {
      const p256PrivateKey = P256.randomPrivateKey();
      const { x, y } = P256.getPublicKey({ privateKey: p256PrivateKey });
      const owner: Owner = {
        type: "p256",
        x: asHex(x, 32, "0x"),
        y: asHex(y, 32, "0x"),
      };

      const deployCall = CatapultarAccount.deploy({
        owner,
        salt: `0x${asHex(0n, 20)}${random(12).replace("0x", "")}`,
        factory: defaultFactory,
      });

      const p256Account = deployCall.account.connectRpc({
        chainId,
        rpc: rpcUrl(),
      });

      const tx = await executor.sendTransaction({
        ...deployCall.call,
      });
      await waitForTransaction(tx);

      await expect(p256Account.validateOwner()).resolves.toBe(p256Account);
    });

    it.serial("should deploy with digest call", async () => {
      const digest = random(32);

      const deployCall = CatapultarAccount.deploy({
        owner: { type: "ecdsa", address: pubkey.address },
        salt: `0x${asHex(0n, 20)}${random(12).replace("0x", "")}`,
        digest: { hash: digest, isSignature: false },
      });
      const tx = await executor.sendTransaction({
        ...deployCall.call,
      });
      // We need to wait for the transaction to be finalised.
      await waitForTransaction(tx);

      const smartAccount = deployCall.account.connectRpc({
        chainId,
        rpc: rpcUrl(),
      });

      const approvalStatus = await smartAccount.getDigestApproval({ digest });

      expect(approvalStatus).toBe(1);
    });

    it.serial("should deploy with digest signature", async () => {
      const digest = random(32);

      const deployCall = CatapultarAccount.deploy({
        owner: { type: "ecdsa", address: pubkey.address },
        salt: `0x${asHex(0n, 20)}${random(12).replace("0x", "")}`,
        factory: defaultFactory,
        digest: { hash: digest, isSignature: true },
      });
      const tx = await executor.sendTransaction({
        ...deployCall.call,
      });
      // We need to wait for the transaction to be finalised.
      await waitForTransaction(tx);

      const smartAccount = deployCall.account.connectRpc({
        chainId,
        rpc: rpcUrl(),
      });

      const approvalStatus = await smartAccount.getDigestApproval({ digest });

      expect(approvalStatus).toBe(2);
    });
  });
});
