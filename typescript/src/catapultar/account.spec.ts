import { createPublicClient, createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { anvil } from "viem/chains";
import { CatapultarAccount } from "./account";
import { random, asHex } from "../utils/helpers";
import { rpcUrl } from "../../test/setup";
import { AccountKeyType } from "../types/types";

const chainId = 31337;
const PUBLIC_DEFAULT_ANVIL_ACCOUNT_0 =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const factories = {
  "0.1.0": "0x1b8FE3BD26940e48a0fcaE97d5AA48Bc598Bf46e",
  "0.0.1": "0x526a216Ab5b39683a3C75796dE4391F686406F2A",
} as const;

describe("Catapultar Account 0.1.0", () => {
  const owner = privateKeyToAccount(random(32));

  const wallet = privateKeyToAccount(PUBLIC_DEFAULT_ANVIL_ACCOUNT_0);
  const executor = createWalletClient({
    account: wallet,
    chain: anvil,
    transport: http(rpcUrl()),
  });

  const publicClient = createPublicClient({
    chain: anvil,
    transport: http(rpcUrl()),
  });

  let deployedAccountV010: CatapultarAccount<"0.1.0", string>;

  beforeAll(async () => {
    const deployCall010 = await CatapultarAccount.deploy({
      chainId,
      ownerType: AccountKeyType.ECDSAOrSmartContract,
      owner: owner.address,
      salt: `0x${asHex(0n, 20)}${random(12).replace("0x", "")}`,
      rpc: rpcUrl(),
      factory: factories["0.1.0"],
      version: "0.1.0",
    });
    deployedAccountV010 = deployCall010.account;
    const tx = await executor.sendTransaction({
      ...deployCall010.call,
    });
    await new Promise((resolve) => setTimeout(resolve, 200));
    // We need to wait for the transaction to be finalised.
    await publicClient.getTransactionReceipt({ hash: tx });
  });

  it.serial("should deploy with set owner", async () => {
    const publicClientOwner = await publicClient.readContract({
      address: deployedAccountV010.address,
      abi: deployedAccountV010.abi(),
      functionName: "owner",
    });
    const onChainOwner = await deployedAccountV010.getAccountOwner();
    const expectedOwner = owner.address;
    expect(publicClientOwner).toBe(expectedOwner);
    expect(onChainOwner).toBe(expectedOwner);
  });

  it.serial("should deploy with digest call", async () => {
    const digest = random(32);

    const deployCall = await CatapultarAccount.deploy({
      chainId,
      ownerType: AccountKeyType.ECDSAOrSmartContract,
      owner: owner.address,
      salt: `0x${asHex(0n, 20)}${random(12).replace("0x", "")}`,
      rpc: rpcUrl(),
      factory: factories["0.1.0"],
      version: "0.1.0",
      callDigest: digest,
      isSignature: false,
    });
    const tx = await executor.sendTransaction({
      ...deployCall.call,
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    // We need to wait for the transaction to be finalised.
    await publicClient.getTransactionReceipt({ hash: tx });

    const smartAccount = deployCall.account;

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
      chainId,
      ownerType: AccountKeyType.ECDSAOrSmartContract,
      owner: owner.address,
      salt: `0x${asHex(0n, 20)}${random(12).replace("0x", "")}`,
      rpc: rpcUrl(),
      factory: factories["0.1.0"],
      version: "0.1.0",
      callDigest: digest,
      isSignature: true,
    });
    const tx = await executor.sendTransaction({
      ...deployCall.call,
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    // We need to wait for the transaction to be finalised.
    await publicClient.getTransactionReceipt({ hash: tx });

    const smartAccount = deployCall.account;

    const approvalStatus = await publicClient.readContract({
      address: smartAccount.address,
      abi: smartAccount.abi(),
      functionName: "approvedDigest",
      args: [digest],
    });

    expect(approvalStatus).toBe(2);
  });
});
