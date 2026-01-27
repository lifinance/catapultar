import {
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  http,
  zeroAddress,
} from "viem";
import { AccountPublicKeyType } from "../types/types";
import { ConstrainedAssetTransaction } from "./constrainedtransaction";
import { anvil } from "viem/chains";
import { rpcUrl } from "../../test/setup";
import { random } from "../utils/helpers";
import { privateKeyToAccount } from "viem/accounts";
import { PUBLIC_DEFAULT_ANVIL_ACCOUNT_0, token1, token2 } from "../config";
import { MOCKERC20_abi } from "../abi/mockerc20";

async function waitForTransaction(hash: `0x${string}`) {
  await new Promise((resolve) => setTimeout(resolve, 50));
  // We need to wait for the transaction to be finalised.
  const publicClient = createPublicClient({
    chain: anvil,
    transport: http(rpcUrl()),
  });
  return await publicClient.getTransactionReceipt({ hash });
}

describe("ConstrainedAssetTransaction", () => {
  describe("unit", () => {
    it("should set nonce 0 if perpetual", () => {
      const catx = new ConstrainedAssetTransaction({
        executor: zeroAddress,
        chainId: 1,
      });
      expect(catx.constraintNonce).toBe(1n);
      catx.perpetual(true);
      expect(catx.constraintNonce).toBe(0n);
      catx.perpetual(false);
      expect(catx.constraintNonce).toBe(1n);

      catx.constraintNonce = 10n;
      catx.perpetual(false);
      expect(catx.constraintNonce).toBe(10n);
    });
  });
  describe("integration", () => {
    const publicClient = createPublicClient({
      chain: anvil,
      transport: http(rpcUrl()),
    });

    const oftenTargetAddress = random(20); // This is acting as a random address.

    const wallet = privateKeyToAccount(PUBLIC_DEFAULT_ANVIL_ACCOUNT_0);
    const executor = createWalletClient({
      account: wallet,
      chain: anvil,
      transport: http(rpcUrl()),
    });

    it.serial(
      "create account and execute contained constraints, happy",
      async () => {
        const amount1 = 10n ** 18n;
        const amount2 = 10n ** 6n;
        const catx = new ConstrainedAssetTransaction({
          executor: wallet.address,
          chainId: 31337,
        });
        // add allowance for token1.
        catx.addAllowances({ token: token1, amount: amount1 });
        // Add outcome for token2.
        catx.addOutcomes({
          token: token2,
          amount: amount2,
          destination: oftenTargetAddress,
        });
        catx.perpetual(false);

        // Generate account.
        const tx = catx.asCatapultarAllowanceTransaction();
        const accountSalt = oftenTargetAddress.padEnd(66, "0") as `0x${string}`;
        const account = tx.asAccount({
          salt: accountSalt,
          keyType: AccountPublicKeyType.ECDSAOrSmartContract,
          pubkey: oftenTargetAddress,
        });

        // Fund the SA account with token1. This simulates the on-board tx.
        executor.writeContract({
          address: token1,
          abi: MOCKERC20_abi,
          functionName: "mint",
          args: [account.address, amount1],
        });

        // Compute the execution data. (mint funds for target)
        const execData = encodeFunctionData({
          abi: MOCKERC20_abi,
          functionName: "mint",
          args: [oftenTargetAddress, amount2],
        });

        const executeCall = catx.asExecuteCall({
          address: account.address,
          executionTarget: token2,
          executionPayload: execData,
          spends: [amount1],
        });

        // We now need to execute 3 transaction. If we had a Catapultar account we could do this in a single one but for simplicity, we will just do them one by one.

        const nonce = await publicClient.getTransactionCount({
          address: wallet.address,
        });
        // Deploy account
        const txe1 = await executor.sendTransaction({
          ...account.deployCall,
          nonce: nonce + 1,
        });
        // Execute approval + signature set
        const txe2 = await executor.sendTransaction({
          ...account.actionCall,
          nonce: nonce + 2,
        });
        // Execute custom payload.
        const txe3 = await executor.sendTransaction({
          ...executeCall,
          nonce: nonce + 3,
        });
        await Promise.all([txe1, txe2, txe3].map((t) => waitForTransaction(t)));

        // Assert that state has been changed.
        // 1. Token2 (recipient of the funds) recived amount1 token1.
        // 2. oftenTargetAddress received amount2 token2.
        expect(
          await publicClient.readContract({
            address: token1,
            abi: MOCKERC20_abi,
            functionName: "balanceOf",
            args: [token2],
          }),
        ).toBe(amount1);
        expect(
          await publicClient.readContract({
            address: token2,
            abi: MOCKERC20_abi,
            functionName: "balanceOf",
            args: [oftenTargetAddress],
          }),
        ).toBe(amount2);
      },
    );

    it("create account and execute contained constraints, refund", async () => {
      const amount1 = 10n ** 18n;
      const amount2 = 10n ** 6n;
      const catx = new ConstrainedAssetTransaction({
        executor: wallet.address,
        chainId: 31337,
      });
      // add allowance for token1.
      catx.addAllowances({ token: token1, amount: amount1 });
      // Add outcome for token2.
      catx.addOutcomes({
        token: token2,
        amount: amount2,
        destination: oftenTargetAddress,
      });
      catx.perpetual(false);

      // Generate account.
      const tx = catx.asCatapultarAllowanceTransaction({
        refund: oftenTargetAddress,
      });
      const accountSalt = oftenTargetAddress.padEnd(66, "0") as `0x${string}`;
      const account = tx.asAccount({
        salt: accountSalt,
        keyType: AccountPublicKeyType.ECDSAOrSmartContract,
        pubkey: oftenTargetAddress,
      });

      // Fund the SA account with token1. This simulates the on-board tx.
      executor.writeContract({
        address: token1,
        abi: MOCKERC20_abi,
        functionName: "mint",
        args: [account.address, amount1],
      });

      const refundCall = catx.asRefundCall({
        address: account.address,
        refund: oftenTargetAddress,
      });

      // We now need to execute 3 transaction. If we had a Catapultar account we could do this in a single one but for simplicity, we will just do them one by one.

      const nonce = await publicClient.getTransactionCount({
        address: wallet.address,
      });
      // Deploy account
      const txe1 = await executor.sendTransaction({
        ...account.deployCall,
        nonce: nonce + 1,
      });
      // Execute approval + signature set
      const txe2 = await executor.sendTransaction({
        ...account.actionCall,
        nonce: nonce + 2,
      });
      // Execute custom payload.
      const txe3 = await executor.sendTransaction({
        ...refundCall,
        nonce: nonce + 3,
      });
      await Promise.all([txe1, txe2, txe3].map((t) => waitForTransaction(t)));

      // Assert that state has been changed.
      // 1. Token2 (recipient of the funds) recived amount1 token1.
      // 2. oftenTargetAddress received amount2 token2.
      expect(
        await publicClient.readContract({
          address: token1,
          abi: MOCKERC20_abi,
          functionName: "balanceOf",
          args: [oftenTargetAddress],
        }),
      ).toBe(amount1);
    });
  });
});
