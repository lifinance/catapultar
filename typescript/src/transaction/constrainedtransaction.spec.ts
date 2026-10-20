import {
  createPublicClient,
  createWalletClient,
  decodeFunctionData,
  encodeFunctionData,
  http,
  zeroAddress,
} from "viem";
import { ConstrainedAssetTransaction } from "./constrainedtransaction";
import { anvil } from "viem/chains";
import { rpcUrl } from "../../test/setup";
import { random } from "../utils/helpers";
import { privateKeyToAccount } from "viem/accounts";
import { cat_validator } from "../config";
import {
  PUBLIC_DEFAULT_ANVIL_ACCOUNT_0,
  token1,
  token2,
} from "../../test/fixtures";
import { MOCKERC20_abi } from "../abi/mockerc20";
import { CAT_VALIDATOR_ABI } from "../abi/CATValidator";

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
    it("should set the constraint nonce", () => {
      const catx = new ConstrainedAssetTransaction({
        executor: zeroAddress,
        chainId: 1,
      });
      expect(catx.constraintNonce).toBe(1n);
      catx.setPerpetual();
      expect(catx.constraintNonce).toBe(0n);
      catx.setConstraintNonce(1n);
      expect(catx.constraintNonce).toBe(1n);
      catx.setConstraintNonce(10n);
      expect(catx.constraintNonce).toBe(10n);
    });

    it("asExecutionBundle binds the embedded batch to the execute validator", () => {
      const amount = 10n ** 18n;
      const customValidator = random(20);
      const salt = random(32);
      const owner = { type: "ecdsa", address: random(20) } as const;
      const execute = {
        executionTarget: token2,
        executionPayload: "0x" as const,
        spends: [amount],
      };
      const buildCatx = () => {
        const c = new ConstrainedAssetTransaction({
          executor: zeroAddress,
          chainId: 31337,
        });
        c.addAllowances({ token: token1, amount });
        c.addOutcomes({ token: token2, amount, destination: zeroAddress });
        return c;
      };

      // Custom validator: the embedded approve/signature batch + the predicted account
      // address must match a batch built explicitly for that validator, and the entry
      // call must target it too. (Regression for the approve-one/execute-another bug.)
      const customBundle = buildCatx().asExecutionBundle({
        salt,
        owner,
        execute: { ...execute, validator: customValidator },
      });
      const expectedCustom = buildCatx()
        .asCatapultarAllowanceTransaction({ validator: customValidator })
        .asAccount({ salt, owner });
      expect(customBundle.entryCall.to).toBe(customValidator);
      expect(customBundle.address).toBe(expectedCustom.address);
      expect(customBundle.actionCall.data).toBe(expectedCustom.actionCall.data);

      // Default path (no override) still binds the library default validator.
      const defaultBundle = buildCatx().asExecutionBundle({
        salt,
        owner,
        execute,
      });
      const expectedDefault = buildCatx()
        .asCatapultarAllowanceTransaction({ validator: cat_validator })
        .asAccount({ salt, owner });
      expect(defaultBundle.entryCall.to).toBe(cat_validator);
      expect(defaultBundle.address).toBe(expectedDefault.address);
      expect(defaultBundle.actionCall.data).toBe(
        expectedDefault.actionCall.data,
      );

      // The validator must actually flow into the digest/address derivation.
      expect(customBundle.address).not.toBe(defaultBundle.address);
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

        // Generate account.
        const tx = catx.asCatapultarAllowanceTransaction();
        const accountSalt = oftenTargetAddress.padEnd(66, "0") as `0x${string}`;
        const account = tx.asAccount({
          salt: accountSalt,
          owner: { type: "ecdsa", address: oftenTargetAddress },
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
          args: [cat_validator, amount2],
        });

        const executeCall = catx.asExecuteCall({
          address: account.address,
          executionTarget: token2,
          executionPayload: execData,
          spends: [amount1],
        });

        // Other spec files fill through token2 on the same anvil instance, so
        // its token1 balance is measured as a delta.
        const token2Before = await publicClient.readContract({
          address: token1,
          abi: MOCKERC20_abi,
          functionName: "balanceOf",
          args: [token2],
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
          (await publicClient.readContract({
            address: token1,
            abi: MOCKERC20_abi,
            functionName: "balanceOf",
            args: [token2],
          })) - token2Before,
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

      // Generate account.
      const tx = catx.asCatapultarAllowanceTransaction({
        refund: oftenTargetAddress,
      });
      const accountSalt = oftenTargetAddress.padEnd(66, "0") as `0x${string}`;
      const account = tx.asAccount({
        salt: accountSalt,
        owner: { type: "ecdsa", address: oftenTargetAddress },
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

    /**
     * Deploy an account embedding a v1 constraint with a refund of
     * `amount1` of token1 to `refund`, mint `funding` of token1 to it, and
     * return its refund call.
     */
    async function deployRefundableAccount(
      refund: `0x${string}`,
      funding: bigint,
    ) {
      const amount1 = 10n ** 18n;
      const catx = new ConstrainedAssetTransaction({
        executor: wallet.address,
        chainId: 31337,
      });
      catx.addAllowances({ token: token1, amount: amount1 });
      catx.addOutcomes({
        token: token2,
        amount: 10n ** 6n,
        destination: refund,
      });
      const account = catx
        .asCatapultarAllowanceTransaction({ refund })
        .asAccount({
          salt: random(32),
          owner: { type: "ecdsa", address: refund },
        });
      for (const call of [
        {
          to: token1,
          data: encodeFunctionData({
            abi: MOCKERC20_abi,
            functionName: "mint",
            args: [account.address, funding],
          }),
        },
        account.deployCall,
        account.actionCall,
      ]) {
        const hash = await executor.sendTransaction(call);
        const receipt = await publicClient.waitForTransactionReceipt({ hash });
        expect(receipt.status).toBe("success");
      }
      const refundCall = catx.asRefundCall({
        address: account.address,
        refund,
      });
      return { account, refundCall };
    }

    async function balanceOf(owner: `0x${string}`) {
      return publicClient.readContract({
        address: token1,
        abi: MOCKERC20_abi,
        functionName: "balanceOf",
        args: [owner],
      });
    }

    // The v1 refund delivers the signed amount exactly: the validator
    // forwards the outcome and enforces it as a floor.
    it("reverts the refund of an account holding less than the signed allowance", async () => {
      const refund = random(20);
      const funding = 10n ** 18n / 2n;
      const { account, refundCall } = await deployRefundableAccount(
        refund,
        funding,
      );
      await expect(executor.sendTransaction(refundCall)).rejects.toThrow();
      expect(await balanceOf(refund)).toBe(0n);
      expect(await balanceOf(account.address)).toBe(funding);
    });

    it("refunds the signed amount and leaves the excess on the account", async () => {
      const refund = random(20);
      const amount1 = 10n ** 18n;
      const funding = amount1 * 3n;
      const { account, refundCall } = await deployRefundableAccount(
        refund,
        funding,
      );
      await waitForTransaction(await executor.sendTransaction(refundCall));
      expect(await balanceOf(refund)).toBe(amount1);
      expect(await balanceOf(account.address)).toBe(funding - amount1);
    });

    // The v1 digest signs no target, so the signed executor may call the
    // validator with any target; the 1:1 outcome floor is what keeps the
    // refund from being diverted.
    it("reverts an executor's attempt to divert the refund elsewhere", async () => {
      const refund = random(20);
      const elsewhere = random(20);
      const funding = 10n ** 18n;
      const { account, refundCall } = await deployRefundableAccount(
        refund,
        funding,
      );
      const decoded = decodeFunctionData({
        abi: CAT_VALIDATOR_ABI,
        data: refundCall.data,
      });
      if (decoded.functionName !== "entry") throw new Error("expected entry");
      const [, ...afterTarget] = decoded.args;
      await expect(
        executor.writeContract({
          address: cat_validator,
          abi: CAT_VALIDATOR_ABI,
          functionName: "entry",
          args: [elsewhere, ...afterTarget],
        }),
      ).rejects.toThrow();
      expect(await balanceOf(elsewhere)).toBe(0n);
      expect(await balanceOf(refund)).toBe(0n);
      expect(await balanceOf(account.address)).toBe(funding);
    });
  });
});
