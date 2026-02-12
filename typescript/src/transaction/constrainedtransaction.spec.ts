import {
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  hashStruct,
  http,
  parseEther,
  zeroAddress,
} from "viem";
import {
  AccountPublicKeyType,
  CallsTyped,
  DigestApproval,
  ExecutionMode,
} from "../types/types";
import { ConstrainedAssetTransaction } from "./constrainedtransaction";
import { anvil } from "viem/chains";
import { rpcUrl } from "../../test/setup";
import { random } from "../utils/helpers";
import { privateKeyToAccount } from "viem/accounts";
import {
  PUBLIC_DEFAULT_ANVIL_ACCOUNT_0,
  WETH,
  token1,
  token2,
} from "../config";
import { MOCKERC20_abi } from "../abi/mockerc20";
import CATAPULTAR_V0_1_0_ABI from "../abi/catapultarV0.1.0";
import WETH_ABI from "../abi/weth";

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

    it("embedNativeWrap throws for zero amount", () => {
      const catx = new ConstrainedAssetTransaction({
        executor: zeroAddress,
        chainId: 1,
      });
      const wtoken =
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" as `0x${string}`;
      expect(() => catx.embedNativeWrap(0n, wtoken)).toThrow(
        "It is meaningless to wrap 0 eth",
      );
    });

    it("embedNativeWrap creates correct embedded transaction", () => {
      const catx = new ConstrainedAssetTransaction({
        executor: zeroAddress,
        chainId: 1,
      });
      const wtoken =
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" as `0x${string}`;
      const amount = parseEther("1");
      catx.embedNativeWrap(amount, wtoken);

      expect(catx.embeddedAccountTransactions).toHaveLength(1);
      const tx = catx.embeddedAccountTransactions[0]!;
      expect(tx.to).toBe(wtoken);
      expect(tx.value).toBe(amount);
      expect(tx.nonce).toBe(255n);
      // deposit() selector
      expect(tx.data).toBe(
        encodeFunctionData({
          abi: WETH_ABI,
          functionName: "deposit",
          args: [],
        }),
      );
    });

    it("embedNativeWrap assigns descending nonces for multiple wraps", () => {
      const catx = new ConstrainedAssetTransaction({
        executor: zeroAddress,
        chainId: 1,
      });
      const wtoken =
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" as `0x${string}`;
      catx.embedNativeWrap(1n, wtoken);
      catx.embedNativeWrap(2n, wtoken);
      catx.embedNativeWrap(3n, wtoken);

      expect(catx.embeddedAccountTransactions).toHaveLength(3);
      expect(catx.embeddedAccountTransactions[0]!.nonce).toBe(255n);
      expect(catx.embeddedAccountTransactions[1]!.nonce).toBe(254n);
      expect(catx.embeddedAccountTransactions[2]!.nonce).toBe(253n);
    });

    it("embeddedCallsAsSetSignatures returns empty when no embeds", () => {
      const catx = new ConstrainedAssetTransaction({
        executor: zeroAddress,
        chainId: 1,
      });
      // @ts-expect-error accessing private method for testing
      expect(catx.embeddedCallsAsSetSignatures()).toEqual([]);
    });

    it("embeddedCallsAsSetSignatures returns correct setSignature calls", () => {
      const catx = new ConstrainedAssetTransaction({
        executor: zeroAddress,
        chainId: 1,
      });
      const wtoken =
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" as `0x${string}`;
      catx.embedNativeWrap(parseEther("1"), wtoken);

      // @ts-expect-error accessing private method for testing
      const sigs = catx.embeddedCallsAsSetSignatures();
      expect(sigs).toHaveLength(1);
      expect(sigs[0]!.to).toBe(zeroAddress);
      expect(sigs[0]!.value).toBe(0n);

      const expectedStructHash = hashStruct({
        types: CallsTyped,
        primaryType: "Calls",
        data: {
          nonce: 255n,
          mode: ExecutionMode.RaiseRevert,
          calls: [catx.embeddedAccountTransactions[0]!],
        },
      });
      const expectedData = encodeFunctionData({
        abi: CATAPULTAR_V0_1_0_ABI,
        functionName: "setSignature",
        args: [expectedStructHash, DigestApproval.Call],
      });
      expect(sigs[0]!.data).toBe(expectedData);
    });

    it("embedNativeWrap throws on zeroAddress wtoken", () => {
      const catx = new ConstrainedAssetTransaction({
        executor: zeroAddress,
        chainId: 1,
      });
      expect(() => catx.embedNativeWrap(1n, zeroAddress)).toThrow(
        "wtoken cannot be the zero address",
      );
    });

    it("embedNativeWrap throws on 255+ embeds (nonce overflow)", () => {
      const catx = new ConstrainedAssetTransaction({
        executor: zeroAddress,
        chainId: 1,
      });
      const wtoken =
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" as `0x${string}`;
      for (let i = 0; i < 255; i++) {
        catx.embedNativeWrap(1n, wtoken);
      }
      expect(() => catx.embedNativeWrap(1n, wtoken)).toThrow(
        "Cannot embed more than 255 transactions: nonce would overflow",
      );
    });

    it("asAdditionalCalls returns complete Call objects with to set", () => {
      const catx = new ConstrainedAssetTransaction({
        executor: zeroAddress,
        chainId: 1,
      });
      const wtoken =
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" as `0x${string}`;
      const account =
        "0x1234567890abcdef1234567890abcdef12345678" as `0x${string}`;
      catx.embedNativeWrap(parseEther("1"), wtoken);

      const calls = catx.asAdditionalCalls(account);
      expect(calls).toHaveLength(1);
      expect(calls[0]!.to).toBe(account);
      expect(calls[0]!.value).toBe(0n);
      expect(calls[0]!.data.startsWith("0x")).toBe(true);
    });

    it("asAdditionalCall returns empty when no embeds", () => {
      const catx = new ConstrainedAssetTransaction({
        executor: zeroAddress,
        chainId: 1,
      });
      expect(catx.asAdditionalCall()).toEqual([]);
    });

    it("asAdditionalCall returns execute calldata for embedded transactions", () => {
      const catx = new ConstrainedAssetTransaction({
        executor: zeroAddress,
        chainId: 1,
      });
      const wtoken =
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" as `0x${string}`;
      catx.embedNativeWrap(parseEther("1"), wtoken);

      const calls = catx.asAdditionalCall();
      expect(calls).toHaveLength(1);
      expect(calls[0]!.value).toBe(0n);
      expect(calls[0]!.data.startsWith("0x")).toBe(true);
    });

    it("asCatapultarAllowanceTransaction includes embedded wrap signatures", () => {
      const catx = new ConstrainedAssetTransaction({
        executor: zeroAddress,
        chainId: 1,
      });
      const wtoken =
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" as `0x${string}`;
      catx.addAllowances({ token: token1, amount: parseEther("1") });
      catx.addOutcomes({
        token: token2,
        amount: 10n ** 6n,
        destination: zeroAddress,
      });
      catx.embedNativeWrap(parseEther("1"), wtoken);

      const txWithWrap = catx.asCatapultarAllowanceTransaction();
      // Should have: 1 approve + 1 constraint signature + 1 wrap signature = 3 calls
      expect(txWithWrap.calls).toHaveLength(3);

      // Compare to without wrap
      const catx2 = new ConstrainedAssetTransaction({
        executor: zeroAddress,
        chainId: 1,
      });
      catx2.addAllowances({ token: token1, amount: parseEther("1") });
      catx2.addOutcomes({
        token: token2,
        amount: 10n ** 6n,
        destination: zeroAddress,
      });
      const txWithoutWrap = catx2.asCatapultarAllowanceTransaction();
      // Without wrap: 1 approve + 1 constraint signature = 2 calls
      expect(txWithoutWrap.calls).toHaveLength(2);

      // The extra call should be the wrap setSignature (targets zeroAddress)
      const lastCall = txWithWrap.calls[txWithWrap.calls.length - 1]!;
      expect(lastCall.to).toBe(zeroAddress);
      expect(lastCall.value).toBe(0n);
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

    it.serial(
      "account with ETH can wrap to WETH using embedNativeWrap",
      async () => {
        const ethAmount = parseEther("1");
        const wrapTargetAddress = random(20);

        const catx = new ConstrainedAssetTransaction({
          executor: wallet.address,
          chainId: 31337,
        });

        catx.embedNativeWrap(ethAmount, WETH);
        catx.addAllowances({ token: WETH, amount: ethAmount });
        catx.addOutcomes({
          token: token2,
          amount: 10n ** 6n,
          destination: wrapTargetAddress,
        });

        const tx = catx.asCatapultarAllowanceTransaction();
        const accountSalt = wrapTargetAddress.padEnd(66, "0") as `0x${string}`;
        const account = tx.asAccount({
          salt: accountSalt,
          keyType: AccountPublicKeyType.ECDSAOrSmartContract,
          pubkey: wrapTargetAddress,
        });

        // Fund account with ETH instead of ERC20.
        executor.sendTransaction({
          to: account.address,
          value: ethAmount,
        });

        const nonce = await publicClient.getTransactionCount({
          address: wallet.address,
        });
        // Deploy account
        const txDeploy = await executor.sendTransaction({
          ...account.deployCall,
          nonce: nonce + 1,
        });
        // Execute action call (sets signatures including wrap digest)
        const txAction = await executor.sendTransaction({
          ...account.actionCall,
          nonce: nonce + 2,
        });
        // Execute wrap call (ETH → WETH)
        const additionalCalls = catx.asAdditionalCall();
        const txWrap = await executor.sendTransaction({
          to: account.address,
          ...additionalCalls[0]!,
          nonce: nonce + 3,
        });
        await Promise.all(
          [txDeploy, txAction, txWrap].map((t) => waitForTransaction(t)),
        );

        // Verify account now holds WETH
        const wethBalance = await publicClient.readContract({
          address: WETH,
          abi: WETH_ABI,
          functionName: "balanceOf",
          args: [account.address],
        });
        expect(wethBalance).toBe(ethAmount);

        // Verify account ETH was fully consumed by the wrap
        const ethBalance = await publicClient.getBalance({
          address: account.address,
        });
        expect(ethBalance).toBe(0n);
      },
    );

    it.serial(
      "wrap ETH and execute CAT constraint with WETH allowance",
      async () => {
        const ethAmount = parseEther("2");
        const outcomeAmount = 10n ** 6n;
        const targetAddress = random(20);

        const catx = new ConstrainedAssetTransaction({
          executor: wallet.address,
          chainId: 31337,
        });

        // Wrap ETH to WETH, then use WETH as the CAT allowance.
        catx.embedNativeWrap(ethAmount, WETH);
        catx.addAllowances({ token: WETH, amount: ethAmount });
        catx.addOutcomes({
          token: token2,
          amount: outcomeAmount,
          destination: targetAddress,
        });

        const tx = catx.asCatapultarAllowanceTransaction();
        const accountSalt = targetAddress.padEnd(66, "0") as `0x${string}`;
        const account = tx.asAccount({
          salt: accountSalt,
          keyType: AccountPublicKeyType.ECDSAOrSmartContract,
          pubkey: targetAddress,
        });

        // Compute execution payload: mint token2 to target
        const execData = encodeFunctionData({
          abi: MOCKERC20_abi,
          functionName: "mint",
          args: [targetAddress, outcomeAmount],
        });

        const executeCall = catx.asExecuteCall({
          address: account.address,
          executionTarget: token2,
          executionPayload: execData,
          spends: [ethAmount],
        });

        // Fund account with ETH
        executor.sendTransaction({
          to: account.address,
          value: ethAmount,
        });

        const nonce = await publicClient.getTransactionCount({
          address: wallet.address,
        });
        // Deploy account
        const txDeploy = await executor.sendTransaction({
          ...account.deployCall,
          nonce: nonce + 1,
        });
        // Set signatures (approve WETH on validator + constraint + wrap digest)
        const txAction = await executor.sendTransaction({
          ...account.actionCall,
          nonce: nonce + 2,
        });
        // Wrap ETH → WETH
        const additionalCalls = catx.asAdditionalCall();
        const txWrap = await executor.sendTransaction({
          to: account.address,
          ...additionalCalls[0]!,
          nonce: nonce + 3,
        });
        // Execute CAT constraint (pulls WETH, executes mint payload)
        const txExec = await executor.sendTransaction({
          ...executeCall,
          nonce: nonce + 4,
        });
        await Promise.all(
          [txDeploy, txAction, txWrap, txExec].map((t) =>
            waitForTransaction(t),
          ),
        );

        // Account WETH should be fully spent by the CAT validator
        const accountWeth = await publicClient.readContract({
          address: WETH,
          abi: WETH_ABI,
          functionName: "balanceOf",
          args: [account.address],
        });
        expect(accountWeth).toBe(0n);

        // WETH allowance was sent to execTarget (token2 contract)
        const execTargetWeth = await publicClient.readContract({
          address: WETH,
          abi: WETH_ABI,
          functionName: "balanceOf",
          args: [token2],
        });
        expect(execTargetWeth).toBe(ethAmount);

        // token2 outcome was received by target
        expect(
          await publicClient.readContract({
            address: token2,
            abi: MOCKERC20_abi,
            functionName: "balanceOf",
            args: [targetAddress],
          }),
        ).toBe(outcomeAmount);
      },
    );
  });
});
