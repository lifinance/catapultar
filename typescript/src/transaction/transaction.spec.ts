import { createPublicClient, createWalletClient, http } from "viem";
import { ExecutionMode, type Call } from "../types/types";
import { random } from "../utils/helpers";
import { BaseTransaction } from "./transaction";
import { rpcUrl } from "../../test/setup";
import { anvil } from "viem/chains";
import { PUBLIC_DEFAULT_ANVIL_ACCOUNT_0 } from "../config";
import { privateKeyToAccount } from "viem/accounts";
import CATAPULTAR_V0_1_0_ABI from "../abi/catapultarV0.1.0";

async function waitForTransaction(hash: `0x${string}`) {
  await new Promise((resolve) => setTimeout(resolve, 50));
  // We need to wait for the transaction to be finalised.
  const publicClient = createPublicClient({
    chain: anvil,
    transport: http(rpcUrl()),
  });
  await publicClient.getTransactionReceipt({ hash });
}

describe("Base Transaction", () => {
  describe("Units", () => {
    it.concurrent("should set nonce", () => {
      const tx = new BaseTransaction();
      expect(tx.nonce).toBeUndefined();
      tx.setNonce(124n);
      expect(tx.nonce).toBe(124n);
      tx.setNonce(1300n);
      expect(tx.nonce).toBe(1300n);
      tx.setNonce(2n ** 256n - 1n);
      expect(tx.nonce).toBe(2n ** 256n - 1n);
    });

    it.concurrent("should set a random nonce", () => {
      const tx = new BaseTransaction();
      const firstNonce = tx.nonce;
      tx.setRandomNonce();
      expect(tx.nonce).not.toBe(firstNonce);
      const secondNonce = tx.nonce;
      tx.setRandomNonce();
      expect(tx.nonce).not.toBe(firstNonce);
      expect(tx.nonce).not.toBe(secondNonce);
    });

    it.concurrent("should set mode", () => {
      const tx = new BaseTransaction();
      expect(tx.mode).toBeUndefined();
      tx.setMode(ExecutionMode.RaiseRevert);
      expect(tx.mode).toBe(ExecutionMode.RaiseRevert);
      tx.setMode(ExecutionMode.RaiseRevertMultiChain);
      expect(tx.mode).toBe(ExecutionMode.RaiseRevertMultiChain);
      tx.setMode(ExecutionMode.SkipRevert);
      expect(tx.mode).toBe(ExecutionMode.SkipRevert);
      tx.setMode(ExecutionMode.SkipRevertMultiChain);
      expect(tx.mode).toBe(ExecutionMode.SkipRevertMultiChain);
    });

    it.concurrent("has valid mode", () => {
      const tx = new BaseTransaction();
      tx.setMode(ExecutionMode.RaiseRevert);
      expect(tx.hasValidMode()).toBe(true);
      tx.setMode(ExecutionMode.RaiseRevertMultiChain);
      expect(tx.hasValidMode()).toBe(true);
      tx.setMode(ExecutionMode.SkipRevert);
      expect(tx.hasValidMode()).toBe(true);
      tx.setMode(ExecutionMode.SkipRevertMultiChain);
      expect(tx.hasValidMode()).toBe(true);
      tx.setMode(
        "0x0200000000007821000100000000000000000000000000000000000000000000" as ExecutionMode,
      );
      expect(tx.hasValidMode()).toBe(false);
    });

    it.concurrent("has multichain mode", () => {
      const tx = new BaseTransaction();
      tx.setMode(ExecutionMode.RaiseRevert);
      expect(tx.hasMultichainMode()).toBe(false);
      tx.setMode(ExecutionMode.RaiseRevertMultiChain);
      expect(tx.hasMultichainMode()).toBe(true);
      tx.setMode(ExecutionMode.SkipRevert);
      expect(tx.hasMultichainMode()).toBe(false);
      tx.setMode(ExecutionMode.SkipRevertMultiChain);
      expect(tx.hasMultichainMode()).toBe(true);
    });

    it.concurrent("should add call", () => {
      const tx = new BaseTransaction();
      expect(tx.calls.length).toBe(0);
      expect(tx.calls).toEqual([]);

      const callA: Call = { to: random(20), data: "0x", value: 0n };
      tx.addCall(callA);

      expect(tx.calls).toEqual([callA]);
      tx.addCall(callA);
      expect(tx.calls).toEqual([callA, callA]);

      const callB: Call = {
        to: random(20),
        data: "0xdeadbeef",
        value: 251251251n,
      };
      tx.addCall(callB);
      expect(tx.calls).toEqual([callA, callA, callB]);
      tx.calls = [];
      expect(tx.calls).toEqual([]);
    });

    it.concurrent("should get total value of calls", () => {
      const tx = new BaseTransaction();
      expect(tx.getTotalValue()).toBe(0n);

      const callA: Call = { to: random(20), data: "0x", value: 1524n };
      tx.addCall(callA);

      expect(tx.getTotalValue()).toEqual(1524n);
      tx.addCall(callA);
      expect(tx.getTotalValue()).toEqual(1524n * 2n);

      const callB: Call = {
        to: random(20),
        data: "0xdeadbeef",
        value: 251251251n,
      };
      tx.addCall(callB);
      expect(tx.getTotalValue()).toEqual(1524n * 2n + 251251251n);
      tx.calls = [];
      expect(tx.getTotalValue()).toEqual(0n);
    });

    //-- Errors --//

    it.concurrent("should disallow nonce 0", () => {
      const tx = new BaseTransaction();
      const nonce0Error = `Nonce 0 is not allowed. It cannot be differentiated from an invalid nonce.`;
      expect(() => tx.setNonce(0n)).toThrow(nonce0Error);
      expect(tx.nonce).toBeUndefined();
      tx.nonce = 0n;
      expect(() => tx.getOpData()).toThrow(nonce0Error);
    });
  });

  describe("integration", () => {
    it("should be account based", async () => {
      const publicClient = createPublicClient({
        chain: anvil,
        transport: http(rpcUrl()),
      });
      const accountOwner = privateKeyToAccount(random(32));

      const walletClient = createWalletClient({
        account: privateKeyToAccount(PUBLIC_DEFAULT_ANVIL_ACCOUNT_0),
        chain: anvil,
        transport: http(rpcUrl()),
      });

      const value = 1000000000n;

      const salt = accountOwner.address.padEnd(64 + 2, "0") as `0x${string}`;

      const tx = new BaseTransaction();
      tx.setMode(ExecutionMode.RaiseRevert);
      tx.setRandomNonce();

      const randomCall = {
        to: random(20),
        data: "0xdeadbeef" as `0x${string}`,
        value,
      };
      tx.addCall(randomCall);

      const txAcct = tx.asAccount({
        salt,
        owner: { type: "ecdsa", address: accountOwner.address },
      });

      // No account deployed:
      let code = await publicClient.getCode({ address: txAcct.address });
      expect(code).toBeUndefined();

      // Execute the account deployment. (Attach value for the account)
      let txHash = await walletClient.sendTransaction({
        ...txAcct.deployCall,
        value,
      });
      await waitForTransaction(txHash);

      // Check that the account has been deployed to predicted address.
      code = await publicClient.getCode({ address: txAcct.address });
      expect(code).not.toBeUndefined();

      // Check the embedded action.
      const embedStatus = await publicClient.readContract({
        address: txAcct.address,
        abi: CATAPULTAR_V0_1_0_ABI,
        functionName: "approvedDigest",
        args: [txAcct.callDigest],
      });
      expect(embedStatus).toBe(1);

      // Execute the embedded action.
      txHash = await walletClient.sendTransaction(txAcct.actionCall);
      await waitForTransaction(txHash);

      // Validate it happened.
      expect(await publicClient.getBalance({ address: randomCall.to })).toBe(
        randomCall.value,
      );
    });
  });
});
