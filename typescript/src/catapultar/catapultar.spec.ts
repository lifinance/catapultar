import { privateKeyToAccount } from "viem/accounts";
import { random, asHex } from "../utils/helpers";
import { CatapultarTx, MetaCatapultarTx } from "./catapultar";
import { ExecutionMode, type Owner, type OwnerType } from "../types/types";
import { anvil } from "viem/chains";
import {
  createPublicClient,
  createWalletClient,
  decodeAbiParameters,
  decodeFunctionData,
  http,
  parseAbiParameters,
  type PublicClient,
} from "viem";
import { CatapultarAccount } from "./account";
import { makeOwnerSigner } from "../../test/signers";
import { rpcUrl } from "../../test/setup";
import { defaultFactory } from "../config";
import { PUBLIC_DEFAULT_ANVIL_ACCOUNT_0 } from "../../test/fixtures";
import CATAPULTAR_ABI from "../abi/catapultar";
import { CATAPULTAR_ACCOUNT_RUNTIME_CODE } from "../bytecode/catapultar";
import { applyCodeOverrideMargin } from "./gas";

const chainId = 31337;
const anvilAccountVersion = "0.1.0";

async function waitForTransaction(hash: `0x${string}`) {
  await new Promise((resolve) => setTimeout(resolve, 50));
  // We need to wait for the transaction to be finalised.
  const publicClient = createPublicClient({
    chain: anvil,
    transport: http(rpcUrl()),
  });
  return await publicClient.getTransactionReceipt({ hash });
}

describe("Catapultar", () => {
  describe("Transaction", () => {
    it.concurrent("should disallow nonce 0", () => {
      const address = "0x1111111111111111111111111111111111111110";
      const tx = new CatapultarTx({
        account: {
          address: "0x1111111111111111111111111111111111111111",
          chainId: 1,
          owner: { type: "ecdsa", address },
        },
      });
      const nonce0Error = `Nonce 0 is not allowed. It cannot be differentiated from an invalid nonce.`;
      tx.nonce = 0n;
      expect(() => tx.getSignerData()).toThrow(nonce0Error);
    });

    it.concurrent("should return a valid domain separator", () => {
      const address = "0x1111111111111111111111111111111111111110";
      const tx = new CatapultarTx({
        account: {
          address: "0x1111111111111111111111111111111111111111",
          chainId: 1,
          owner: { type: "ecdsa", address },
          version: "0.1.1",
        },
      });

      const domainSeparator = tx.account.getDomainSeparator();
      expect(domainSeparator.name).toBe("Catapultar");
      expect(domainSeparator.version).toBe("0.1.1");
      expect(domainSeparator.chainId).toBe(1);
      expect(domainSeparator.verifyingContract).toBe(
        "0x1111111111111111111111111111111111111111",
      );

      const txNext = new CatapultarTx({
        account: {
          address: "0x1111111111111111111111111111111111111112",
          chainId: 2,
          owner: { type: "ecdsa", address },
          version: "0.1.1",
          name: "Catapulting",
        },
      });

      const domainSeparatorNext = txNext.account.getDomainSeparator();
      expect(domainSeparatorNext.name).toBe("Catapulting");
      expect(domainSeparatorNext.version).toBe("0.1.1");
      expect(domainSeparatorNext.chainId).toBe(2);
      expect(domainSeparatorNext.verifyingContract).toBe(
        "0x1111111111111111111111111111111111111112",
      );
    });

    it.concurrent(
      "should be able to validate a provided signature is valid",
      async () => {
        const key = random(32);
        const account = privateKeyToAccount(key);

        const tx = new CatapultarTx({
          account: {
            address: "0x1111111111111111111111111111111111111111",
            chainId: 1,
            owner: { type: "ecdsa", address: account.address },
          },
        })
          .setMode(ExecutionMode.RaiseRevert)
          .setRandomNonce()
          .addCall({
            to: "0x1111111111111111111111111111111111111111",
            value: 0n,
            data: "0x",
          });
        expect(await tx.hasValidSignature()).toBe(false);
        expect(await tx.hasValidSignature({ noSignatureIsValid: false })).toBe(
          false,
        );
        expect(await tx.hasValidSignature({ noSignatureIsValid: true })).toBe(
          true,
        );

        const digest = tx.getTypeHashDigest({ ignoreNoCalls: true });
        const signature = await account.sign({ hash: digest });
        tx.signature = signature;

        expect(await tx.hasValidSignature()).toBe(true);
        expect(await tx.hasValidSignature({ noSignatureIsValid: false })).toBe(
          true,
        );
        expect(await tx.hasValidSignature({ noSignatureIsValid: true })).toBe(
          true,
        );
      },
    );

    it.concurrent("should allow you to BYO signer", async () => {
      const key = random(32);
      const account = privateKeyToAccount(key);

      const tx = new CatapultarTx({
        account: {
          address: "0x1111111111111111111111111111111111111111",
          chainId: 1,
          owner: { type: "ecdsa", address: account.address },
        },
      })
        .setMode(ExecutionMode.RaiseRevert)
        .setRandomNonce()
        .addCall({
          to: "0x1111111111111111111111111111111111111111",
          value: 0n,
          data: "0x",
        });
      expect(await tx.hasValidSignature()).toBe(false);
      expect(await tx.hasValidSignature({ noSignatureIsValid: false })).toBe(
        false,
      );
      expect(await tx.hasValidSignature({ noSignatureIsValid: true })).toBe(
        true,
      );

      // ! Wrap the signing function to carry over the context of wallet !
      await tx.sign(({ domain, types, primaryType, message }) =>
        account.signTypedData({ domain, types, primaryType, message }),
      );

      // Check that it matches manual sign
      const digest = tx.getTypeHashDigest({ ignoreNoCalls: true });
      const signature = await account.sign({ hash: digest });

      expect(tx.signature).toBe(signature);

      expect(await tx.hasValidSignature({ noSignatureIsValid: false })).toBe(
        true,
      );
    });

    it.concurrent("should return proper getOpData", async () => {
      // Sign it.
      const key = random(32);
      const account = privateKeyToAccount(key);

      const tx = new CatapultarTx({
        account: {
          address: "0x1111111111111111111111111111111111111111",
          chainId: 1,
          owner: { type: "ecdsa", address: account.address },
        },
        nonce: 1n,
      }).setMode(ExecutionMode.RaiseRevert);
      const opData = await tx.getOpData();

      // 0x + 64 hex chars (32 bytes) = 66 length
      expect(opData.startsWith("0x")).toBe(true);
      expect(opData.length).toBe(2 + 64);
      // last hex nibble should be '1' (nonce was 1)
      expect(opData.endsWith("1")).toBe(true);

      await tx.sign((...args) => account.signTypedData(...args), {
        ignoreNoCalls: true,
      });

      tx.validateSignature();

      const opDataWithSignature = await tx.getOpData({
        compactSignature: false,
      });
      expect(opDataWithSignature.startsWith("0x")).toBe(true);
      expect(opDataWithSignature.length).toBe(2 + 194);
      expect(
        opDataWithSignature.endsWith(tx.signature!.replace("0x", "")),
      ).toBe(true);

      const opDataWithCompactSignature = await tx.getOpData({
        compactSignature: true,
      });
      expect(opDataWithCompactSignature.startsWith("0x")).toBe(true);
      expect(opDataWithCompactSignature.length).toBe(2 + 192);
    });

    it.concurrent(
      "estimates the meta tx with every mode mirrored to its estimation twin and no signer",
      async () => {
        const ownerAccount = privateKeyToAccount(random(32));
        const estimateArgs: unknown[] = [];
        const getCodeArgs: unknown[] = [];
        const fakeClient = {
          getCode: async (args: unknown) => {
            getCodeArgs.push(args);
            return "0x6000" as `0x${string}`;
          },
          estimateGas: async (args: unknown) => {
            estimateArgs.push(args);
            return 123n;
          },
        };
        const account = new CatapultarAccount({
          address: random(20),
          chainId: 1,
          owner: { type: "ecdsa", address: ownerAccount.address },
        }).connect(fakeClient as unknown as PublicClient);
        const nonceBase = BigInt(random(31)) << 8n;
        const metaTx = new MetaCatapultarTx({
          account,
          outerNonce: nonceBase,
          innerNonce: nonceBase + 1n,
        })
          .setMode(ExecutionMode.SkipRevert)
          .addCalls(
            {
              calls: [{ to: random(20), value: 0n, data: "0x" }],
              mode: ExecutionMode.RaiseRevert,
            },
            {
              calls: [{ to: random(20), value: 0n, data: "0x" }],
              mode: ExecutionMode.SkipRevert,
            },
            // No mode: mirrored like RaiseRevert in the twin.
            {
              calls: [{ to: random(20), value: 0n, data: "0x" }],
            },
            {
              calls: [{ to: random(20), value: 0n, data: "0x" }],
              mode: ExecutionMode.SkipRevertMultiChain,
            },
          );

        const gas = await metaTx.estimateGas({ useCodeOverride: true });

        // 123n from the fake client plus the ceiling-rounded 10% override margin.
        expect(gas).toBe(applyCodeOverrideMargin(123n));
        expect(gas).toBe(136n);
        // The source object is not mutated.
        expect(metaTx.mode).toBe(ExecutionMode.SkipRevert);
        expect(metaTx.calls.map((c) => c.mode)).toEqual([
          ExecutionMode.RaiseRevert,
          ExecutionMode.SkipRevert,
          undefined,
          ExecutionMode.SkipRevertMultiChain,
        ]);
        expect(getCodeArgs).toEqual([]);
        expect(estimateArgs).toHaveLength(1);

        const estimate = estimateArgs[0] as {
          account: `0x${string}`;
          data: `0x${string}`;
          stateOverride: { address: `0x${string}`; code: `0x${string}` }[];
        };
        expect(estimate.account).toBe(account.address);
        expect(estimate.stateOverride).toEqual([
          { address: account.address, code: CATAPULTAR_ACCOUNT_RUNTIME_CODE },
        ]);

        const decoded = decodeFunctionData({
          abi: CATAPULTAR_ABI,
          data: estimate.data,
        });
        expect(decoded.functionName).toBe("execute");
        expect(decoded.args[0]).toBe(ExecutionMode.EstimateGas);
        const [innerCalls, opData] = decodeAbiParameters(
          parseAbiParameters(
            "(address to, uint256 value, bytes data)[] calls, bytes opData",
          ),
          decoded.args[1] as `0x${string}`,
        );
        // Unsigned self-call: opData is the bare 32-byte outer nonce.
        expect(opData.length).toBe(2 + 64);

        // Sub-batches are self-calls; skip-policy modes are mirrored to
        // EstimateGas and atomic (RaiseRevert/unset) sub-batches to
        // RaiseRevertEstimate — bubbling like RaiseRevert so their rollback
        // semantics hold, with the starvation check run inside the frame.
        expect(innerCalls).toHaveLength(4);
        const innerModes = innerCalls.map((call) => {
          expect(call.to.toLowerCase()).toBe(account.address.toLowerCase());
          const inner = decodeFunctionData({
            abi: CATAPULTAR_ABI,
            data: call.data,
          });
          expect(inner.functionName).toBe("execute");
          return inner.args[0];
        });
        expect(innerModes).toEqual([
          ExecutionMode.RaiseRevertEstimate,
          ExecutionMode.EstimateGas,
          ExecutionMode.RaiseRevertEstimate,
          ExecutionMode.EstimateGasMultiChain,
        ]);

        // Without an override the raw estimate passes through unchanged (the
        // deployed proxy hop is already in the trace) and no stateOverride is
        // sent.
        expect(await metaTx.estimateGas()).toBe(123n);
        expect(estimateArgs).toHaveLength(2);
        expect(estimateArgs[1]).not.toHaveProperty("stateOverride");

        // overrideCode alone implies the override — and its margin.
        expect(await metaTx.estimateGas({ overrideCode: "0x6001" })).toBe(
          applyCodeOverrideMargin(123n),
        );
        expect(
          (estimateArgs[2] as { stateOverride: unknown }).stateOverride,
        ).toEqual([{ address: account.address, code: "0x6001" }]);

        // overrideCodeAddress alone implies the override too, reading the
        // code from the given address.
        expect(
          await metaTx.estimateGas({ overrideCodeAddress: random(20) }),
        ).toBe(applyCodeOverrideMargin(123n));
        expect(getCodeArgs).toHaveLength(1);
        expect(
          (estimateArgs[3] as { stateOverride: unknown }).stateOverride,
        ).toEqual([{ address: account.address, code: "0x6000" }]);
      },
    );

    it.concurrent(
      "refuses to estimate a RaiseRevert-outer meta tx",
      async () => {
        const ownerAccount = privateKeyToAccount(random(32));
        const account = new CatapultarAccount({
          address: random(20),
          chainId: 1,
          owner: { type: "ecdsa", address: ownerAccount.address },
        }).connect({} as PublicClient);
        const metaTx = new MetaCatapultarTx({ account })
          .setMode(ExecutionMode.RaiseRevert)
          .addCalls({ calls: [{ to: random(20), value: 0n, data: "0x" }] });

        await expect(metaTx.estimateGas()).rejects.toThrow(
          "requires a SkipRevert outer mode",
        );
      },
    );
  });

  describe("Meta Transactions", () => {
    it.concurrent("should correctly set nonces for calls", async () => {
      const address = "0x1111111111111111111111111111111111111111";
      const call = {
        calls: [
          {
            to: address as `0x${string}`,
            value: 0n,
            data: `0x` as `0x${string}`,
          },
        ],
      };
      const calls = [call, call, call, call];
      const outerNonce = 5n;
      const innerNonce = outerNonce + 1n;
      const mTx = new MetaCatapultarTx({
        account: {
          address,
          chainId: 1,
          owner: { type: "ecdsa", address },
        },
        outerNonce,
        innerNonce,
      });

      const subTxs = mTx.addCalls(...calls).getCallsAsTxs();
      for (let i = 0; i < subTxs.length; ++i) {
        expect(subTxs[i]!.nonce).toEqual(innerNonce + BigInt(i));
      }
      const batchTx = await mTx.asCatapultarTx();
      expect(batchTx.nonce).toBe(outerNonce);
    });

    it.concurrent("should validate that nonces are not Duplicates", () => {
      const address = "0x1111111111111111111111111111111111111111";
      const call = {
        calls: [
          {
            to: address as `0x${string}`,
            value: 0n,
            data: `0x` as `0x${string}`,
          },
        ],
      };
      const calls = [
        call,
        call,
        { ...call, nonce: 5n },
        { ...call, nonce: 5n },
      ];
      const mTx = new MetaCatapultarTx({
        account: { address, chainId: 1, owner: { type: "ecdsa", address } },
      });
      mTx.addCalls(...calls);
      expect(() => mTx.checkNonces()).toThrow(
        "Duplicate nonces were found: 5,5",
      );
      expect(() => mTx.asCatapultarTx()).toThrow(
        "Duplicate nonces were found: 5,5",
      );
    });
  });

  const integrationTest = (ownerType: OwnerType) =>
    describe(`Integration ${ownerType}`, () => {
      const publicClient = createPublicClient({
        chain: anvil,
        transport: http(rpcUrl()),
      });

      const { owner, signTypedData } = makeOwnerSigner(ownerType);

      const oftenTargetAddress = random(20); // This is acting as a random address.

      const wallet = privateKeyToAccount(PUBLIC_DEFAULT_ANVIL_ACCOUNT_0);
      const executor = createWalletClient({
        account: wallet,
        chain: anvil,
        transport: http(rpcUrl()),
      });

      let deployedAccountV010: CatapultarAccount<Owner, true>;

      beforeEach(async () => {
        const deployCall010 = CatapultarAccount.deploy({
          owner,
          salt: `0x${asHex(0n, 20)}${random(12).replace("0x", "")}`,
          factory: defaultFactory,
          version: anvilAccountVersion,
        });
        deployedAccountV010 = deployCall010.account.connectRpc({
          chainId,
          rpc: rpcUrl(),
        });
        const tx = await executor.sendTransaction({
          ...deployCall010.call,
        });
        await waitForTransaction(tx);
      });

      it.serial("should be able to call", async () => {
        const tx = new CatapultarTx({
          account: deployedAccountV010,
        });

        // Send tokens to the account.
        const value = 1000000000000000000n;
        await executor.sendTransaction({
          to: deployedAccountV010.address,
          value,
        });
        // await waitForTransaction(transferTransaction);

        // This is our validation statement. We will be transferring the value to this address.
        expect(
          await publicClient.getBalance({ address: oftenTargetAddress }),
        ).toBe(0n);

        // Generate our call.
        const calldata = await (
          await tx
            .setRandomNonce()
            .setMode(ExecutionMode.RaiseRevert)
            .addCall({
              to: oftenTargetAddress,
              value,
              data: "0x",
            })
            .sign((...args) => signTypedData(...args))
        ).asCall();

        const executionTransaction = await executor.sendTransaction(calldata);
        await waitForTransaction(executionTransaction);

        expect(
          await publicClient.getBalance({ address: oftenTargetAddress }),
        ).toBe(value);
      });

      it.serial("execute meta transaction", async () => {
        // Send tokens to the account.
        const value = 1000000000000000000n;
        await executor.sendTransaction({
          to: deployedAccountV010.address,
          value,
        });
        // await waitForTransaction(transferTransaction);

        // Lets make 4 transactions that we will batch.
        const targets = [random(20), random(20), random(20), random(20)];
        await Promise.all(
          targets.map(async (address) =>
            expect(await publicClient.getBalance({ address })).toBe(0n),
          ),
        );

        const calls = targets.map((a) => {
          return {
            calls: [
              {
                to: a,
                value: value / 4n,
                data: random(32),
              },
            ],
          };
        });
        const metaTx = new MetaCatapultarTx({
          account: deployedAccountV010,
        });

        const signedTx = await (
          await metaTx
            .setMode(ExecutionMode.SkipRevert)
            .addCalls(...calls)
            .asCatapultarTx()
        ).sign((...args) => signTypedData(...args));

        const executionTransaction = await executor.sendTransaction(
          await signedTx.asCall(),
        );
        await waitForTransaction(executionTransaction);

        await Promise.all(
          targets.map(async (address) =>
            expect(await publicClient.getBalance({ address })).toBe(value / 4n),
          ),
        );
      });

      // --- Catapultar Account --- //

      it.serial("get next valid nonce", async () => {
        // Because we are running the above functions with some randomness, we need to use a reference as a random nonce...
        const referenceNonce = BigInt(random(32));
        let nextNonce = await deployedAccountV010.getNextValidNonce({
          nonce: referenceNonce,
        });
        expect(nextNonce).toBe(referenceNonce);

        // Invalidate the nonce.
        let invalidateCall = deployedAccountV010.buildInvalidateNoncesCalls(
          referenceNonce,
          referenceNonce + 1n,
        );
        // Execute the invalidation on the account.
        let calldata = await (
          await new CatapultarTx({ account: deployedAccountV010 })
            .setRandomNonce()
            .setMode(ExecutionMode.RaiseRevert)
            .addCall(...invalidateCall)
            .sign((...args) => signTypedData(...args))
        ).asCall();
        let executionTransaction = await executor.sendTransaction(calldata);
        await waitForTransaction(executionTransaction);

        nextNonce = await deployedAccountV010.getNextValidNonce({
          nonce: referenceNonce,
        });
        expect(nextNonce).toBe(referenceNonce + 2n);

        // Invalidate more nonces.
        invalidateCall = deployedAccountV010.buildInvalidateNoncesCalls(
          ...[...Array(1001).keys()].map((i) => BigInt(i) + referenceNonce),
        );
        calldata = await (
          await new CatapultarTx({ account: deployedAccountV010 })
            .setRandomNonce()
            .setMode(ExecutionMode.RaiseRevert)
            .addCall(...invalidateCall)
            .sign((...args) => signTypedData(...args))
        ).asCall();
        executionTransaction = await executor.sendTransaction(calldata);
        await waitForTransaction(executionTransaction);

        nextNonce = await deployedAccountV010.getNextValidNonce({
          nonce: referenceNonce,
        });
        expect(nextNonce).toBe(referenceNonce + 1001n);
      });
    });

  describe("execute() one-call send", () => {
    const publicClient = createPublicClient({
      chain: anvil,
      transport: http(rpcUrl()),
    });
    const deployer = privateKeyToAccount(PUBLIC_DEFAULT_ANVIL_ACCOUNT_0);
    const executor = createWalletClient({
      account: deployer,
      chain: anvil,
      transport: http(rpcUrl()),
    });

    it.serial("signs and sends via a viem WalletClient", async () => {
      const ownerAccount = privateKeyToAccount(random(32));
      const owner: Owner = { type: "ecdsa", address: ownerAccount.address };

      const deployCall = CatapultarAccount.deploy({
        owner,
        salt: `0x${asHex(0n, 20)}${random(12).replace("0x", "")}`,
        factory: defaultFactory,
        version: anvilAccountVersion,
      });
      const account = deployCall.account.connectRpc({ chainId, rpc: rpcUrl() });
      await waitForTransaction(
        await executor.sendTransaction({ ...deployCall.call }),
      );

      // Fund the owner EOA (for gas) and the smart account (value to forward).
      const value = 1000000000000000000n;
      await waitForTransaction(
        await executor.sendTransaction({ to: ownerAccount.address, value }),
      );
      await waitForTransaction(
        await executor.sendTransaction({ to: account.address, value }),
      );

      const target = random(20);
      expect(await publicClient.getBalance({ address: target })).toBe(0n);

      // The owner's own wallet signs AND broadcasts in one call.
      const ownerWallet = createWalletClient({
        account: ownerAccount,
        chain: anvil,
        transport: http(rpcUrl()),
      });
      const tx = new CatapultarTx({ account })
        .setRandomNonce()
        .setMode(ExecutionMode.RaiseRevert)
        .addCall({ to: target, value, data: "0x" });
      const hash = await tx.execute(ownerWallet);
      await waitForTransaction(hash);

      expect(await publicClient.getBalance({ address: target })).toBe(value);
    });
  });

  integrationTest("ecdsa");
  integrationTest("p256");
  integrationTest("webauthn-p256");
});
