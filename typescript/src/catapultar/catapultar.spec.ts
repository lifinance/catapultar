import { privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";
import { random, asHex } from "../utils/helpers";
import { CatapultarTx, MetaCatapultarTx } from "./catapultar";
import {
  AccountPublicKeyType,
  ExecutionMode,
  type P256Points,
  type Version,
  type WebAuthnSignature,
} from "../types/types";
import { anvil } from "viem/chains";
import {
  createPublicClient,
  createWalletClient,
  encodeAbiParameters,
  hashTypedData,
  http,
  sha256,
  stringToBytes,
  toHex,
} from "viem";
import { Account } from "viem/tempo";
import { Base64, P256 } from "ox";
import { CatapultarAccount } from "./account";
import { rpcUrl } from "../../test/setup";
import { sha } from "bun";

const chainId = 31337;
const PUBLIC_DEFAULT_ANVIL_ACCOUNT_0 =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const factories = {
  "0.1.0": "0x1b8FE3BD26940e48a0fcaE97d5AA48Bc598Bf46e",
  "0.0.1": "0x526a216Ab5b39683a3C75796dE4391F686406F2A",
} as const;

async function waitForTransaction(hash: `0x${string}`) {
  await new Promise((resolve) => setTimeout(resolve, 200));
  // We need to wait for the transaction to be finalised.
  const publicClient = createPublicClient({
    chain: anvil,
    transport: http(rpcUrl()),
  });
  await publicClient.getTransactionReceipt({ hash });
}

describe("Catapultar", () => {
  describe("Transaction", () => {
    it.concurrent("should set a random nonce", () => {
      const pubkey = "0x1111111111111111111111111111111111111110";
      const tx = new CatapultarTx({
        account: {
          address: "0x1111111111111111111111111111111111111111",
          chainId: 1,
          pubkey,
        },
        nonce: 1n,
      });
      const firstNonce = tx.nonce;
      tx.setRandomNonce();
      expect(tx.nonce).not.toBe(firstNonce);
      const secondNonce = tx.nonce;
      tx.setRandomNonce();
      expect(tx.nonce).not.toBe(firstNonce);
      expect(tx.nonce).not.toBe(secondNonce);
    });

    it.concurrent("should disallow nonce 0", () => {
      const pubkey = "0x1111111111111111111111111111111111111110";
      const tx = new CatapultarTx({
        account: {
          address: "0x1111111111111111111111111111111111111111",
          chainId: 1,
          pubkey,
        },
      });
      const nonce0Error = `Nonce 0 is not allowed. It cannot be differentiated from an invalid nonce.`;
      expect(() => tx.setNonce(0n)).toThrow(nonce0Error);
      expect(tx.nonce).toBeUndefined();
      tx.nonce = 0n;
      expect(() => tx.getOpData()).toThrow(nonce0Error);
      expect(() => tx.getSignerData()).toThrow(nonce0Error);
    });

    it.concurrent("should return a valid domain separator", () => {
      const pubkey = "0x1111111111111111111111111111111111111110";
      const tx = new CatapultarTx({
        account: {
          address: "0x1111111111111111111111111111111111111111",
          chainId: 1,
          pubkey,
          version: "0.0.1",
        },
      });

      const domainSeparator = tx.account.getDomainSeparator();
      expect(domainSeparator.name).toBe("Catapultar");
      expect(domainSeparator.version).toBe("0.0.1");
      expect(domainSeparator.chainId).toBe(1);
      expect(domainSeparator.verifyingContract).toBe(
        "0x1111111111111111111111111111111111111111",
      );

      const txNext = new CatapultarTx({
        account: {
          address: "0x1111111111111111111111111111111111111112",
          chainId: 2,
          pubkey,
          version: "0.1.0",
          name: "Catapulting",
        },
      });

      const domainSeparatorNext = txNext.account.getDomainSeparator();
      expect(domainSeparatorNext.name).toBe("Catapulting");
      expect(domainSeparatorNext.version).toBe("0.1.0");
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
            pubkey: account.address,
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
        expect(await tx.hasValidSignature({ noSignatureIsValid: true })).toBe(
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
          pubkey: account.address,
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
          pubkey: account.address as `0x${string}`,
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
          pubkey: address,
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
        account: { address, chainId: 1, pubkey: address },
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

  function p256signFunction(privateKey: `0x${string}`) {
    return async (...args: Parameters<typeof hashTypedData>) => {
      const payload = hashTypedData(...args);
      const signedPayload = P256.sign({ payload, privateKey });
      return `0x${asHex(signedPayload.r, 32, "")}${asHex(signedPayload.s, 32, "")}` as `0x${string}`;
    };
  }

  function webAuthnSignFunction(privateKey: `0x${string}`) {
    return async (...args: Parameters<typeof hashTypedData>) => {
      const payload = hashTypedData(...args); // ABI.encoded hash of typedData.
      const clientDataJson = {
        type: "webauthn.get",
        challenge: Base64.fromHex(payload, { url: true, pad: false }),
        origin: "http://localhost:3000",
      };
      const clientDataJsonString = JSON.stringify(clientDataJson);
      const typeIndex = clientDataJsonString.indexOf('"type":');
      const challengeIndex = clientDataJsonString.indexOf('"challenge":');

      const rpIdHash = sha256(stringToBytes("localhost"));
      const flags = "01"; // UUP ‑ user present
      const counter = "00000001";
      const authenticatorData = (rpIdHash + flags + counter) as `0x${string}`;

      const clientHash = sha256(stringToBytes(clientDataJsonString));
      const messageHash = sha256(
        (authenticatorData + clientHash.replace("0x", "")) as `0x${string}`,
      );

      const signedMessage = P256.sign({ payload: messageHash, privateKey });

      const webAuthnSignature: WebAuthnSignature = {
        authenticatorData,
        clientDataJSON: clientDataJsonString,
        challengeIndex,
        typeIndex,
        ...signedMessage,
      };
      return webAuthnSignature;
    };
  }

  const integrationTest = (
    keyType:
      | AccountPublicKeyType.ECDSAOrSmartContract
      | AccountPublicKeyType.P256
      | AccountPublicKeyType.WebAuthnP256,
  ) =>
    describe(`Integration ${keyType}`, () => {
      const publicClient = createPublicClient({
        chain: anvil,
        transport: http(rpcUrl()),
      });

      const privateKey =
        keyType === AccountPublicKeyType.ECDSAOrSmartContract
          ? random(32)
          : P256.randomPrivateKey();
      const p256PubKey = (privateKey: `0x${string}`) => {
        const { x, y } = P256.getPublicKey({ privateKey });
        return [asHex(x, 32, "0x"), asHex(y, 32, "0x")] as P256Points;
      };
      const pubkey =
        keyType === AccountPublicKeyType.ECDSAOrSmartContract
          ? privateKeyToAccount(privateKey)
          : keyType === AccountPublicKeyType.P256
            ? { signTypedData: p256signFunction(privateKey) }
            : { signTypedData: webAuthnSignFunction(privateKey) };

      const publicKey =
        keyType === AccountPublicKeyType.ECDSAOrSmartContract
          ? (pubkey as PrivateKeyAccount).address
          : p256PubKey(privateKey);

      const oftenTargetAddress = random(20); // This is acting as a random address.

      const a = Account.fromP256(privateKey);
      a.signTypedData;

      const wallet = privateKeyToAccount(PUBLIC_DEFAULT_ANVIL_ACCOUNT_0);
      const executor = createWalletClient({
        account: wallet,
        chain: anvil,
        transport: http(rpcUrl()),
      });

      let deployedAccountV010: CatapultarAccount<
        Version,
        string,
        typeof keyType
      >;

      beforeEach(async () => {
        const deployCall010 = await CatapultarAccount.deploy({
          chainId,
          keyType: keyType,
          pubkey: publicKey,
          salt: `0x${asHex(0n, 20)}${random(12).replace("0x", "")}`,
          rpc: rpcUrl(),
          factory: factories["0.1.0"],
        });
        deployedAccountV010 = deployCall010.account;
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
            .sign((...args) => pubkey.signTypedData(...args))
        ).asCall();

        await executor.sendTransaction(calldata);
        // await waitForTransaction(executionTransaction);

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
        ).sign((...args) => pubkey.signTypedData(...args));

        await executor.sendTransaction(await signedTx.asCall());
        // await waitForTransaction(executionTransaction);

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
        let invalidateCall = await deployedAccountV010.getSpendNoncesCalls(
          referenceNonce,
          referenceNonce + 1n,
        );
        // Execute the invalidation on the account.
        let calldata = await (
          await new CatapultarTx({ account: deployedAccountV010 })
            .setRandomNonce()
            .setMode(ExecutionMode.RaiseRevert)
            .addCall(...invalidateCall)
            .sign((...args) => pubkey.signTypedData(...args))
        ).asCall();
        let executionTransaction = await executor.sendTransaction(calldata);
        await waitForTransaction(executionTransaction);

        nextNonce = await deployedAccountV010.getNextValidNonce({
          nonce: referenceNonce,
        });
        expect(nextNonce).toBe(referenceNonce + 2n);

        // Invalidate more nonces.
        invalidateCall = await deployedAccountV010.getSpendNoncesCalls(
          ...[...Array(1001).keys()].map((i) => BigInt(i) + referenceNonce),
        );
        calldata = await (
          await new CatapultarTx({ account: deployedAccountV010 })
            .setRandomNonce()
            .setMode(ExecutionMode.RaiseRevert)
            .addCall(...invalidateCall)
            .sign((...args) => pubkey.signTypedData(...args))
        ).asCall();
        executionTransaction = await executor.sendTransaction(calldata);
        await waitForTransaction(executionTransaction);

        nextNonce = await deployedAccountV010.getNextValidNonce({
          nonce: referenceNonce,
        });
        expect(nextNonce).toBe(referenceNonce + 1001n);
      });
    });

  integrationTest(AccountPublicKeyType.ECDSAOrSmartContract);
  integrationTest(AccountPublicKeyType.P256);
  integrationTest(AccountPublicKeyType.WebAuthnP256);
});
