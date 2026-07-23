import { hashTypedData, sha256, stringToBytes } from "viem";
import { privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";
import { Base64, P256 } from "ox";
import type { Owner, OwnerType, WebAuthnSignature } from "../src/types/types";
import { asHex, random } from "../src/utils/helpers";

/** Sign the EIP-712 digest with a raw P256 key, returning `0x{r}{s}`. */
export function p256signFunction(privateKey: `0x${string}`) {
  return async (...args: Parameters<typeof hashTypedData>) => {
    const payload = hashTypedData(...args);
    const signedPayload = P256.sign({ payload, privateKey });
    return `0x${asHex(signedPayload.r, 32, "")}${asHex(signedPayload.s, 32, "")}` as `0x${string}`;
  };
}

/** Sign the EIP-712 digest through a synthesized WebAuthn assertion. */
export function webAuthnSignFunction(privateKey: `0x${string}`) {
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

export type OwnerSigner = {
  owner: Owner;
  signTypedData: (
    ...args: Parameters<typeof hashTypedData>
  ) => Promise<`0x${string}` | WebAuthnSignature>;
};

/**
 * Generate a fresh keypair for the given owner type and return the matching
 * {@link Owner} plus a `signTypedData` implementation for it.
 */
export function makeOwnerSigner(ownerType: OwnerType): OwnerSigner {
  if (ownerType === "ecdsa") {
    const account: PrivateKeyAccount = privateKeyToAccount(random(32));
    return {
      owner: { type: "ecdsa", address: account.address },
      signTypedData: (...args) => account.signTypedData(...args),
    };
  }
  const privateKey = P256.randomPrivateKey();
  const { x, y } = P256.getPublicKey({ privateKey });
  return {
    owner: {
      type: ownerType,
      x: asHex(x, 32, "0x"),
      y: asHex(y, 32, "0x"),
    },
    signTypedData:
      ownerType === "p256"
        ? p256signFunction(privateKey)
        : webAuthnSignFunction(privateKey),
  };
}
