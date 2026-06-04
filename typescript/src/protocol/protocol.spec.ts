import {
  enumToOwnerType,
  keyArrayToOwner,
  ownersEqual,
  ownerToKeyArray,
  ownerTypeToEnum,
  type Owner,
} from "./owner";
import { buildOpData } from "./opdata";
import { callsDigest } from "./calls";
import { compactSignature, normalizeP256 } from "./signature";
import { ExecutionMode } from "../types/types";

describe("protocol/owner", () => {
  it("maps owner types to the on-chain enum and back", () => {
    expect(ownerTypeToEnum("ecdsa")).toBe(0);
    expect(ownerTypeToEnum("p256")).toBe(1);
    expect(ownerTypeToEnum("webauthn-p256")).toBe(2);
    expect(enumToOwnerType(0)).toBe("ecdsa");
    expect(enumToOwnerType(1)).toBe("p256");
    expect(enumToOwnerType(2)).toBe("webauthn-p256");
    expect(() => enumToOwnerType(3)).toThrow();
  });

  it("encodes an ecdsa owner as a single left-padded word", () => {
    const address = "0xaabbccddeeff00112233445566778899aabbccdd";
    const owner: Owner = { type: "ecdsa", address };
    expect(ownerToKeyArray(owner)).toEqual([
      `0x000000000000000000000000${address.slice(2)}`,
    ]);
  });

  it("accepts an already 32-byte padded ecdsa address", () => {
    const padded =
      "0x000000000000000000000000aabbccddeeff00112233445566778899aabbccdd";
    expect(ownerToKeyArray({ type: "ecdsa", address: padded })).toEqual([
      padded,
    ]);
  });

  it("rejects a malformed ecdsa address", () => {
    expect(() =>
      ownerToKeyArray({ type: "ecdsa", address: "0x1234" }),
    ).toThrow();
  });

  it("rejects zero keys (mirrors _isValidKey)", () => {
    expect(() =>
      ownerToKeyArray({
        type: "ecdsa",
        address: "0x0000000000000000000000000000000000000000",
      }),
    ).toThrow();
    expect(() =>
      ownerToKeyArray({
        type: "p256",
        x: `0x${"00".repeat(32)}`,
        y: `0x${"22".repeat(32)}`,
      }),
    ).toThrow();
  });

  it("encodes p256 owners as [x, y]", () => {
    const owner: Owner = {
      type: "p256",
      x: `0x${"11".repeat(32)}`,
      y: `0x${"22".repeat(32)}`,
    };
    expect(ownerToKeyArray(owner)).toEqual([owner.x, owner.y]);
  });

  it("round-trips ecdsa owners through the key array decoder", () => {
    const owner: Owner = {
      type: "ecdsa",
      address: "0xaabbccddeeff00112233445566778899aabbccdd",
    };
    const decoded = keyArrayToOwner(0, ownerToKeyArray(owner));
    expect(ownersEqual(owner, decoded)).toBe(true);
  });

  it("round-trips p256 owners through the key array decoder", () => {
    const owner: Owner = {
      type: "p256",
      x: `0x${"11".repeat(32)}`,
      y: `0x${"22".repeat(32)}`,
    };
    const decoded = keyArrayToOwner(1, ownerToKeyArray(owner));
    expect(ownersEqual(owner, decoded)).toBe(true);
  });

  it("compares owners case-insensitively", () => {
    expect(
      ownersEqual(
        {
          type: "ecdsa",
          address: "0xABCD000000000000000000000000000000000000",
        },
        {
          type: "ecdsa",
          address: "0xabcd000000000000000000000000000000000000",
        },
      ),
    ).toBe(true);
    expect(
      ownersEqual(
        {
          type: "ecdsa",
          address: "0x1100000000000000000000000000000000000000",
        },
        { type: "p256", x: "0x11", y: "0x22" },
      ),
    ).toBe(false);
  });
});

describe("protocol/opdata", () => {
  it("packs a bare 32-byte nonce when no signature is given", () => {
    const opData = buildOpData(1n);
    expect(opData.length).toBe(2 + 64);
    expect(opData.endsWith("1")).toBe(true);
  });

  it("appends the signature after the nonce", () => {
    const opData = buildOpData(1n, "0xdeadbeef");
    expect(opData.length).toBe(2 + 64 + 8);
    expect(opData.endsWith("deadbeef")).toBe(true);
  });

  it("rejects nonce 0 and undefined", () => {
    expect(() => buildOpData(0n)).toThrow();
    expect(() => buildOpData(undefined)).toThrow();
  });
});

describe("protocol/signature", () => {
  it("pads a 64-byte P256 signature to 66 bytes with a 00 prehash flag", () => {
    const sig = `0x${"ab".repeat(64)}` as `0x${string}`;
    const normalized = normalizeP256(sig);
    expect(normalized.replace("0x", "").length).toBe(66 * 2);
    expect(normalized.endsWith("00")).toBe(true);
  });

  it("leaves an already-flagged P256 signature unchanged", () => {
    const sig = `0x${"ab".repeat(66)}` as `0x${string}`;
    expect(normalizeP256(sig)).toBe(sig);
  });

  it("leaves non-ECDSA-length signatures untouched when compacting", () => {
    const sig = `0x${"ab".repeat(66)}` as `0x${string}`;
    expect(compactSignature(sig)).toBe(sig);
    const already64 = `0x${"cd".repeat(64)}` as `0x${string}`;
    expect(compactSignature(already64)).toBe(already64);
  });
});

describe("protocol/calls", () => {
  it("produces a different digest for multichain (chainId-less) domains", () => {
    const message = {
      nonce: 1n,
      mode: ExecutionMode.RaiseRevertMultiChain,
      calls: [],
    };
    const verifyingContract =
      "0x1111111111111111111111111111111111111111" as const;
    const singleChain = callsDigest(
      { name: "Catapultar", version: "0.1.0", chainId: 1, verifyingContract },
      message,
    );
    const multiChain = callsDigest(
      { name: "Catapultar", version: "0.1.0", verifyingContract },
      message,
    );
    expect(singleChain).not.toBe(multiChain);
  });
});
