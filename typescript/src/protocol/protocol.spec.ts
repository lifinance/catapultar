import { hashTypedData, zeroAddress } from "viem";
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
import {
  erc1967CloneInitCode,
  predictCloneAddress,
  pushZeroCloneInitCode,
} from "./factory";
import {
  constraintDigest,
  constraintDomain,
  OUTCOME_TO_SIGNER,
  SPEND_FULL_BALANCE,
} from "./constraint";
import {
  ExecutionConstraintTyped,
  ExecutionMode,
  type ExecutionConstraint,
} from "../types/types";
import { defaultFactory } from "../config";

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

describe("protocol/factory", () => {
  const template = defaultFactory.template;
  const factory = defaultFactory.factory;
  // bytes32(uint256(123))
  const salt = `0x${"0".repeat(62)}7b` as `0x${string}`;

  it("derives PUSH0 and ERC-1967 init code with the right shape", () => {
    const push0 = pushZeroCloneInitCode(template);
    const erc1967 = erc1967CloneInitCode(template);
    expect(push0.startsWith("0x602d5f8160095f39f3")).toBe(true);
    expect(erc1967.startsWith("0x603d3d8160223d3973")).toBe(true);
    // ERC-1967 minimal proxy init code is 95 bytes.
    expect(erc1967.replace("0x", "").length).toBe(95 * 2);
    expect(push0.toLowerCase()).toContain(template.slice(2).toLowerCase());
    expect(erc1967.toLowerCase()).toContain(template.slice(2).toLowerCase());
  });

  it("predicts the ERC-1967 clone address (golden, verified vs Solady LibClone)", () => {
    // Cross-checked against LibClone.predictDeterministicAddressERC1967 in the
    // Foundry suite for (template, bytes32(123), factory).
    expect(
      predictCloneAddress({ template, salt, factory, kind: "upgradeable" }),
    ).toBe("0xaf12f58BdF9d8FcdBd94D2D0d3A1Eb297dAA5e92");
  });

  it("predicts a different address for clone vs upgradeable", () => {
    const clone = predictCloneAddress({ template, salt, factory });
    const upgradeable = predictCloneAddress({
      template,
      salt,
      factory,
      kind: "upgradeable",
    });
    expect(clone).not.toBe(upgradeable);
  });
});

describe("protocol/constraint", () => {
  it("exposes the on-chain magic values", () => {
    expect(SPEND_FULL_BALANCE).toBe(1n << 255n);
    expect(OUTCOME_TO_SIGNER).toBe(zeroAddress);
  });

  it("matches a hand-built EIP-712 digest (centralized encoder is correct)", () => {
    const validator = "0xf44cBb09C5b32cdFC1049464ba632B59E25EC00E" as const;
    const token = "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6" as const;
    const constraint: ExecutionConstraint = {
      allowances: [{ token, amount: 1000n }],
      outcomes: [{ token, amount: 900n, destination: OUTCOME_TO_SIGNER }],
      executor: "0x3333333333333333333333333333333333333333",
      nonce: 1n,
    };
    const domain = { chainId: 31337, verifyingContract: validator };

    const fromEncoder = constraintDigest(domain, constraint);
    const handBuilt = hashTypedData({
      domain: constraintDomain(domain),
      types: ExecutionConstraintTyped,
      primaryType: "ExecutionConstraint",
      message: constraint,
    });
    expect(fromEncoder).toBe(handBuilt);
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
      { name: "Catapultar", version: "0.1.1", chainId: 1, verifyingContract },
      message,
    );
    const multiChain = callsDigest(
      { name: "Catapultar", version: "0.1.1", verifyingContract },
      message,
    );
    expect(singleChain).not.toBe(multiChain);
  });
});
