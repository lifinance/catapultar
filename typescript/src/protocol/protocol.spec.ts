import {
  concat,
  encodeAbiParameters,
  hashStruct,
  hashTypedData,
  keccak256,
  toBytes,
  zeroAddress,
  zeroHash,
} from "viem";
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
  constraintV2Digest,
  constraintV2Domain,
  hashValidationParams,
  hashValidationProgram,
  OUTCOME_TO_SIGNER,
  SPEND_FULL_BALANCE,
} from "./constraint";
import {
  ExecutionConstraintTyped,
  ExecutionConstraintV2Typed,
  ExecutionMode,
  type ExecutionConstraint,
  type ExecutionConstraintV2,
} from "../types/types";
import { ValidationError } from "../errors";
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

describe("protocol/constraint v2", () => {
  // The type string of `LibExecutionConstraintV2`, written out literally so the
  // viem type table is checked against an independent copy of the Solidity one.
  const EXECUTION_CONSTRAINT_V2_TYPE =
    "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,bytes32 validationProgramHash,bytes32 paramsHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)";

  const WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" as const;
  const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" as const;
  const DEST = "0x1111111111111111111111111111111111111111" as const;
  const PROGRAM_HASH =
    "0xd71a5feb2589caa974cee8d91b3420319fed8975bf2c5cccdf3a42ce10eb3c55" as const;
  const PARAMS_HASH =
    "0x6f119f4892c1928b59c0cb3f60046c7bfcac7b23db280b459b933bcbc9ac35fc" as const;
  const domain = {
    chainId: 1,
    verifyingContract: "0x00000000000000000000000000000000ca7A0002",
  } as const;
  const base: ExecutionConstraint = {
    allowances: [{ token: WETH, amount: 2000000000000000000n }],
    outcomes: [
      { token: WETH, amount: 1000000000000000000n, destination: DEST },
      { token: USDC, amount: 1000000000n, destination: DEST },
    ],
    executor: "0x00000000000000000000000000000000ca7A0003",
    nonce: 1n,
  };

  // Reference struct hash built the way `LibExecutionConstraintV2.t.sol`'s
  // `typehashReferenceV2` does: abi.encode of the type hash and every field.
  function referenceStructHash(c: ExecutionConstraintV2): `0x${string}` {
    const allowanceType = keccak256(
      toBytes("Allowance(address token,uint256 amount)"),
    );
    const outcomeType = keccak256(
      toBytes("Outcome(address token,uint256 amount,address destination)"),
    );
    const allowancesHash = keccak256(
      concat(
        c.allowances.map((a) =>
          keccak256(
            encodeAbiParameters(
              [{ type: "bytes32" }, { type: "address" }, { type: "uint256" }],
              [allowanceType, a.token, a.amount],
            ),
          ),
        ),
      ),
    );
    const outcomesHash = keccak256(
      concat(
        c.outcomes.map((o) =>
          keccak256(
            encodeAbiParameters(
              [
                { type: "bytes32" },
                { type: "address" },
                { type: "uint256" },
                { type: "address" },
              ],
              [outcomeType, o.token, o.amount, o.destination],
            ),
          ),
        ),
      ),
    );
    return keccak256(
      encodeAbiParameters(
        [
          { type: "bytes32" },
          { type: "bytes32" },
          { type: "bytes32" },
          { type: "address" },
          { type: "uint256" },
          { type: "bytes32" },
          { type: "bytes32" },
        ],
        [
          keccak256(toBytes(EXECUTION_CONSTRAINT_V2_TYPE)),
          allowancesHash,
          outcomesHash,
          c.executor,
          c.nonce,
          c.validationProgramHash,
          c.paramsHash,
        ],
      ),
    );
  }

  // Pinned struct hashes and digests of the shared hash-parity vectors (domain
  // "CAT Validator" version "2", chain 1, validator 0x…ca7A0002).
  const vectors = [
    {
      name: "zero hashes",
      nonce: 1n,
      validationProgramHash: zeroHash,
      paramsHash: zeroHash,
      structHash:
        "0x8ad43b9eace85ce4ab9da203e0f0b71ed5b1dee54da8c6b6b86a4ce9eb810ae2",
      digest:
        "0x5d971d0218079cfe42273fc27f22a2d227b965a1ae457b89f3c6d878b86d0ae9",
    },
    {
      name: "program committed",
      nonce: 1n,
      validationProgramHash: PROGRAM_HASH,
      paramsHash: zeroHash,
      structHash:
        "0x656c3a96699b5e689814183305826793b81e87691cc45c7a31c81cd03b9bf9ea",
      digest:
        "0x7eb56e992428dd16af794cf84e51f12b416a7be60c0c6a1493eb8f493bd7cdf2",
    },
    {
      name: "program and params committed",
      nonce: 1n,
      validationProgramHash: PROGRAM_HASH,
      paramsHash: PARAMS_HASH,
      structHash:
        "0x0058850b10d018f3e294caeef84093c70363f0eac00e44da161bfdfa55fe58e9",
      digest:
        "0x7d4c914e187930b8426ba20a2b2d4bd7a3d883111efd559b9c173986e5e3c492",
    },
    {
      name: "perpetual nonce",
      nonce: 0n,
      validationProgramHash: PROGRAM_HASH,
      paramsHash: PARAMS_HASH,
      structHash:
        "0x64c06a5c077a048b072c23af9a59990a7ae44ab96018303c35572a59ef2cda61",
      digest:
        "0xbb50196d59d4056745bd48ce439a5a03ab4005655abbc5a540399b384c9e8715",
    },
  ] as const;

  for (const vector of vectors) {
    it(`matches the pinned struct hash and digest: ${vector.name}`, () => {
      const constraint: ExecutionConstraintV2 = {
        ...base,
        nonce: vector.nonce,
        validationProgramHash: vector.validationProgramHash,
        paramsHash: vector.paramsHash,
      };
      const structHash = hashStruct({
        types: ExecutionConstraintV2Typed,
        primaryType: "ExecutionConstraint",
        data: constraint,
      });
      expect(structHash).toBe(vector.structHash);
      expect(referenceStructHash(constraint)).toBe(vector.structHash);
      expect(constraintV2Digest(domain, constraint)).toBe(vector.digest);
    });
  }

  it("signs under domain version 2, so zero hashes never collide with v1", () => {
    expect(constraintV2Domain(domain).version).toBe("2");
    expect(constraintDomain(domain).version).toBe("1");
    const v2 = constraintV2Digest(domain, {
      ...base,
      validationProgramHash: zeroHash,
      paramsHash: zeroHash,
    });
    expect(v2).not.toBe(constraintDigest(domain, base));
  });

  it("hashes programs and params like LibValidationVM", () => {
    const program = `0x01${"aa".repeat(32)}02${"bb".repeat(32)}` as const;
    const params = [`0x${"11".repeat(32)}`, `0x${"22".repeat(32)}`] as const;
    expect(hashValidationProgram("0x")).toBe(zeroHash);
    expect(hashValidationProgram(program)).toBe(keccak256(program));
    expect(hashValidationParams([])).toBe(zeroHash);
    expect(hashValidationParams([...params])).toBe(keccak256(concat(params)));
    expect(() => hashValidationParams(["0x1234"])).toThrow(ValidationError);
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
