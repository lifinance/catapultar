import { describe, expect, it } from "bun:test";
import {
  hashStruct,
  hashTypedData,
  toFunctionSelector,
  zeroAddress,
  zeroHash,
} from "viem";
import { CAT_VALIDATOR_V1_1_ABI } from "../abi/CATValidatorV1_1";
import {
  factorySalt,
  factorySaltWithDigest,
  predictCloneAddress,
} from "./factory";
import fixture from "../../test/fixtures/sca-parity.v1_1.vectors.json";

type Hex = `0x${string}`;
type FixtureConstraint = (typeof fixture.vectors)[number]["execute"];

const KECCAK_EMPTY =
  "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

const V1_1_TYPES = {
  ExecutionConstraint: [
    { name: "allowances", type: "Allowance[]" },
    { name: "outcomes", type: "Outcome[]" },
    { name: "executor", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "executionTarget", type: "address" },
    { name: "payloadHash", type: "bytes32" },
  ],
  Allowance: [
    { name: "token", type: "address" },
    { name: "amount", type: "uint256" },
  ],
  Outcome: [
    { name: "token", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "destination", type: "address" },
  ],
} as const;

const domain = {
  name: fixture.domain.name,
  version: fixture.domain.version,
  chainId: fixture.domain.chainId,
  verifyingContract: fixture.domain.verifyingContract as Hex,
} as const;

function messageOf(c: FixtureConstraint) {
  return {
    allowances: c.allowances.map((a) => ({
      token: a.token as Hex,
      amount: BigInt(a.amount),
    })),
    outcomes: c.outcomes.map((o) => ({
      token: o.token as Hex,
      amount: BigInt(o.amount),
      destination: o.destination as Hex,
    })),
    executor: fixture.executor as Hex,
    nonce: BigInt(c.nonce),
    executionTarget: c.executionTarget as Hex,
    payloadHash: c.payloadHash as Hex,
  };
}

describe("sca-parity v1.1 fixture", () => {
  it("is the v1.1 vector set", () => {
    expect(fixture.schema).toBe("c2-sca-parity-v1_1/v1");
    expect(fixture.domain.name).toBe("CAT Validator");
    expect(fixture.domain.version).toBe("1.1");
  });

  for (const vector of fixture.vectors) {
    describe(vector.name, () => {
      it("execute commits the sentinels on a non-zero nonce", () => {
        expect(vector.execute.executionTarget).toBe(zeroAddress);
        expect(vector.execute.payloadHash).toBe(zeroHash);
        expect(BigInt(vector.execute.nonce)).not.toBe(0n);
      });

      it("refund commits the refund address and keccak256('') on nonce 0", () => {
        expect(vector.refund.nonce).toBe("0");
        expect(vector.refund.executionTarget).toBe(fixture.refundAddress);
        expect(vector.refund.payloadHash).toBe(KECCAK_EMPTY);
      });

      it("struct hashes and digests match", () => {
        for (const [c, structHash, digest] of [
          [
            vector.execute,
            vector.expected.executeStructHash,
            vector.expected.executeDigest,
          ],
          [
            vector.refund,
            vector.expected.refundStructHash,
            vector.expected.refundDigest,
          ],
        ] as const) {
          expect(
            hashStruct({
              data: messageOf(c),
              primaryType: "ExecutionConstraint",
              types: V1_1_TYPES,
            }),
          ).toBe(structHash as Hex);
          expect(
            hashTypedData({
              domain,
              primaryType: "ExecutionConstraint",
              types: V1_1_TYPES,
              message: messageOf(c),
            }),
          ).toBe(digest as Hex);
        }
      });

      it("the execute digest reproduces the escrow through the factory salt", () => {
        const ownerKey: Hex = `0x${vector.salt.slice(2, 42).padStart(64, "0")}`;
        const salted = factorySaltWithDigest(
          factorySalt(vector.salt as Hex, 0, [ownerKey]),
          vector.expected.executeDigest as Hex,
          vector.flavorNonce === 2,
        );
        expect(salted).toBe(vector.expected.saltWithDigest as Hex);
        expect(
          predictCloneAddress({
            template: fixture.clone.executorImpl as Hex,
            salt: salted,
            factory: fixture.clone.factory as Hex,
          }),
        ).toBe(vector.expected.escrow as Hex);
      });
    });
  }
});

describe("v1.1 ABI", () => {
  const functions = CAT_VALIDATOR_V1_1_ABI.filter((i) => i.type === "function");

  it("has the 9-argument entry with the committed words before signature", () => {
    const entry = functions.find(
      (i) => i.name === "entry" && i.inputs.length === 9,
    )!;
    expect(toFunctionSelector(entry)).toBe("0x6e84b055");
    expect(entry.inputs.slice(6).map((i) => i.name)).toEqual([
      "executionTarget",
      "payloadHash",
      "signature",
    ]);
  });

  it("keeps the base's 7-argument entry", () => {
    const entry = functions.find(
      (i) => i.name === "entry" && i.inputs.length === 7,
    )!;
    expect(toFunctionSelector(entry)).toBe("0xe5ce4787");
  });

  it("adds pulled and entryId", () => {
    const selector = (name: string) =>
      toFunctionSelector(functions.find((i) => i.name === name)!);
    expect(selector("pulled")).toBe("0x6ea6f87f");
    expect(selector("entryId")).toBe("0xd323e74d");
  });

  it("carries the commitment errors and the base's receive", () => {
    const errors = CAT_VALIDATOR_V1_1_ABI.filter((i) => i.type === "error").map(
      (i) => i.name,
    );
    expect(errors).toContain("TargetNotCommitted");
    expect(errors).toContain("PayloadNotCommitted");
    expect(errors).toContain("ZeroDestination");
    expect(errors).toContain("BalanceOfFailed");
    expect(CAT_VALIDATOR_V1_1_ABI.some((i) => i.type === "receive")).toBe(true);
  });
});
