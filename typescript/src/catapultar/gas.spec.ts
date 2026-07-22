import type { Owner, OwnerType } from "../types/types";
import {
  ESTIMATE_GAS_MARGIN_PERCENT,
  SIGNED_PATH_GAS_OVERHEAD,
  SIGNED_PATH_GAS_OVERHEAD_WITH_P256_PRECOMPILE,
  applyCodeOverrideMargin,
  applyEstimateGasMargin,
} from "./gas";

const estimate = 1_000_000n;

describe("applyCodeOverrideMargin", () => {
  it.concurrent("adds the proportional margin", () => {
    expect(applyCodeOverrideMargin(estimate)).toBe(
      estimate + (estimate * ESTIMATE_GAS_MARGIN_PERCENT) / 100n,
    );
  });

  it.concurrent("rounds the proportional margin upward", () => {
    // 1n * 10% = 0.1 -> ceil to 1n.
    expect(applyCodeOverrideMargin(1n)).toBe(2n);
    // Exact multiples do not over-round: 100n * 10% = 10n.
    expect(applyCodeOverrideMargin(100n)).toBe(110n);
  });

  it.concurrent("handles a zero estimate", () => {
    expect(applyCodeOverrideMargin(0n)).toBe(0n);
  });

  it.concurrent("rejects negative inputs", () => {
    expect(() => applyCodeOverrideMargin(-1n)).toThrow(
      "Estimate must be non-negative",
    );
  });
});

describe("applyEstimateGasMargin", () => {
  const ownerTypes: OwnerType[] = ["ecdsa", "p256", "webauthn-p256"];

  it.concurrent.each(ownerTypes)(
    "applies the conservative table for %s",
    (type) => {
      expect(applyEstimateGasMargin(estimate, type)).toBe(
        estimate + SIGNED_PATH_GAS_OVERHEAD[type],
      );
    },
  );

  it.concurrent.each(ownerTypes)(
    "applies the precompile table for %s when p256Precompile is set",
    (type) => {
      expect(
        applyEstimateGasMargin(estimate, type, { p256Precompile: true }),
      ).toBe(estimate + SIGNED_PATH_GAS_OVERHEAD_WITH_P256_PRECOMPILE[type]);
    },
  );

  it.concurrent("accepts an Owner object as well as a type tag", () => {
    const owner: Owner = {
      type: "p256",
      x: `0x${"11".repeat(32)}`,
      y: `0x${"22".repeat(32)}`,
    };
    expect(applyEstimateGasMargin(estimate, owner)).toBe(
      applyEstimateGasMargin(estimate, "p256"),
    );
  });

  it.concurrent(
    "signatureValidationGas replaces the owner-type default",
    () => {
      expect(
        applyEstimateGasMargin(estimate, "webauthn-p256", {
          signatureValidationGas: 1_000_000n,
        }),
      ).toBe(estimate + 1_000_000n);
      expect(
        applyEstimateGasMargin(estimate, "ecdsa", {
          signatureValidationGas: 0n,
        }),
      ).toBe(estimate);
    },
  );

  it.concurrent("handles a zero estimate", () => {
    expect(applyEstimateGasMargin(0n, "ecdsa")).toBe(
      SIGNED_PATH_GAS_OVERHEAD.ecdsa,
    );
  });

  it.concurrent("rejects negative inputs", () => {
    expect(() => applyEstimateGasMargin(-1n, "ecdsa")).toThrow(
      "Estimate must be non-negative",
    );
    expect(() =>
      applyEstimateGasMargin(estimate, "ecdsa", {
        signatureValidationGas: -1n,
      }),
    ).toThrow("signatureValidationGas must be non-negative");
  });

  it.concurrent("rejects an unknown owner type", () => {
    expect(() =>
      applyEstimateGasMargin(estimate, "ed25519" as OwnerType),
    ).toThrow("Unknown owner type");
  });

  it.concurrent("covers every owner type in both tables", () => {
    for (const table of [
      SIGNED_PATH_GAS_OVERHEAD,
      SIGNED_PATH_GAS_OVERHEAD_WITH_P256_PRECOMPILE,
    ]) {
      expect([...Object.keys(table)].sort()).toEqual([...ownerTypes].sort());
    }
  });
});
