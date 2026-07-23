import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Hex } from "viem";
import { CATAPULTAR_ACCOUNT_RUNTIME_CODE } from "./catapultar";
import {
  dirtyStateTargetBytecode,
  gasEstimateTargetBytecode,
} from "../../test/mock-bytecode";

const solidityOut = join(import.meta.dir, "../../../solidity/out");

function forgeArtifact(name: string): { path: string; json?: any } {
  const path = join(solidityOut, `${name}.sol`, `${name}.json`);
  if (!existsSync(path)) return { path };
  return { path, json: JSON.parse(readFileSync(path, "utf8")) };
}

/**
 * Guards the hand-embedded bytecode constants against drifting from the
 * Solidity sources they were copied from. Requires `forge build` output in
 * solidity/out; when the artifacts are absent (e.g. the TypeScript-only CI
 * job, which does not check out submodules), the checks are skipped.
 */
describe("embedded bytecode matches forge artifacts", () => {
  const cases: {
    name: string;
    embedded: Hex;
    // Catapultar is compared against runtime (deployed) code used for RPC
    // state overrides; the test mocks are deployed from creation code.
    field: "deployedBytecode" | "bytecode";
  }[] = [
    {
      name: "Catapultar",
      embedded: CATAPULTAR_ACCOUNT_RUNTIME_CODE,
      field: "deployedBytecode",
    },
    {
      name: "GasEstimateTarget",
      embedded: gasEstimateTargetBytecode,
      field: "bytecode",
    },
    {
      name: "DirtyStateTarget",
      embedded: dirtyStateTargetBytecode,
      field: "bytecode",
    },
  ];

  for (const { name, embedded, field } of cases) {
    const { json } = forgeArtifact(name);
    test.skipIf(!json)(`${name} ${field} is in sync`, () => {
      expect(embedded).toBe(json[field].object);
    });
  }
});
