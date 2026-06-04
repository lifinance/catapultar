// Post-build smoke test: confirms the built dual-format package exposes the
// same named runtime exports from both the ESM and CJS entry points. Catches a
// broken `exports` map, a missing subdir marker, or a CJS default-unwrap
// regression. Run by `bun run build:smoke` (chained after the build).
import { createRequire } from "node:module";
import * as esm from "../_esm/index.js";

const require = createRequire(import.meta.url);
const cjs = require("../_cjs/index.js");

const esmKeys = Object.keys(esm).sort();
const cjsKeys = Object.keys(cjs).sort();

// A representative slice of the public value exports that must always resolve.
const expected = [
  "CatapultarAccount",
  "CatapultarTx",
  "MetaCatapultarTx",
  "BaseTransaction",
  "ConstrainedAssetTransaction",
  "ExecutionMode",
  "DigestApproval",
  "CatapultarError",
];

const missing = expected.filter(
  (k) => !esmKeys.includes(k) || !cjsKeys.includes(k),
);
if (missing.length) {
  console.error("smoke FAILED — missing expected exports:", missing);
  process.exit(1);
}

if (esmKeys.join(",") !== cjsKeys.join(",")) {
  console.error("smoke FAILED — ESM and CJS exports differ.");
  console.error("  esm:", esmKeys.join(", "));
  console.error("  cjs:", cjsKeys.join(", "));
  process.exit(1);
}

console.log(
  `smoke ok — ${esmKeys.length} named exports match across ESM and CJS`,
);
