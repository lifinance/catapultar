// Per-subdir package.json markers, mirroring the ox/viem packaging convention.
// The root package.json declares no "type" field — Node defaults to CommonJS
// at the package root. These markers override that default within each
// subtree:
//   _esm/package.json → {"type":"module"}    so .js files there load as ESM
//   _cjs/package.json → {"type":"commonjs"}  explicit; matches root default
import fs from "node:fs/promises";
import path from "node:path";

// `sideEffects: false` on the _esm marker is NOT redundant with the root
// package.json: bundlers resolve `sideEffects` from the package.json *nearest*
// to a module, and modules under _esm/ find this marker, not the root. It is
// what enables tree-shaking of the ESM build. The _cjs marker omits it (CJS is
// not tree-shaken). This mirrors ox/viem exactly.
const markers = [
  ["_esm", { type: "module", sideEffects: false }],
  ["_cjs", { type: "commonjs" }],
];

await Promise.all(
  markers.map(async ([dir, contents]) => {
    const target = path.resolve(dir, "package.json");
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, JSON.stringify(contents) + "\n");
  }),
);
