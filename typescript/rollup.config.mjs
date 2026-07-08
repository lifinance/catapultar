// Dual-format build mirroring the ox/viem layout: path-preserved sources are
// emitted to `_esm/` and `_cjs/` at the package root. Per-subdir
// `package.json` markers (written by scripts/write-subdir-markers.mjs) flip
// the module type per subtree. Declarations are emitted separately by tsc.
import esbuild from "rollup-plugin-esbuild";
import pkg from "./package.json" with { type: "json" };

// Externalise every runtime dep (and any subpath under it, e.g. `viem/chains`)
// so consumers' deduplication keeps working. Node built-ins (`node:*`) are
// externalised too for safety.
const depNames = [
  ...Object.keys(pkg.dependencies ?? {}),
  ...Object.keys(pkg.peerDependencies ?? {}),
];
const isExternal = (id) =>
  id.startsWith("node:") ||
  depNames.some((dep) => id === dep || id.startsWith(`${dep}/`));

export default {
  // Single entry point: `preserveModules` walks the import graph from here and
  // emits one output file per reachable source module (path-preserved). Only
  // the `.` export is published today, so this is sufficient. If subpath
  // exports are added later (`catapultar/abi`, …), add their entry modules here
  // and extend the `exports` map in package.json accordingly.
  input: "src/index.ts",
  external: isExternal,
  output: [
    {
      dir: "_esm",
      format: "esm",
      preserveModules: true,
      preserveModulesRoot: "src",
      entryFileNames: "[name].js",
      sourcemap: true,
    },
    {
      dir: "_cjs",
      format: "cjs",
      preserveModules: true,
      preserveModulesRoot: "src",
      entryFileNames: "[name].js",
      sourcemap: true,
      // `named` prevents rollup from synthesising a default-export wrapper
      // that CJS callers would have to unwrap with `.default`.
      exports: "named",
    },
  ],
  plugins: [
    esbuild({
      // Keep in sync with `target` in tsconfig.base.json. esbuild does NOT read
      // `target` from a tsconfig (esbuild's `tsconfigRaw` only honours a subset
      // of options, and `target` is not among them), so it must be set here
      // explicitly — tsc and rollup are two independent knobs on the same value.
      target: "es2021",
      sourceMap: true,
      tsconfig: "tsconfig.base.json",
    }),
  ],
};
