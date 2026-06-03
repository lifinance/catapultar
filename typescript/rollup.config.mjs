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
      target: "es2021",
      sourceMap: true,
      tsconfig: "tsconfig.base.json",
    }),
  ],
};
