// Test-only fixtures. Lives under `test/` (outside `tsconfig.build.json`'s
// `rootDir: ./src` and the package `files` allowlist) so the well-known Anvil dev key
// and fixture addresses never ship in `src/`, `_types/`, or the source maps.

/** Private key of anvil's default account 0 (test convenience only — public, do not fund). */
export const PUBLIC_DEFAULT_ANVIL_ACCOUNT_0: `0x${string}` =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/** Test fixture token addresses (deterministic anvil deployments). */
export const token1: `0x${string}` =
  "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6";
export const token2: `0x${string}` =
  "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318";
export const token3: `0x${string}` =
  "0x610178dA211FEF7D417bC0e6FeD39F05609AD788";
