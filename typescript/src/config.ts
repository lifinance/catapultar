import type { Factory } from "./types/types";

/** The library's well-known default factory/template pair. */
export const defaultFactory: Factory = {
  factory: "0x1640C69CE5b44A6127FcaCD92727e7df2d73AA3D",
  template: "0xc493Dbb75d30967A5feeA8e5e1c2bb5aFeb0e99e",
};

/** Private key of anvil's default account 0 (test convenience only — public, do not fund). */
export const PUBLIC_DEFAULT_ANVIL_ACCOUNT_0 =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/** Deployed `CATValidator` address used as the default constraint validator. */
export const cat_validator = "0xf44cBb09C5b32cdFC1049464ba632B59E25EC00E";

/** Test fixture token addresses (deterministic anvil deployments). */
export const token1 = "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6";
export const token2 = "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318";
export const token3 = "0x610178dA211FEF7D417bC0e6FeD39F05609AD788";

/** Resolve the factory/template pair to use, defaulting to the library's well-known pair. */
export function _factory(opt: { factory?: Factory }): Factory {
  // `Factory` requires both keys, so the compiler already enforces both-or-neither.
  return opt.factory ?? defaultFactory;
}
