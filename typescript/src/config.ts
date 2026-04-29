import type { Factory, MaybeFactory } from "./types/types";

export const factories = {
  "0.1.0": "0x1640C69CE5b44A6127FcaCD92727e7df2d73AA3D",
} as const;
export const templates = {
  "0.1.0": "0xc493Dbb75d30967A5feeA8e5e1c2bb5aFeb0e99e",
} as const;

export const PUBLIC_DEFAULT_ANVIL_ACCOUNT_0 =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

export const cat_validator = "0xf44cBb09C5b32cdFC1049464ba632B59E25EC00E";

export const token1 = "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6";
export const token2 = "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318";
export const token3 = "0x610178dA211FEF7D417bC0e6FeD39F05609AD788";

export function _factory(opt: MaybeFactory): Factory {
  // Ensure that if one key is set, both are set.
  if ("factory" in opt || "template" in opt) {
    if ("factory" in opt && "template" in opt) return opt as Factory;
    throw new Error("Factory and template incorrectly set.");
  }
  return {
    factory: factories["0.1.0"],
    template: templates["0.1.0"],
  };
}
