import type { Factory } from "./types/types";

/** The library's well-known default factory/template pair. */
export const defaultFactory: Factory = {
  factory: "0x1640C69CE5b44A6127FcaCD92727e7df2d73AA3D",
  template: "0xc493Dbb75d30967A5feeA8e5e1c2bb5aFeb0e99e",
};

/** Deployed `CATValidator` address used as the default constraint validator. */
export const cat_validator = "0xf44cBb09C5b32cdFC1049464ba632B59E25EC00E";

/** Resolve the factory/template pair to use, defaulting to the library's well-known pair. */
export function _factory(opt: { factory?: Factory }): Factory {
  // `Factory` requires both keys, so the compiler already enforces both-or-neither.
  return opt.factory ?? defaultFactory;
}
