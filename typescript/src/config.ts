import type { Factory, MaybeFactory } from "./types/types";

export const factories = {
  "0.1.0": "0x92cEf6f87b4350C9ebA3D73A97b251b41D4AA348",
} as const;
export const templates = {
  "0.1.0": "0xD57dEeEaBb0d4Dd2c8421DB036aC2225E54Cd9cC",
} as const;

export const PUBLIC_DEFAULT_ANVIL_ACCOUNT_0 =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

export const cat_validator = "0x40099B52ed0dE7423Dbfb7B891750501AD1500F0";

export const token1 = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0";
export const token2 = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9";
export const token3 = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9";

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
