import { getCreate2Address, keccak256, encodePacked } from "viem";

/**
 * CREATE2 salt derivation for the Catapultar factory.
 *
 * Mirrors `CatapultarFactory._salt`:
 * `keccak256(preSalt || ktp(1 byte) || numOwners(1 byte) || key[0] || ... || key[n])`,
 * and the digest variant appended for `deployWithDigest`.
 */

/**
 * Clone strategy used by the factory.
 * - `clone`: Solady minimal PUSH0 proxy (`deploy` / `deployWithDigest`). Cheapest,
 *   immutable. This is the default for {@link DeployOptions}.
 * - `upgradeable`: Solady minimal ERC-1967 proxy (`deployUpgradeable`). Durable;
 *   the owner can later call `upgradeToAndCall`. Cannot embed a digest (the
 *   factory's `deployWithDigest` only mints PUSH0 clones).
 */
export type DeployKind = "clone" | "upgradeable";

/**
 * Init code of the Solady minimal PUSH0 proxy for `implementation`.
 * Mirrors `LibClone.cloneDeterministic_PUSH0` (used by `CatapultarFactory.deploy`).
 */
export function pushZeroCloneInitCode(
  implementation: `0x${string}`,
): `0x${string}` {
  return `0x602d5f8160095f39f35f5f365f5f37365f73${implementation
    .replace("0x", "")
    .toLowerCase()}5af43d5f5f3e6029573d5ffd5b3d5ff3`;
}

/**
 * Init code of the Solady minimal ERC-1967 proxy for `implementation`.
 * Mirrors `LibClone.initCodeERC1967` (used by
 * `CatapultarFactory.deployUpgradeable`). Verified byte-identical against
 * `LibClone.initCodeHashERC1967` in the Foundry suite.
 */
export function erc1967CloneInitCode(
  implementation: `0x${string}`,
): `0x${string}` {
  return `0x603d3d8160223d3973${implementation
    .replace("0x", "")
    .toLowerCase()}600951${"55f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3"}`;
}

/**
 * Predict the CREATE2 address a clone of `template` deploys to from `factory`
 * with `salt`. Selects the PUSH0 or ERC-1967 init code by {@link DeployKind} so
 * a single call covers both `deploy*` and `deployUpgradeable` strategies.
 */
export function predictCloneAddress(options: {
  template: `0x${string}`;
  salt: `0x${string}`;
  factory: `0x${string}`;
  kind?: DeployKind;
}): `0x${string}` {
  const { template, salt, factory, kind = "clone" } = options;
  const initCode =
    kind === "upgradeable"
      ? erc1967CloneInitCode(template)
      : pushZeroCloneInitCode(template);
  return getCreate2Address({
    bytecodeHash: keccak256(initCode),
    salt,
    from: factory,
  });
}

/**
 * Inner factory salt over the key array.
 * @param preSalt Caller-provided salt.
 * @param ktp Numeric `PublicKeyType` enum value.
 * @param keyArray Owner key encoded as `bytes32[]` (see `ownerToKeyArray`).
 */
export function factorySalt(
  preSalt: `0x${string}`,
  ktp: number,
  keyArray: `0x${string}`[],
): `0x${string}` {
  const numOwners = keyArray.length;
  const types = [
    "bytes32",
    "uint8",
    "uint8",
    ...keyArray.map((): "bytes32" => "bytes32"),
  ] as const;
  const values = [preSalt, ktp, numOwners, ...keyArray] as const;
  return keccak256(
    encodePacked(types as unknown as string[], values as unknown as unknown[]),
  );
}

/**
 * Final salt for an account deployed with an embedded digest:
 * `keccak256(internalSalt || digest || uint256(isSignature ? 2 : 1))`.
 */
export function factorySaltWithDigest(
  internalSalt: `0x${string}`,
  callDigest: `0x${string}`,
  isSignature: boolean,
): `0x${string}` {
  return keccak256(
    encodePacked(
      ["bytes32", "bytes32", "uint256"],
      [internalSalt, callDigest, isSignature ? 2n : 1n],
    ),
  );
}
