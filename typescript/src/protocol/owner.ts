import { padEven } from "../utils/helpers";

/**
 * The owner of a Catapultar account, expressed in customer terms.
 *
 * A Catapultar account is controlled by exactly one of:
 * - `ecdsa`: a regular Ethereum address (EOA) or an ERC-1271 smart contract.
 * - `p256`: a raw P256 (secp256r1) public key, given as its `x` / `y` coordinates.
 * - `webauthn-p256`: a P256 key used through the WebAuthn signing flow.
 *
 * This discriminated union replaces the previous protocol-level `pubkey` /
 * `AccountPublicKeyType` pair: the `type` tag carries the shape, so callers no
 * longer have to remember which key type wants an address versus a coordinate
 * pair.
 */
export type EcdsaOwner = { type: "ecdsa"; address: `0x${string}` };
export type P256Owner = { type: "p256"; x: `0x${string}`; y: `0x${string}` };
export type WebAuthnOwner = {
  type: "webauthn-p256";
  x: `0x${string}`;
  y: `0x${string}`;
};

export type Owner = EcdsaOwner | P256Owner | WebAuthnOwner;

export type OwnerType = Owner["type"];

/** Narrow {@link Owner} to a single variant by its `type` tag. */
export type OwnerOf<T extends OwnerType> = Extract<Owner, { type: T }>;

/**
 * Internal-only mapping from the customer-facing owner type to the on-chain
 * numeric `PublicKeyType` enum. Mirrors `KeyedOwnable.sol`:
 * `enum PublicKeyType { ECDSAOrSmartContract = 0, P256 = 1, WebAuthnP256 = 2 }`.
 *
 * The `satisfies Record<OwnerType, 0 | 1 | 2>` makes the compiler enforce that
 * every owner variant is mapped — adding a variant without a mapping fails to
 * compile. These integers are load-bearing: they feed the factory salt
 * (`encodePacked`) and the deploy/transferOwnership ABI args, so a reorder here
 * would silently change every predicted CREATE2 address.
 */
const OWNER_TYPE_TO_ENUM = {
  ecdsa: 0,
  p256: 1,
  "webauthn-p256": 2,
} as const satisfies Record<OwnerType, 0 | 1 | 2>;

const ENUM_TO_OWNER_TYPE = {
  0: "ecdsa",
  1: "p256",
  2: "webauthn-p256",
} as const satisfies Record<0 | 1 | 2, OwnerType>;

/** Map an owner type to its on-chain `PublicKeyType` enum value. */
export function ownerTypeToEnum(type: OwnerType): 0 | 1 | 2 {
  return OWNER_TYPE_TO_ENUM[type];
}

/** Map an on-chain `PublicKeyType` enum value back to an owner type. */
export function enumToOwnerType(value: number): OwnerType {
  const type = ENUM_TO_OWNER_TYPE[value as 0 | 1 | 2];
  if (type === undefined) throw new Error(`Unknown public key type: ${value}`);
  return type;
}

/**
 * Number of 32-byte words a key occupies on-chain. Mirrors
 * `KeyedOwnable._keyTypeLength`: ECDSA -> 1, P256 -> 2, WebAuthnP256 -> 2.
 */
export function keyTypeLength(type: OwnerType): number {
  return type === "ecdsa" ? 1 : 2;
}

/**
 * Encode an ECDSA owner address into the single left-padded 32-byte word the
 * factory and `KeyedOwnable._isValidKey` (case 0) expect: the address occupies
 * the rightmost 20 bytes and the upper 12 bytes are zero. Accepts either a
 * 20-byte address or an already 32-byte left-padded word.
 */
function ecdsaAddressToWord(address: `0x${string}`): `0x${string}` {
  const raw = address.replace("0x", "");
  if (
    !(
      raw.length === 20 * 2 ||
      (raw.length === 32 * 2 &&
        raw.slice(0, 12 * 2) === "000000000000000000000000")
    )
  )
    throw new Error(`Owner address incorrectly formatted: ${address}`);
  // Mirror KeyedOwnable._isValidKey (case 0): the lower 20 bytes must be non-zero.
  // The zero address is only valid via the dedicated resignation path, never here.
  if (BigInt(`0x${raw}`) === 0n)
    throw new Error(`Owner address must be non-zero: ${address}`);
  return `0x${padEven(raw, 64)}`;
}

/**
 * Encode an {@link Owner} into the `bytes32[]` key array consumed by the
 * factory's `deploy` / `deployWithDigest`, by `transferOwnership(uint8,bytes32[])`,
 * and by `KeyedOwnable._isValidKey`.
 *
 * - `ecdsa`   -> one word: the address left-padded to 32 bytes.
 * - `p256` / `webauthn-p256` -> two words: `[x, y]`, passed through unchanged.
 */
export function ownerToKeyArray(owner: Owner): `0x${string}`[] {
  if (owner.type === "ecdsa") return [ecdsaAddressToWord(owner.address)];
  // Mirror KeyedOwnable._isValidKey (cases 1/2): both coordinate words must be non-zero.
  if (BigInt(owner.x) === 0n || BigInt(owner.y) === 0n)
    throw new Error(`${owner.type} owner coordinates must be non-zero`);
  return [owner.x, owner.y];
}

/**
 * Decode the raw `(keyType, bytes32[] key)` returned by the on-chain
 * `getPublicKey()` view into an {@link Owner}. The ECDSA case extracts the
 * rightmost 20 bytes and asserts the upper 12 are zero (mirroring
 * `KeyedOwnable._asAddressNotDirty`).
 */
export function keyArrayToOwner(
  keyType: number,
  key: readonly `0x${string}`[],
): Owner {
  const type = enumToOwnerType(keyType);
  if (type === "ecdsa") {
    const word = key[0];
    if (!word) throw new Error("Missing key word for ecdsa owner");
    const raw = word.replace("0x", "").padStart(64, "0");
    if (raw.slice(0, 12 * 2) !== "000000000000000000000000")
      throw new Error(`Dirty ethereum address: ${word}`);
    return { type: "ecdsa", address: `0x${raw.slice(12 * 2)}` };
  }
  const x = key[0];
  const y = key[1];
  if (!x || !y) throw new Error(`Missing key words for ${type} owner`);
  return { type, x, y };
}

/** Structural, case-insensitive equality of two owners. */
export function ownersEqual(a: Owner, b: Owner): boolean {
  if (a.type !== b.type) return false;
  if (a.type === "ecdsa") {
    return (
      b.type === "ecdsa" && a.address.toLowerCase() === b.address.toLowerCase()
    );
  }
  return (
    b.type !== "ecdsa" &&
    a.x.toLowerCase() === b.x.toLowerCase() &&
    a.y.toLowerCase() === b.y.toLowerCase()
  );
}
