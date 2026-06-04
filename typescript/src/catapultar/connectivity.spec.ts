import { CatapultarAccount } from "./account";
import type { Owner } from "../types/types";

const ADDRESS = "0x1111111111111111111111111111111111111111" as const;
const OWNER: Owner = {
  type: "ecdsa",
  address: "0x2222222222222222222222222222222222222222",
};
const SALT = `0x${"00".repeat(32)}` as `0x${string}`;

const offlineAccount = () =>
  new CatapultarAccount({ address: ADDRESS, owner: OWNER });

describe("connectivity gating", () => {
  it("throws when reading without a client", () => {
    const account = offlineAccount();
    // @ts-expect-error read methods require a connected account (Connected=true)
    expect(() => account.publicClient()).toThrow();
  });

  it("connect() returns a new handle and leaves the original offline", () => {
    const offline = offlineAccount();
    const online = offline.connect({ chain: undefined } as never);
    expect(online).not.toBe(offline);
    // The original handle is still offline at runtime (non-mutating connect).
    // @ts-expect-error read methods require a connected account
    expect(() => offline.publicClient()).toThrow();
  });
});

/**
 * Compile-time gates. Never executed at runtime (exported but never called);
 * they exist so `tsc` enforces these invariants. If a gate stops holding its
 * `@ts-expect-error` becomes "unused" and the typecheck fails.
 */
export async function _connectivityTypeGates() {
  const offline = offlineAccount();
  // @ts-expect-error offline account cannot read on-chain (Connected=false)
  await offline.getPublicKey();
  // @ts-expect-error offline account cannot read on-chain (Connected=false)
  await offline.getNextValidNonce({ nonce: 1n });
  // @ts-expect-error offline account cannot validate its owner (Connected=false)
  await offline.validateOwner();

  // Once connected, the same reads type-check.
  const online = offline.connectRpc({
    rpc: "http://localhost:8545",
    chainId: 1,
  });
  await online.getPublicKey();
  await online.validateOwner();

  // The deploy option-bag is strict: misspelled / partial options fail to compile.
  // @ts-expect-error misspelled embed option
  CatapultarAccount.predict({ salt: SALT, owner: OWNER, callDigst: "0x" });
  CatapultarAccount.predict({
    salt: SALT,
    owner: OWNER,
    // @ts-expect-error partial digest (missing isSignature)
    digest: { hash: SALT },
  });
  CatapultarAccount.predict({
    salt: SALT,
    owner: OWNER,
    digest: { hash: SALT, isSignature: false },
  });
}
