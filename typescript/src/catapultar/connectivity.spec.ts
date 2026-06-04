import { CatapultarAccount } from "./account";

const offlineAccount = () =>
  new CatapultarAccount({
    address: "0x1111111111111111111111111111111111111111",
    owner: {
      type: "ecdsa",
      address: "0x2222222222222222222222222222222222222222",
    },
  });

describe("connectivity gating", () => {
  it("throws when reading without a client", () => {
    const account = offlineAccount();
    // @ts-expect-error read methods require a connected account (Connected=true)
    expect(() => account.publicClient()).toThrow();
  });
});

/**
 * Compile-time gate checks. Never executed at runtime (the function is exported
 * but never called); they exist so `tsc` enforces that read methods are only
 * callable on a connected account. If the `Connected` marker stops gating, the
 * `@ts-expect-error` directives below become "unused" and the typecheck fails.
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
}
