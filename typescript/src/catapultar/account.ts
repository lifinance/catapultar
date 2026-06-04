import {
  createPublicClient,
  decodeAbiParameters,
  encodeFunctionData,
  getCreate2Address,
  http,
  keccak256,
  parseAbiParameters,
  recoverAddress,
  zeroAddress,
  type PublicClient,
} from "viem";
import {
  DigestApproval,
  type AccountConstructorParams,
  type Call,
  type EmbeddedCall,
  type KeyedSignature,
  type MaybeFactory,
  type Owner,
  type OwnerOf,
  type Version,
} from "../types/types";
import { getViemChainId } from "../utils/viem";
import CATAPULTAR_V0_1_0_ABI from "../abi/catapultarV0.1.0";
import CATAPULTAR_FACTORY_V0_1_0_ABI from "../abi/catapultarFactoryV0.1.0";
import {
  keyArrayToOwner,
  ownersEqual,
  ownerToKeyArray,
  ownerTypeToEnum,
} from "../protocol/owner";
import { factorySalt, factorySaltWithDigest } from "../protocol/factory";
import {
  fromCompactSignature,
  normalizeSignature,
} from "../protocol/signature";
import type { CatapultarDomain } from "../protocol/calls";
import { P256, PublicKey, WebAuthnP256 } from "ox";
import { _factory } from "../config";

/**
 * A Catapultar smart account.
 *
 * The account is identified by its {@link Owner} (an ECDSA address, or a P256 /
 * WebAuthn public key). It is offline by default; attach a viem client with
 * {@link CatapultarAccount.connect} (or {@link CatapultarAccount.connectRpc})
 * to unlock on-chain reads. The `Connected` type parameter records, at compile
 * time, whether a client is attached so read methods are only callable once it is.
 *
 * @typeParam O The owner variant controlling this account.
 * @typeParam Connected Whether a viem client is attached (read methods require `true`).
 */
export class CatapultarAccount<
  O extends Owner = Owner,
  Connected extends boolean = false,
> {
  /** Address of the smart account itself (not the owner key). */
  readonly address: `0x${string}`;
  /** ChainId of the account. Used for the single-chain domain separator. */
  chainId: number | undefined;

  /** Name of the account. Used for the domainSeparator. */
  readonly name: string;
  /** Version of the account. Used for the domainSeparator. */
  readonly version: Version;

  /** Owner of the account (ECDSA address or P256/WebAuthn public key). */
  readonly owner: O;

  /** Attached viem client used for on-chain reads, if any. */
  private _client: PublicClient | undefined;

  /**
   * Phantom marker — never assigned at runtime. It makes `Connected` part of the
   * structural type so `CatapultarAccount<O, false>` and `CatapultarAccount<O, true>`
   * are not interchangeable, which is what lets the `this: CatapultarAccount<O, true>`
   * annotations actually reject reads on a not-yet-connected account.
   */
  declare readonly __connected: Connected;

  constructor(options: AccountConstructorParams<O>) {
    const {
      address,
      owner,
      chainId,
      name = "Catapultar",
      version = "0.1.0",
      client,
      rpc,
    } = options;

    // Owner definition / validation. The discriminated union already guarantees
    // the field shapes, so this only guards against malformed runtime values.
    if (owner.type === "ecdsa") {
      if (!owner.address) throw new Error("ecdsa owner requires an address");
    } else if (owner.type === "p256" || owner.type === "webauthn-p256") {
      if (!owner.x || !owner.y)
        throw new Error(`${owner.type} owner requires x and y coordinates`);
    } else {
      throw new Error(
        `Unknown owner type: ${(owner as { type: string }).type}`,
      );
    }

    this.address = address;
    this.owner = owner;
    this.name = name;
    this.version = version;

    // Connectivity (Finding 4): accept a viem client directly, or build one
    // from an rpc + chainId convenience pair.
    this.chainId = chainId;
    if (client) {
      this._client = client;
      if (this.chainId === undefined) this.chainId = client.chain?.id;
    } else if (rpc) {
      this._client = createPublicClient({
        chain: chainId !== undefined ? getViemChainId(chainId) : undefined,
        transport: http(rpc),
      });
    }
  }

  static deploy<O extends Owner>(
    options: {
      salt: `0x${string}`;
      owner: O;
    } & MaybeFactory &
      ({} | EmbeddedCall),
  ): { call: Call; account: CatapultarAccount<O, false> } {
    let callDigest: `0x${string}` | undefined = undefined;
    let isSignature: boolean | undefined = undefined;
    if ("callDigest" in options && "isSignature" in options) {
      callDigest = options.callDigest;
      isSignature = options.isSignature;
    }

    const { factory } = _factory(options);
    // predict() performs the same `callDigest`/`isSignature` check internally.
    const derivedAddress = CatapultarAccount.predict(options);

    const keyType = ownerTypeToEnum(options.owner.type);
    const keyArray = ownerToKeyArray(options.owner);
    const call: Call = {
      to: factory,
      data: callDigest
        ? encodeFunctionData({
            abi: CATAPULTAR_FACTORY_V0_1_0_ABI,
            functionName: "deployWithDigest",
            args: [
              keyType,
              keyArray,
              options.salt,
              callDigest,
              isSignature as boolean,
            ],
          })
        : encodeFunctionData({
            abi: CATAPULTAR_FACTORY_V0_1_0_ABI,
            functionName: "deploy",
            args: [keyType, keyArray, options.salt],
          }),
      value: 0n,
    };

    return {
      call,
      account: new CatapultarAccount<O, false>({
        address: derivedAddress,
        owner: options.owner,
      }),
    };
  }

  private static deriveCloneAddress(
    executor: `0x${string}`,
    salt: `0x${string}`,
    factory: `0x${string}`,
  ) {
    // https://github.com/Vectorized/solady/blob/90db92ce173856605d24a554969f2c67cadbc7e9/src/utils/LibClone.sol#L366-L368
    const initCode = ("0x602d5f8160095f39f35f5f365f5f37365f73" +
      executor.replace("0x", "") +
      "5af43d5f5f3e6029573d5ffd5b3d5ff3") as `0x${string}`;
    const initCodeHash = keccak256(initCode);
    return getCreate2Address({
      bytecodeHash: initCodeHash,
      salt,
      from: factory,
    });
  }

  static predict<O extends Owner>(
    opt: {
      salt: `0x${string}`;
      owner: O;
    } & MaybeFactory &
      ({} | EmbeddedCall),
  ) {
    const { salt } = opt;
    const { factory, template } = _factory(opt);
    const keyArray = ownerToKeyArray(opt.owner);

    const internalSalt = factorySalt(
      salt,
      ownerTypeToEnum(opt.owner.type),
      keyArray,
    );

    if ("callDigest" in opt && "isSignature" in opt) {
      const finalSalt = factorySaltWithDigest(
        internalSalt,
        opt.callDigest,
        opt.isSignature,
      );
      return CatapultarAccount.deriveCloneAddress(template, finalSalt, factory);
    }
    return CatapultarAccount.deriveCloneAddress(
      template,
      internalSalt,
      factory,
    );
  }

  // --- Connectivity (Finding 4) --- //

  /**
   * Attach a viem `PublicClient`, enabling on-chain reads. Returns the
   * account narrowed to the connected type — use the returned value.
   */
  connect(client: PublicClient): CatapultarAccount<O, true> {
    this._client = client;
    if (this.chainId === undefined) this.chainId = client.chain?.id;
    return this as unknown as CatapultarAccount<O, true>;
  }

  /**
   * Convenience: build a `PublicClient` from an RPC URL + chainId and attach it.
   */
  connectRpc(options: {
    rpc: string;
    chainId: number;
  }): CatapultarAccount<O, true> {
    this.chainId = options.chainId;
    return this.connect(
      createPublicClient({
        chain: getViemChainId(options.chainId),
        transport: http(options.rpc),
      }),
    );
  }

  /** The attached viem client. Throws if the account is not connected. */
  publicClient(this: CatapultarAccount<O, true>): PublicClient {
    if (!this._client)
      throw new Error(
        "No client attached. Call connect() or connectRpc() first.",
      );
    return this._client;
  }

  abi(): typeof CATAPULTAR_V0_1_0_ABI {
    return CATAPULTAR_V0_1_0_ABI;
  }

  // --- Type guards --- //

  isConnected(): this is CatapultarAccount<O, true> {
    return this._client !== undefined;
  }

  isEcdsa(): this is CatapultarAccount<OwnerOf<"ecdsa">, Connected> {
    return this.owner.type === "ecdsa";
  }

  isP256(): this is CatapultarAccount<OwnerOf<"p256">, Connected> {
    return this.owner.type === "p256";
  }

  isWebAuthn(): this is CatapultarAccount<OwnerOf<"webauthn-p256">, Connected> {
    return this.owner.type === "webauthn-p256";
  }

  /**
   * Normalize a keyed signature into the on-chain wire format for this owner.
   * Delegates to the centralized protocol encoder.
   */
  parseSignature(signature: KeyedSignature<O>): `0x${string}` {
    return normalizeSignature(this.owner, signature as KeyedSignature<Owner>);
  }

  // --- Writing Functions (build calls) --- //

  /**
   * Build a call that approves a digest on the account (`setSignature`). Use
   * {@link DigestApproval.Call} for an embedded call digest or
   * {@link DigestApproval.Signature} for a pre-approved message hash.
   *
   * Requires the account owner (or a self-call inside an executed batch).
   */
  buildApproveDigestCall(options: {
    digest: `0x${string}`;
    approval: DigestApproval;
  }): Call {
    return {
      to: this.address,
      value: 0n,
      data: encodeFunctionData({
        abi: CATAPULTAR_V0_1_0_ABI,
        functionName: "setSignature",
        args: [options.digest, options.approval],
      }),
    };
  }

  /**
   * Build a call that transfers ownership to a new {@link Owner}. Requires the
   * current owner (or a self-call inside an executed batch).
   *
   * Normal handovers use the `transferOwnership(uint8, bytes32[])` overload so
   * every key type flows through one path. To resign ownership, pass
   * `{ type: "ecdsa", address: <zero address> }` — that is routed through the
   * `transferOwnership(address)` overload, the only on-chain path that accepts a
   * zero owner (the keyed overload would revert `InvalidKey`).
   */
  buildTransferOwnershipCall(options: { newOwner: Owner }): Call {
    const { newOwner } = options;
    const data =
      newOwner.type === "ecdsa" && BigInt(newOwner.address) === 0n
        ? encodeFunctionData({
            abi: CATAPULTAR_V0_1_0_ABI,
            functionName: "transferOwnership",
            args: [zeroAddress],
          })
        : encodeFunctionData({
            abi: CATAPULTAR_V0_1_0_ABI,
            functionName: "transferOwnership",
            args: [ownerTypeToEnum(newOwner.type), ownerToKeyArray(newOwner)],
          });
    return {
      to: this.address,
      value: 0n,
      data,
    };
  }

  /**
   * Build a call that upgrades the account implementation (`upgradeToAndCall`).
   * Only meaningful for upgradeable-proxy clones (see {@link isUpgradeable}).
   * Requires the owner (or a self-call).
   */
  buildUpgradeCall(options: {
    implementation: `0x${string}`;
    data?: `0x${string}`;
  }): Call {
    return {
      to: this.address,
      value: 0n,
      data: encodeFunctionData({
        abi: CATAPULTAR_V0_1_0_ABI,
        functionName: "upgradeToAndCall",
        args: [options.implementation, options.data ?? "0x"],
      }),
    };
  }

  /**
   * Build the calls that invalidate a set of nonces, batching nonces that share
   * a bitmap word into a single `invalidateUnorderedNonces` call. Requires the
   * owner (or a self-call).
   * @param nonces Nonces to invalidate.
   */
  invalidateNonces(...nonces: bigint[]): Call[] {
    const pairs = new Set(nonces.map((n) => n >> 8n));
    const bitMaps = [...pairs].map((wordPos) => {
      const toInvalidate = nonces.filter((n) => n >> 8n === wordPos);
      const bits = toInvalidate.map((v) => v % 256n);
      let mask = 0n;
      for (const bit of bits) {
        mask |= 1n << bit;
      }
      return [wordPos, mask] as [bigint, bigint];
    });
    return bitMaps.map(([wordPos, mask]) => ({
      to: this.address,
      value: 0n,
      data: encodeFunctionData({
        abi: CATAPULTAR_V0_1_0_ABI,
        functionName: "invalidateUnorderedNonces",
        args: [wordPos, mask],
      }),
    }));
  }

  // --- Reading Functions (require a client) --- //

  /**
   * @param nonce Starting nonce.
   * @returns Next valid nonce that has not been spent on-chain yet. If no nonce is found in the given attempts, -1 is returned.
   */
  async getNextValidNonce(
    this: CatapultarAccount<O, true>,
    options: { nonce: bigint; attempts?: number },
  ) {
    const { nonce: startingNonce, attempts = 10 } = options;

    let wordPos = startingNonce >> 8n;
    let bitPos = startingNonce % 256n;
    let found = false;
    const client = this.publicClient();
    for (
      wordPos;
      wordPos < (startingNonce >> 8n) + BigInt(attempts);
      wordPos += 1n
    ) {
      const spentNonces = await client.readContract({
        address: this.address,
        abi: this.abi(),
        functionName: "nonceBitmap",
        args: [wordPos],
      });

      for (bitPos; bitPos < 256n; bitPos += 1n) {
        if (!(spentNonces & (1n << bitPos))) {
          found = true;
          break;
        }
      }
      if (found === true) break;
      bitPos = 0n;
    }
    if (!found) return -1n;
    return (wordPos << 8n) + bitPos;
  }

  async validateNonces(
    this: CatapultarAccount<O, true>,
    options: { nonces: bigint[] },
  ) {
    const lookups: { [upper: string]: bigint } = {};
    for (const nonce of options.nonces) {
      const wordPos = nonce >> 8n;
      const bitPos = nonce & 255n;
      const val = lookups[wordPos.toString(16)];
      if (!val) lookups[wordPos.toString(16)] = 0n;
      if (val && val & (1n << bitPos))
        throw new Error(`Duplicate Nonce ${nonce}`);
      lookups[wordPos.toString(16)]! |= 1n << bitPos;
    }
    const client = this.publicClient();
    const entries = Object.entries(lookups);
    const spent = await Promise.all(
      entries.map(([upper]) =>
        client.readContract({
          address: this.address,
          abi: this.abi(),
          functionName: "nonceBitmap",
          args: [BigInt(`0x${upper}`)],
        }),
      ),
    );
    entries.forEach(([upper, word], i) => {
      const spentNonces = spent[i]!;
      if (spentNonces & word)
        throw new Error(
          `Nonce collision on ${upper}, words: ${word} and ${spentNonces}`,
        );
    });
  }

  /** Read the raw ECDSA owner address (`owner()` view). */
  async getAccountOwner(this: CatapultarAccount<O, true>) {
    return this.publicClient().readContract({
      address: this.address,
      abi: this.abi(),
      functionName: "owner",
    });
  }

  /** Read the on-chain owner and decode it into an {@link Owner}. */
  async getPublicKey(this: CatapultarAccount<O, true>): Promise<Owner> {
    const [keyType, key] = await this.publicClient().readContract({
      address: this.address,
      abi: this.abi(),
      functionName: "getPublicKey",
    });
    return keyArrayToOwner(Number(keyType), key as `0x${string}`[]);
  }

  /** Whether the account is an upgradeable-proxy clone (`upgradeable()` view). */
  async isUpgradeable(this: CatapultarAccount<O, true>): Promise<boolean> {
    return this.publicClient().readContract({
      address: this.address,
      abi: this.abi(),
      functionName: "upgradeable",
    });
  }

  /** Read the approval flag stored for a digest (`approvedDigest` view). */
  async isDigestApproved(
    this: CatapultarAccount<O, true>,
    options: { digest: `0x${string}` },
  ): Promise<DigestApproval> {
    const flag = await this.publicClient().readContract({
      address: this.address,
      abi: this.abi(),
      functionName: "approvedDigest",
      args: [options.digest],
    });
    return Number(flag) as DigestApproval;
  }

  // --- Get Functions --- //

  /**
   * @returns EIP-712 Domain Separator for the account.
   */
  getDomainSeparator(
    options: { chain: boolean } = { chain: true },
  ): CatapultarDomain {
    const { chain } = options;
    if (chain) {
      if (!this.chainId)
        throw new Error(`Chain is not provided, but signing single chain.`);
      return {
        name: this.name,
        version: this.version,
        chainId: this.chainId,
        verifyingContract: this.address,
      };
    } else {
      return {
        name: this.name,
        version: this.version,
        verifyingContract: this.address,
      };
    }
  }

  // --- Statement Functions --- //

  /**
   * Return whether a signature is valid.
   * @dev Does not support P256 prehash-flag handling; it verifies the raw digest.
   */
  async isSignatureValid(options: {
    signature: `0x${string}`;
    hash: `0x${string}`;
  }): Promise<boolean> {
    const { signature, hash } = options;

    if (this.isEcdsa()) {
      // Check ECDSA. Only attempt recovery for ECDSA-sized signatures (65 bytes,
      // or a 64-byte EIP-2098 compact signature). Any other length is a
      // contract-specific signature: skip recovery (which would otherwise throw)
      // and defer to the ERC-1271 check below. The try/catch also covers
      // correctly-sized but unrecoverable signatures (e.g. invalid v/yParity).
      let signer: `0x${string}` = "0x";
      if (signature.length === 65 * 2 + 2 || signature.length === 64 * 2 + 2) {
        try {
          signer = (await recoverAddress({
            hash: hash,
            signature:
              signature.length === 64 * 2 + 2
                ? fromCompactSignature(signature)
                : signature,
          })) as `0x${string}`;
        } catch {
          // Not a recoverable ECDSA signature; defer to ERC-1271.
        }
      }
      // Normalize case before comparing: recoverAddress returns a checksummed
      // address while this.owner.address may have been supplied lower-cased.
      if (this.owner.address.toLowerCase() === signer.toLowerCase())
        return true;
      if (!this.isConnected()) return false;

      const result1271 = await this.publicClient().readContract({
        address: this.owner.address,
        abi: this.abi(),
        functionName: "isValidSignature",
        args: [hash, signature],
      });
      return result1271 === "0x1626ba7e";
    }
    // 0.0.1 does not support anymore validations
    if (this.version === "0.0.1") return false;

    // Lets run P256 and Webauth. First, lets check the formatting of the signature.
    const raw = signature.replace("0x", "");
    if (raw.length <= 65 * 2) {
      return false;
    }
    if (this.isP256() || this.isWebAuthn()) {
      const publicKey = PublicKey.from({
        x: BigInt(this.owner.x),
        y: BigInt(this.owner.y),
      });
      if (this.isP256()) {
        const r = BigInt("0x" + raw.slice(0, 64));
        const s = BigInt("0x" + raw.slice(64, 128));
        return await P256.verify({
          payload: hash,
          publicKey,
          signature: { r, s },
        });
      }
      const unpackedSig = decodeAbiParameters(
        parseAbiParameters([
          "WebAuthnAuth auth",
          "struct WebAuthnAuth { bytes authenticatorData; string clientDataJSON; uint256 challengeIndex; uint256 typeIndex; uint256 r; uint256 s;}",
        ]),
        signature,
      )[0];
      const metadata = {
        authenticatorData: unpackedSig.authenticatorData,
        clientDataJSON: unpackedSig.clientDataJSON,
        challengeIndex: Number(unpackedSig.challengeIndex),
        typeIndex: Number(unpackedSig.typeIndex),
      };
      return await WebAuthnP256.verify({
        metadata,
        challenge: hash,
        publicKey,
        signature: { r: unpackedSig.r, s: unpackedSig.s },
      });
    }
    return false;
  }

  // --- Validation --- //

  /** Validate that the on-chain owner matches this account's configured owner. */
  async validateOwner(this: CatapultarAccount<O, true>) {
    const onchain = await this.getPublicKey();
    if (!ownersEqual(this.owner, onchain))
      throw new Error(
        `Expected owner: ${JSON.stringify(this.owner)}, actual owner: ${JSON.stringify(onchain)}`,
      );
    return this;
  }

  async validateNonce(
    this: CatapultarAccount<O, true>,
    options: {
      nonce: bigint | undefined;
    },
  ) {
    const { nonce } = options;
    if (nonce === 0n)
      throw new Error(
        "Nonce 0 is not allowed. It cannot be differentiated from an invalid nonce.",
      );
    if (!nonce) throw new Error("No nonce has been set");
    await this.validateNonces({ nonces: [nonce] });
    return this;
  }
}
