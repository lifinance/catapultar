import {
  createPublicClient,
  decodeAbiParameters,
  encodeFunctionData,
  encodePacked,
  http,
  keccak256,
  parseAbiParameters,
  recoverAddress,
  toBytes,
  zeroAddress,
  type Chain,
  type PublicClient,
} from "viem";
import {
  DigestApproval,
  type AccountConstructorParams,
  type Call,
  type DeployOptions,
  type KeyedSignature,
  type Owner,
  type OwnerOf,
} from "../types/types";
import { resolveChain } from "../utils/viem";
import CATAPULTAR_ABI from "../abi/catapultar";
import CATAPULTAR_FACTORY_ABI from "../abi/catapultarFactory";
import {
  keyArrayToOwner,
  ownersEqual,
  ownerToKeyArray,
  ownerTypeToEnum,
} from "../protocol/owner";
import {
  factorySalt,
  factorySaltWithDigest,
  predictCloneAddress,
} from "../protocol/factory";
import {
  fromCompactSignature,
  normalizeSignature as encodeKeyedSignature,
} from "../protocol/signature";
import type { CatapultarDomain } from "../protocol/calls";
import {
  DuplicateNonceError,
  InvalidChainError,
  NonceCollisionError,
  NonceUnsetError,
  NonceZeroError,
  NotConnectedError,
  OwnerMismatchError,
} from "../errors";
import { P256, PublicKey, WebAuthnP256 } from "ox";
import { _factory } from "../config";

/**
 * `keccak256("Replay(address account,bytes32 payload)")` — the envelope tag the
 * account prepends when validating an ERC-1271 message (mirrors
 * `Catapultar.REPLAY_PROTECTION`). Exposed so callers can reproduce the digest
 * a Catapultar account attests to off-chain.
 */
export const REPLAY_PROTECTION = keccak256(
  toBytes("Replay(address account,bytes32 payload)"),
);

/** ERC-1271 magic value returned by `isValidSignature` for a valid signature. */
export const ERC1271_MAGIC_VALUE = "0x1626ba7e" as const;

/**
 * A Catapultar smart account.
 *
 * The account is identified by its {@link Owner} (an ECDSA address, or a P256 /
 * WebAuthn public key). It is offline by default; attach a viem client with
 * {@link CatapultarAccount.connect} (or {@link CatapultarAccount.connectRpc})
 * to unlock on-chain reads. `connect`/`connectRpc` are non-mutating: they return
 * a fresh, connected handle — use the returned value. The `Connected` type
 * parameter records, at compile time, whether a client is attached so read
 * methods are only callable once it is.
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
  readonly chainId: number | undefined;

  /** Name of the account. Used for the domainSeparator. */
  readonly name: string;
  /** EIP-712 domain version of the account. Used for the domainSeparator. */
  readonly version: string;

  /** Owner of the account (ECDSA address or P256/WebAuthn public key). */
  readonly owner: O;

  /** Attached viem client used for on-chain reads, if any. */
  private readonly _client: PublicClient | undefined;

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

    // Connectivity: accept a viem client directly, or build one from an
    // rpc + chainId convenience pair.
    if (client) {
      this._client = client;
      this.chainId = chainId ?? client.chain?.id;
    } else if (rpc) {
      if (chainId === undefined)
        throw new InvalidChainError(
          "An rpc was provided without a chainId; cannot build a client.",
        );
      this._client = createPublicClient({
        chain: resolveChain({ chainId }),
        transport: http(rpc),
      });
      this.chainId = chainId;
    } else {
      this._client = undefined;
      this.chainId = chainId;
    }
  }

  /**
   * Build the factory call that deploys this account and return the call paired
   * with the (offline) account handle at its deterministic CREATE2 address.
   *
   * The factory function is selected from {@link DeployOptions}:
   * - `upgradeable: true` -> `deployUpgradeable` (durable ERC-1967 proxy).
   * - `digest` present -> `deployWithDigest` (PUSH0 clone with an embedded
   *   call/signature digest approved at init).
   * - otherwise -> `deploy` (cheap immutable PUSH0 clone).
   */
  static deploy<O extends Owner>(
    options: DeployOptions<O>,
  ): { call: Call; account: CatapultarAccount<O, false> } {
    const { factory } = _factory(options);
    // predict() performs the same digest/kind derivation internally.
    const derivedAddress = CatapultarAccount.predict(options);

    const keyType = ownerTypeToEnum(options.owner.type);
    const keyArray = ownerToKeyArray(options.owner);
    let data: `0x${string}`;
    if (options.upgradeable) {
      data = encodeFunctionData({
        abi: CATAPULTAR_FACTORY_ABI,
        functionName: "deployUpgradeable",
        args: [keyType, keyArray, options.salt],
      });
    } else if (options.digest) {
      data = encodeFunctionData({
        abi: CATAPULTAR_FACTORY_ABI,
        functionName: "deployWithDigest",
        args: [
          keyType,
          keyArray,
          options.salt,
          options.digest.hash,
          options.digest.isSignature,
        ],
      });
    } else {
      data = encodeFunctionData({
        abi: CATAPULTAR_FACTORY_ABI,
        functionName: "deploy",
        args: [keyType, keyArray, options.salt],
      });
    }

    return {
      call: { to: factory, data, value: 0n },
      account: new CatapultarAccount<O, false>({
        address: derivedAddress,
        owner: options.owner,
      }),
    };
  }

  /**
   * Predict the deterministic CREATE2 address for the given deploy options,
   * without building a call. The kind (PUSH0 clone vs ERC-1967 proxy) and any
   * embedded digest are mirrored exactly from `CatapultarFactory`, so the
   * returned address matches what {@link deploy} would produce.
   */
  static predict<O extends Owner>(opt: DeployOptions<O>): `0x${string}` {
    const { salt } = opt;
    const { factory, template } = _factory(opt);
    const keyArray = ownerToKeyArray(opt.owner);

    const internalSalt = factorySalt(
      salt,
      ownerTypeToEnum(opt.owner.type),
      keyArray,
    );

    // Upgradeable proxies use a distinct init code; they never carry a digest
    // (guarded at the type level by DeployOptions).
    if (opt.upgradeable) {
      return predictCloneAddress({
        template,
        salt: internalSalt,
        factory,
        kind: "upgradeable",
      });
    }

    const finalSalt = opt.digest
      ? factorySaltWithDigest(
          internalSalt,
          opt.digest.hash,
          opt.digest.isSignature,
        )
      : internalSalt;
    return predictCloneAddress({ template, salt: finalSalt, factory });
  }

  // --- Connectivity --- //

  /**
   * Attach a viem `PublicClient`, returning a fresh connected handle (the
   * original handle stays offline). Use the returned value.
   */
  connect(client: PublicClient): CatapultarAccount<O, true> {
    return new CatapultarAccount<O>({
      address: this.address,
      owner: this.owner,
      name: this.name,
      version: this.version,
      chainId: this.chainId ?? client.chain?.id,
      client,
    }) as unknown as CatapultarAccount<O, true>;
  }

  /**
   * Convenience: build a `PublicClient` from an RPC URL + chainId and attach it.
   * Pass an explicit `chain` to override chain resolution for unknown networks.
   */
  connectRpc(options: {
    rpc: string;
    chainId: number;
    chain?: Chain;
  }): CatapultarAccount<O, true> {
    const client = createPublicClient({
      chain: resolveChain({ chainId: options.chainId, chain: options.chain }),
      transport: http(options.rpc),
    });
    return new CatapultarAccount<O>({
      address: this.address,
      owner: this.owner,
      name: this.name,
      version: this.version,
      chainId: options.chainId,
      client,
    }) as unknown as CatapultarAccount<O, true>;
  }

  /** The attached viem client. Throws if the account is not connected. */
  publicClient(this: CatapultarAccount<O, true>): PublicClient {
    if (!this._client)
      throw new NotConnectedError(
        "No client attached. Call connect() or connectRpc() first.",
      );
    return this._client;
  }

  /** The ABI of the Catapultar account contract this handle targets. */
  abi(): typeof CATAPULTAR_ABI {
    return CATAPULTAR_ABI;
  }

  // --- Type guards --- //

  /** Narrowing guard: whether a viem client is attached (read methods available). */
  isConnected(): this is CatapultarAccount<O, true> {
    return this._client !== undefined;
  }

  /** Narrowing guard: whether the owner is an ECDSA / ERC-1271 owner. */
  isEcdsa(): this is CatapultarAccount<OwnerOf<"ecdsa">, Connected> {
    return this.owner.type === "ecdsa";
  }

  /** Narrowing guard: whether the owner is a raw P256 key. */
  isP256(): this is CatapultarAccount<OwnerOf<"p256">, Connected> {
    return this.owner.type === "p256";
  }

  /** Narrowing guard: whether the owner is a WebAuthn passkey. */
  isWebAuthn(): this is CatapultarAccount<OwnerOf<"webauthn-p256">, Connected> {
    return this.owner.type === "webauthn-p256";
  }

  /**
   * Normalize a keyed signature into the on-chain wire format for this owner.
   * Delegates to the centralized protocol encoder.
   */
  normalizeSignature(signature: KeyedSignature<O>): `0x${string}` {
    return encodeKeyedSignature(this.owner, signature as KeyedSignature<Owner>);
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
        abi: CATAPULTAR_ABI,
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
            abi: CATAPULTAR_ABI,
            functionName: "transferOwnership",
            args: [zeroAddress],
          })
        : encodeFunctionData({
            abi: CATAPULTAR_ABI,
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
        abi: CATAPULTAR_ABI,
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
  buildInvalidateNoncesCalls(...nonces: bigint[]): Call[] {
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
        abi: CATAPULTAR_ABI,
        functionName: "invalidateUnorderedNonces",
        args: [wordPos, mask],
      }),
    }));
  }

  // --- Reading Functions (require a client) --- //

  /**
   * @param nonce Starting nonce.
   * @returns Next valid nonce that has not been spent on-chain yet. If no nonce is found in the given attempts, `null` is returned.
   */
  async getNextValidNonce(
    this: CatapultarAccount<O, true>,
    options: { nonce: bigint; attempts?: number },
  ): Promise<bigint | null> {
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
    if (!found) return null;
    return (wordPos << 8n) + bitPos;
  }

  /**
   * Assert that none of `options.nonces` has already been spent on-chain, and
   * that the set contains no duplicates. Reads are batched per bitmap word.
   * Requires a connected account.
   * @throws {NonceZeroError} If any nonce is 0 (reserved as "unset"; rejected on-chain).
   * @throws {DuplicateNonceError} If a nonce appears twice in the input.
   * @throws {NonceCollisionError} If a nonce is already spent on-chain.
   */
  async validateNonces(
    this: CatapultarAccount<O, true>,
    options: { nonces: bigint[] },
  ) {
    const lookups: { [upper: string]: bigint } = {};
    for (const nonce of options.nonces) {
      // Nonce 0 is rejected on-chain (BitmapNonce `_useUnorderedNonce`), so guard it
      // here too — this is the shared entry point that `validateNonce` delegates to.
      if (nonce === 0n)
        throw new NonceZeroError(
          "Nonce 0 is not allowed. It cannot be differentiated from an invalid nonce.",
        );
      const wordPos = nonce >> 8n;
      const bitPos = nonce & 255n;
      const val = lookups[wordPos.toString(16)];
      if (!val) lookups[wordPos.toString(16)] = 0n;
      if (val && val & (1n << bitPos))
        throw new DuplicateNonceError(`Duplicate Nonce ${nonce}`);
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
        throw new NonceCollisionError(
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
  async getDigestApproval(
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
   * @dev Verifies the raw digest; does not apply the P256 prehash flag.
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

    // Run P256 and WebAuthn. First, check the formatting of the signature.
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

  // --- ERC-1271 (account as a signer) --- //

  /**
   * The digest the account's owner must actually sign for the account to attest
   * to `payloadHash` via ERC-1271 (`isValidSignature(payloadHash, sig)`).
   *
   * Mirrors `Catapultar.isValidSignature`, which rehashes inside a replay
   * envelope so a signature is bound to this specific account:
   * `keccak256(REPLAY_PROTECTION || bytes32(address(this)) || payloadHash)`.
   *
   * Use this when a third-party protocol asks the Catapultar account (as a
   * smart-contract signer) to sign some `payloadHash`: sign the value returned
   * here with the owner key, then hand the original `payloadHash` + signature to
   * the verifier.
   */
  getReplayProtectedDigest(payloadHash: `0x${string}`): `0x${string}` {
    return keccak256(
      encodePacked(
        ["bytes32", "bytes32", "bytes32"],
        [
          REPLAY_PROTECTION,
          // address(this) left-padded to 32 bytes (matches asUnsafeBytes32).
          `0x${this.address.replace("0x", "").toLowerCase().padStart(64, "0")}`,
          payloadHash,
        ],
      ),
    );
  }

  /**
   * Verify a signature against the deployed account via its on-chain ERC-1271
   * `isValidSignature` view (the account rehashes `payloadHash` internally, so
   * pass the original payload hash — not {@link getReplayProtectedDigest}).
   *
   * This differs from {@link isSignatureValid}, which checks a raw digest
   * against the owner key directly. Requires a connected account.
   */
  async isValidAccountSignature(
    this: CatapultarAccount<O, true>,
    options: { payloadHash: `0x${string}`; signature: `0x${string}` },
  ): Promise<boolean> {
    const result = await this.publicClient().readContract({
      address: this.address,
      abi: this.abi(),
      functionName: "isValidSignature",
      args: [options.payloadHash, options.signature],
    });
    return result === ERC1271_MAGIC_VALUE;
  }

  // --- Validation --- //

  /** Validate that the on-chain owner matches this account's configured owner. */
  async validateOwner(this: CatapultarAccount<O, true>) {
    const onchain = await this.getPublicKey();
    if (!ownersEqual(this.owner, onchain))
      throw new OwnerMismatchError(
        `Expected owner: ${JSON.stringify(this.owner)}, actual owner: ${JSON.stringify(onchain)}`,
      );
    return this;
  }

  /**
   * Assert a single nonce is usable: present, non-zero, and not yet spent
   * on-chain. Returns `this`. Requires a connected account.
   * @throws {NonceZeroError} If the nonce is 0 (reserved as "unset").
   * @throws {NonceUnsetError} If no nonce was provided.
   * @throws {NonceCollisionError} If the nonce is already spent on-chain.
   */
  async validateNonce(
    this: CatapultarAccount<O, true>,
    options: {
      nonce: bigint | undefined;
    },
  ) {
    const { nonce } = options;
    if (nonce === 0n)
      throw new NonceZeroError(
        "Nonce 0 is not allowed. It cannot be differentiated from an invalid nonce.",
      );
    if (!nonce) throw new NonceUnsetError("No nonce has been set");
    await this.validateNonces({ nonces: [nonce] });
    return this;
  }
}
