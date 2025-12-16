import {
  createPublicClient,
  decodeAbiParameters,
  encodeAbiParameters,
  encodeFunctionData,
  http,
  parseAbiParameters,
  recoverAddress,
} from "viem";
import {
  type Version,
  type Call,
  AccountKeyType,
  type AccountPublicVar,
  type AccountConstructorParams,
  type KeyedSignature,
} from "../types/types";
import { getViemChainId } from "../utils/viem";
import CATAPULTAR_V0_1_0_ABI from "../abi/catapultarV0.1.0";
import CATAPULTAR_FACTORY_V0_1_0_ABI from "../abi/catapultarFactoryV0.1.0";
import { padEven, asHex } from "../utils/helpers";
// import { CATAPULTAR_V0_0_1_ABI } from "../abi/catapultarV0.0.1";
import { PublicKey, WebAuthnP256, WebCryptoP256 } from "ox";

const factories: Record<string, `0x${string}`> = {
  "0.1.0": "0x",
  "0.0.1": "0x",
} as const;

export class CatapultarAccount<
  V extends Version = "0.1.0",
  RPC extends string | undefined = undefined,
  AKT extends AccountKeyType = AccountKeyType.ECDSAOrSmartContract,
> {
  /** This is not the owner of the account, this is the smart account itself. */
  readonly address: `0x${string}`;
  /** ChainId of the account. */
  readonly chainId: number;

  /** Name of the account. Used for the domainSeparator. */
  readonly name: string;
  /** Version of the account. Used for the domainSeparator. */
  readonly version: V;

  rpc: RPC | undefined;

  /** Account to validate account signatures against. */
  owner: AccountPublicVar<AKT>;
  accountKeyType: AKT;

  constructor(options: AccountConstructorParams<V, RPC, AKT>) {
    const {
      address,
      accountKeyType = AccountKeyType.ECDSAOrSmartContract as AKT,
      chainId,
      owner,
      name = "Catapultar",
      version = "0.1.0" as V,
      rpc,
    } = options;

    // Account definition
    this.address = address;
    this.chainId = chainId;

    // Validation
    if (
      accountKeyType === AccountKeyType.ECDSAOrSmartContract &&
      Array.isArray(owner)
    )
      throw new Error(
        `Only one key allowed for ECDSA or SmartContract: ${owner}`,
      );
    if (
      [AccountKeyType.P256, AccountKeyType.WebAuthnP256].includes(
        accountKeyType,
      ) &&
      !Array.isArray(owner)
    )
      throw new Error(
        `P256 signatures requires the owner as exactly 2 points: ${owner}`,
      );
    this.owner = owner;
    this.accountKeyType = accountKeyType;

    this.rpc = rpc;

    // Custom domainSeparator
    this.name = name;
    this.version = version;
  }

  static async deploy<V extends Version>(
    options: {
      chainId: number;
      owner: `0x${string}`;
      salt: `0x${string}` | bigint;
      rpc: string;
    } & ({ version: V } | { factory: `0x${string}` }),
  ): Promise<{ call: Call; account: CatapultarAccount<V, string> }> {
    const { rpc, chainId, owner } = options;
    let factory: `0x${string}`;
    let version: V;
    const viemChain = getViemChainId(chainId);
    const publicClient = createPublicClient({
      chain: viemChain,
      transport: http(rpc),
    });
    if ("factory" in options) {
      factory = options.factory;
      const readVersion = await publicClient.readContract({
        address: factory,
        abi: CATAPULTAR_FACTORY_V0_1_0_ABI,
        functionName: "VERSION",
      });
      version = readVersion as V;
    } else {
      version = options.version;
      if (version === `0.0.1` || !Object.keys(factories).includes(version)) {
        throw new Error(`Unsupported version: ${version}`);
      }
      factory = factories[version]!;
    }
    const ownerArray = [
      `0x${padEven(owner.replace("0x", ""), 64)}`,
    ] as `0x${string}`[];
    let salt = options.salt;
    if (typeof salt === "bigint") {
      salt = asHex(salt, 32, "0x");
    }

    // TODO: derive statically
    const expectedAddress = await publicClient.readContract({
      address: factory,
      abi: CATAPULTAR_FACTORY_V0_1_0_ABI,
      functionName: "predictDeploy",
      args: [0, ownerArray, salt],
    });

    const call = {
      to: factory,
      data: encodeFunctionData({
        abi: CATAPULTAR_FACTORY_V0_1_0_ABI,
        functionName: "deploy",
        args: [0, ownerArray, salt],
      }),
      value: 0n,
    };

    return {
      call,
      account: new CatapultarAccount({
        address: expectedAddress,
        chainId,
        owner,
        name: "Catapultar",
        version: version,
        rpc,
      }),
    };
  }

  publicClient(this: CatapultarAccount<any, string, any>) {
    const viemChain = getViemChainId(this.chainId);
    return createPublicClient({
      chain: viemChain,
      transport: http(this.rpc),
    });
  }

  abi(this: CatapultarAccount<V, any, any>): typeof CATAPULTAR_V0_1_0_ABI {
    if (this.version.startsWith("0.1")) {
      return CATAPULTAR_V0_1_0_ABI;
    } else {
      throw new Error(`Unsupported version: ${this.version}`);
    }
  }

  hasRpc(): this is CatapultarAccount<any, string, any> {
    return typeof this.rpc === "string" && this.rpc.length > 0;
  }

  hasECDSAOrSmartContractKey(): this is CatapultarAccount<
    any,
    any,
    AccountKeyType.ECDSAOrSmartContract
  > {
    return this.accountKeyType === AccountKeyType.ECDSAOrSmartContract;
  }

  hasP256Key(): this is CatapultarAccount<any, any, AccountKeyType.P256> {
    return this.accountKeyType === AccountKeyType.P256;
  }

  hasWebAuthnP256Key(): this is CatapultarAccount<
    any,
    any,
    AccountKeyType.WebAuthnP256
  > {
    return this.accountKeyType === AccountKeyType.WebAuthnP256;
  }

  parseSignature(signature: KeyedSignature<AKT>): `0x${string}` | undefined {
    if (this.hasECDSAOrSmartContractKey())
      return signature as KeyedSignature<AccountKeyType.ECDSAOrSmartContract>;
    if (this.hasP256Key()) {
      let rawSignature = (
        signature as KeyedSignature<AccountKeyType.P256>
      ).replace("0x", "");
      // If the signature is 64 bytes long (default) or 65 (mistake?)
      // then add 0001 to the signature. This indicate an additional SHA256 hash.
      if ([64 * 2, 65 * 2].includes(rawSignature.length)) {
        rawSignature = `${padEven(rawSignature, 65)}${"01"}`;
      }
      return `0x${rawSignature}`;
    }
    if (this.hasWebAuthnP256Key()) {
      const sig = signature as KeyedSignature<AccountKeyType.WebAuthnP256>;
      // const abiencode the directory.
      const encodedParams = encodeAbiParameters(
        parseAbiParameters([
          "WebAuthnAuth auth",
          "struct WebAuthnAuth { bytes authenticatorData; string clientDataJSON; uint256 challengeIndex; uint256 typeIndex; uint256 r; uint256 s;}",
        ]),
        [
          {
            ...sig,
            typeIndex: BigInt(sig.typeIndex),
            challengeIndex: BigInt(sig.challengeIndex),
          },
        ],
      );
      return `${encodedParams}01`; // Use SHA256 hash.
    }
  }

  // --- Writing Functions --- //

  //  upgrade(options: {
  //   target: `0x${string}`;
  //   implementation: `0x${string}`;
  //   data?: `0x${string}`;
  // }) {
  //   let { data } = options;
  //   if (!data) data = `0x`;
  // target.upgradeToAndCall
  // }

  // TransferOwnership

  // spend nonces.

  /**
   * Invalidates a set of nonces. Batches nonces that can be invalidated in a single call.
   * @param nonces Nonces to invalidate
   */
  async getSpendNoncesCalls(...nonces: bigint[]): Promise<Call[]> {
    const pairs = new Set(nonces.map((n) => n >> 8n));
    const bitMaps = [...pairs].map((wordPos) => {
      const toInvalidate = nonces.filter((n) => n >> 8n === wordPos);
      const bits = toInvalidate.map((v) => v % 256n);
      let mask = 0n;
      for (const bit of bits) {
        mask += 1n << bit;
      }
      return [wordPos, mask] as [bigint, bigint];
    });
    return bitMaps.map(([wordPos, mask]) => {
      const data = encodeFunctionData({
        abi: CATAPULTAR_V0_1_0_ABI,
        functionName: "invalidateUnorderedNonces",
        args: [wordPos, mask],
      });
      return {
        to: this.address,
        value: 0n,
        data: data,
      };
    });
  }

  // --- Helper functions for the account --- //

  /**
   * @param nonce Starting nonce.
   * @returns Next valid nonce that has not been spent on-chain yet. If no nonce is found in the given attempts, -1 is returned.
   */
  async getNextValidNonce(
    this: CatapultarAccount<any, string, any>,
    options: { nonce: bigint; attempts?: number },
  ) {
    const { nonce: startingNonce, attempts = 10 } = options;

    let wordPos = startingNonce >> 8n;
    let bitPos = startingNonce % 256n;
    let found = false;
    for (
      wordPos;
      wordPos < (startingNonce >> 8n) + BigInt(attempts);
      wordPos += 1n
    ) {
      const spentNonces = await this.publicClient().readContract({
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
    this: CatapultarAccount<any, string, any>,
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
    for (const [upper, word] of Object.entries(lookups)) {
      const spentNonces = await this.publicClient().readContract({
        address: this.address,
        abi: this.abi(),
        functionName: "nonceBitmap",
        args: [BigInt(`0x${upper}`)],
      });
      if (spentNonces & word)
        throw new Error(
          `Nonce collision on ${upper}, words: ${word} and ${spentNonces}`,
        );
    }
  }

  // TODO: P256.
  async getAccountOwner(this: CatapultarAccount<V, string, any>) {
    return this.publicClient().readContract({
      address: this.address,
      abi: this.abi(),
      functionName: "owner",
    });
  }

  // --- Get Functions --- //

  /**
   * @returns EIP-712 Domain Separator for the account.
   */
  getDomainSeparator(options: { chain: boolean } = { chain: true }) {
    const { chain } = options;
    if (chain) {
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
   * @dev Does not support P256 signatures
   */
  async isSignatureValid(options: {
    signature: `0x${string}`;
    hash: `0x${string}`;
  }): Promise<boolean> {
    const { signature, hash } = options;

    if (this.hasECDSAOrSmartContractKey()) {
      // Check ECDSA
      let signer: `0x${string}` = "0x";
      if (signature && signature.length > 2) {
        signer = (await recoverAddress({
          hash: hash,
          signature,
        })) as `0x${string}`;
      }
      if (this.owner === signer) return true;
      if (!this.hasRpc()) return false;
      const publicClient = this.publicClient();

      const result1271 = await publicClient.readContract({
        address: this.owner,
        abi: this.abi(),
        functionName: "isValidSignature",
        args: [hash, signature],
      });
      if (result1271 === "0x1626ba7e") {
        return true;
      }
      return false;
    }
    // 0.0.1 does not support anymore validations
    if (this.version === "0.0.1") return false;

    // Lets run P256 and Webauth. First, lets check the formatting of the signature.
    if ([64 * 2, 65 * 2].includes(signature.length)) {
      return false;
    }
    // Get last byte.
    const lastByte = signature.slice(signature.length - 2);
    if (lastByte != "00")
      throw new Error(`Library cannot validate non-sha256'ed hash`);

    const owner = this.owner as [`0x${string}`, `0x${string}`];
    const publicKey = PublicKey.from({
      x: BigInt(owner[0]),
      y: BigInt(owner[1]),
    });
    if (this.hasP256Key()) {
      const r = BigInt(signature.replace("0x", "").slice(0, 64));
      const s = BigInt(signature.replace("0x", "").slice(64, 128));
      return await WebCryptoP256.verify({
        payload: hash,
        publicKey,
        signature: { r, s },
      });
    }
    if (this.hasWebAuthnP256Key()) {
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

  async validateOwner(this: CatapultarAccount<any, string, any>) {
    const actualAccountOwner = await this.getAccountOwner();
    if (this.owner !== actualAccountOwner)
      throw new Error(
        `Expected owner: ${actualAccountOwner}, Provided owner: ${this.owner}`,
      );
    return this;
  }

  async validateNonce(
    this: CatapultarAccount<any, string, any>,
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
