import {
  createPublicClient,
  decodeAbiParameters,
  encodeAbiParameters,
  encodeFunctionData,
  encodePacked,
  getCreate2Address,
  http,
  keccak256,
  parseAbiParameters,
  recoverAddress,
} from "viem";
import {
  type Version,
  type Call,
  AccountPublicKeyType,
  type AccountPublicVar,
  type AccountConstructorParams,
  type KeyedSignature,
  type EmbeddedCall,
  type Factory,
  type Pubkey,
} from "../types/types";
import { getViemChainId } from "../utils/viem";
import CATAPULTAR_V0_1_0_ABI from "../abi/catapultarV0.1.0";
import CATAPULTAR_FACTORY_V0_1_0_ABI from "../abi/catapultarFactoryV0.1.0";
import { pubkeyAsArray } from "../utils/helpers";
// import { CATAPULTAR_V0_0_1_ABI } from "../abi/catapultarV0.0.1";
import { P256, PublicKey, WebAuthnP256 } from "ox";
import { fromCompactSignature } from "../utils/signature";

export class CatapultarAccount<
  V extends Version = "0.1.0",
  RPC extends string | undefined = undefined,
  AKT extends AccountPublicKeyType = AccountPublicKeyType.ECDSAOrSmartContract,
> {
  /** This is not the pubkey of the account, this is the smart account itself. */
  readonly address: `0x${string}`;
  /** ChainId of the account. */
  chainId: undefined extends RPC ? number | undefined : number;

  /** Name of the account. Used for the domainSeparator. */
  readonly name: string;
  /** Version of the account. Used for the domainSeparator. */
  readonly version: V;

  rpc: RPC | undefined;

  /** Account to validate account signatures against. */
  pubkey: AccountPublicVar<AKT>;
  accountPublicKeyType: AKT;

  constructor(options: AccountConstructorParams<V, RPC, AKT>) {
    const {
      address,
      accountPublicKeyType = AccountPublicKeyType.ECDSAOrSmartContract as AKT,
      chainId,
      pubkey,
      name = "Catapultar",
      version = "0.1.0",
      rpc,
    } = options;

    // Account definition
    this.address = address;
    this.chainId = chainId as undefined extends RPC
      ? number | undefined
      : number;

    // Validation
    if (
      accountPublicKeyType === AccountPublicKeyType.ECDSAOrSmartContract &&
      Array.isArray(pubkey)
    )
      throw new Error(
        `Only one key allowed for ECDSA or SmartContract: ${pubkey}`,
      );
    if (
      [AccountPublicKeyType.P256, AccountPublicKeyType.WebAuthnP256].includes(
        accountPublicKeyType,
      ) &&
      !Array.isArray(pubkey)
    )
      throw new Error(
        `P256 signatures requires the pubkey as exactly 2 points: ${pubkey}`,
      );
    this.pubkey = pubkey;
    this.accountPublicKeyType = accountPublicKeyType;

    this.rpc = rpc;

    // Custom domainSeparator
    this.name = name;
    this.version = version as V;
  }

  static deploy<V extends Version, AKT extends AccountPublicKeyType>(
    options: {
      salt: `0x${string}`;
    } & Pubkey<AKT> &
      Factory &
      ({} | EmbeddedCall),
  ): { call: Call; account: CatapultarAccount<V, undefined, AKT> } {
    let callDigest: `0x${string}` | undefined = undefined;
    let isSignature: boolean | undefined = undefined;

    let derivedAddress: `0x${string}`;
    if ("callDigest" in options && "isSignature" in options) {
      callDigest = options.callDigest;
      isSignature = options.isSignature;

      derivedAddress = CatapultarAccount.predict({
        ...options,
        callDigest: callDigest,
        isSignature: isSignature,
      });
    } else {
      derivedAddress = CatapultarAccount.predict({
        ...options,
      });
    }

    const pubkeyArray = pubkeyAsArray(options);
    const call = {
      to: options.factory,
      data: callDigest
        ? encodeFunctionData({
            abi: CATAPULTAR_FACTORY_V0_1_0_ABI,
            functionName: "deployWithDigest",
            args: [
              options.keyType,
              pubkeyArray,
              options.salt,
              callDigest,
              isSignature as boolean,
            ],
          })
        : encodeFunctionData({
            abi: CATAPULTAR_FACTORY_V0_1_0_ABI,
            functionName: "deploy",
            args: [options.keyType, pubkeyArray, options.salt],
          }),
      value: 0n,
    };

    return {
      call,
      account: new CatapultarAccount({
        address: derivedAddress,
        accountPublicKeyType: options.keyType,
        pubkey: options.pubkey,
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

  private static ownerInSalt<AKT extends AccountPublicKeyType>(
    opt: {
      salt: `0x${string}`;
    } & Pubkey<AKT>,
  ) {
    const pubkeyArray = pubkeyAsArray(opt);
    const saltPrefix =
      opt.keyType === AccountPublicKeyType.ECDSAOrSmartContract
        ? opt.pubkey
        : keccak256(encodePacked(["bytes32[]"], [pubkeyArray]));

    const saltSlice = opt.salt.slice(0, 20 * 2 + 2);
    return BigInt(saltSlice) === 0n || saltSlice === saltPrefix;
  }

  static predict<AKT extends AccountPublicKeyType>(
    opt: {
      salt: `0x${string}`;
    } & Pubkey<AKT> &
      Factory &
      ({} | EmbeddedCall),
  ) {
    if (!CatapultarAccount.ownerInSalt(opt))
      throw new Error(`Pubkey: ${opt.pubkey} not in salt: ${opt.salt}`);
    let { salt, template, factory } = opt;
    // If a digest is used, rehash the hash.
    if ("callDigest" in opt && "isSignature" in opt) {
      const { callDigest, isSignature } = opt;
      salt = keccak256(
        encodePacked(
          ["bytes32", "bytes32", "uint256"],
          [salt, callDigest, isSignature ? 2n : 1n],
        ),
      );
    }
    return CatapultarAccount.deriveCloneAddress(template, salt, factory);
  }

  publicClient(this: CatapultarAccount<any, string, any>) {
    const viemChain = getViemChainId(this.chainId);
    return createPublicClient({
      chain: viemChain,
      transport: http(this.rpc),
    });
  }

  abi(this: CatapultarAccount<V, any, any>): typeof CATAPULTAR_V0_1_0_ABI {
    return CATAPULTAR_V0_1_0_ABI;
  }

  hasRpc(): this is CatapultarAccount<any, string, any> {
    return typeof this.rpc === "string" && this.rpc.length > 0;
  }

  hasECDSAOrSmartContractKey(): this is CatapultarAccount<
    any,
    any,
    AccountPublicKeyType.ECDSAOrSmartContract
  > {
    return (
      this.accountPublicKeyType === AccountPublicKeyType.ECDSAOrSmartContract
    );
  }

  hasP256Key(): this is CatapultarAccount<any, any, AccountPublicKeyType.P256> {
    return this.accountPublicKeyType === AccountPublicKeyType.P256;
  }

  hasWebAuthnP256Key(): this is CatapultarAccount<
    any,
    any,
    AccountPublicKeyType.WebAuthnP256
  > {
    return this.accountPublicKeyType === AccountPublicKeyType.WebAuthnP256;
  }

  attachRpc(opt: {
    rpc: string;
    chainId: number;
  }): CatapultarAccount<V, string, AKT> {
    this.rpc = opt.rpc as RPC;
    this.chainId = opt.chainId;
    return this as this & CatapultarAccount<V, string, AKT>;
  }

  parseSignature(signature: KeyedSignature<AKT>): `0x${string}` | undefined {
    if (this.hasECDSAOrSmartContractKey())
      return signature as KeyedSignature<AccountPublicKeyType.ECDSAOrSmartContract>;
    if (this.hasP256Key()) {
      let rawSignature = (
        signature as KeyedSignature<AccountPublicKeyType.P256>
      ).replace("0x", "");
      // If the signature is 64 bytes long (default) or 65 (mistake?)
      // then add 0000 to the signature. This indicate an additional SHA256 hash.
      if (rawSignature.length <= 65 * 2) {
        rawSignature = `${rawSignature.padEnd(65 * 2, "0")}${"00"}`;
      }
      return `0x${rawSignature}`;
    }
    if (this.hasWebAuthnP256Key()) {
      const sig =
        signature as KeyedSignature<AccountPublicKeyType.WebAuthnP256>;
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
      return `${encodedParams}00`; // Use SHA256 hash.
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
          signature:
            signature.length === 64 * 2 + 2
              ? fromCompactSignature(signature)
              : signature,
        })) as `0x${string}`;
      }
      if (this.pubkey === signer) return true;
      if (!this.hasRpc()) return false;
      const publicClient = this.publicClient();

      const result1271 = await publicClient.readContract({
        address: this.pubkey,
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
    if (signature.replace("0x", "").length <= 65 * 2) {
      return false;
    }
    const pubkey = this.pubkey as [`0x${string}`, `0x${string}`];
    const publicKey = PublicKey.from({
      x: BigInt(pubkey[0]),
      y: BigInt(pubkey[1]),
    });
    if (this.hasP256Key()) {
      const r = BigInt("0x" + signature.replace("0x", "").slice(0, 64));
      const s = BigInt("0x" + signature.replace("0x", "").slice(64, 128));
      return await P256.verify({
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
    if (this.pubkey !== actualAccountOwner)
      throw new Error(
        `Expected pubkey: ${actualAccountOwner}, Provided pubkey: ${this.pubkey}`,
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
