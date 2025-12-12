import { encodeFunctionData, recoverAddress, type Call } from "viem";

export class CatapultarAccount {
  /** This is not the owner of the account, this is the smart account itself. */
  readonly address: `0x${string}`;
  /** ChainId of the account. */
  readonly chainId: number;

  /** Name of the account. Used for the domainSeperator. */
  readonly name: string = "Catapultar";
  /** Version of the account. Used for the domainSeperator. */
  readonly version: string = "0.1.0";

  /** Account to validate account signatures against. */
  owner: `0x${string}`;

  constructor(options: {
    address: `0x${string}`;
    chainId: number;
    owner: `0x${string}`;
    name?: string;
    version?: string;
  }) {
    const { address, chainId, owner, name, version } = options;

    // Account definition
    this.address = address;
    this.chainId = chainId;
    // Validation
    this.owner = owner;

    // Custom domainSeperator
    if (name) this.name = name;
    if (version) this.version = version;
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
      return [wordPos, mask];
    });
    return bitMaps.map(([wordPos, mask]) => {
      const data = encodeFunctionData({
        abi: [
          "function invalidateUnorderedNonces(uint256 wordPos, uint256 mask) external",
        ] as const,
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

  // /**
  //  * @param nonce Starting nonce.
  //  * @returns Next valid nonce that has not been spent on-chain yet.
  //  */
  // async getNextValidNonce(
  //   options: { nonce: bigint; attempts?: number },
  //   provider: Provider
  // ) {
  //   const { nonce: startingNonce, attempts = 10 } = options;
  //   const acc = new Contract(this.address, CatapultarTx.ACCOUNT_ABI, provider);

  //   let wordPos = startingNonce >> 8n;
  //   let bitPos = startingNonce % 256n;
  //   let found = false;
  //   for (
  //     wordPos;
  //     wordPos < (startingNonce >> 8n) + BigInt(attempts);
  //     wordPos += 1n
  //   ) {
  //     const spentNonces = await (acc.nonceBitmap(wordPos) as Promise<bigint>);
  //     for (bitPos; bitPos < 256n; bitPos += 1n) {
  //       if (!(spentNonces & (1n << bitPos))) {
  //         found = true;
  //         break;
  //       }
  //     }
  //     if (found === true) break;
  //     bitPos = 0n;
  //   }
  //   if (!found) return -1n;
  //   return (wordPos << 8n) + bitPos;
  // }

  async validateNonces(options: { nonces: bigint[] }) {
    const lookups: { [upper: string]: bigint } = {};
    for (const nonce of options.nonces) {
      const wordPos = nonce >> 8n;
      const bitPos = nonce & 256n;
      const val = lookups[wordPos.toString(16)];
      if (!val) lookups[wordPos.toString(16)] = 0n;
      if (val && val & (1n << bitPos))
        throw new Error(`Dublicate Nonce ${nonce}`);
      lookups[wordPos.toString(16)]! |= 1n << bitPos;
    }
    // const acc = new Contract(this.address, CatapultarTx.ACCOUNT_ABI, provider);
    // for (const [upper, word] of Object.entries(lookups)) {
    //   const spentNonces = await (acc.nonceBitmap(
    //     BigInt(`0x${upper}`)
    //   ) as Promise<bigint>);
    //   if (spentNonces & word)
    //     throw new Error(
    //       `Nonce collision on ${upper}, words: ${word} and ${spentNonces}`
    //     );
    // }
  }

  // async getAccountOwner(provider) {
  //   {
  //     const acc = new Contract(
  //       this.address,
  //       CatapultarTx.ACCOUNT_ABI,
  //       provider,
  //     );

  //     return acc.owner() as Promise<`0x${string}`>;
  //   }
  // }

  // --- Get Functions --- //

  /**
   * @returns EIP-712 Domain Seperator for the account.
   */
  getDomainSeperator() {
    return {
      name: this.name,
      version: this.version,
      chainId: this.chainId,
      verifyingContract: this.address,
    };
  }

  // --- Statement Functions --- //

  /**
   * Return whether a signature is valid.
   * @dev Does not support 1271 signatures yet.
   */
  async isSignatureValid(options: {
    signature: `0x${string}`;
    typeHash: `0x${string}`;
  }): Promise<boolean> {
    const { signature, typeHash } = options;
    if (signature && signature.length > 2) {
      const signer = (await recoverAddress({
        hash: typeHash,
        signature,
      })) as `0x${string}`;
      return this.owner === signer;
    }
    return false;
  }

  // --- Validation --- //

  // async validateOwner(options: { provider: Provider }) {
  // const { provider } = options;
  // const actualAccountOwner = await this.getAccountOwner(provider);
  // if (this.owner !== actualAccountOwner)
  //   throw new Error(
  //     `Expected owner: ${actualAccountOwner}, Provided owner: ${this.owner}`
  //   );
  // return this;
  // }

  async validateNonce(options: {
    nonce: bigint | undefined;
    // provider: Provider;
  }) {
    const { nonce } = options;
    if (nonce === 0n)
      throw new Error(
        "Nonce 0 is not allowed. It cannot be differentiated from an invalid nonce."
      );
    if (!nonce) throw new Error("No nonce has been set");
    await this.validateNonces({ nonces: [nonce] });
    return this;
  }
}