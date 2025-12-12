import { encodeFunctionData } from "viem";
import { random, saltContainsAddress } from "../utils/helpers";
import { type Call } from "../types/types";

/**
 * Catapultar factory handler for deploying accounts & fetching deployed accounts.
 */
export class CatapultarFactory {
  /** Factory address to use to deploy accounts. */
  readonly factory: `0x${string}`;

  static readonly abi = [
    "function deploy(address owner, bytes32 salt) public returns (address proxy)",
    "function deployUpgradable(address owner, bytes32 salt) external returns(address proxy)",
  ] as const;

  /**
   * @param options.factory Factory address to use to deploy accounts.
   */
  constructor(options: { factory: `0x${string}` }) {
    this.factory = options.factory;
  }

  /**
   * Signs and broadcasts the deloyment transaction for an non-upgradable account
   * @param options.owner Owner of the deployed account
   * @param options.salt Salt of the deployed account. The first 20 bytes should be owner. Default: Random.
   * @param options.signer Signer to sign for the transaction.
   * @returns Transaction hash
   */
  deploy(options: { owner: `0x${string}`; salt?: `0x${string}` }): {
    call: Call;
  } {
    let { owner, salt } = options;
    if (!salt) salt = `${owner}${random(12).replace("0x", "")}`;
    if (!saltContainsAddress(options.owner, salt))
      throw new Error(`SaltDoesNotStartWith()`);

    return {
      call: {
        to: this.factory,
        data: encodeFunctionData({
          abi: CatapultarFactory.abi,
          functionName: "deploy",
          args: [owner, salt],
        }),
        value: 0n,
      },
    };
  }

  /**
   * Signs and broadcasts the deloyment transaction for an upgradable account
   * @param options.owner Owner of the deployed account
   * @param options.salt Salt of the deployed account. The first 20 bytes should be owner. Default: Random.
   * @param options.signer Signer to sign for the transaction.
   * @returns Transaction hash
   */
  deployUpgradable(options: { owner: `0x${string}`; salt?: `0x${string}` }): {
    call: Call;
  } {
    let { owner, salt } = options;
    if (!salt) salt = `${owner}${random(12)}`;
    if (!saltContainsAddress(options.owner, salt))
      throw new Error(`SaltDoesNotStartWith()`);

    return {
      call: {
        to: this.factory,
        data: encodeFunctionData({
          abi: CatapultarFactory.abi,
          functionName: "deployUpgradable",
          args: [owner, salt],
        }),
        value: 0n,
      },
    };
  }

  // /**
  //  * Search transaction for the account initialised event. Returns the address of the event. If multiple accounts are deployed in the same transaction OR if another contract has been initialised in the contract this will not return the expected address.
  //  * @param options.hash Transaction hash to lookup.
  //  * @param options.provider Ethers provider to use.
  //  * @returns First instance of a contract emitting the initialised event. If an account has been deployed in a transaction and no other initialised event has been executed, the account will be returned. Otherwise undefined.
  //  */
  // static async getAccountFromTransaction(options: {
  //   hash: `0x${string}`;
  //   provider: Provider;
  // }): Promise<`0x${string}` | undefined> {
  //   const { hash, provider } = options;
  //   const receipt = await provider.getTransactionReceipt(hash);
  //   if (!receipt) throw new Error(`Could not get receipt for ${hash}`);

  //   // We are searching for the first "initialised" event.
  //   // We could also search for the ownership transfer but this one is more reliable
  //   // and indicates a correct and successful creation.
  //   const INITIALISED_EVENT_TOPIC_0 =
  //     "0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2" as const;
  //   for (const log of receipt.logs) {
  //     const match = log.topics[0] === INITIALISED_EVENT_TOPIC_0;
  //     if (match) return log.address as `0x${string}`;
  //   }
  // }
}
