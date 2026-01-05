/**
 * @param RaiseRevert If a call fails, raise the revert message and do not spend the nonce.
 * @param SkipRevert If a call fails, skip the call, emit an event. The nonce will be spent if the transaction does not run out of gas.
 */
export enum ExecutionMode {
  RaiseRevert = "0x0100000000007821000100000000000000000000000000000000000000000000",
  SkipRevert = "0x0101000000007821000100000000000000000000000000000000000000000000",
  RaiseRevertMultiChain = "0x0100010000007821000100000000000000000000000000000000000000000000",
  SkipRevertMultiChain = "0x0101010000007821000100000000000000000000000000000000000000000000",
}
export enum AccountPublicKeyType {
  ECDSAOrSmartContract = 0,
  P256 = 1,
  WebAuthnP256 = 2,
}

export type P256Points = [`0x${string}`, `0x${string}`];
export type AccountPublicVar<T extends AccountPublicKeyType> =
  T extends AccountPublicKeyType.ECDSAOrSmartContract
    ? `0x${string}`
    : P256Points;

export type WebAuthnSignature = {
  authenticatorData: `0x${string}`;
  clientDataJSON: string;
  challengeIndex: number;
  typeIndex: number;
  r: bigint;
  s: bigint;
};

export type KeyedSignature<T extends AccountPublicKeyType> =
  T extends AccountPublicKeyType.ECDSAOrSmartContract
    ? `0x${string}`
    : T extends AccountPublicKeyType.P256
      ? `0x${string}`
      : WebAuthnSignature;

export type Version = `0.1.0` | "0.0.1";

export type Executable = Call;
// export type Signable = {
//   domain: any,
//   types: any,
//   primaryType: string,
//   message: any,
// }

export type AccountConstructorParams<
  V,
  RPC,
  AKT extends AccountPublicKeyType,
> = {
  address: `0x${string}`;
  accountPublicKeyType?: AKT;
  pubkey: AccountPublicVar<AKT>;
  name?: string;
  version?: V;
} & (undefined extends RPC
  ? {
      rpc?: RPC;
      chainId?: number;
    }
  : {
      rpc: RPC;
      chainId: number;
    });

export type Call = {
  to: `0x${string}`;
  value: bigint;
  data: `0x${string}`;
};

export type Calls = {
  nonce: bigint;
  mode: `0x${string}`;
  calls: Call[];
};

export const CallsTyped = {
  Calls: [
    { name: "nonce", type: "uint256" },
    { name: "mode", type: "bytes32" },
    { name: "calls", type: "Call[]" },
  ],
  Call: [
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "data", type: "bytes" },
  ],
} as const;

//-- Factory pattern types --//

export type EmbeddedCall = {
  callDigest: `0x${string}`;
  isSignature: boolean;
};

export type Factory = {
  factory: `0x${string}`;
  template: `0x${string}`;
};

export type Pubkey<AKT extends AccountPublicKeyType> = {
  keyType: AKT;
  pubkey: AccountPublicVar<AKT>;
};
