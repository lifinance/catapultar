/**
 * @param RaiseRevert If a call fails, raise the revert message and no not spend the nonce.
 * @param SkipRevert If a call fails, skip the call, emit an event. The nonce will be spent if the transaction does not run out of gas.
 */
export enum ExecutionMode {
  RaiseRevert = '0x0100000000007821000100000000000000000000000000000000000000000000',
  SkipRevert = '0x0101000000007821000100000000000000000000000000000000000000000000',
  RaiseRevertMultiChain = '0x0100010000007821000100000000000000000000000000000000000000000000',
  SkipRevertMultiChain = '0x0101010000007821000100000000000000000000000000000000000000000000',
}

export type Executable = Call;
// export type Signable = {
//   domain: any,
//   types: any,
//   primaryType: string,
//   message: any,
// }

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
    { name: 'nonce', type: 'uint256' },
    { name: 'mode', type: 'bytes32' },
    { name: 'calls', type: 'Call[]' },
  ],
  Call: [
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'data', type: 'bytes' },
  ],
} as const;
