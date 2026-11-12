/**
 * ABI of the IntentExecutor (v3, solver-gated execution target). Re-exported as
 * `intentExecutorAbi`.
 *
 * Mirrors the `solidity/src/libs/IntentExecutor.sol` forge artifact; the
 * `IntentExecutor ABI matches the forge artifact` spec guards it against drift.
 * A solver runs a validator `entry` through `fill(validator, entryData)`, which
 * authorizes the entry's `execPayload` for that call only.
 */
export const INTENT_EXECUTOR_ABI = [
  {
    type: "constructor",
    inputs: [
      { name: "owner_", type: "address", internalType: "address" },
      { name: "solvers", type: "address[]", internalType: "address[]" },
    ],
    stateMutability: "nonpayable",
  },
  { type: "receive", stateMutability: "payable" },
  {
    type: "function",
    name: "cancelOwnershipHandover",
    inputs: [],
    outputs: [],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "completeOwnershipHandover",
    inputs: [
      { name: "pendingOwner", type: "address", internalType: "address" },
    ],
    outputs: [],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "executeAndSweep",
    inputs: [
      {
        name: "approvals",
        type: "tuple[]",
        internalType: "struct IntentExecutor.Approval[]",
        components: [
          { name: "token", type: "address", internalType: "address" },
          { name: "spender", type: "address", internalType: "address" },
        ],
      },
      {
        name: "calls",
        type: "tuple[]",
        internalType: "struct IntentExecutor.Call3[]",
        components: [
          { name: "target", type: "address", internalType: "address" },
          { name: "allowFailure", type: "bool", internalType: "bool" },
          { name: "callData", type: "bytes", internalType: "bytes" },
        ],
      },
      {
        name: "sweepTargets",
        type: "tuple[]",
        internalType: "struct IntentExecutor.SweepTarget[]",
        components: [
          { name: "token", type: "address", internalType: "address" },
          { name: "recipient", type: "address", internalType: "address" },
        ],
      },
    ],
    outputs: [
      {
        name: "results",
        type: "tuple[]",
        internalType: "struct IntentExecutor.Result[]",
        components: [
          { name: "success", type: "bool", internalType: "bool" },
          { name: "returnData", type: "bytes", internalType: "bytes" },
        ],
      },
    ],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "executeAndSweepNative",
    inputs: [
      {
        name: "approvals",
        type: "tuple[]",
        internalType: "struct IntentExecutor.Approval[]",
        components: [
          { name: "token", type: "address", internalType: "address" },
          { name: "spender", type: "address", internalType: "address" },
        ],
      },
      {
        name: "calls",
        type: "tuple[]",
        internalType: "struct IntentExecutor.Call3Value[]",
        components: [
          { name: "target", type: "address", internalType: "address" },
          { name: "allowFailure", type: "bool", internalType: "bool" },
          { name: "value", type: "uint256", internalType: "uint256" },
          { name: "callData", type: "bytes", internalType: "bytes" },
        ],
      },
      {
        name: "sweepTargets",
        type: "tuple[]",
        internalType: "struct IntentExecutor.SweepTarget[]",
        components: [
          { name: "token", type: "address", internalType: "address" },
          { name: "recipient", type: "address", internalType: "address" },
        ],
      },
      {
        name: "nativeSweepRecipient",
        type: "address",
        internalType: "address payable",
      },
    ],
    outputs: [
      {
        name: "results",
        type: "tuple[]",
        internalType: "struct IntentExecutor.Result[]",
        components: [
          { name: "success", type: "bool", internalType: "bool" },
          { name: "returnData", type: "bytes", internalType: "bytes" },
        ],
      },
    ],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "fill",
    inputs: [
      { name: "validator", type: "address", internalType: "address" },
      { name: "entryData", type: "bytes", internalType: "bytes" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "isSolver",
    inputs: [{ name: "solver", type: "address", internalType: "address" }],
    outputs: [{ name: "allowed", type: "bool", internalType: "bool" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "owner",
    inputs: [],
    outputs: [{ name: "result", type: "address", internalType: "address" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "ownershipHandoverExpiresAt",
    inputs: [
      { name: "pendingOwner", type: "address", internalType: "address" },
    ],
    outputs: [{ name: "result", type: "uint256", internalType: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "renounceOwnership",
    inputs: [],
    outputs: [],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "requestOwnershipHandover",
    inputs: [],
    outputs: [],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "setSolver",
    inputs: [
      { name: "solver", type: "address", internalType: "address" },
      { name: "allowed", type: "bool", internalType: "bool" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "transferOwnership",
    inputs: [{ name: "", type: "address", internalType: "address" }],
    outputs: [],
    stateMutability: "payable",
  },
  {
    type: "event",
    name: "OwnershipHandoverCanceled",
    inputs: [
      {
        name: "pendingOwner",
        type: "address",
        indexed: true,
        internalType: "address",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "OwnershipHandoverRequested",
    inputs: [
      {
        name: "pendingOwner",
        type: "address",
        indexed: true,
        internalType: "address",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "OwnershipTransferred",
    inputs: [
      {
        name: "oldOwner",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "newOwner",
        type: "address",
        indexed: true,
        internalType: "address",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "SolverSet",
    inputs: [
      {
        name: "solver",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      { name: "allowed", type: "bool", indexed: false, internalType: "bool" },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "Swept",
    inputs: [
      {
        name: "token",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "recipient",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "amount",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "SweptNative",
    inputs: [
      {
        name: "recipient",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "amount",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
    ],
    anonymous: false,
  },
  { type: "error", name: "AlreadyInitialized", inputs: [] },
  { type: "error", name: "CallNotAuthorized", inputs: [] },
  { type: "error", name: "CallNotConsumed", inputs: [] },
  { type: "error", name: "NewOwnerIsZeroAddress", inputs: [] },
  { type: "error", name: "NoHandoverRequest", inputs: [] },
  { type: "error", name: "NotSolver", inputs: [] },
  { type: "error", name: "OwnershipTransferDisabled", inputs: [] },
  { type: "error", name: "Reentrancy", inputs: [] },
  { type: "error", name: "TransientStorageUnsupported", inputs: [] },
  { type: "error", name: "Unauthorized", inputs: [] },
  { type: "error", name: "ZeroRecipient", inputs: [] },
  { type: "error", name: "ZeroSolver", inputs: [] },
] as const;
