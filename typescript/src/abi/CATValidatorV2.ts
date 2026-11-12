/**
 * ABI of the CATValidatorV2 (constraint validator with a committed validation
 * program). Re-exported as `catValidatorV2Abi`.
 *
 * Mirrors the `solidity/src/CATValidatorV2.sol` forge artifact; the
 * `CATValidatorV2 ABI matches the forge artifact` spec guards it against drift.
 * The 10-argument `entry` takes v1's inputs with the signed `binding`
 * (`executionTarget`, `payloadHash`), `validationProgram` and
 * `validationParams` inserted between `outcomes` and `signature`; the
 * contract derives both program hashes itself. The inherited 7-argument
 * `entry` always reverts `V1EntryDisabled()`.
 */
export const CAT_VALIDATOR_V2_ABI = [
  {
    type: "constructor",
    inputs: [
      {
        name: "virtualMachine",
        type: "address",
        internalType: "address",
      },
    ],
    stateMutability: "nonpayable",
  },
  {
    type: "receive",
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "CALL_PROXY",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "address",
        internalType: "address",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "DOMAIN_SEPARATOR",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "VIRTUAL_MACHINE",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "address",
        internalType: "address",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "__activateTstore",
    inputs: [],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "eip712Domain",
    inputs: [],
    outputs: [
      {
        name: "fields",
        type: "bytes1",
        internalType: "bytes1",
      },
      {
        name: "name",
        type: "string",
        internalType: "string",
      },
      {
        name: "version",
        type: "string",
        internalType: "string",
      },
      {
        name: "chainId",
        type: "uint256",
        internalType: "uint256",
      },
      {
        name: "verifyingContract",
        type: "address",
        internalType: "address",
      },
      {
        name: "salt",
        type: "bytes32",
        internalType: "bytes32",
      },
      {
        name: "extensions",
        type: "uint256[]",
        internalType: "uint256[]",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "entry",
    inputs: [
      {
        name: "execTarget",
        type: "address",
        internalType: "address",
      },
      {
        name: "execPayload",
        type: "bytes",
        internalType: "bytes",
      },
      {
        name: "account",
        type: "address",
        internalType: "address",
      },
      {
        name: "nonce",
        type: "uint256",
        internalType: "uint256",
      },
      {
        name: "allowances",
        type: "tuple[]",
        internalType: "struct AllowanceSpend[]",
        components: [
          {
            name: "token",
            type: "address",
            internalType: "address",
          },
          {
            name: "allocated",
            type: "uint256",
            internalType: "uint256",
          },
          {
            name: "spend",
            type: "uint256",
            internalType: "uint256",
          },
        ],
      },
      {
        name: "outcomes",
        type: "tuple[]",
        internalType: "struct Outcome[]",
        components: [
          {
            name: "token",
            type: "address",
            internalType: "address",
          },
          {
            name: "amount",
            type: "uint256",
            internalType: "uint256",
          },
          {
            name: "destination",
            type: "address",
            internalType: "address",
          },
        ],
      },
      {
        name: "binding",
        type: "tuple",
        internalType: "struct ExecutionBinding",
        components: [
          {
            name: "executionTarget",
            type: "address",
            internalType: "address",
          },
          {
            name: "payloadHash",
            type: "bytes32",
            internalType: "bytes32",
          },
        ],
      },
      {
        name: "validationProgram",
        type: "tuple[]",
        internalType: "struct VMCommand[]",
        components: [
          {
            name: "op",
            type: "uint8",
            internalType: "uint8",
          },
          {
            name: "data",
            type: "bytes32",
            internalType: "bytes32",
          },
        ],
      },
      {
        name: "validationParams",
        type: "bytes32[]",
        internalType: "bytes32[]",
      },
      {
        name: "signature",
        type: "bytes",
        internalType: "bytes",
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "entry",
    inputs: [
      {
        name: "",
        type: "address",
        internalType: "address",
      },
      {
        name: "",
        type: "bytes",
        internalType: "bytes",
      },
      {
        name: "",
        type: "address",
        internalType: "address",
      },
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
      {
        name: "",
        type: "tuple[]",
        internalType: "struct AllowanceSpend[]",
        components: [
          {
            name: "token",
            type: "address",
            internalType: "address",
          },
          {
            name: "allocated",
            type: "uint256",
            internalType: "uint256",
          },
          {
            name: "spend",
            type: "uint256",
            internalType: "uint256",
          },
        ],
      },
      {
        name: "",
        type: "tuple[]",
        internalType: "struct Outcome[]",
        components: [
          {
            name: "token",
            type: "address",
            internalType: "address",
          },
          {
            name: "amount",
            type: "uint256",
            internalType: "uint256",
          },
          {
            name: "destination",
            type: "address",
            internalType: "address",
          },
        ],
      },
      {
        name: "",
        type: "bytes",
        internalType: "bytes",
      },
    ],
    outputs: [],
    stateMutability: "pure",
  },
  {
    type: "function",
    name: "spentNonces",
    inputs: [
      {
        name: "",
        type: "address",
        internalType: "address",
      },
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    outputs: [
      {
        name: "",
        type: "bool",
        internalType: "bool",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "error",
    name: "AllocationTooSmall",
    inputs: [
      {
        name: "allocated",
        type: "uint256",
        internalType: "uint256",
      },
      {
        name: "spend",
        type: "uint256",
        internalType: "uint256",
      },
    ],
  },
  {
    type: "error",
    name: "BadSignature",
    inputs: [],
  },
  {
    type: "error",
    name: "BadValidationParams",
    inputs: [],
  },
  {
    type: "error",
    name: "BalanceOfFailed",
    inputs: [
      {
        name: "token",
        type: "address",
        internalType: "address",
      },
    ],
  },
  {
    type: "error",
    name: "InvalidTokenAmount",
    inputs: [
      {
        name: "expected",
        type: "uint256",
        internalType: "uint256",
      },
      {
        name: "received",
        type: "uint256",
        internalType: "uint256",
      },
    ],
  },
  {
    type: "error",
    name: "InvalidVirtualMachine",
    inputs: [],
  },
  {
    type: "error",
    name: "NonceAlreadySpent",
    inputs: [],
  },
  {
    type: "error",
    name: "OnlyDirectCalls",
    inputs: [],
  },
  {
    type: "error",
    name: "PayloadNotCommitted",
    inputs: [],
  },
  {
    type: "error",
    name: "Reentrancy",
    inputs: [],
  },
  {
    type: "error",
    name: "TStoreAlreadyActivated",
    inputs: [],
  },
  {
    type: "error",
    name: "TStoreNotSupported",
    inputs: [],
  },
  {
    type: "error",
    name: "TargetNotCommitted",
    inputs: [],
  },
  {
    type: "error",
    name: "TloadTestContractDeploymentFailed",
    inputs: [],
  },
  {
    type: "error",
    name: "V1EntryDisabled",
    inputs: [],
  },
  {
    type: "error",
    name: "ValidationFailed",
    inputs: [
      {
        name: "revertData",
        type: "bytes",
        internalType: "bytes",
      },
    ],
  },
] as const;
