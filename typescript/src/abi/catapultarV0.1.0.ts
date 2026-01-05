const CATAPULTAR_V0_1_0_ABI = [
  {
    type: "constructor",
    inputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "fallback",
    stateMutability: "payable",
  },
  {
    type: "receive",
    stateMutability: "payable",
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
    name: "approvedDigest",
    inputs: [
      {
        name: "hash",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    outputs: [
      {
        name: "flag",
        type: "uint8",
        internalType: "enum Catapultar.DigestApproval",
      },
    ],
    stateMutability: "view",
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
    name: "execute",
    inputs: [
      {
        name: "mode",
        type: "bytes32",
        internalType: "bytes32",
      },
      {
        name: "executionData",
        type: "bytes",
        internalType: "bytes",
      },
    ],
    outputs: [],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "getPublicKey",
    inputs: [],
    outputs: [
      {
        name: "keyType",
        type: "uint8",
        internalType: "enum KeyedOwnable.PublicKeyType",
      },
      {
        name: "key",
        type: "bytes32[]",
        internalType: "bytes32[]",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "init",
    inputs: [
      {
        name: "ktp",
        type: "uint8",
        internalType: "enum KeyedOwnable.PublicKeyType",
      },
      {
        name: "owner",
        type: "bytes32[]",
        internalType: "bytes32[]",
      },
    ],
    outputs: [],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "invalidateUnorderedNonces",
    inputs: [
      {
        name: "wordPos",
        type: "uint256",
        internalType: "uint256",
      },
      {
        name: "mask",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    outputs: [],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "isValidSignature",
    inputs: [
      {
        name: "hash",
        type: "bytes32",
        internalType: "bytes32",
      },
      {
        name: "signature",
        type: "bytes",
        internalType: "bytes",
      },
    ],
    outputs: [
      {
        name: "result",
        type: "bytes4",
        internalType: "bytes4",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "nonceBitmap",
    inputs: [
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    outputs: [
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "owner",
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
    name: "publicKeyType",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "uint8",
        internalType: "enum KeyedOwnable.PublicKeyType",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "proxiableUUID",
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
    name: "setSignature",
    inputs: [
      {
        name: "hash",
        type: "bytes32",
        internalType: "bytes32",
      },
      {
        name: "flag",
        type: "uint8",
        internalType: "enum Catapultar.DigestApproval",
      },
    ],
    outputs: [],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "supportsExecutionMode",
    inputs: [
      {
        name: "mode",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    outputs: [
      {
        name: "result",
        type: "bool",
        internalType: "bool",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "transferOwnership",
    inputs: [
      {
        name: "ktp",
        type: "uint8",
        internalType: "enum KeyedOwnable.PublicKeyType",
      },
      {
        name: "nextKey",
        type: "bytes32[]",
        internalType: "bytes32[]",
      },
    ],
    outputs: [],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "transferOwnership",
    inputs: [
      {
        name: "newOwner",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "upgradeToAndCall",
    inputs: [
      {
        name: "newImplementation",
        type: "address",
        internalType: "address",
      },
      {
        name: "data",
        type: "bytes",
        internalType: "bytes",
      },
    ],
    outputs: [],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "upgradeable",
    inputs: [],
    outputs: [
      {
        name: "up",
        type: "bool",
        internalType: "bool",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "CallReverted",
    inputs: [
      {
        name: "extraData",
        type: "bytes32",
        indexed: false,
        internalType: "bytes32",
      },
      {
        name: "revertData",
        type: "bytes",
        indexed: false,
        internalType: "bytes",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "Initialized",
    inputs: [
      {
        name: "version",
        type: "uint64",
        indexed: false,
        internalType: "uint64",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "OwnershipTransferred",
    inputs: [
      {
        name: "newKey",
        type: "uint8",
        indexed: false,
        internalType: "enum KeyedOwnable.PublicKeyType",
      },
      {
        name: "newOwner",
        type: "bytes32[]",
        indexed: false,
        internalType: "bytes32[]",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "SignatureSet",
    inputs: [
      {
        name: "hash",
        type: "bytes32",
        indexed: true,
        internalType: "bytes32",
      },
      {
        name: "flag",
        type: "uint8",
        indexed: false,
        internalType: "enum Catapultar.DigestApproval",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "UnorderedNonceInvalidation",
    inputs: [
      {
        name: "word",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
      {
        name: "mask",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "Upgraded",
    inputs: [
      {
        name: "implementation",
        type: "address",
        indexed: true,
        internalType: "address",
      },
    ],
    anonymous: false,
  },
  {
    type: "error",
    name: "BatchOfBatchesDecodingError",
    inputs: [],
  },
  {
    type: "error",
    name: "DirtyEthereumAddress",
    inputs: [
      {
        name: "",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
  },
  {
    type: "error",
    name: "FnSelectorNotRecognized",
    inputs: [],
  },
  {
    type: "error",
    name: "InvalidInitialization",
    inputs: [],
  },
  {
    type: "error",
    name: "InvalidKey",
    inputs: [],
  },
  {
    type: "error",
    name: "InvalidNonce",
    inputs: [],
  },
  {
    type: "error",
    name: "InvalidOpData",
    inputs: [],
  },
  {
    type: "error",
    name: "NotInitializing",
    inputs: [],
  },
  {
    type: "error",
    name: "NotUpgradeable",
    inputs: [],
  },
  {
    type: "error",
    name: "OpDataTooSmall",
    inputs: [],
  },
  {
    type: "error",
    name: "TooManyCalls",
    inputs: [],
  },
  {
    type: "error",
    name: "Unauthorized",
    inputs: [],
  },
  {
    type: "error",
    name: "UnauthorizedCallContext",
    inputs: [],
  },
  {
    type: "error",
    name: "UnsupportedExecutionMode",
    inputs: [],
  },
  {
    type: "error",
    name: "UpgradeFailed",
    inputs: [],
  },
] as const;

export default CATAPULTAR_V0_1_0_ABI;
