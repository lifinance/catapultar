/** ABI of the CatapultarFactory. Re-exported as `catapultarFactoryAbi`. */
const CATAPULTAR_FACTORY_ABI = [
  {
    type: "constructor",
    inputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "EXECUTOR",
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
    name: "VERSION",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "string",
        internalType: "string",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "deploy",
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
      {
        name: "salt",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    outputs: [
      {
        name: "proxy",
        type: "address",
        internalType: "address",
      },
    ],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "deployUpgradeable",
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
      {
        name: "salt",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    outputs: [
      {
        name: "proxy",
        type: "address",
        internalType: "address",
      },
    ],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "deployWithDigest",
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
      {
        name: "salt",
        type: "bytes32",
        internalType: "bytes32",
      },
      {
        name: "digest",
        type: "bytes32",
        internalType: "bytes32",
      },
      {
        name: "isSignature",
        type: "bool",
        internalType: "bool",
      },
    ],
    outputs: [
      {
        name: "proxy",
        type: "address",
        internalType: "address",
      },
    ],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "predictDeploy",
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
      {
        name: "salt",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    outputs: [
      {
        name: "proxy",
        type: "address",
        internalType: "address",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "predictDeployUpgradeable",
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
      {
        name: "salt",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    outputs: [
      {
        name: "proxy",
        type: "address",
        internalType: "address",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "predictDeployWithDigest",
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
      {
        name: "salt",
        type: "bytes32",
        internalType: "bytes32",
      },
      {
        name: "digest",
        type: "bytes32",
        internalType: "bytes32",
      },
      {
        name: "isSignature",
        type: "bool",
        internalType: "bool",
      },
    ],
    outputs: [
      {
        name: "proxy",
        type: "address",
        internalType: "address",
      },
    ],
    stateMutability: "view",
  },
] as const;

export default CATAPULTAR_FACTORY_ABI;
