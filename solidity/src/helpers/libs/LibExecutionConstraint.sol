// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { EfficientHashLib } from "solady/src/utils/EfficientHashLib.sol";

struct Input {
    address token;
    uint256 amount;
}

struct InputTarget {
    address token;
    uint256 allocated;
    uint256 spend; // 0 means balanceOf. Note that if allocated != 0, then this may fail since balanceOf may be larger
    // than allocated.
}

struct Output {
    address token;
    uint256 amount;
    address destination;
}

struct ExecutionConstraint {
    Input[] inputs;
    Output[] outputs;
    address executor;
    uint256 nonce;
}

library LibExecutionConstraint {
    using EfficientHashLib for uint256;
    using EfficientHashLib for bytes;
    using EfficientHashLib for bytes32;
    using EfficientHashLib for bytes32[];

    bytes32 constant EXECUTION_CONSTRAINT_TYPE_HASH = keccak256(
        bytes(
            "ExecutionConstraint(Input[] inputs,Output[] outputs,address executor,uint256 nonce)Input(address token,uint256 amount)Output(address token,uint256 amount,address destination)"
        )
    );

    bytes32 constant INPUT_TYPE_HASH = keccak256(bytes("Input(address token,uint256 amount)"));

    bytes32 constant OUTPUT_TYPE_HASH = keccak256(bytes("Output(address token,uint256 amount,address destination)"));

    function inputsHash(
        InputTarget[] calldata inputs
    ) internal pure returns (bytes32 h) {
        uint256 numInputs = inputs.length;
        bytes32[] memory buffer = numInputs.malloc();
        for (uint256 i; i < numInputs; ++i) {
            InputTarget calldata input = inputs[i];
            buffer[i] = INPUT_TYPE_HASH.hash(bytes32(uint256(uint160(input.token))), bytes32(input.allocated));
        }
        h = buffer.hash();
        buffer.free();
    }

    function outputsHash(
        Output[] calldata outputs
    ) internal pure returns (bytes32 h) {
        uint256 numOutputs = outputs.length;
        bytes32[] memory buffer = numOutputs.malloc();
        for (uint256 i; i < numOutputs; ++i) {
            Output calldata output = outputs[i];
            buffer[i] = OUTPUT_TYPE_HASH.hash(
                bytes32(uint256(uint160(output.token))),
                bytes32(output.amount),
                bytes32(uint256(uint160(output.destination)))
            );
        }
        h = buffer.hash();
        buffer.free();
    }

    function typehash(
        InputTarget[] calldata inputs,
        Output[] calldata outputs,
        address executor,
        uint256 nonce
    ) internal pure returns (bytes32 messageHash) {
        messageHash = EXECUTION_CONSTRAINT_TYPE_HASH.hash(
            inputsHash(inputs), outputsHash(outputs), bytes32(uint256(uint160(executor))), bytes32(nonce)
        );
    }
}
