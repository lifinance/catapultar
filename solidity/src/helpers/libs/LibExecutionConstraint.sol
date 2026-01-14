// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { EfficientHashLib } from "solady/src/utils/EfficientHashLib.sol";

struct Allowance {
    address token;
    uint256 amount;
}

struct AllowanceSpend {
    address token;
    uint256 allocated;
    uint256 spend; // 0 means balanceOf.
}

struct Outcome {
    address token;
    uint256 amount;
    address destination;
}

struct ExecutionConstraint {
    Allowance[] allowances;
    Outcome[] outcomes;
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
            "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)"
        )
    );

    bytes32 constant ALLOWANCE_TYPE_HASH = keccak256(bytes("Allowance(address token,uint256 amount)"));

    bytes32 constant OUTPUT_TYPE_HASH = keccak256(bytes("Outcome(address token,uint256 amount,address destination)"));

    function allowancesHash(
        AllowanceSpend[] calldata allowances
    ) internal pure returns (bytes32 h) {
        uint256 numAllowances = allowances.length;
        bytes32[] memory buffer = numAllowances.malloc();
        for (uint256 i; i < numAllowances; ++i) {
            AllowanceSpend calldata allowance = allowances[i];
            buffer[i] =
                ALLOWANCE_TYPE_HASH.hash(bytes32(uint256(uint160(allowance.token))), bytes32(allowance.allocated));
        }
        h = buffer.hash();
        buffer.free();
    }

    function outcomesHash(
        Outcome[] calldata outcomes
    ) internal pure returns (bytes32 h) {
        uint256 numOutcomes = outcomes.length;
        bytes32[] memory buffer = numOutcomes.malloc();
        for (uint256 i; i < numOutcomes; ++i) {
            Outcome calldata outcome = outcomes[i];
            buffer[i] = OUTPUT_TYPE_HASH.hash(
                bytes32(uint256(uint160(outcome.token))),
                bytes32(outcome.amount),
                bytes32(uint256(uint160(outcome.destination)))
            );
        }
        h = buffer.hash();
        buffer.free();
    }

    function typehash(
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        address executor,
        uint256 nonce
    ) internal pure returns (bytes32 messageHash) {
        messageHash = EXECUTION_CONSTRAINT_TYPE_HASH.hash(
            allowancesHash(allowances), outcomesHash(outcomes), bytes32(uint256(uint160(executor))), bytes32(nonce)
        );
    }
}
