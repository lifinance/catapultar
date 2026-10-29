// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { EfficientHashLib } from "solady/src/utils/EfficientHashLib.sol";

import { AllowanceSpend, LibExecutionConstraint, Outcome } from "./LibExecutionConstraint.sol";

/// @notice v1 type string plus the committed `executionTarget` and `payloadHash`.
library LibExecutionConstraintV1_1 {
    using EfficientHashLib for bytes32;

    bytes32 constant EXECUTION_CONSTRAINT_TYPE_HASH = keccak256(
        bytes(
            "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,address executionTarget,bytes32 payloadHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)"
        )
    );

    function typehash(
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        address executor,
        uint256 nonce,
        address executionTarget,
        bytes32 payloadHash
    ) internal pure returns (bytes32 messageHash) {
        messageHash = EXECUTION_CONSTRAINT_TYPE_HASH.hash(
            LibExecutionConstraint.allowancesHash(allowances),
            LibExecutionConstraint.outcomesHash(outcomes),
            bytes32(uint256(uint160(executor))),
            bytes32(nonce),
            bytes32(uint256(uint160(executionTarget))),
            payloadHash
        );
    }
}
