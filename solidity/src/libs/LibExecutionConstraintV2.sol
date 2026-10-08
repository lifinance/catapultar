// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.25;

import { EfficientHashLib } from "solady/src/utils/EfficientHashLib.sol";

import { AllowanceSpend, LibExecutionConstraint, Outcome } from "./LibExecutionConstraint.sol";

/**
 * @title LibExecutionConstraintV2
 * @notice EIP-712 struct hashing for the CATValidatorV2 constraint. The v1
 * library stays untouched; this library appends the two commitment hashes to
 * the v1 field list and reuses the v1 `Allowance` and `Outcome` hashing.
 * @dev The type string appends `bytes32 validationProgramHash,bytes32 paramsHash`
 * at the end of the `ExecutionConstraint(...)` field list. The catapultar
 * TypeScript SDK and the LI.FI compose compiler encode the same string; the
 * three must agree byte for byte, or an escrow address derived off-chain can
 * never be settled on-chain.
 */
library LibExecutionConstraintV2 {
    using EfficientHashLib for bytes32;

    bytes32 constant EXECUTION_CONSTRAINT_V2_TYPE_HASH = keccak256(
        bytes(
            "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,bytes32 validationProgramHash,bytes32 paramsHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)"
        )
    );

    function typehash(
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        address executor,
        uint256 nonce,
        bytes32 validationProgramHash,
        bytes32 paramsHash
    ) internal pure returns (bytes32 messageHash) {
        messageHash = EXECUTION_CONSTRAINT_V2_TYPE_HASH.hash(
            LibExecutionConstraint.allowancesHash(allowances),
            LibExecutionConstraint.outcomesHash(outcomes),
            bytes32(uint256(uint160(executor))),
            bytes32(nonce),
            validationProgramHash,
            paramsHash
        );
    }
}
