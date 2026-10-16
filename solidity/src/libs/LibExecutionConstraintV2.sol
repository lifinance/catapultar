// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.25;

import { EfficientHashLib } from "solady/src/utils/EfficientHashLib.sol";

import { AllowanceSpend, LibExecutionConstraint, Outcome } from "./LibExecutionConstraint.sol";

/**
 * @notice The committed fill of a V2 constraint: where the allowances go and what
 * the validator calls there.
 * @dev `CATValidatorV2.entry` takes the two fields as one calldata struct, which
 * costs one stack slot instead of two; flat arguments leave `entry` too deep for
 * `forge coverage --ir-minimum`. In the EIP-712 type they stay two flat fields.
 * @param executionTarget Committed `execTarget`. Zero means unconstrained.
 * @param payloadHash Committed `keccak256(execPayload)`. Zero means unconstrained.
 */
struct ExecutionBinding {
    address executionTarget;
    bytes32 payloadHash;
}

/**
 * @title LibExecutionConstraintV2
 * @notice EIP-712 struct hashing for the CATValidatorV2 constraint. The v1
 * library stays untouched; this library extends the v1 field list and reuses
 * the v1 `Allowance` and `Outcome` hashing.
 * @dev The type string appends, after v1's `nonce`, the fill commitment
 * `address executionTarget,bytes32 payloadHash` (the same two fields, in the
 * same position, as intent-factory's CATValidatorV1_1), then the program
 * commitment `bytes32 validationProgramHash,bytes32 paramsHash`. The catapultar
 * TypeScript SDK and the LI.FI compose compiler encode the same string; the
 * three must agree byte for byte, or an escrow address derived off-chain can
 * never be settled on-chain.
 */
library LibExecutionConstraintV2 {
    using EfficientHashLib for bytes32;

    bytes32 constant EXECUTION_CONSTRAINT_V2_TYPE_HASH = keccak256(
        bytes(
            "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,address executionTarget,bytes32 payloadHash,bytes32 validationProgramHash,bytes32 paramsHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)"
        )
    );

    function typehash(
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        address executor,
        uint256 nonce,
        address executionTarget,
        bytes32 payloadHash,
        bytes32 validationProgramHash,
        bytes32 paramsHash
    ) internal pure returns (bytes32 messageHash) {
        messageHash = EXECUTION_CONSTRAINT_V2_TYPE_HASH.hash(
            LibExecutionConstraint.allowancesHash(allowances),
            LibExecutionConstraint.outcomesHash(outcomes),
            bytes32(uint256(uint160(executor))),
            bytes32(nonce),
            bytes32(uint256(uint160(executionTarget))),
            payloadHash,
            validationProgramHash,
            paramsHash
        );
    }
}
