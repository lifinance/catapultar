// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { EfficientHashLib } from "solady/src/utils/EfficientHashLib.sol";

import { AllowanceSpend, LibExecutionConstraint, Outcome } from "./LibExecutionConstraint.sol";

/**
 * @title LibExecutionConstraintV2
 * @notice EIP-712 struct hashing for the v2 constraint. Standalone by design:
 * v1 (`LibExecutionConstraint`) stays byte-identical for existing bundles and
 * addresses; only `CATValidatorV2` consumes this library.
 * @dev The type string appends `bytes32 validationProgramHash,bytes32 paramsHash`
 * at the END of the ExecutionConstraint(...) field list; the Allowance/Outcome
 * sub-type strings (and their hashing, reused from v1) are unchanged. This string
 * is independently encoded by the catapultar TS SDK (and, in a later PR of
 * this stack, the catapultar-utils mirror) — the encoders
 * are pinned to each other by the shared C2 fixture
 * (contract/fixtures/sca-parity/ in the umbrella workspace).
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
