// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { ExecutionBinding } from "../../src/libs/LibExecutionConstraintV2.sol";

/**
 * @notice The `CATValidatorV2` EIP-712 digest, encoded without
 * `LibExecutionConstraintV2`: the type string is written out here, so a drift in
 * the library makes every test that signs with this helper fail its signature
 * check. `LibExecutionConstraintV2.t.sol` keeps its own literal copy on purpose,
 * to test the library constants directly.
 */
library V2ConstraintDigest {
    bytes32 internal constant ALLOWANCE_TYPEHASH = keccak256(bytes("Allowance(address token,uint256 amount)"));
    bytes32 internal constant OUTCOME_TYPEHASH =
        keccak256(bytes("Outcome(address token,uint256 amount,address destination)"));
    bytes32 internal constant EXECUTION_CONSTRAINT_TYPEHASH = keccak256(
        bytes(
            "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,address executionTarget,bytes32 payloadHash,bytes32 validationProgramHash,bytes32 paramsHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)"
        )
    );

    function digest(
        bytes32 domainSeparator,
        AllowanceSpend[] memory allowances,
        Outcome[] memory outcomes,
        address executor,
        uint256 nonce,
        ExecutionBinding memory binding,
        bytes32 validationProgramHash,
        bytes32 paramsHash
    ) internal pure returns (bytes32) {
        bytes32 structHash = hashConstraint(
            hashAllowances(allowances),
            hashOutcomes(outcomes),
            executor,
            nonce,
            binding,
            validationProgramHash,
            paramsHash
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function hashConstraint(
        bytes32 allowancesHash,
        bytes32 outcomesHash,
        address executor,
        uint256 nonce,
        ExecutionBinding memory binding,
        bytes32 validationProgramHash,
        bytes32 paramsHash
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                EXECUTION_CONSTRAINT_TYPEHASH,
                allowancesHash,
                outcomesHash,
                executor,
                nonce,
                binding.executionTarget,
                binding.payloadHash,
                validationProgramHash,
                paramsHash
            )
        );
    }

    /// @notice The digest of an unbound constraint: zero `executionTarget` and `payloadHash`.
    function unbound(
        bytes32 domainSeparator,
        AllowanceSpend[] memory allowances,
        Outcome[] memory outcomes,
        address executor,
        uint256 nonce,
        bytes32 validationProgramHash,
        bytes32 paramsHash
    ) internal pure returns (bytes32) {
        return digest(
            domainSeparator,
            allowances,
            outcomes,
            executor,
            nonce,
            ExecutionBinding({ executionTarget: address(0), payloadHash: bytes32(0) }),
            validationProgramHash,
            paramsHash
        );
    }

    function hashAllowances(
        AllowanceSpend[] memory allowances
    ) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](allowances.length);
        for (uint256 i; i < allowances.length; ++i) {
            hashes[i] = keccak256(abi.encode(ALLOWANCE_TYPEHASH, allowances[i].token, allowances[i].allocated));
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function hashOutcomes(
        Outcome[] memory outcomes
    ) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](outcomes.length);
        for (uint256 i; i < outcomes.length; ++i) {
            hashes[i] = keccak256(
                abi.encode(OUTCOME_TYPEHASH, outcomes[i].token, outcomes[i].amount, outcomes[i].destination)
            );
        }
        return keccak256(abi.encodePacked(hashes));
    }
}
