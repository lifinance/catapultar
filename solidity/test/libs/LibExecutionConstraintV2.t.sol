// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import { Allowance, AllowanceSpend, LibExecutionConstraint, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { LibExecutionConstraintV2 } from "../../src/libs/LibExecutionConstraintV2.sol";

/// @dev The frozen v2 type string: `bytes32 validationProgramHash,bytes32 paramsHash`
/// appended at the END of the ExecutionConstraint(...) field list, sub-type strings
/// unchanged after it. Written out literally here so a drift in the library constant
/// fails against an independent copy.
string constant EXECUTION_CONSTRAINT_V2_TYPE =
    "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,bytes32 validationProgramHash,bytes32 paramsHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)";

contract LibExecutionConstraintV2Test is Test {
    function allowanceSpendToAllowance(
        AllowanceSpend[] memory allowanceSpends
    ) internal pure returns (Allowance[] memory allowances) {
        allowances = new Allowance[](allowanceSpends.length);
        for (uint256 i; i < allowanceSpends.length; ++i) {
            allowances[i] = Allowance({ token: allowanceSpends[i].token, amount: allowanceSpends[i].allocated });
        }
    }

    function typehashReferenceV2(
        Allowance[] memory allowances,
        Outcome[] memory outcomes,
        address executor,
        uint256 nonce,
        bytes32 validationProgramHash,
        bytes32 paramsHash
    ) internal pure returns (bytes32) {
        bytes32[] memory allowanceHashes = new bytes32[](allowances.length);
        for (uint256 i; i < allowances.length; ++i) {
            allowanceHashes[i] = keccak256(
                abi.encode(
                    keccak256(bytes("Allowance(address token,uint256 amount)")),
                    allowances[i].token,
                    allowances[i].amount
                )
            );
        }

        bytes32[] memory outputHashes = new bytes32[](outcomes.length);
        for (uint256 i; i < outcomes.length; ++i) {
            outputHashes[i] = keccak256(
                abi.encode(
                    keccak256(bytes("Outcome(address token,uint256 amount,address destination)")),
                    outcomes[i].token,
                    outcomes[i].amount,
                    outcomes[i].destination
                )
            );
        }

        return keccak256(
            abi.encode(
                keccak256(bytes(EXECUTION_CONSTRAINT_V2_TYPE)),
                keccak256(abi.encodePacked(allowanceHashes)),
                keccak256(abi.encodePacked(outputHashes)),
                executor,
                nonce,
                validationProgramHash,
                paramsHash
            )
        );
    }

    function test_v2TypeHashConstant() external pure {
        assertEq(
            LibExecutionConstraintV2.EXECUTION_CONSTRAINT_V2_TYPE_HASH,
            keccak256(bytes(EXECUTION_CONSTRAINT_V2_TYPE)),
            "type-hash constant drifted from the frozen v2 type string"
        );
    }

    function test_typehashV2(
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        address executor,
        uint256 nonce,
        bytes32 validationProgramHash,
        bytes32 paramsHash
    ) external pure {
        bytes32 libraryTypeHash = LibExecutionConstraintV2.typehash(
            allowances, outcomes, executor, nonce, validationProgramHash, paramsHash
        );
        bytes32 expectedTypeHash = typehashReferenceV2(
            allowanceSpendToAllowance(allowances), outcomes, executor, nonce, validationProgramHash, paramsHash
        );

        assertEq(libraryTypeHash, expectedTypeHash);
    }

    /// @dev v1 and v2 struct hashes must never collide, even for the degenerate
    /// zero-hash constraint (belt to the domain-version-bump braces).
    function test_typehashV2_zeroHashesStillDifferFromV1Shape(
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        address executor,
        uint256 nonce
    ) external pure {
        bytes32 v2 = LibExecutionConstraintV2.typehash(allowances, outcomes, executor, nonce, bytes32(0), bytes32(0));
        bytes32 v1 = LibExecutionConstraint.typehash(allowances, outcomes, executor, nonce);
        assertNotEq(v2, v1);
    }
}
