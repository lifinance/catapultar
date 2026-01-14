// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import {
    Allowance,
    AllowanceSpend,
    LibExecutionConstraint,
    Outcome
} from "../../../src/helpers/libs/LibExecutionConstraint.sol";

contract LibExecutionConstraintTest is Test {
    function allowanceSpendToAllowance(
        AllowanceSpend[] memory allowanceSpends
    ) internal pure returns (Allowance[] memory allowances) {
        allowances = new Allowance[](allowanceSpends.length);
        for (uint256 i; i < allowanceSpends.length; ++i) {
            allowances[i] = Allowance({ token: allowanceSpends[i].token, amount: allowanceSpends[i].allocated });
        }
    }

    function typehashReference(
        Allowance[] memory allowances,
        Outcome[] memory outcomes,
        address executor,
        uint256 nonce
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
                keccak256(
                    bytes(
                        "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)"
                    )
                ),
                keccak256(abi.encodePacked(allowanceHashes)),
                keccak256(abi.encodePacked(outputHashes)),
                executor,
                nonce
            )
        );
    }

    function test_typehash(
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        address executor,
        uint256 nonce
    ) external pure {
        bytes32 libraryTypeHash = LibExecutionConstraint.typehash(allowances, outcomes, executor, nonce);
        bytes32 expectedTypeHash = typehashReference(allowanceSpendToAllowance(allowances), outcomes, executor, nonce);

        assertEq(libraryTypeHash, expectedTypeHash);
    }
}
