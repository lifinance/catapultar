// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import {
    Input,
    InputTarget,
    LibExecutionConstraint,
    Output
} from "../../../src/helpers/libs/LibExecutionConstraint.sol";

contract LibExecutionConstraintTest is Test {
    function inputTargetToInput(
        InputTarget[] memory inputTargets
    ) internal pure returns (Input[] memory inputs) {
        inputs = new Input[](inputTargets.length);
        for (uint256 i; i < inputTargets.length; ++i) {
            inputs[i] = Input({ token: inputTargets[i].token, amount: inputTargets[i].allocated });
        }
    }

    function typehashReference(
        Input[] memory inputs,
        Output[] memory outputs,
        address executor,
        uint256 nonce
    ) internal pure returns (bytes32) {
        bytes32[] memory inputHashes = new bytes32[](inputs.length);
        for (uint256 i; i < inputs.length; ++i) {
            inputHashes[i] = keccak256(
                abi.encode(keccak256(bytes("Input(address token,uint256 amount)")), inputs[i].token, inputs[i].amount)
            );
        }

        bytes32[] memory outputHashes = new bytes32[](outputs.length);
        for (uint256 i; i < outputs.length; ++i) {
            outputHashes[i] = keccak256(
                abi.encode(
                    keccak256(bytes("Output(address token,uint256 amount,address destination)")),
                    outputs[i].token,
                    outputs[i].amount,
                    outputs[i].destination
                )
            );
        }

        return keccak256(
            abi.encode(
                keccak256(
                    bytes(
                        "ExecutionConstraint(Input[] inputs,Output[] outputs,address executor,uint256 nonce)Input(address token,uint256 amount)Output(address token,uint256 amount,address destination)"
                    )
                ),
                keccak256(abi.encodePacked(inputHashes)),
                keccak256(abi.encodePacked(outputHashes)),
                executor,
                nonce
            )
        );
    }

    function test_typehash(
        InputTarget[] calldata inputs,
        Output[] calldata outputs,
        address executor,
        uint256 nonce
    ) external pure {
        bytes32 libraryTypeHash = LibExecutionConstraint.typehash(inputs, outputs, executor, nonce);
        bytes32 expectedTypeHash = typehashReference(inputTargetToInput(inputs), outputs, executor, nonce);

        assertEq(libraryTypeHash, expectedTypeHash);
    }
}
