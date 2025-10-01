// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/Test.sol";

import { ERC7821 } from "solady/src/accounts/ERC7821.sol";

import { LibCalls } from "../../src/libs/LibCalls.sol";

contract LibCallsTest is Test {
    function typehashReference(
        uint256 nonce,
        bytes32 mode,
        ERC7821.Call[] calldata calls
    ) internal pure returns (bytes32) {
        bytes32[] memory callHashes = new bytes32[](calls.length);
        for (uint256 i; i < calls.length; ++i) {
            callHashes[i] = keccak256(
                abi.encode(
                    keccak256(bytes("Call(address to,uint256 value,bytes data)")),
                    calls[i].to,
                    calls[i].value,
                    keccak256(calls[i].data)
                )
            );
        }

        return keccak256(
            abi.encode(
                keccak256(
                    bytes("Calls(uint256 nonce,bytes32 mode,Call[] calls)Call(address to,uint256 value,bytes data)")
                ),
                nonce,
                mode,
                keccak256(abi.encodePacked(callHashes))
            )
        );
    }

    function test_typehash(uint256 nonce, bytes32 mode, ERC7821.Call[] calldata calls) external pure {
        bytes32 libraryTypeHash = LibCalls.typehash(nonce, mode, calls);
        bytes32 expectedTypeHash = typehashReference(nonce, mode, calls);

        assertEq(libraryTypeHash, expectedTypeHash);
    }
}
