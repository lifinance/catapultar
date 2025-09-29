// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import {ERC7821} from "solady/src/accounts/ERC7821.sol";
import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";

struct Calls {
    bytes32 mode;
    uint256 nonce;
    ERC7821.Call[] calls;
}

library LibCalls {
    using EfficientHashLib for uint256;
    using EfficientHashLib for bytes;
    using EfficientHashLib for bytes32;
    using EfficientHashLib for bytes32[];

    bytes32 constant CALLS_TYPE_HASH =
        keccak256(bytes("Calls(bytes32 mode,uint256 nonce,Call[] calls)Call(address to,uint256 value,bytes data)"));

    bytes32 constant CALL_TYPE_HASH = keccak256(bytes("Call(address to,uint256 value,bytes data)"));

    function typehash(bytes32 mode, uint256 nonce, ERC7821.Call[] calldata calls)
        internal
        pure
        returns (bytes32 messageHash)
    {
        uint256 numCalls = calls.length;
        // Create a buffer for hashing
        bytes32[] memory buffer = numCalls.malloc();
        // Insert typehashes of all calls into the buffer
        for (uint256 i; i < numCalls; ++i) {
            ERC7821.Call calldata call = calls[i];
            buffer[i] =
                CALL_TYPE_HASH.hash(bytes32(uint256(uint160(call.to))), bytes32(call.value), call.data.hashCalldata());
        }
        // Get typehash of struct Calls
        messageHash = CALLS_TYPE_HASH.hash(mode, bytes32(nonce), buffer.hash());
        // Destory buffer
        buffer.free();
    }
}
