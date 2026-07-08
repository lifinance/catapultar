// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import { Brutalizer } from "solady/test/utils/Brutalizer.sol";

import { KeyedOwnable } from "../../src/libs/KeyedOwnable.sol";

/// @dev WARNING! This mock is strictly intended for testing purposes only.
/// Do NOT copy anything here into production code unless you really know what you are doing.
contract MockKeyedOwnable is KeyedOwnable, Brutalizer {
    function setOwnership(
        PublicKeyType ktp,
        bytes32[] calldata nextKey
    ) public payable {
        _transferOwnership(ktp, nextKey);
    }

    function getPublicKeySlice(
        uint256 index
    ) public view returns (bytes32) {
        return _getPublicKeySlice(index);
    }

    function validateSignature(
        bytes32 digest,
        bytes calldata signature
    ) public view returns (bool) {
        return _validateSignature(digest, signature);
    }

    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) public view returns (bytes4 result) {
        if (_validateSignature(hash, signature)) return bytes4(0x1626ba7e);
        return 0xffffffff;
    }
}
