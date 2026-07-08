// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @dev WARNING! This mock is strictly intended for testing purposes only.
/// Do NOT copy anything here into production code unless you really know what you are doing.
///
/// A configurable ERC-1271 mock. Returns the magic value if and only if both:
///   - the provided signature bytes exactly match `acceptedSignature`, and
///   - the provided hash exactly matches `acceptedDigest`.
contract MockERC1271 {
    bytes4 internal constant _ERC1271_MAGIC_VALUE = 0x1626ba7e;

    bytes32 public acceptedDigest;
    bytes public acceptedSignature;

    constructor(
        bytes32 digest,
        bytes memory signature
    ) {
        acceptedDigest = digest;
        acceptedSignature = signature;
    }

    function setAccepted(
        bytes32 digest,
        bytes calldata signature
    ) external {
        acceptedDigest = digest;
        acceptedSignature = signature;
    }

    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4) {
        if (hash == acceptedDigest && keccak256(signature) == keccak256(acceptedSignature)) {
            return _ERC1271_MAGIC_VALUE;
        }
        return 0xffffffff;
    }
}
