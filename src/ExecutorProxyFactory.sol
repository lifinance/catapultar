// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import {LibClone} from "solady/src/utils/LibClone.sol";
import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";

import {ExecutorLIFI} from "./ExecutorLIFI.sol";

/**
 * @title LI.FI Executor Proxy Factory
 * @author LIFI
 * @notice Allows deploying proxies (upgradable and not) in front of LI.FI Executors.
 */
contract ExecutorProxyFactory {
    error OwnerNotContainedInSalt(address owner, bytes32 salt);

    address public immutable EXECUTOR_NO_EMBEDDED_CALLS;
    address public immutable EXECUTOR_EMBEDDED_CALLS;

    constructor() {
        EXECUTOR_NO_EMBEDDED_CALLS = address(new ExecutorLIFI(false));
        EXECUTOR_EMBEDDED_CALLS = address(new ExecutorLIFI(true));
    }

    /// @param salt Requires that the first 20 bytes of salt is the owner
    function deploy(address owner, bytes32 salt) external ownerInSalt(owner, salt) returns (address proxy) {
        proxy = LibClone.cloneDeterministic_PUSH0(address(EXECUTOR_NO_EMBEDDED_CALLS), salt);

        ExecutorLIFI(payable(proxy)).init(owner, bytes32(0));
    }

    function deployUpgradable(address owner, bytes32 salt) external ownerInSalt(owner, salt) returns (address proxy) {
        proxy = LibClone.deployDeterministicERC1967(address(EXECUTOR_NO_EMBEDDED_CALLS), salt);

        ExecutorLIFI(payable(proxy)).init(owner, bytes32(0));
    }

    function deployWithEmbedCall(address owner, bytes32 salt, bytes32 callsTypeHash)
        external
        ownerInSalt(owner, salt)
        returns (address proxy)
    {
        proxy = LibClone.deployDeterministicERC1967(
            address(EXECUTOR_EMBEDDED_CALLS), EfficientHashLib.hash(salt, callsTypeHash)
        );

        ExecutorLIFI(payable(proxy)).init(owner, callsTypeHash);
    }

    function deployUpgradableWithEmbedCall(address owner, bytes32 salt, bytes32 callsTypeHash)
        external
        ownerInSalt(owner, salt)
        returns (address proxy)
    {
        proxy = LibClone.deployDeterministicERC1967(
            address(EXECUTOR_EMBEDDED_CALLS), EfficientHashLib.hash(salt, callsTypeHash)
        );

        ExecutorLIFI(payable(proxy)).init(owner, callsTypeHash);
    }

    // --- Helpers --- //

    modifier ownerInSalt(address owner, bytes32 salt) {
        if (!addrInSalt(owner, salt)) revert OwnerNotContainedInSalt(owner, salt);
        _;
    }

    function addrInSalt(address addr, bytes32 salt) internal pure returns (bool contains) {
        assembly ("memory-safe") {
            contains := eq(addr, shr(mul(8, 96), salt))
        }
    }
}
