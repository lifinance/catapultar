// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { LibClone } from "solady/src/utils/LibClone.sol";

import { ExecutorLIFI } from "./ExecutorLIFI.sol";

/**
 * @title LI.FI Executor Proxy Factory
 * @author LIFI
 * @notice Allows deploying proxies (upgradable and not) in front of LI.FI Executors.
 */
contract ExecutorLIFIFactory {
    address public immutable EXECUTOR_NO_EMBEDDED_CALLS;
    address public immutable EXECUTOR_EMBEDDED_CALLS;

    constructor() {
        EXECUTOR_NO_EMBEDDED_CALLS = address(new ExecutorLIFI(false));
        EXECUTOR_EMBEDDED_CALLS = address(new ExecutorLIFI(true));
    }

    /// @param salt The first 20 bytes of salt has to be the owner or 0.
    function deploy(address owner, bytes32 salt) external ownerInSalt(salt, owner) returns (address proxy) {
        proxy = LibClone.cloneDeterministic_PUSH0(address(EXECUTOR_NO_EMBEDDED_CALLS), salt);

        ExecutorLIFI(payable(proxy)).init(owner);
    }

    /// @param salt The first 20 bytes of salt has to be the owner or 0.
    function deployWithEmbedCall(
        address owner,
        bytes32 salt,
        bytes32 callsTypeHash
    ) external ownerInSalt(salt, owner) returns (address proxy) {
        proxy = LibClone.cloneDeterministic(address(EXECUTOR_EMBEDDED_CALLS), abi.encodePacked(callsTypeHash), salt);

        ExecutorLIFI(payable(proxy)).init(owner);
    }

    /// @param salt The first 20 bytes of salt has to be the owner or 0.
    function deployUpgradable(address owner, bytes32 salt) external ownerInSalt(salt, owner) returns (address proxy) {
        proxy = LibClone.deployDeterministicERC1967(address(EXECUTOR_NO_EMBEDDED_CALLS), salt);

        ExecutorLIFI(payable(proxy)).init(owner);
    }

    // --- Helpers --- //

    modifier ownerInSalt(bytes32 salt, address owner) {
        LibClone.checkStartsWith(salt, owner);
        _;
    }
}
