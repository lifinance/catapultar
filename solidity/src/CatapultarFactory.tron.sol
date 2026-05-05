// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.25;

import { LibCloneTron } from "./libs/LibClone.tron.sol";

import { CatapultarFactory } from "./CatapultarFactory.sol";

/// @title Catapultar Factory Tron
/// @author Alexander @ LIFI (https://li.fi)
/// @notice Tron variant of CatapultarFactory. Overrides clone helpers to use
/// the Tron CREATE2 prefix (0x41) for deterministic address prediction.
contract CatapultarFactoryTron is CatapultarFactory {
    function _cloneDeterministic(
        bytes32 salt
    ) internal override returns (address) {
        return LibCloneTron.cloneDeterministic_PUSH0(EXECUTOR, salt);
    }

    function _predictCloneAddress(
        bytes32 salt
    ) internal view override returns (address) {
        return LibCloneTron.predictDeterministicAddress_PUSH0(EXECUTOR, salt, address(this));
    }

    function _deployUpgradeable(
        bytes32 salt
    ) internal override returns (address) {
        return LibCloneTron.deployDeterministicERC1967(EXECUTOR, salt);
    }

    function _predictUpgradeableAddress(
        bytes32 salt
    ) internal view override returns (address) {
        return LibCloneTron.predictDeterministicAddressERC1967(EXECUTOR, salt, address(this));
    }
}
